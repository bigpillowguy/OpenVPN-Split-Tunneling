//! Opt-in transparent port-53 routing. No resolver API or direct fallback.
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Result};
use etherparse::{NetSlice, SlicedPacket, TransportSlice};

use crate::pidlookup::OwnerLookup;
use crate::process::Resolver;
use crate::session_binding::{DnsSession, SessionSource};
use crate::shutdown::Shutdown;
use crate::vpn_state::{self, VpnState};

pub const POLL: Duration = Duration::from_millis(250);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    UnknownOwner,
    AmbiguousOwner,
    UnavailablePolicy,
    UnavailableSession,
    UnsupportedTransport,
    InvalidPacket,
    InjectionFailed,
    FlowRejected,
    QueueUnavailable,
    Revoked,
}

impl Fault {
    pub fn code(self) -> &'static str {
        match self {
            Self::UnknownOwner => "unknown_owner",
            Self::AmbiguousOwner => "ambiguous_owner",
            Self::UnavailablePolicy => "unavailable_policy",
            Self::UnavailableSession => "unavailable_session",
            Self::UnsupportedTransport => "unsupported_transport",
            Self::InvalidPacket => "invalid_packet",
            Self::InjectionFailed => "injection_failed",
            Self::FlowRejected => "flow_rejected",
            Self::QueueUnavailable => "queue_unavailable",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lease {
    pub pid: u32,
    pub creation_time: u64,
    pub exe_path: String,
    pub dns: DnsSession,
    pub control_revision: u64,
}

pub enum Decision {
    Pass,
    Tunnel(Lease),
    Drop(Fault),
}

pub trait Authority: Send + Sync {
    fn decide(&self, owner: OwnerLookup) -> Decision;
}

pub struct LiveAuthority {
    resolver: Arc<Resolver>,
    session: SessionSource,
    vpn: VpnState,
    shutdown: Shutdown,
    control: crate::dns_control::ControlSource,
}

impl LiveAuthority {
    pub fn new(
        resolver: Arc<Resolver>,
        session: SessionSource,
        vpn: VpnState,
        shutdown: Shutdown,
        control: crate::dns_control::ControlSource,
    ) -> Self {
        Self {
            resolver,
            session,
            vpn,
            shutdown,
            control,
        }
    }

    pub fn ready_session(&self) -> Option<DnsSession> {
        if self.shutdown.is_stopped() {
            return None;
        }
        let dns = self.session.current_dns().ok()??;
        (vpn_state::current(&self.vpn) == Some(dns.target)).then_some(dns)
    }

    pub fn control_state(&self) -> crate::dns_control::Acknowledgement {
        self.control.current()
    }

    pub fn poll_control(
        &self,
        dns: Option<&DnsSession>,
        cleanup: impl FnOnce(),
    ) -> crate::dns_control::Acknowledgement {
        self.control.poll(dns, &self.resolver, cleanup)
    }
}

impl Authority for LiveAuthority {
    fn decide(&self, owner: OwnerLookup) -> Decision {
        let applied = self.control.current();
        if !applied.armed {
            return Decision::Pass;
        }
        let result = decide_with(
            owner,
            std::process::id(),
            |pid| self.resolver.resolve(pid),
            crate::tunneled::load_from_disk,
            || self.ready_session().filter(|dns| applied.permits(dns)),
        );
        let now = self.control.current();
        if !now.armed || now.revision != applied.revision {
            return Decision::Drop(Fault::Revoked);
        }
        match result {
            Decision::Tunnel(mut lease) => {
                lease.control_revision = applied.revision;
                Decision::Tunnel(lease)
            }
            other => other,
        }
    }
}

fn decide_with(
    owner: OwnerLookup,
    self_pid: u32,
    resolve: impl FnOnce(u32) -> Option<crate::process::ProcessInfo>,
    policy: impl FnOnce() -> Result<Vec<std::path::PathBuf>>,
    session: impl FnOnce() -> Option<DnsSession>,
) -> Decision {
    let pid = match owner {
        OwnerLookup::Unique(pid) if pid == self_pid => return Decision::Pass,
        OwnerLookup::Unique(pid) => pid,
        OwnerLookup::Unknown => return Decision::Drop(Fault::UnknownOwner),
        OwnerLookup::Ambiguous => return Decision::Drop(Fault::AmbiguousOwner),
    };
    let Some(process) = resolve(pid) else {
        if crate::dns_broker::trace::allow(crate::dns_broker::trace::Category::Ownership) {
            tracing::warn!(pid, "split DNS owner process identity unavailable");
        }
        return Decision::Drop(Fault::UnknownOwner);
    };
    // Read synchronously: a newly selected application must not use the
    // watcher's previous path list for its first DNS query.
    let Ok(paths) = policy() else {
        return Decision::Drop(Fault::UnavailablePolicy);
    };
    let selected = paths.iter().any(|path| same_path(path, &process.exe_path));
    if !selected {
        return Decision::Pass;
    }
    let Some(dns) = session() else {
        return Decision::Drop(Fault::UnavailableSession);
    };
    Decision::Tunnel(Lease {
        pid,
        creation_time: process.creation_time,
        exe_path: process.exe_path,
        dns,
        control_revision: 0,
    })
}

fn same_path(path: &Path, other: &str) -> bool {
    path.to_string_lossy()
        .replace('/', "\\")
        .eq_ignore_ascii_case(&other.replace('/', "\\"))
}

#[derive(Clone)]
pub struct Permit {
    pub lease: Lease,
    authority: Arc<dyn Authority>,
}

impl Permit {
    pub fn new(lease: Lease, authority: Arc<dyn Authority>) -> Self {
        Self { lease, authority }
    }

    pub fn valid(&self) -> bool {
        matches!(self.authority.decide(OwnerLookup::Unique(self.lease.pid)), Decision::Tunnel(now) if now == self.lease)
    }

    pub fn check(&self) -> Result<()> {
        if !self.valid() {
            bail!("split DNS lease revoked")
        }
        Ok(())
    }

    pub fn can_deliver_to(&self, owner: OwnerLookup) -> bool {
        owner == OwnerLookup::Unique(self.lease.pid) && self.valid()
    }

    /// Cancels pending connect/read/write too. Final validation prevents a
    /// queued old-generation result being accepted at the end of the future.
    pub async fn guard<T>(&self, work: impl Future<Output = Result<T>>) -> Result<T> {
        self.check()?;
        tokio::pin!(work);
        let mut tick = tokio::time::interval(POLL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                result = &mut work => { self.check()?; return result; }
                _ = tick.tick() => self.check()?,
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Packet {
    Other,
    Dns {
        local: SocketAddr,
        remote: SocketAddr,
        protocol: u8,
        supported: bool,
    },
    Unclassifiable,
}

pub fn inspect(bytes: &[u8], loopback: bool) -> Packet {
    let Ok(packet) = SlicedPacket::from_ip(bytes) else {
        return Packet::Unclassifiable;
    };
    let (source, destination, ipv4) = match packet.net {
        Some(NetSlice::Ipv4(ip)) => {
            if ip.header().is_fragmenting_payload() {
                return if matches!(ip.header().protocol().0, 6 | 17) {
                    Packet::Unclassifiable
                } else {
                    Packet::Other
                };
            }
            (
                IpAddr::V4(ip.header().source_addr()),
                IpAddr::V4(ip.header().destination_addr()),
                true,
            )
        }
        Some(NetSlice::Ipv6(ip)) => {
            if ip.is_payload_fragmented() {
                // The Fragment header still identifies its payload protocol.
                // Pass known non-DNS transports (including ICMPv6). Remaining
                // extension headers cannot safely rule out an eventual TCP/UDP
                // header without reassembly, so those stay fail-closed.
                return if matches!(ip.payload().ip_number.0, 6 | 17 | 0 | 43 | 44 | 51 | 60) {
                    Packet::Unclassifiable
                } else {
                    Packet::Other
                };
            }
            (
                IpAddr::V6(ip.header().source_addr()),
                IpAddr::V6(ip.header().destination_addr()),
                false,
            )
        }
        _ => return Packet::Unclassifiable,
    };
    let (local_port, remote_port, protocol) = match packet.transport {
        Some(TransportSlice::Tcp(tcp)) => (tcp.source_port(), tcp.destination_port(), 6),
        Some(TransportSlice::Udp(udp)) => (udp.source_port(), udp.destination_port(), 17),
        _ => return Packet::Other,
    };
    if remote_port != 53 {
        return Packet::Other;
    }
    Packet::Dns {
        local: SocketAddr::new(source, local_port),
        remote: SocketAddr::new(destination, remote_port),
        protocol,
        // IPv6 and local-resolver socket injection have not been validated.
        // Explicitly block selected clients rather than leak through a proxy.
        supported: ipv4 && !loopback && !source.is_loopback() && !destination.is_loopback(),
    }
}

#[cfg(test)]
pub(crate) mod tests;
