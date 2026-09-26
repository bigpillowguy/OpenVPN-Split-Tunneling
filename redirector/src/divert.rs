use std::borrow::Cow;
use std::collections::{hash_map::Entry, HashMap};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use windivert::layer::NetworkLayer;
use windivert::prelude::*;
use windivert_sys::ChecksumFlags;

use crate::adapter::VpnTarget;
use crate::flows::{self, FlowTable, PROTO_TCP, PROTO_UDP};
use crate::pidlookup;
use crate::policy::{self, PolicyState};
use crate::process::Resolver;
use crate::split_dns::{self, Authority, Decision, Fault, Permit};
use crate::stack::VirtualDevice;
use crate::status_server::StatusBus;
use crate::tunneled::{self, TunneledPaths};
use crate::vpn_state::{self, VpnState};

const BRIDGE_CHANNEL_DEPTH: usize = 64;
const SMOLTCP_CHUNK: usize = 16 * 1024;
const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const TCP_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
const FLOW_REVALIDATE_INTERVAL: Duration = Duration::from_millis(250);
const MAX_TCP_FLOWS: usize = 1024;
const MAX_UDP_FLOWS: usize = 4096;
const MAX_DNS_FLOWS: usize = 32;
const STATS_INTERVAL: Duration = Duration::from_secs(5);

#[allow(clippy::too_many_arguments)]
pub fn run(
    policy_state: PolicyState,
    flows: FlowTable,
    vpn_state: VpnState,
    bus: Arc<StatusBus>,
    resolver: Arc<Resolver>,
    tunneled_paths: TunneledPaths,
    shutdown: crate::shutdown::Shutdown,
    dns: Option<Arc<split_dns::LiveAuthority>>,
) -> Result<()> {
    let capture_filter = if dns.is_some() {
        // Catch local resolvers and IPv6 DNS too, even though those selected
        // transports are currently rejected. Fragments cannot bypass attribution.
        "outbound and ((ip and (tcp or udp) and !loopback) or tcp.DstPort == 53 or udp.DstPort == 53 or (fragment and (ipv6 or ip.Protocol == 6 or ip.Protocol == 17)))"
    } else {
        "outbound and ip and (tcp or udp) and !loopback"
    };
    let capture = WinDivert::network(capture_filter, 1040, WinDivertFlags::new())
        .context("WinDivert::network capture handle failed (need admin)")?;
    let inject = WinDivert::network("false", 1039, WinDivertFlags::new().set_send_only())
        .context("WinDivert::network inject handle failed")?;

    tracing::info!(
        "divert: capture+inject open, filter={}, smoltcp mode",
        capture_filter
    );

    let tokio_handle = tokio::runtime::Handle::current();

    let mut device = VirtualDevice::new();
    let mut iface = Interface::new(
        Config::new(HardwareAddress::Ip),
        &mut device,
        smoltcp::time::Instant::now(),
    );
    iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(
            IpAddress::Ipv4(Ipv4Address::new(0, 0, 0, 0)),
            0,
        ));
    });
    iface.set_any_ip(true);

    let mut sockets: SocketSet<'static> = SocketSet::new(Vec::new());
    let mut tcp_flows: HashMap<TcpKey, TcpFlow> = HashMap::new();
    let mut udp_flows: HashMap<UdpKey, UdpFlow> = HashMap::new();

    let stats = Stats::new(bus.clone());
    let _dns_status = DnsStatusGuard {
        bus: bus.clone(),
        enabled: dns.is_some(),
    };
    let started = Instant::now();
    let mut last_report = started;
    let mut previous_stats = [0; 7];

    let mut buffer = vec![0u8; 65535];
    let mut last_vpn = vpn_state::current(&vpn_state);
    let mut last_revalidate = Instant::now();
    let mut last_dns = None;

    while !shutdown.is_stopped() {
        let now_dns = dns.as_ref().and_then(|authority| authority.ready_session());
        bus.set_split_dns(
            dns.is_some(),
            now_dns
                .as_ref()
                .map(|lease| (lease.target.session_id, lease.generation)),
        );
        if now_dns != last_dns {
            remove_dns_flows(&mut tcp_flows, &mut udp_flows, &mut sockets, &stats);
            if now_dns.is_some() {
                bus.clear_split_dns_fault();
            }
            last_dns = now_dns;
        }
        let now_vpn = vpn_state::current(&vpn_state);
        if now_vpn != last_vpn {
            on_vpn_change(
                last_vpn,
                now_vpn,
                &mut tcp_flows,
                &mut udp_flows,
                &mut sockets,
                &stats,
            );
            last_vpn = now_vpn;
        }

        if last_revalidate.elapsed() >= FLOW_REVALIDATE_INTERVAL {
            revoke_invalid_flows(
                &resolver,
                &tunneled_paths,
                &mut tcp_flows,
                &mut udp_flows,
                &mut sockets,
                &stats,
            );
            last_revalidate = Instant::now();
        }

        if let Some(packet) = capture
            .recv_wait(&mut buffer, 50)
            .context("WinDivert capture receive failed")?
        {
            handle_capture(
                packet,
                &capture,
                &policy_state,
                &flows,
                &mut tcp_flows,
                &mut udp_flows,
                &mut sockets,
                &mut device,
                &tokio_handle,
                now_vpn,
                &stats,
                &resolver,
                &tunneled_paths,
                &bus,
                dns.as_ref(),
            );
        }

        let _ = iface.poll(smoltcp::time::Instant::now(), &mut device, &mut sockets);
        drain_tx(&mut device, &inject, &stats, &tcp_flows, dns.is_some());

        service_tcp_flows(&mut tcp_flows, &mut sockets, &tokio_handle, now_vpn, &stats);
        service_udp_flows(&mut udp_flows, &inject, &stats);

        let _ = iface.poll(smoltcp::time::Instant::now(), &mut device, &mut sockets);
        drain_tx(&mut device, &inject, &stats, &tcp_flows, dns.is_some());
        if last_report.elapsed() >= STATS_INTERVAL {
            stats.report_delta(&mut previous_stats, started);
            last_report = Instant::now();
        }
    }
    Ok(())
}

struct DnsStatusGuard {
    bus: Arc<StatusBus>,
    enabled: bool,
}
impl Drop for DnsStatusGuard {
    fn drop(&mut self) {
        self.bus.set_split_dns(self.enabled, None);
    }
}

fn remove_dns_flows(
    tcp: &mut HashMap<TcpKey, TcpFlow>,
    udp: &mut HashMap<UdpKey, UdpFlow>,
    sockets: &mut SocketSet<'static>,
    stats: &Stats,
) {
    tcp.retain(|_, flow| {
        if flow.dns.is_none() {
            return true;
        }
        sockets.remove(flow.handle);
        if flow.task.is_some() {
            stats.bridges_closed.fetch_add(1, Ordering::Relaxed);
        }
        false
    });
    udp.retain(|_, flow| {
        if flow.dns.is_none() {
            return true;
        }
        stats.bridges_closed.fetch_add(1, Ordering::Relaxed);
        false
    });
}

fn on_vpn_change(
    prev: Option<VpnTarget>,
    now: Option<VpnTarget>,
    tcp_flows: &mut HashMap<TcpKey, TcpFlow>,
    udp_flows: &mut HashMap<UdpKey, UdpFlow>,
    sockets: &mut SocketSet<'static>,
    stats: &Stats,
) {
    if prev.is_some() && prev != now {
        let tcp_n = tcp_flows.len();
        let udp_n = udp_flows.len();
        if tcp_n + udp_n > 0 {
            tracing::warn!(
                "VPN target changed — closing {} TCP + {} UDP tunneled flows",
                tcp_n,
                udp_n
            );
        }
        for (_, flow) in tcp_flows.drain() {
            sockets.remove(flow.handle);
            if flow.task.is_some() {
                stats.bridges_closed.fetch_add(1, Ordering::Relaxed);
            }
        }
        // BridgeTask aborts the worker, including a pending socket recv/send.
        let dropped = udp_flows.drain().count() as u64;
        stats.bridges_closed.fetch_add(dropped, Ordering::Relaxed);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TcpKey {
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct UdpKey {
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
}

struct TcpFlow {
    handle: SocketHandle,
    pid: u32,
    creation_time: u64,
    original_dst: SocketAddr,
    dns: Option<Permit>,
    state: TcpState,
    task: Option<BridgeTask>,
}

enum TcpState {
    Pending {
        since: Instant,
    },
    Bridging {
        app_to_remote: Option<mpsc::Sender<Vec<u8>>>,
        remote_to_app: mpsc::Receiver<Vec<u8>>,
        pending_remote: Option<PendingWrite>,
    },
    Closed,
}

struct UdpFlow {
    pid: u32,
    creation_time: u64,
    app_endpoint: (Ipv4Addr, u16),
    original_dst: (Ipv4Addr, u16),
    dns: Option<Permit>,
    app_to_remote: mpsc::Sender<Vec<u8>>,
    remote_to_app: mpsc::Receiver<Vec<u8>>,
    last_active: Instant,
    _task: BridgeTask,
}

/// A flow owns its worker. Removing the flow must also cancel pending network
/// I/O; dropping a bare JoinHandle would leave the task and socket running.
struct BridgeTask(tokio::task::JoinHandle<()>);

impl Drop for BridgeTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct PendingWrite {
    data: Vec<u8>,
    written: usize,
}

#[derive(Debug, PartialEq, Eq)]
enum TcpAdmission {
    Tunnel,
    PassThrough,
    Drop,
}

struct TcpRequest {
    key: TcpKey,
    pid: u32,
    creation_time: u64,
    destination: SocketAddrV4,
    initial_syn: bool,
    dns: Option<Permit>,
}

fn ensure_tcp_flow(
    flows: &mut HashMap<TcpKey, TcpFlow>,
    sockets: &mut SocketSet<'static>,
    request: TcpRequest,
    limit: usize,
) -> TcpAdmission {
    let is_new = !flows.contains_key(&request.key);
    if is_new && !request.initial_syn {
        // An already-running direct connection cannot be adopted by the TCP
        // proxy midstream. Let it finish on its original route; new SYNs follow
        // the configured policy. Do not create orphan listeners for its ACKs.
        return if request.dns.is_some() {
            TcpAdmission::Drop
        } else {
            TcpAdmission::PassThrough
        };
    }
    if is_new
        && (flows.len() >= limit
            || (request.dns.is_some()
                && flows.values().filter(|flow| flow.dns.is_some()).count() >= MAX_DNS_FLOWS))
    {
        return TcpAdmission::Drop;
    }
    if let Entry::Vacant(entry) = flows.entry(request.key) {
        let rx_buf = tcp::SocketBuffer::new(vec![0u8; 65536]);
        let tx_buf = tcp::SocketBuffer::new(vec![0u8; 65536]);
        let mut sock = tcp::Socket::new(rx_buf, tx_buf);
        let endpoint = IpEndpoint::new(
            IpAddress::Ipv4(*request.destination.ip()),
            request.destination.port(),
        );
        if let Err(error) = sock.listen(endpoint) {
            tracing::warn!("smoltcp tcp::listen({}) failed: {:?}", endpoint, error);
            return TcpAdmission::Drop;
        }
        entry.insert(TcpFlow {
            handle: sockets.add(sock),
            pid: request.pid,
            creation_time: request.creation_time,
            original_dst: SocketAddr::V4(request.destination),
            dns: request.dns,
            state: TcpState::Pending {
                since: Instant::now(),
            },
            task: None,
        });
    }
    TcpAdmission::Tunnel
}

struct UdpRequest {
    key: UdpKey,
    pid: u32,
    creation_time: u64,
    target: Option<VpnTarget>,
    dns: Option<Permit>,
}

fn ensure_udp_flow<'a>(
    flows: &'a mut HashMap<UdpKey, UdpFlow>,
    request: UdpRequest,
    tokio_handle: &tokio::runtime::Handle,
    stats: &Stats,
    limit: usize,
) -> Option<&'a mut UdpFlow> {
    if !flows.contains_key(&request.key)
        && (flows.len() >= limit
            || (request.dns.is_some()
                && flows.values().filter(|flow| flow.dns.is_some()).count() >= MAX_DNS_FLOWS))
    {
        return None;
    }
    Some(match flows.entry(request.key) {
        Entry::Occupied(entry) => entry.into_mut(),
        Entry::Vacant(entry) => {
            let (a2r_tx, a2r_rx) = mpsc::channel(BRIDGE_CHANNEL_DEPTH);
            let (r2a_tx, r2a_rx) = mpsc::channel(BRIDGE_CHANNEL_DEPTH);
            let key = request.key;
            let dst = SocketAddr::V4(SocketAddrV4::new(key.dst_ip, key.dst_port));
            let dns = request.dns.clone();
            tracing::info!(
                "udp bridge open: pid={} {}:{} -> {}",
                request.pid,
                key.src_ip,
                key.src_port,
                dst,
            );
            let task = BridgeTask(tokio_handle.spawn(async move {
                let result = match dns {
                    Some(permit) => udp_dns_bridge(permit, a2r_rx, r2a_tx).await,
                    None => udp_bridge(dst, request.target, a2r_rx, r2a_tx).await,
                };
                if let Err(error) = result {
                    tracing::warn!("udp bridge to {} failed: {:#}", dst, error);
                }
            }));
            stats.bridges_opened.fetch_add(1, Ordering::Relaxed);
            entry.insert(UdpFlow {
                pid: request.pid,
                creation_time: request.creation_time,
                app_endpoint: (key.src_ip, key.src_port),
                original_dst: (key.dst_ip, key.dst_port),
                dns: request.dns,
                app_to_remote: a2r_tx,
                remote_to_app: r2a_rx,
                last_active: Instant::now(),
                _task: task,
            })
        }
    })
}

fn revoke_invalid_flows(
    resolver: &Resolver,
    tunneled_paths: &TunneledPaths,
    tcp_flows: &mut HashMap<TcpKey, TcpFlow>,
    udp_flows: &mut HashMap<UdpKey, UdpFlow>,
    sockets: &mut SocketSet<'static>,
    stats: &Stats,
) {
    // Resolve each process once per sweep, even if it owns many connections.
    let mut generations = HashMap::new();
    let mut allowed = |pid, creation_time| {
        *generations.entry(pid).or_insert_with(|| {
            resolver
                .resolve(pid)
                .filter(|info| {
                    tunneled::matches(tunneled_paths, std::path::Path::new(&info.exe_path))
                })
                .map(|info| info.creation_time)
        }) == Some(creation_time)
    };
    tcp_flows.retain(|_, flow| {
        if flow
            .dns
            .as_ref()
            .map_or_else(|| allowed(flow.pid, flow.creation_time), Permit::valid)
        {
            return true;
        }
        sockets.remove(flow.handle);
        if flow.task.is_some() {
            stats.bridges_closed.fetch_add(1, Ordering::Relaxed);
        }
        false
    });
    udp_flows.retain(|_, flow| {
        if flow
            .dns
            .as_ref()
            .map_or_else(|| allowed(flow.pid, flow.creation_time), Permit::valid)
        {
            return true;
        }
        stats.bridges_closed.fetch_add(1, Ordering::Relaxed);
        false
    });
}

/// Resolve the owning PID for a freshly-seen flow. The fast path is the
/// observer-populated flow table; on miss we query the Windows TCP/UDP
/// table directly. On both-miss we tight-loop for ~1 ms because the kernel
/// builds the SYN packet *after* creating the TCB, so the TCP table is
/// guaranteed to have the row by the time we'd reasonably give up — but
/// IPHLPAPI may serve a stale snapshot for a few hundred microseconds.
/// Holding the packet here is fine: WinDivert has it queued and it doesn't
/// hit the wire until we call capture.send() or push it into smoltcp.
fn resolve_pid_with_retry(
    flows: &FlowTable,
    src_ip: Ipv4Addr,
    src_port: u16,
    proto: u8,
) -> Option<u32> {
    let lookup = |flows: &FlowTable| -> Option<u32> {
        flows::lookup_with_wildcard(flows, IpAddr::V4(src_ip), src_port, proto)
            .map(|e| e.pid)
            .or_else(|| pidlookup::pid_for_local_v4(src_ip, src_port, proto))
    };

    if let Some(p) = lookup(flows) {
        return Some(p);
    }
    for _ in 0..5 {
        std::thread::sleep(Duration::from_micros(200));
        if let Some(p) = lookup(flows) {
            return Some(p);
        }
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn handle_capture(
    packet: WinDivertPacket<'_, NetworkLayer>,
    capture: &WinDivert<NetworkLayer>,
    policy_state: &PolicyState,
    flows: &FlowTable,
    tcp_flows: &mut HashMap<TcpKey, TcpFlow>,
    udp_flows: &mut HashMap<UdpKey, UdpFlow>,
    sockets: &mut SocketSet<'static>,
    device: &mut VirtualDevice,
    tokio_handle: &tokio::runtime::Handle,
    vpn_target: Option<VpnTarget>,
    stats: &Stats,
    resolver: &Arc<Resolver>,
    tunneled_paths: &TunneledPaths,
    bus: &Arc<StatusBus>,
    dns_authority: Option<&Arc<split_dns::LiveAuthority>>,
) {
    let dns = if let Some(authority) = dns_authority {
        match split_dns::inspect(&packet.data, packet.address.loopback()) {
            split_dns::Packet::Other => None,
            split_dns::Packet::Unclassifiable => {
                stats.dns_drop(Fault::InvalidPacket);
                return;
            }
            split_dns::Packet::Dns {
                local,
                remote,
                protocol,
                supported,
            } => {
                let owner = pidlookup::owner_for_tuple(local, remote, protocol);
                match authority.decide(owner) {
                    Decision::Pass => {
                        let _ = capture.send(&packet);
                        stats.passed.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                    Decision::Drop(fault) => {
                        stats.dns_drop(fault);
                        return;
                    }
                    Decision::Tunnel(lease) => {
                        if !supported {
                            stats.dns_drop(Fault::UnsupportedTransport);
                            return;
                        }
                        Some(Permit::new(lease, authority.clone()))
                    }
                }
            }
        }
    } else {
        None
    };
    let parsed = match parse_ipv4_l4(&packet.data) {
        Some(p) => p,
        None => {
            let _ = capture.send(&packet);
            stats.passed.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };

    let (src_ip, src_port, dst_ip, dst_port, is_tcp, initial_syn) = match parsed {
        ParsedL4::Tcp {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            initial_syn,
        } => (src_ip, src_port, dst_ip, dst_port, true, initial_syn),
        ParsedL4::Udp {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            ..
        } => (src_ip, src_port, dst_ip, dst_port, false, false),
    };

    let proto = if is_tcp { PROTO_TCP } else { PROTO_UDP };
    let pid = dns
        .as_ref()
        .map(|permit| permit.lease.pid)
        .or_else(|| resolve_pid_with_retry(flows, src_ip, src_port, proto));
    if pid == Some(std::process::id()) {
        let _ = capture.send(&packet);
        stats.passed.fetch_add(1, Ordering::Relaxed);
        return;
    }
    // A policy PID is a display/cache hint, never authority across PID reuse or
    // a path-list edit. Revalidate the current process identity on admission.
    // Packet-derived aliases are deliberately not inserted into the SOCKET
    // event table: their lifetime cannot be paired reliably with CLOSE events.
    let admitted = if let Some(permit) = &dns {
        Some((
            permit.lease.pid,
            crate::process::ProcessInfo {
                exe_path: permit.lease.exe_path.clone(),
                exe_name: String::new(),
                creation_time: permit.lease.creation_time,
            },
        ))
    } else {
        pid.and_then(|p| {
            resolver
                .resolve(p)
                .filter(|info| {
                    tunneled::matches(tunneled_paths, std::path::Path::new(&info.exe_path))
                })
                .map(|info| (p, info))
        })
    };
    let identity = admitted.as_ref().map(|(p, info)| (*p, info.creation_time));
    if is_tcp {
        let key = TcpKey {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
        };
        if tcp_flows.get(&key).is_some_and(|flow| {
            Some((flow.pid, flow.creation_time)) != identity
                || flow.dns.as_ref().map(|p| &p.lease) != dns.as_ref().map(|p| &p.lease)
        }) {
            let flow = tcp_flows.remove(&key).unwrap();
            sockets.remove(flow.handle);
            if flow.task.is_some() {
                stats.bridges_closed.fetch_add(1, Ordering::Relaxed);
            }
        }
    } else {
        let key = UdpKey {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
        };
        if udp_flows.get(&key).is_some_and(|flow| {
            Some((flow.pid, flow.creation_time)) != identity
                || flow.dns.as_ref().map(|p| &p.lease) != dns.as_ref().map(|p| &p.lease)
        }) {
            udp_flows.remove(&key);
            stats.bridges_closed.fetch_add(1, Ordering::Relaxed);
        }
    }
    let Some((pid, info)) = admitted else {
        if let Some(p) = pid {
            policy::remove(policy_state, p);
            bus.pid_paths.remove(&p);
        }
        let _ = capture.send(&packet);
        stats.passed.fetch_add(1, Ordering::Relaxed);
        return;
    };
    if !policy::contains(policy_state, pid) {
        tracing::info!(
            "auto-tunnel (packet): pid={} matches {}",
            pid,
            info.exe_path
        );
        policy::add(policy_state, pid);
        bus.pid_paths.insert(pid, info.exe_path);
    }
    let creation_time = info.creation_time;

    // Fail-open: if the VPN is down, send the packet out the default route
    // instead of dropping it. This trades the "no clear-text leak when VPN
    // disconnects mid-session" guarantee for "tunneled apps keep working
    // when the user has the VPN off." Existing smoltcp flows for this PID
    // were already torn down by on_vpn_change when the VPN went away, so
    // the app will see a RST and reconnect — and that reconnect goes
    // straight through here.
    if vpn_target.is_none() {
        if dns.is_some() {
            stats.dns_drop(Fault::UnavailableSession);
            return;
        }
        let _ = capture.send(&packet);
        stats.passed.fetch_add(1, Ordering::Relaxed);
        return;
    }

    if is_tcp {
        let request = TcpRequest {
            key: TcpKey {
                src_ip,
                src_port,
                dst_ip,
                dst_port,
            },
            pid,
            creation_time,
            destination: SocketAddrV4::new(dst_ip, dst_port),
            initial_syn,
            dns,
        };
        match ensure_tcp_flow(tcp_flows, sockets, request, MAX_TCP_FLOWS) {
            TcpAdmission::Tunnel => device.push_rx(packet.data.into_owned()),
            TcpAdmission::PassThrough => {
                let _ = capture.send(&packet);
                stats.passed.fetch_add(1, Ordering::Relaxed);
                return;
            }
            TcpAdmission::Drop => {}
        }
        stats.captured.fetch_add(1, Ordering::Relaxed);
    } else {
        let request = UdpRequest {
            key: UdpKey {
                src_ip,
                src_port,
                dst_ip,
                dst_port,
            },
            pid,
            creation_time,
            target: vpn_target,
            dns,
        };
        let Some(flow) = ensure_udp_flow(udp_flows, request, tokio_handle, stats, MAX_UDP_FLOWS)
        else {
            // Reject excess new flows before allocating channels, workers or
            // payload buffers. Existing flows are allowed to drain at the cap.
            stats.captured.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let payload = match extract_udp_payload(&packet.data) {
            Some(p) => p,
            None => {
                tracing::warn!("could not extract UDP payload");
                return;
            }
        };

        flow.last_active = Instant::now();
        let len = packet.data.len() as u64;
        if flow.app_to_remote.try_send(payload).is_ok() {
            stats.add_app_to_remote(len);
            stats.add_pid_out(flow.pid, len);
        }
        stats.captured.fetch_add(1, Ordering::Relaxed);
        // packet consumed - do NOT reinject
    }
}

fn drain_tx(
    device: &mut VirtualDevice,
    inject: &WinDivert<NetworkLayer>,
    stats: &Stats,
    tcp_flows: &HashMap<TcpKey, TcpFlow>,
    split_dns: bool,
) {
    while let Some(data) = device.pop_tx() {
        if split_dns {
            if let Some(ParsedL4::Tcp {
                src_ip,
                src_port: 53,
                dst_ip,
                dst_port,
                ..
            }) = parse_ipv4_l4(&data)
            {
                let key = TcpKey {
                    src_ip: dst_ip,
                    src_port: dst_port,
                    dst_ip: src_ip,
                    dst_port: 53,
                };
                let owner = pidlookup::owner_for_tuple(
                    SocketAddr::from((dst_ip, dst_port)),
                    SocketAddr::from((src_ip, 53)),
                    PROTO_TCP,
                );
                if !tcp_flows
                    .get(&key)
                    .and_then(|flow| flow.dns.as_ref())
                    .is_some_and(|permit| permit.can_deliver_to(owner))
                {
                    stats.dns_drop(Fault::Revoked);
                    continue;
                }
            }
        }
        send_injected(inject, data, stats);
    }
}

fn send_injected(inject: &WinDivert<NetworkLayer>, data: Vec<u8>, stats: &Stats) {
    let mut addr = unsafe { WinDivertAddress::<NetworkLayer>::new() };
    addr.set_outbound(true);
    addr.set_ip_checksum(false);
    addr.set_tcp_checksum(false);
    addr.set_udp_checksum(false);
    let mut pkt = WinDivertPacket {
        address: addr,
        data: Cow::Owned(data),
    };
    if let Err(e) = pkt.recalculate_checksums(ChecksumFlags::new()) {
        tracing::warn!("inject checksum recalc failed: {}", e);
        return;
    }
    if let Err(e) = inject.send(&pkt) {
        tracing::warn!("inject send failed: {}", e);
        return;
    }
    stats.injected.fetch_add(1, Ordering::Relaxed);
}

fn service_tcp_flows(
    tcp_flows: &mut HashMap<TcpKey, TcpFlow>,
    sockets: &mut SocketSet<'static>,
    tokio_handle: &tokio::runtime::Handle,
    vpn_target: Option<VpnTarget>,
    stats: &Stats,
) {
    let mut to_remove = Vec::new();
    for (key, flow) in tcp_flows.iter_mut() {
        if flow.dns.as_ref().is_some_and(|permit| !permit.valid()) {
            stats.dns_drop(Fault::Revoked);
            to_remove.push(*key);
            continue;
        }
        match &mut flow.state {
            TcpState::Pending { since } => {
                let socket = sockets.get_mut::<tcp::Socket>(flow.handle);
                // The first post-handshake packet can contain FIN as well as
                // data, so CloseWait still needs a bridge to drain the request.
                if matches!(
                    socket.state(),
                    tcp::State::Established | tcp::State::CloseWait
                ) {
                    let (a2r_tx, a2r_rx) = mpsc::channel::<Vec<u8>>(BRIDGE_CHANNEL_DEPTH);
                    let (r2a_tx, r2a_rx) = mpsc::channel::<Vec<u8>>(BRIDGE_CHANNEL_DEPTH);

                    tracing::info!(
                        "tcp bridge open: pid={} {}:{} -> {}",
                        flow.pid,
                        key.src_ip,
                        key.src_port,
                        flow.original_dst
                    );

                    let dst = flow.original_dst;
                    let dns = flow.dns.clone();
                    flow.task = Some(BridgeTask(tokio_handle.spawn(async move {
                        let result = match dns {
                            Some(permit) => tcp_dns_bridge(permit, a2r_rx, r2a_tx).await,
                            None => tcp_bridge(dst, vpn_target, a2r_rx, r2a_tx).await,
                        };
                        if let Err(e) = result {
                            tracing::warn!("tcp bridge to {} failed: {:#}", dst, e);
                        }
                    })));
                    stats.bridges_opened.fetch_add(1, Ordering::Relaxed);

                    flow.state = TcpState::Bridging {
                        app_to_remote: Some(a2r_tx),
                        remote_to_app: r2a_rx,
                        pending_remote: None,
                    };
                } else if !socket.is_open() || since.elapsed() >= TCP_HANDSHAKE_TIMEOUT {
                    // Keep the aborted socket until the next poll has had a
                    // chance to emit RST, then remove its buffers next turn.
                    socket.abort();
                    flow.state = TcpState::Closed;
                }
            }
            TcpState::Bridging {
                app_to_remote,
                remote_to_app,
                pending_remote,
            } => {
                let socket = sockets.get_mut::<tcp::Socket>(flow.handle);
                pump_tcp_app_to_remote(socket, app_to_remote, flow.pid, stats);
                pump_tcp_remote_to_app(socket, remote_to_app, pending_remote, flow.pid, stats);
                if matches!(socket.state(), tcp::State::Closed | tcp::State::TimeWait) {
                    flow.state = TcpState::Closed;
                }
            }
            TcpState::Closed => to_remove.push(*key),
        }
    }
    for k in to_remove {
        if let Some(flow) = tcp_flows.remove(&k) {
            sockets.remove(flow.handle);
            if flow.task.is_some() {
                stats.bridges_closed.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

fn service_udp_flows(
    udp_flows: &mut HashMap<UdpKey, UdpFlow>,
    inject: &WinDivert<NetworkLayer>,
    stats: &Stats,
) {
    let now = Instant::now();
    let mut to_remove = Vec::new();

    for (key, flow) in udp_flows.iter_mut() {
        loop {
            if flow.dns.as_ref().is_some_and(|permit| !permit.valid()) {
                stats.dns_drop(Fault::Revoked);
                to_remove.push(*key);
                break;
            }
            match flow.remote_to_app.try_recv() {
                Ok(payload) => {
                    if let Some(permit) = &flow.dns {
                        let owner = pidlookup::owner_for_tuple(
                            SocketAddr::from(flow.app_endpoint),
                            SocketAddr::from(flow.original_dst),
                            PROTO_UDP,
                        );
                        if !permit.can_deliver_to(owner) {
                            stats.dns_drop(Fault::Revoked);
                            to_remove.push(*key);
                            break;
                        }
                    }
                    flow.last_active = now;
                    let Some(pkt) = build_udp_packet(
                        flow.original_dst.0,
                        flow.original_dst.1,
                        flow.app_endpoint.0,
                        flow.app_endpoint.1,
                        &payload,
                    ) else {
                        stats.dns_drop(Fault::InvalidPacket);
                        continue;
                    };
                    stats.add_remote_to_app(payload.len() as u64);
                    stats.add_pid_in(flow.pid, payload.len() as u64);
                    send_injected(inject, pkt, stats);
                }
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    to_remove.push(*key);
                    break;
                }
            }
        }
        if now.duration_since(flow.last_active) > UDP_IDLE_TIMEOUT {
            to_remove.push(*key);
        }
    }

    for k in to_remove {
        if udp_flows.remove(&k).is_some() {
            stats.bridges_closed.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn pump_tcp_app_to_remote(
    socket: &mut tcp::Socket,
    sender: &mut Option<mpsc::Sender<Vec<u8>>>,
    pid: u32,
    stats: &Stats,
) {
    let Some(tx) = sender.as_ref() else { return };
    while socket.can_recv() {
        // Reserve capacity before dequeuing acknowledged TCP bytes. On a full
        // bridge queue, leave them in smoltcp so its receive window applies
        // backpressure to the application.
        let permit = match tx.try_reserve() {
            Ok(permit) => permit,
            Err(mpsc::error::TrySendError::Full(_)) => break,
            Err(mpsc::error::TrySendError::Closed(_)) => {
                socket.abort();
                return;
            }
        };
        let mut buf = vec![0u8; SMOLTCP_CHUNK];
        let n = match socket.recv_slice(&mut buf) {
            Ok(n) => n,
            Err(_) => break,
        };
        if n == 0 {
            break;
        }
        buf.truncate(n);
        permit.send(buf);
        stats.add_app_to_remote(n as u64);
        stats.add_pid_out(pid, n as u64);
    }
    if !socket.may_recv() {
        // may_recv stays true until every buffered byte preceding FIN has
        // been drained. Closing this sender then delivers EOF after the queued
        // chunks, and the bridge shuts down only the remote write half.
        sender.take();
    }
}

fn pump_tcp_remote_to_app(
    socket: &mut tcp::Socket,
    receiver: &mut mpsc::Receiver<Vec<u8>>,
    pending: &mut Option<PendingWrite>,
    pid: u32,
    stats: &Stats,
) {
    loop {
        if pending.is_none() {
            match receiver.try_recv() {
                Ok(data) => *pending = Some(PendingWrite { data, written: 0 }),
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    // close() queues FIN after bytes already in the TX buffer.
                    socket.close();
                    break;
                }
            }
        }
        let data = pending.as_mut().unwrap();
        if data.written == data.data.len() {
            *pending = None;
            continue;
        }
        if !socket.can_send() {
            break;
        }
        match socket.send_slice(&data.data[data.written..]) {
            Ok(0) => break,
            Ok(n) => {
                data.written += n;
                stats.add_remote_to_app(n as u64);
                stats.add_pid_in(pid, n as u64);
            }
            Err(_) => break,
        }
    }
}

/// Pin a TCP/UDP socket to a specific outgoing interface so the kernel ignores
/// the system routing table and egresses via the chosen NIC. Combined with
/// `--pull-filter ignore redirect-gateway` on the OpenVPN side, this is what
/// turns the tunnel into a true split-tunnel — only sockets we explicitly pin
/// land on the VPN, everything else stays on the default route.
fn set_unicast_if_v4<S: std::os::windows::io::AsRawSocket>(
    socket: &S,
    if_index: u32,
) -> Result<()> {
    use windows::Win32::Networking::WinSock::{setsockopt, IPPROTO_IP, SOCKET};

    // IP_UNICAST_IF wants the index in network byte order.
    let val = if_index.to_be();
    let bytes = val.to_ne_bytes();
    let s = SOCKET(socket.as_raw_socket() as usize);
    // IP_UNICAST_IF is not exposed as a constant in the windows crate at our
    // version — its numeric value is 31. Defined this way in the WinSock SDK.
    const IP_UNICAST_IF: i32 = 31;
    let rc = unsafe { setsockopt(s, IPPROTO_IP.0, IP_UNICAST_IF, Some(&bytes)) };
    if rc != 0 {
        anyhow::bail!(
            "setsockopt(IP_UNICAST_IF, ifindex={}) failed: {}",
            if_index,
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

async fn tcp_bridge(
    dst: SocketAddr,
    target: Option<VpnTarget>,
    from_app: mpsc::Receiver<Vec<u8>>,
    to_app: mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    let stream = match target {
        Some(t) => {
            let socket = tokio::net::TcpSocket::new_v4()?;
            set_unicast_if_v4(&socket, t.if_index)?;
            socket.bind(SocketAddr::V4(SocketAddrV4::new(t.ipv4, 0)))?;
            socket
                .connect(dst)
                .await
                .with_context(|| format!("tcp connect({}) via ifindex {}", dst, t.if_index))?
        }
        None => tokio::net::TcpStream::connect(dst)
            .await
            .with_context(|| format!("tcp connect({})", dst))?,
    };
    tracing::debug!(
        "tcp bridge connected to {} (local={:?})",
        dst,
        stream.local_addr().ok()
    );
    tcp_stream_bridge(stream, from_app, to_app, None).await
}

async fn tcp_stream_bridge(
    stream: tokio::net::TcpStream,
    mut from_app: mpsc::Receiver<Vec<u8>>,
    to_app: mpsc::Sender<Vec<u8>>,
    permit: Option<&Permit>,
) -> Result<()> {
    let (mut rd, mut wr) = stream.into_split();

    let write = async move {
        while let Some(data) = from_app.recv().await {
            if let Some(permit) = permit {
                permit.check().map_err(std::io::Error::other)?;
            }
            wr.write_all(&data).await?;
        }
        wr.shutdown().await
    };

    let read = async move {
        let mut buf = vec![0u8; SMOLTCP_CHUNK];
        loop {
            let n = rd.read(&mut buf).await?;
            if let Some(permit) = permit {
                permit.check().map_err(std::io::Error::other)?;
            }
            if n == 0 || to_app.send(buf[..n].to_vec()).await.is_err() {
                return Ok::<(), std::io::Error>(());
            }
        }
    };

    // These are child futures, not detached tasks. A transport error cancels
    // its peer, while a normal half-close lets the opposite direction finish.
    // Aborting the owning BridgeTask drops both halves, even during pending I/O.
    tokio::try_join!(write, read)?;
    Ok(())
}

async fn tcp_dns_bridge(
    permit: Permit,
    from_app: mpsc::Receiver<Vec<u8>>,
    to_app: mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    let binding = crate::dns_broker::transport::Binding::vpn(permit.lease.dns.target);
    tcp_dns_bridge_bound(permit, binding, from_app, to_app).await
}

async fn tcp_dns_bridge_bound(
    permit: Permit,
    binding: crate::dns_broker::transport::Binding,
    from_app: mpsc::Receiver<Vec<u8>>,
    to_app: mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    let work = async {
        for server in &permit.lease.dns.servers {
            permit.check()?;
            let socket = binding
                .tcp_socket()
                .map_err(|code| anyhow::anyhow!("DNS socket binding failed: {code}"))?;
            // Try only current provider endpoints, and only before any bytes
            // are sent. Never replay a partially written DNS stream elsewhere.
            if let Ok(Ok(stream)) = tokio::time::timeout(
                Duration::from_secs(2),
                socket.connect(SocketAddr::V4(*server)),
            )
            .await
            {
                return tcp_stream_bridge(stream, from_app, to_app, Some(&permit)).await;
            }
        }
        anyhow::bail!("all provider DNS TCP endpoints failed")
    };
    permit.guard(work).await
}

async fn udp_dns_bridge(
    permit: Permit,
    from_app: mpsc::Receiver<Vec<u8>>,
    to_app: mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    let binding = crate::dns_broker::transport::Binding::vpn(permit.lease.dns.target);
    udp_dns_bridge_bound(permit, binding, from_app, to_app).await
}

async fn udp_dns_bridge_bound(
    permit: Permit,
    binding: crate::dns_broker::transport::Binding,
    mut from_app: mpsc::Receiver<Vec<u8>>,
    to_app: mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    use crate::dns_broker::{transport, wire};
    let work = async {
        while let Some(query) = from_app.recv().await {
            permit.check()?;
            let Ok(question) = wire::query(&query) else {
                continue;
            };
            // Bounded sequential requests per flow. UDP overload is dropped by
            // the existing bounded channel; it never opens a direct resolver.
            if let Ok(response) =
                transport::exchange_datagram(binding, &permit.lease.dns.servers, &query, &question)
                    .await
            {
                permit.check()?;
                if response.len() <= 65507 && to_app.send(response).await.is_err() {
                    return Ok(());
                }
            }
        }
        Ok(())
    };
    permit.guard(work).await
}

async fn udp_bridge(
    dst: SocketAddr,
    target: Option<VpnTarget>,
    mut from_app: mpsc::Receiver<Vec<u8>>,
    to_app: mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    let local = match target {
        Some(t) => SocketAddr::V4(SocketAddrV4::new(t.ipv4, 0)),
        None => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
    };
    let socket = tokio::net::UdpSocket::bind(local)
        .await
        .with_context(|| format!("udp bind({})", local))?;
    if let Some(t) = target {
        set_unicast_if_v4(&socket, t.if_index)?;
    }
    socket
        .connect(dst)
        .await
        .with_context(|| format!("udp connect({})", dst))?;
    tracing::debug!(
        "udp bridge {} -> {} (local={:?})",
        local,
        dst,
        socket.local_addr().ok()
    );
    let send = async {
        while let Some(data) = from_app.recv().await {
            socket.send(&data).await?;
        }
        Ok::<(), std::io::Error>(())
    };

    let recv = async {
        let mut buf = vec![0u8; 65536];
        loop {
            let n = socket.recv(&mut buf).await?;
            // A zero-byte UDP datagram is data, not the EOF used by TCP.
            if to_app.send(buf[..n].to_vec()).await.is_err() {
                return Ok::<(), std::io::Error>(());
            }
        }
    };

    // Finishing either direction closes the UDP flow. Cancelling the other
    // future also releases the sole socket, including an idle pending recv.
    tokio::select! {
        result = send => result?,
        result = recv => result?,
    }
    Ok(())
}

enum ParsedL4 {
    Tcp {
        src_ip: Ipv4Addr,
        src_port: u16,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        initial_syn: bool,
    },
    Udp {
        src_ip: Ipv4Addr,
        src_port: u16,
        dst_ip: Ipv4Addr,
        dst_port: u16,
    },
}

fn parse_ipv4_l4(data: &[u8]) -> Option<ParsedL4> {
    let sliced = SlicedPacket::from_ip(data).ok()?;
    let net = sliced.net?;
    let ipv4 = match net {
        NetSlice::Ipv4(ip) => ip,
        _ => return None,
    };
    let src_ip = ipv4.header().source_addr();
    let dst_ip = ipv4.header().destination_addr();
    match sliced.transport? {
        TransportSlice::Tcp(tcp) => Some(ParsedL4::Tcp {
            src_ip,
            src_port: tcp.source_port(),
            dst_ip,
            dst_port: tcp.destination_port(),
            initial_syn: tcp.syn() && !tcp.ack() && !tcp.rst() && !tcp.fin(),
        }),
        TransportSlice::Udp(udp_slice) => Some(ParsedL4::Udp {
            src_ip,
            src_port: udp_slice.source_port(),
            dst_ip,
            dst_port: udp_slice.destination_port(),
        }),
        _ => None,
    }
}

fn extract_udp_payload(data: &[u8]) -> Option<Vec<u8>> {
    let sliced = SlicedPacket::from_ip(data).ok()?;
    match sliced.transport? {
        TransportSlice::Udp(udp_slice) => Some(udp_slice.payload().to_vec()),
        _ => None,
    }
}

fn build_udp_packet(
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    payload: &[u8],
) -> Option<Vec<u8>> {
    if payload.len() > 65507 {
        return None;
    }
    let total_len = 20 + 8 + payload.len();
    let udp_len = 8 + payload.len();
    let mut buf = Vec::with_capacity(total_len);

    // IPv4 header (20 bytes, no options, IHL=5)
    buf.push(0x45);
    buf.push(0);
    buf.extend_from_slice(&(total_len as u16).to_be_bytes());
    buf.extend_from_slice(&[0, 0]); // identification
    buf.extend_from_slice(&[0, 0]); // flags + fragment offset
    buf.push(64); // ttl
    buf.push(17); // protocol = UDP
    buf.extend_from_slice(&[0, 0]); // header checksum (WinDivert will recompute)
    buf.extend_from_slice(&src_ip.octets());
    buf.extend_from_slice(&dst_ip.octets());

    // UDP header (8 bytes)
    buf.extend_from_slice(&src_port.to_be_bytes());
    buf.extend_from_slice(&dst_port.to_be_bytes());
    buf.extend_from_slice(&(udp_len as u16).to_be_bytes());
    buf.extend_from_slice(&[0, 0]); // checksum (WinDivert will recompute)

    buf.extend_from_slice(payload);
    Some(buf)
}

struct Stats {
    passed: AtomicU64,
    captured: AtomicU64,
    injected: AtomicU64,
    bridges_opened: AtomicU64,
    bridges_closed: AtomicU64,
    dns_dropped: AtomicU64,
    bus: Arc<StatusBus>,
}

impl Stats {
    fn dns_drop(&self, fault: Fault) {
        let total = self.dns_dropped.fetch_add(1, Ordering::Relaxed) + 1;
        self.bus.split_dns_drop(fault.code());
        // Counter is exact; logging is bounded under sustained packet floods.
        if total.is_power_of_two() {
            tracing::warn!(
                reason = fault.code(),
                total,
                "split DNS packet/flow blocked"
            );
        }
    }
    fn new(bus: Arc<StatusBus>) -> Self {
        Self {
            passed: AtomicU64::new(0),
            captured: AtomicU64::new(0),
            injected: AtomicU64::new(0),
            bridges_opened: AtomicU64::new(0),
            bridges_closed: AtomicU64::new(0),
            dns_dropped: AtomicU64::new(0),
            bus,
        }
    }

    fn add_app_to_remote(&self, n: u64) {
        self.bus.bytes_out.fetch_add(n, Ordering::Relaxed);
    }
    fn add_remote_to_app(&self, n: u64) {
        self.bus.bytes_in.fetch_add(n, Ordering::Relaxed);
    }
    fn add_pid_out(&self, pid: u32, n: u64) {
        self.bus.add_pid_out(pid, n);
    }
    fn add_pid_in(&self, pid: u32, n: u64) {
        self.bus.add_pid_in(pid, n);
    }

    fn report_delta(&self, last: &mut [u64; 7], started: Instant) {
        let cur = [
            self.passed.load(Ordering::Relaxed),
            self.captured.load(Ordering::Relaxed),
            self.injected.load(Ordering::Relaxed),
            self.bridges_opened.load(Ordering::Relaxed),
            self.bridges_closed.load(Ordering::Relaxed),
            self.bus.bytes_out.load(Ordering::Relaxed),
            self.bus.bytes_in.load(Ordering::Relaxed),
        ];
        let delta: [u64; 7] = std::array::from_fn(|i| cur[i].saturating_sub(last[i]));
        *last = cur;
        tracing::info!(
            "divert 5s: pass={} cap={} inj={} bridges +{}/-{} a→r={}B r→a={}B (uptime {:?})",
            delta[0],
            delta[1],
            delta[2],
            delta[3],
            delta[4],
            delta[5],
            delta[6],
            started.elapsed()
        );
    }
}

#[cfg(test)]
#[path = "divert_tests.rs"]
mod tests;
