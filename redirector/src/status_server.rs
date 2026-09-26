use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use dashmap::DashMap;
use ipc::status::{
    status_message::Body, AppStats, PidStats, Snapshot, SplitDnsState, StatusMessage, Totals,
    VpnState,
};
use ipc::STATUS_PIPE_NAME;
use prost::Message;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use windows::core::{BOOL, PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{
    GetTokenInformation, TokenUser, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY,
    TOKEN_USER,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::vpn_state::{self, VpnState as VpnStateHandle};

const TICK: Duration = Duration::from_millis(500);
const MAX_CLIENTS: usize = 4;
const WRITE_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_FRAME: usize = 1024 * 1024;
const DNS_READY_TTL: Duration = Duration::from_secs(2);

#[derive(Default)]
struct DnsStatus {
    state: SplitDnsState,
    refreshed: Option<Instant>,
}

fn guid_hex(bytes: [u8; 16]) -> String {
    use std::fmt::Write;
    let mut result = String::with_capacity(32);
    for byte in bytes {
        let _ = write!(result, "{byte:02x}");
    }
    result
}

fn dns_snapshot(status: &DnsStatus, now: Instant, session: Option<[u8; 16]>) -> SplitDnsState {
    let mut state = status.state.clone();
    let fresh = status
        .refreshed
        .is_some_and(|time| now.saturating_duration_since(time) <= DNS_READY_TTL);
    let same_session = session.is_some_and(|id| state.session_id == guid_hex(id));
    if !state.enabled || !fresh || !same_session {
        state.ready = false;
        state.session_id.clear();
        state.generation.clear();
        if state.enabled && !fresh {
            state.fault = "dataplane_stale".into();
        }
    }
    state
}

pub struct StatusBus {
    pub bytes_out: Arc<AtomicU64>,
    pub bytes_in: Arc<AtomicU64>,
    pub vpn_up_since_ms: Arc<AtomicU64>,
    /// Per-PID byte counters updated by bridges.
    pub pid_bytes_out: Arc<DashMap<u32, AtomicU64>>,
    pub pid_bytes_in: Arc<DashMap<u32, AtomicU64>>,
    /// PID → canonical exe path, populated by proc_watcher.
    pub pid_paths: Arc<DashMap<u32, String>>,
    split_dns: Mutex<DnsStatus>,
}

impl StatusBus {
    pub fn new() -> Self {
        Self {
            bytes_out: Arc::new(AtomicU64::new(0)),
            bytes_in: Arc::new(AtomicU64::new(0)),
            vpn_up_since_ms: Arc::new(AtomicU64::new(0)),
            pid_bytes_out: Arc::new(DashMap::new()),
            pid_bytes_in: Arc::new(DashMap::new()),
            pid_paths: Arc::new(DashMap::new()),
            split_dns: Mutex::new(DnsStatus::default()),
        }
    }

    pub fn add_pid_out(&self, pid: u32, n: u64) {
        self.pid_bytes_out
            .entry(pid)
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(n, Ordering::Relaxed);
    }

    pub fn add_pid_in(&self, pid: u32, n: u64) {
        self.pid_bytes_in
            .entry(pid)
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(n, Ordering::Relaxed);
    }

    /// Called only by the running capture loop after both packet handles opened.
    /// A missing provider/session revokes readiness without disabling DNS drops.
    pub fn set_split_dns(&self, enabled: bool, lease: Option<([u8; 16], [u8; 16])>) {
        let mut status = self.split_dns.lock().unwrap();
        status.state.enabled = enabled;
        let lease = lease.filter(|(session, generation)| {
            enabled && *session != [0; 16] && *generation != [0; 16]
        });
        status.state.ready = lease.is_some();
        status.state.session_id = lease.map(|value| guid_hex(value.0)).unwrap_or_default();
        status.state.generation = lease.map(|value| guid_hex(value.1)).unwrap_or_default();
        status.refreshed = Some(Instant::now());
    }

    pub fn split_dns_drop(&self, fault: &'static str) {
        let mut status = self.split_dns.lock().unwrap();
        status.state.dropped = status.state.dropped.saturating_add(1);
        // Never allow this status field to become a query/profile logging path.
        status.state.fault = if !fault.is_empty()
            && fault.len() <= 64
            && fault
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            fault.into()
        } else {
            "dns_packet_rejected".into()
        };
    }

    pub fn clear_split_dns_fault(&self) {
        self.split_dns.lock().unwrap().state.fault.clear();
    }
}

struct SecurityDescriptor {
    psd: PSECURITY_DESCRIPTOR,
}

impl SecurityDescriptor {
    fn current_user() -> Result<Self> {
        let sid = current_user_sid()?;
        let sddl: Vec<u16> = format!("D:P(A;;GA;;;SY)(A;;GA;;;{sid})")
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let mut psd = PSECURITY_DESCRIPTOR::default();
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl.as_ptr()),
                SDDL_REVISION_1,
                &mut psd,
                None,
            )
        }
        .context("ConvertStringSecurityDescriptorToSecurityDescriptorW failed")?;
        Ok(Self { psd })
    }

    fn attrs(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.psd.0,
            bInheritHandle: BOOL(0),
        }
    }
}

fn current_user_sid() -> Result<String> {
    struct Token(HANDLE);
    impl Drop for Token {
        fn drop(&mut self) {
            let _ = unsafe { CloseHandle(self.0) };
        }
    }
    let mut raw = HANDLE::default();
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) }?;
    let token = Token(raw);
    let mut bytes = 0;
    let _ = unsafe { GetTokenInformation(token.0, TokenUser, None, 0, &mut bytes) };
    anyhow::ensure!(
        bytes as usize >= std::mem::size_of::<TOKEN_USER>(),
        "invalid token user size"
    );
    // Win32 requires aligned TOKEN_USER storage (Vec<u8> does not promise it).
    let mut buffer = vec![0usize; (bytes as usize).div_ceil(std::mem::size_of::<usize>())];
    unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            Some(buffer.as_mut_ptr().cast()),
            bytes,
            &mut bytes,
        )
    }?;
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    let mut sid = PWSTR::null();
    unsafe { ConvertSidToStringSidW(user.User.Sid, &mut sid) }?;
    let result = unsafe { sid.to_string() };
    let _ = unsafe { LocalFree(Some(HLOCAL(sid.0.cast()))) };
    Ok(result?)
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        unsafe {
            let _ = LocalFree(Some(HLOCAL(self.psd.0)));
        }
    }
}

unsafe impl Send for SecurityDescriptor {}
unsafe impl Sync for SecurityDescriptor {}

fn create_pipe(sd: &SecurityDescriptor, first: bool) -> Result<NamedPipeServer> {
    let attrs = sd.attrs();
    let mut opts = ServerOptions::new();
    opts.reject_remote_clients(true);
    if first {
        opts.first_pipe_instance(true);
    }
    unsafe {
        opts.create_with_security_attributes_raw(STATUS_PIPE_NAME, &attrs as *const _ as *mut _)
    }
    .context("create_with_security_attributes_raw failed")
}

pub async fn run(bus: Arc<StatusBus>, vpn_state: VpnStateHandle) -> Result<()> {
    let sd = SecurityDescriptor::current_user()?;
    let mut server = create_pipe(&sd, true)?;
    tracing::info!("status pipe server listening on {}", STATUS_PIPE_NAME);

    let permits = Arc::new(tokio::sync::Semaphore::new(MAX_CLIENTS));
    let mut clients = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            result = server.connect() => result.context("status pipe accept failed")?,
            _ = clients.join_next(), if !clients.is_empty() => continue,
        }
        let connected = server;
        server = create_pipe(&sd, false)?;
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            drop(connected);
            continue;
        };

        let bus = bus.clone();
        let vpn_state = vpn_state.clone();
        clients.spawn(async move {
            let _permit = permit;
            if let Err(e) = handle_client(connected, bus, vpn_state).await {
                tracing::warn!("status client disconnected: {}", e);
            }
        });
    }
}

async fn handle_client(
    mut pipe: NamedPipeServer,
    bus: Arc<StatusBus>,
    vpn_state: VpnStateHandle,
) -> Result<()> {
    tracing::info!("status client connected");
    let mut frame_buf = Vec::with_capacity(256);
    let mut prev_pids: HashMap<u32, (u64, u64)> = HashMap::new();
    let mut prev_sample: Instant = Instant::now();
    loop {
        frame_buf.clear();
        let now = Instant::now();
        let elapsed = now.duration_since(prev_sample).as_secs_f64().max(0.001);
        let (msg, snapshot_pids) = build_snapshot(&bus, &vpn_state, &prev_pids, elapsed);
        prev_pids = snapshot_pids;
        prev_sample = now;
        anyhow::ensure!(
            msg.encoded_len() <= MAX_FRAME - 4,
            "status frame exceeds limit"
        );
        ipc::encode_status_frame(&msg, &mut frame_buf);
        if let Err(e) = write_frame(&mut pipe, &frame_buf, WRITE_TIMEOUT).await {
            if matches!(
                e.kind(),
                std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::UnexpectedEof
            ) {
                return Ok(());
            }
            return Err(e.into());
        }
        tokio::time::sleep(TICK).await;
    }
}

async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    frame: &[u8],
    deadline: Duration,
) -> std::io::Result<()> {
    tokio::time::timeout(deadline, async {
        writer.write_all(frame).await?;
        writer.flush().await
    })
    .await
    .map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::TimedOut, "status client is not reading")
    })?
}

fn build_snapshot(
    bus: &StatusBus,
    vpn_state: &VpnStateHandle,
    prev_pids: &HashMap<u32, (u64, u64)>,
    elapsed_s: f64,
) -> (StatusMessage, HashMap<u32, (u64, u64)>) {
    let now = vpn_state::current(vpn_state);
    let (up, adapter_ip, uptime_ms) = match now {
        Some(target) => {
            let up_since = bus.vpn_up_since_ms.load(Ordering::Relaxed);
            let now_ms = unix_millis();
            let uptime = if up_since > 0 && now_ms >= up_since {
                now_ms - up_since
            } else {
                0
            };
            (true, target.ipv4.to_string(), uptime)
        }
        None => (false, String::new(), 0),
    };

    // First gather raw per-PID counters and compute per-PID rates by diffing
    // against the previous sample. Then group those into per-app AppStats.
    struct PidSnapshot {
        pid: u32,
        bytes_out: u64,
        bytes_in: u64,
        bps_out: u64,
        bps_in: u64,
    }
    let mut next_pids: HashMap<u32, (u64, u64)> = HashMap::new();
    let mut per_path_pids: HashMap<String, Vec<PidSnapshot>> = HashMap::new();
    for entry in bus.pid_paths.iter() {
        let pid = *entry.key();
        let path = entry.value().clone();
        let out = bus
            .pid_bytes_out
            .get(&pid)
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0);
        let in_ = bus
            .pid_bytes_in
            .get(&pid)
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0);
        let prev = prev_pids.get(&pid).copied().unwrap_or((out, in_));
        let bps_out = ((out.saturating_sub(prev.0)) as f64 / elapsed_s).max(0.0) as u64;
        let bps_in = ((in_.saturating_sub(prev.1)) as f64 / elapsed_s).max(0.0) as u64;
        next_pids.insert(pid, (out, in_));
        per_path_pids.entry(path).or_default().push(PidSnapshot {
            pid,
            bytes_out: out,
            bytes_in: in_,
            bps_out,
            bps_in,
        });
    }

    let apps: Vec<AppStats> = per_path_pids
        .into_iter()
        .map(|(path, mut pids)| {
            // Most-active first inside each app.
            pids.sort_by_key(|p| std::cmp::Reverse(p.bytes_out.saturating_add(p.bytes_in)));
            let active = pids.len() as u32;
            let total_out: u64 = pids.iter().map(|p| p.bytes_out).sum();
            let total_in: u64 = pids.iter().map(|p| p.bytes_in).sum();
            let total_bps_out: u64 = pids.iter().map(|p| p.bps_out).sum();
            let total_bps_in: u64 = pids.iter().map(|p| p.bps_in).sum();
            let pid_stats: Vec<PidStats> = pids
                .into_iter()
                .map(|p| PidStats {
                    pid: p.pid,
                    bytes_out: p.bytes_out,
                    bytes_in: p.bytes_in,
                    bytes_out_per_sec: p.bps_out,
                    bytes_in_per_sec: p.bps_in,
                })
                .collect();
            AppStats {
                exe_path: path,
                bytes_out: total_out,
                bytes_in: total_in,
                bytes_out_per_sec: total_bps_out,
                bytes_in_per_sec: total_bps_in,
                active_pids: active,
                pids: pid_stats,
            }
        })
        .collect();

    let msg = StatusMessage {
        body: Some(Body::Snapshot(Snapshot {
            vpn: Some(VpnState {
                up,
                adapter_ip,
                uptime_ms,
                adapter_name: String::new(),
            }),
            totals: Some(Totals {
                bytes_app_to_remote: bus.bytes_out.load(Ordering::Relaxed),
                bytes_remote_to_app: bus.bytes_in.load(Ordering::Relaxed),
                active_tcp_flows: 0,
                active_udp_flows: 0,
            }),
            apps,
            split_dns: Some(dns_snapshot(
                &bus.split_dns.lock().unwrap(),
                Instant::now(),
                now.map(|target| target.session_id),
            )),
        })),
    };
    (msg, next_pids)
}

fn unix_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn stalled_client_hits_write_deadline() {
        let (mut writer, _reader) = tokio::io::duplex(1);
        let error = write_frame(&mut writer, &[0; 16], Duration::from_millis(20))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    }
    #[test]
    fn status_acl_uses_current_account() {
        assert!(current_user_sid().unwrap().starts_with("S-1-"));
        SecurityDescriptor::current_user().unwrap();
    }

    #[test]
    fn dns_readiness_requires_fresh_matching_nonzero_identity() {
        let bus = StatusBus::new();
        let session = [0x12; 16];
        let generation = [0xab; 16];
        bus.set_split_dns(true, Some((session, generation)));
        let status = bus.split_dns.lock().unwrap();
        let time = status.refreshed.unwrap();
        let valid = dns_snapshot(&status, time, Some(session));
        assert!(valid.ready);
        assert_eq!(valid.session_id, "12121212121212121212121212121212");
        assert_eq!(valid.generation, "abababababababababababababababab");
        for (instant, identity) in [
            (
                time + DNS_READY_TTL + Duration::from_nanos(1),
                Some(session),
            ),
            (time, Some([0x34; 16])),
            (time, None),
        ] {
            let revoked = dns_snapshot(&status, instant, identity);
            assert!(!revoked.ready);
            assert!(revoked.session_id.is_empty() && revoked.generation.is_empty());
        }
        drop(status);
        bus.set_split_dns(true, Some(([0; 16], generation)));
        assert!(!bus.split_dns.lock().unwrap().state.ready);
    }

    #[test]
    fn dns_revocation_keeps_mode_and_drop_diagnostics() {
        let bus = StatusBus::new();
        bus.set_split_dns(true, Some(([1; 16], [2; 16])));
        bus.split_dns_drop("ambiguous_owner");
        bus.set_split_dns(true, None);
        let status = bus.split_dns.lock().unwrap();
        assert!(status.state.enabled);
        assert!(!status.state.ready);
        assert!(status.state.session_id.is_empty());
        assert_eq!(status.state.dropped, 1);
        assert_eq!(status.state.fault, "ambiguous_owner");
        drop(status);
        bus.clear_split_dns_fault();
        assert!(bus.split_dns.lock().unwrap().state.fault.is_empty());
        bus.split_dns_drop("unsafe query/name");
        assert_eq!(
            bus.split_dns.lock().unwrap().state.fault,
            "dns_packet_rejected"
        );
    }
}
