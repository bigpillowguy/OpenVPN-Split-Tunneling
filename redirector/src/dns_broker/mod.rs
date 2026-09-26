//! Opt-in private DNS transport broker for selected Windows processes.
//! The UI does not start it; Windows VPN Platform integration is still research.
//! No system resolver API, system cache, public resolver, or unbound fallback.
mod security;
mod transport;
mod wire;

use anyhow::Result;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::NamedPipeServer;

use crate::process::Resolver;
use crate::session_binding::{DnsSession, SessionSource};
use crate::shutdown::Shutdown;
use crate::vpn_state::{self, VpnState};

const MAGIC: u32 = 0x31534e44;
const MAX_CLIENTS: usize = 32;
const ACCESS_DENIED: u32 = 5;
const INVALID_PARAMETER: u32 = 87;
const NOT_READY: u32 = 1231;
const CANCELLED: u32 = 1223;
const TIMEOUT: u32 = 1460;
const SERVER_FAILURE: u32 = 9002;
const POLL: Duration = Duration::from_millis(250);

pub fn pipe_path(name: &str) -> Result<String> {
    let suffix = name.strip_prefix("VpnClient-Dns-").unwrap_or("");
    anyhow::ensure!(
        suffix.len() == 32 && suffix.bytes().all(|c| c.is_ascii_hexdigit()),
        "invalid private DNS pipe name"
    );
    Ok(format!(r"\\.\pipe\{name}"))
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Lease {
    pid: u32,
    creation_time: u64,
    exe_path: String,
    dns: DnsSession,
}

trait Authority: Send + Sync {
    fn capture(&self, pid: u32) -> std::result::Result<Lease, u32>;
}

struct LiveAuthority {
    resolver: Arc<Resolver>,
    session: SessionSource,
    vpn: VpnState,
}
impl Authority for LiveAuthority {
    fn capture(&self, pid: u32) -> std::result::Result<Lease, u32> {
        let process = self.resolver.resolve(pid).ok_or(ACCESS_DENIED)?;
        // Synchronous fresh policy read: the watcher may not yet have seen a
        // just-added/removed executable. Parse/I/O failure never grants access.
        let paths = crate::tunneled::load_from_disk().map_err(|_| ACCESS_DENIED)?;
        if !selected(&paths, &process.exe_path) {
            return Err(ACCESS_DENIED);
        }
        let dns = self
            .session
            .current_dns()
            .map_err(|_| NOT_READY)?
            .ok_or(NOT_READY)?;
        if vpn_state::current(&self.vpn) != Some(dns.target) {
            return Err(NOT_READY);
        }
        Ok(Lease {
            pid,
            creation_time: process.creation_time,
            exe_path: process.exe_path,
            dns,
        })
    }
}

fn selected(paths: &[std::path::PathBuf], candidate: &str) -> bool {
    let path = Path::new(candidate)
        .to_string_lossy()
        .replace('/', "\\")
        .to_lowercase();
    paths
        .iter()
        .any(|p| p.to_string_lossy().replace('/', "\\").to_lowercase() == path)
}

pub async fn run(
    name: String,
    resolver: Arc<Resolver>,
    vpn: VpnState,
    session: SessionSource,
    shutdown: Shutdown,
) -> Result<()> {
    let authority = Arc::new(LiveAuthority {
        resolver,
        session,
        vpn,
    });
    listen(&pipe_path(&name)?, authority, shutdown).await
}

async fn listen(path: &str, authority: Arc<dyn Authority>, shutdown: Shutdown) -> Result<()> {
    let security = security::SecurityDescriptor::new()?;
    let mut server = security.pipe(path, true)?;
    let permits = Arc::new(tokio::sync::Semaphore::new(MAX_CLIENTS));
    let mut clients = tokio::task::JoinSet::new();
    tracing::info!("private DNS broker listening");
    loop {
        tokio::select! {
            _=tokio::time::sleep(Duration::from_millis(100)) => {
                if shutdown.is_stopped() { break }
            }
            result=clients.join_next(), if !clients.is_empty() => {
                if let Some(Err(error))=result { tracing::warn!(%error,"DNS client worker failed"); }
            }
            result=server.connect() => {
                result?;
                let Ok(permit)=permits.clone().try_acquire_owned() else {
                    // Reuse this listening instance; do not allocate unbounded
                    // rejection workers when the broker is saturated.
                    server.disconnect()?;
                    continue;
                };
                let next=security.pipe(path,false)?;
                let connected=std::mem::replace(&mut server,next);
                let authority=authority.clone(); let shutdown=shutdown.clone();
                clients.spawn(async move {
                    let _permit=permit;
                    if let Err(error)=serve(connected,authority,shutdown).await {
                        tracing::debug!(%error,"DNS client disconnected");
                    }
                });
            }
        }
    }
    clients.abort_all();
    while clients.join_next().await.is_some() {}
    Ok(())
}

async fn read_request(pipe: &mut NamedPipeServer) -> std::result::Result<(u32, Vec<u8>), u32> {
    let mut header = [0; 12];
    pipe.read_exact(&mut header)
        .await
        .map_err(|_| INVALID_PARAMETER)?;
    let field = |at| u32::from_le_bytes(header[at..at + 4].try_into().unwrap());
    let operation = field(4);
    let length = field(8) as usize;
    if field(0) != MAGIC
        || operation > 1
        || length > wire::MAX_QUERY
        || (operation == 0 && length != 0)
        || (operation == 1 && length < 12)
    {
        return Err(INVALID_PARAMETER);
    }
    let mut payload = vec![0; length];
    pipe.read_exact(&mut payload)
        .await
        .map_err(|_| INVALID_PARAMETER)?;
    Ok((operation, payload))
}

async fn write_response(
    pipe: &mut NamedPipeServer,
    status: u32,
    bytes: &[u8],
) -> std::io::Result<()> {
    let mut header = [0; 12];
    header[..4].copy_from_slice(&MAGIC.to_le_bytes());
    header[4..8].copy_from_slice(&status.to_le_bytes());
    header[8..].copy_from_slice(&(bytes.len() as u32).to_le_bytes());
    pipe.write_all(&header).await?;
    pipe.write_all(bytes).await
}

async fn serve(
    mut pipe: NamedPipeServer,
    authority: Arc<dyn Authority>,
    shutdown: Shutdown,
) -> Result<()> {
    // This PID is supplied by the kernel, not by any client-controlled frame.
    let pid = security::client_pid(&pipe)?;
    let result = async {
        let connected = authority.capture(pid)?;
        let (operation, request) =
            tokio::time::timeout(Duration::from_secs(2), read_request(&mut pipe))
                .await
                .map_err(|_| TIMEOUT)??;
        let lease = authority.capture(pid)?;
        if connected.creation_time != lease.creation_time || connected.exe_path != lease.exe_path {
            return Err(ACCESS_DENIED);
        }
        if shutdown.is_stopped() {
            return Err(CANCELLED);
        }
        if operation == 0 {
            return Ok(Vec::new());
        }
        let question = wire::query(&request).map_err(|_| INVALID_PARAMETER)?;
        let binding = transport::Binding::vpn(lease.dns.target);
        let exchange = transport::exchange(binding, &lease.dns.servers, &request, &question);
        let mut disconnected = [0; 1];
        tokio::select! {
            response=guarded(exchange,authority.as_ref(),&lease,&shutdown) => response,
            _=pipe.read(&mut disconnected) => Err(CANCELLED),
        }
    }
    .await;
    let (status, bytes) = match result {
        Ok(bytes) => (0, bytes),
        Err(status) => (status, Vec::new()),
    };
    tokio::time::timeout(
        Duration::from_secs(1),
        write_response(&mut pipe, status, &bytes),
    )
    .await??;
    // Keep the instance alive while the peer consumes the buffered response.
    // Clients close this one-shot connection after reading its complete frame.
    let mut byte = [0; 1];
    let _ = tokio::time::timeout(Duration::from_secs(1), pipe.read(&mut byte)).await;
    Ok(())
}

async fn guarded<F>(
    work: F,
    authority: &dyn Authority,
    lease: &Lease,
    shutdown: &Shutdown,
) -> std::result::Result<Vec<u8>, u32>
where
    F: std::future::Future<Output = std::result::Result<Vec<u8>, u32>>,
{
    tokio::pin!(work);
    let mut tick = tokio::time::interval(POLL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let valid =
        || !shutdown.is_stopped() && authority.capture(lease.pid).is_ok_and(|now| now == *lease);
    loop {
        tokio::select! {
            result=&mut work => return if valid() { result } else { Err(CANCELLED) },
            _=tick.tick() => if !valid() { return Err(CANCELLED) },
        }
    }
}

#[cfg(test)]
mod tests;
