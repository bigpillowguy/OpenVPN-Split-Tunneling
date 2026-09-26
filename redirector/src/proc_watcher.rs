use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System};

use crate::policy::{self, PolicyState};
use crate::status_server::StatusBus;
use crate::tunneled::{self, TunneledPaths};

// We still poll, but the *primary* admission path is now in divert.rs (it
// admits PIDs the instant their first packet shows up). This watcher exists
// mainly to (a) catch already-running processes when the user adds a path
// to the tunnel list, and (b) garbage-collect dead PIDs.
const POLL_INTERVAL: Duration = Duration::from_millis(500);
const CONFIG_RELOAD_INTERVAL: Duration = Duration::from_secs(2);

pub async fn run(
    policy_state: PolicyState,
    bus: Arc<StatusBus>,
    tunneled_paths: TunneledPaths,
) -> Result<()> {
    tracing::info!("proc watcher running (polls every {:?})", POLL_INTERVAL);

    let mut sys = System::new_all();
    let mut last_config_load = std::time::Instant::now() - CONFIG_RELOAD_INTERVAL;

    loop {
        if last_config_load.elapsed() >= CONFIG_RELOAD_INTERVAL {
            match tunneled::load_from_disk() {
                Ok(from_disk) => tunneled::replace(&tunneled_paths, from_disk),
                Err(error) => tracing::warn!(%error, "keeping last valid tunnel configuration"),
            }
            last_config_load = std::time::Instant::now();
        }

        sys.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::new().with_exe(sysinfo::UpdateKind::Always),
        );

        // Snapshot the path list so we don't hold the read lock during sysinfo
        // iteration (which can be a few ms on a busy box).
        let paths: Vec<PathBuf> = tunneled_paths.read().unwrap().clone();
        let mut auto_tunneled = HashSet::new();
        for (pid, process) in sys.processes() {
            let pid_u32 = pid.as_u32();
            let Some(exe) = process.exe() else { continue };
            if !path_matches_any(exe, &paths) {
                continue;
            }
            let path_str = exe.to_string_lossy().to_string();
            bus.pid_paths.insert(pid_u32, path_str);
            auto_tunneled.insert(pid_u32);
        }

        policy::replace(&policy_state, auto_tunneled.iter().copied());
        bus.pid_paths.retain(|p, _| auto_tunneled.contains(p));
        bus.pid_bytes_out.retain(|p, _| auto_tunneled.contains(p));
        bus.pid_bytes_in.retain(|p, _| auto_tunneled.contains(p));

        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

fn path_matches_any(candidate: &std::path::Path, list: &[PathBuf]) -> bool {
    let candidate_lower = candidate.to_string_lossy().to_lowercase();
    list.iter()
        .any(|p| p.to_string_lossy().to_lowercase() == candidate_lower)
}
