use std::net::Ipv4Addr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::Result;

use crate::adapter::{self, VpnTarget};
use crate::status_server::StatusBus;

pub type VpnState = Arc<RwLock<Option<VpnTarget>>>;

const POLL_INTERVAL: Duration = Duration::from_secs(2);

pub fn new() -> VpnState {
    Arc::new(RwLock::new(None))
}

pub fn current(state: &VpnState) -> Option<VpnTarget> {
    *state.read().unwrap()
}

pub async fn watcher(state: VpnState, bus: Arc<StatusBus>) -> Result<()> {
    let mut last: Option<VpnTarget> = None;
    let mut last_gateway: Option<Ipv4Addr> = None;
    loop {
        let adapters = tokio::task::spawn_blocking(adapter::enumerate).await??;
        let now = adapter::find_vpn_target(&adapters);
        let same = match (last, now) {
            (Some(a), Some(b)) => a.ipv4 == b.ipv4 && a.if_index == b.if_index,
            (None, None) => true,
            _ => false,
        };
        if !same {
            match (last, now) {
                (None, Some(t)) => {
                    tracing::info!("VPN adapter UP at {} (ifindex {})", t.ipv4, t.if_index);
                    bus.vpn_up_since_ms.store(unix_millis(), Ordering::Relaxed);
                    last_gateway = ensure_split_tunnel_route(t).await;
                }
                (Some(old), None) => {
                    tracing::warn!("VPN adapter DOWN (was {})", old.ipv4);
                    bus.vpn_up_since_ms.store(0, Ordering::Relaxed);
                    if let Some(gw) = last_gateway.take() {
                        remove_split_tunnel_route(gw, old.if_index).await;
                    }
                }
                (Some(old), Some(new)) => {
                    tracing::info!(
                        "VPN adapter changed: {} (ifindex {}) -> {} (ifindex {})",
                        old.ipv4, old.if_index, new.ipv4, new.if_index
                    );
                    bus.vpn_up_since_ms.store(unix_millis(), Ordering::Relaxed);
                    if let Some(gw) = last_gateway.take() {
                        remove_split_tunnel_route(gw, old.if_index).await;
                    }
                    last_gateway = ensure_split_tunnel_route(new).await;
                }
                _ => {}
            }
            *state.write().unwrap() = now;
            last = now;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Adds a high-metric `0.0.0.0/0` route via the VPN gateway, pinned to the VPN
/// interface. Normal apps still prefer the Ethernet default route (lower
/// metric), but sockets pinned with IP_UNICAST_IF on the VPN's ifindex now
/// have a valid next-hop and the kernel routes them through the tunnel.
async fn ensure_split_tunnel_route(target: VpnTarget) -> Option<Ipv4Addr> {
    let gateway = find_vpn_gateway(target.ipv4).await?;
    tracing::info!(
        "adding split-tunnel route: 0.0.0.0/0 via {} ifindex {} metric 9999",
        gateway, target.if_index
    );
    let output = tokio::process::Command::new("route.exe")
        .args([
            "ADD", "0.0.0.0", "MASK", "0.0.0.0",
            &gateway.to_string(),
            "METRIC", "9999",
            "IF", &target.if_index.to_string(),
        ])
        .output()
        .await
        .ok()?;
    if !output.status.success() {
        tracing::warn!(
            "route ADD failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Some(gateway)
}

async fn remove_split_tunnel_route(gateway: Ipv4Addr, _ifindex: u32) {
    tracing::info!("removing split-tunnel route: 0.0.0.0/0 via {}", gateway);
    let _ = tokio::process::Command::new("route.exe")
        .args(["DELETE", "0.0.0.0", "MASK", "0.0.0.0", &gateway.to_string()])
        .output()
        .await;
}

/// Find the VPN's peer / next-hop by scanning `route print -4` for a /32 route
/// whose Interface column equals the VPN adapter's IP. The Gateway column on
/// that row is the next-hop OpenVPN installed at handshake time.
async fn find_vpn_gateway(vpn_ip: Ipv4Addr) -> Option<Ipv4Addr> {
    let output = tokio::process::Command::new("route.exe")
        .args(["print", "-4"])
        .output()
        .await
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    let vpn_ip_str = vpn_ip.to_string();

    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }
        // Layout: Network Destination, Netmask, Gateway, Interface, Metric
        if parts[1] != "255.255.255.255" {
            continue;
        }
        if parts[3] != vpn_ip_str {
            continue;
        }
        if let Ok(gw) = parts[2].parse::<Ipv4Addr>() {
            if !gw.is_unspecified() && gw != vpn_ip {
                return Some(gw);
            }
        }
    }
    None
}

fn unix_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
