//! The UI publishes this snapshot only after authenticated OpenVPN management
//! UP/CONNECTED metadata identifies its adapter and tunnel gateway. It atomically
//! replaces a private, per-launch file and removes it on DOWN/reconnect/exit.
//! Missing or invalid snapshots revoke readiness; adapters are never guessed.

use std::fs::File;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use serde_json::{Map, Value};

use crate::adapter::{self, Adapter, VpnTarget};
use crate::process::{ProcessInfo, Resolver};

const MAX_SNAPSHOT_BYTES: u64 = 16 * 1024;

pub struct SessionSource {
    path: PathBuf,
    resolver: Arc<Resolver>,
}

impl SessionSource {
    pub fn new(path: &Path, resolver: Arc<Resolver>) -> Result<Self> {
        if !path.is_absolute() {
            bail!("--session-file must be an absolute private session snapshot path");
        }
        Ok(Self {
            path: path.to_owned(),
            resolver,
        })
    }

    pub fn current(&self) -> Result<Option<VpnTarget>> {
        let binding = match read_snapshot(&self.path)? {
            Some(binding) => binding,
            None => return Ok(None),
        };
        let process = self.resolver.resolve(binding.open_vpn_pid);
        binding
            .validate(&adapter::enumerate()?, process.as_ref())
            .map(Some)
    }
}

fn read_snapshot(path: &Path) -> Result<Option<SessionBinding>> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("open VPN session snapshot"),
    };
    let mut bytes = Vec::new();
    file.take(MAX_SNAPSHOT_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_SNAPSHOT_BYTES {
        bail!("VPN session snapshot exceeds size limit");
    }
    SessionBinding::parse(&bytes).map(Some)
}

#[derive(Debug)]
struct SessionBinding {
    session_id: [u8; 16],
    open_vpn_pid: u32,
    open_vpn_creation_time: u64,
    open_vpn_exe_path: String,
    adapter_guid: [u8; 16],
    interface_index: u32,
    ipv4: Ipv4Addr,
    gateway: Ipv4Addr,
}

impl SessionBinding {
    fn parse(bytes: &[u8]) -> Result<Self> {
        let value: Value = serde_json::from_slice(bytes).context("parse VPN session snapshot")?;
        let fields = value
            .as_object()
            .context("VPN session snapshot must be an object")?;
        if number(fields, "version")? != 1 {
            bail!("unsupported VPN session snapshot version");
        }
        let session_id = guid(string(fields, "sessionId")?)?;
        let adapter_guid = guid(string(fields, "adapterGuid")?)?;
        let open_vpn_pid: u32 = number(fields, "openVpnPid")?.try_into()?;
        let interface_index: u32 = number(fields, "interfaceIndex")?.try_into()?;
        let open_vpn_creation_time = number(fields, "openVpnCreationTime")?;
        let open_vpn_exe_path = string(fields, "openVpnExePath")?;
        if open_vpn_pid <= 4 || interface_index == 0 || open_vpn_creation_time == 0 {
            bail!("VPN session snapshot has an invalid process or interface identity");
        }
        if !Path::new(open_vpn_exe_path).is_absolute()
            || open_vpn_exe_path.contains('\0')
            || !open_vpn_exe_path
                .rsplit(['\\', '/'])
                .next()
                .is_some_and(|name| name.eq_ignore_ascii_case("openvpn.exe"))
        {
            bail!("VPN session executable must be an absolute OpenVPN executable path");
        }
        let ipv4 = string(fields, "ipv4")?
            .parse()
            .context("invalid VPN IPv4")?;
        let gateway = string(fields, "gateway")?
            .parse()
            .context("invalid VPN gateway")?;
        if !usable_unicast(ipv4) || !usable_unicast(gateway) || ipv4 == gateway {
            bail!("VPN session requires distinct unicast IPv4 and gateway addresses");
        }
        Ok(Self {
            session_id,
            open_vpn_pid,
            open_vpn_creation_time,
            open_vpn_exe_path: open_vpn_exe_path.to_owned(),
            adapter_guid,
            interface_index,
            ipv4,
            gateway,
        })
    }

    fn validate(&self, adapters: &[Adapter], process: Option<&ProcessInfo>) -> Result<VpnTarget> {
        let process = process.context("bound OpenVPN process is not running")?;
        if process.creation_time != self.open_vpn_creation_time
            || !same_executable(&process.exe_path, &self.open_vpn_exe_path)
        {
            bail!("bound OpenVPN process identity changed");
        }
        let mut matches = adapters.iter().filter(|adapter| {
            adapter.if_index == self.interface_index
                && guid(&adapter.adapter_name).ok() == Some(self.adapter_guid)
        });
        let adapter = matches.next().context("bound VPN adapter is missing")?;
        if matches.next().is_some()
            || !adapter.is_up
            || adapter.interface_luid == 0
            || !adapter.addresses.contains(&IpAddr::V4(self.ipv4))
        {
            bail!("bound VPN adapter is not ready with its session IPv4");
        }
        Ok(VpnTarget {
            ipv4: self.ipv4,
            if_index: self.interface_index,
            interface_luid: adapter.interface_luid,
            adapter_guid: self.adapter_guid,
            session_id: self.session_id,
            gateway: self.gateway,
        })
    }
}

fn string<'a>(fields: &'a Map<String, Value>, field: &str) -> Result<&'a str> {
    fields
        .get(field)
        .and_then(Value::as_str)
        .with_context(|| format!("missing or invalid {field}"))
}

fn number(fields: &Map<String, Value>, field: &str) -> Result<u64> {
    fields
        .get(field)
        .and_then(Value::as_u64)
        .with_context(|| format!("missing or invalid {field}"))
}

fn same_executable(left: &str, right: &str) -> bool {
    left.replace('/', "\\").to_lowercase() == right.replace('/', "\\").to_lowercase()
}

fn usable_unicast(ip: Ipv4Addr) -> bool {
    !ip.is_unspecified()
        && !ip.is_loopback()
        && !ip.is_link_local()
        && !ip.is_multicast()
        && !ip.is_broadcast()
        && (1..224).contains(&ip.octets()[0])
}

fn guid(value: &str) -> Result<[u8; 16]> {
    let value = value
        .strip_prefix('{')
        .and_then(|s| s.strip_suffix('}'))
        .unwrap_or(value);
    if value.len() != 36 || !value.is_ascii() {
        bail!("invalid GUID in VPN session snapshot");
    }
    let mut result = [0; 16];
    let mut digit = 0;
    for (index, byte) in value.bytes().enumerate() {
        if [8, 13, 18, 23].contains(&index) {
            if byte != b'-' {
                bail!("invalid GUID separator");
            }
            continue;
        }
        let nibble = (byte as char).to_digit(16).context("invalid GUID digit")? as u8;
        result[digit / 2] = (result[digit / 2] << 4) | nibble;
        digit += 1;
    }
    if result == [0; 16] {
        bail!("empty GUID in VPN session snapshot");
    }
    Ok(result)
}

#[cfg(test)]
mod tests;
