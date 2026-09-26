use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use windows::Win32::Foundation::NO_ERROR;
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
    MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows::Win32::Networking::WinSock::AF_INET;

/// Synchronous fallback when the observer-populated flow table hasn't caught
/// up with a fresh socket yet. Hits the Windows IP helper to find the PID
/// that owns (proto, local_addr, local_port).
///
/// Cost: ~hundreds of microseconds. We only call it on first-packet misses,
/// because the second the flow lands in the policy, every subsequent packet
/// from that PID takes the fast path.
pub fn pid_for_local_v4(local_addr: Ipv4Addr, local_port: u16, proto: u8) -> Option<u32> {
    match proto {
        6 => pid_for_tcp_v4(local_addr, local_port),
        17 => pid_for_udp_v4(local_addr, local_port),
        _ => None,
    }
}

fn pid_for_tcp_v4(local_addr: Ipv4Addr, local_port: u16) -> Option<u32> {
    let mut size: u32 = 0;
    unsafe {
        let _ = GetExtendedTcpTable(
            None,
            &mut size,
            false,
            AF_INET.0 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
    }
    if size == 0 {
        return None;
    }
    let mut buf = vec![0u8; size as usize];
    let rc = unsafe {
        GetExtendedTcpTable(
            Some(buf.as_mut_ptr() as *mut _),
            &mut size,
            false,
            AF_INET.0 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };
    if rc != NO_ERROR.0 {
        return None;
    }
    let table = unsafe { &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID) };
    let count = table.dwNumEntries as usize;
    if count == 0 {
        return None;
    }
    let rows: &[MIB_TCPROW_OWNER_PID] =
        unsafe { std::slice::from_raw_parts(table.table.as_ptr(), count) };
    let target_addr_be = u32::from(local_addr).to_be();
    for row in rows {
        let port = port_from_dword(row.dwLocalPort);
        if port != local_port {
            continue;
        }
        if row.dwLocalAddr != 0 && row.dwLocalAddr != target_addr_be {
            continue;
        }
        return Some(row.dwOwningPid);
    }
    None
}

fn pid_for_udp_v4(local_addr: Ipv4Addr, local_port: u16) -> Option<u32> {
    let mut size: u32 = 0;
    unsafe {
        let _ = GetExtendedUdpTable(
            None,
            &mut size,
            false,
            AF_INET.0 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        );
    }
    if size == 0 {
        return None;
    }
    let mut buf = vec![0u8; size as usize];
    let rc = unsafe {
        GetExtendedUdpTable(
            Some(buf.as_mut_ptr() as *mut _),
            &mut size,
            false,
            AF_INET.0 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        )
    };
    if rc != NO_ERROR.0 {
        return None;
    }
    let table = unsafe { &*(buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID) };
    let count = table.dwNumEntries as usize;
    if count == 0 {
        return None;
    }
    let rows: &[MIB_UDPROW_OWNER_PID] =
        unsafe { std::slice::from_raw_parts(table.table.as_ptr(), count) };
    let target_addr_be = u32::from(local_addr).to_be();
    for row in rows {
        let port = port_from_dword(row.dwLocalPort);
        if port != local_port {
            continue;
        }
        if row.dwLocalAddr != 0 && row.dwLocalAddr != target_addr_be {
            continue;
        }
        return Some(row.dwOwningPid);
    }
    None
}

/// dwLocalPort is a DWORD whose low 16 bits hold the port in network byte
/// order. Mask + byte-swap to get the host-order port.
fn port_from_dword(d: u32) -> u16 {
    u16::from_be((d & 0xFFFF) as u16)
}

/// A DNS decision must not pick the first row when endpoints are shared.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum OwnerLookup {
    Unique(u32),
    #[default]
    Unknown,
    Ambiguous,
}

impl OwnerLookup {
    fn add(&mut self, pid: u32) {
        *self = match *self {
            Self::Unknown => Self::Unique(pid),
            Self::Unique(existing) if existing == pid => *self,
            _ => Self::Ambiguous,
        };
    }

    fn merge(&mut self, other: Self) {
        match other {
            Self::Unknown => {}
            Self::Unique(pid) => self.add(pid),
            Self::Ambiguous => *self = Self::Ambiguous,
        }
    }
}

/// Fresh authoritative OS table, without SOCKET event aliases. TCP matches the
/// entire four-tuple; UDP reports ambiguity across all matching wildcard/exact
/// owners because the OS UDP table does not provide the remote endpoint.
pub fn owner_for_tuple(local: SocketAddr, remote: SocketAddr, proto: u8) -> OwnerLookup {
    let started = std::time::Instant::now();
    let mut lookup_failed = false;
    let mut lookup = || {
        let result = owner_once(local, remote, proto);
        if let (SocketAddr::V4(local), SocketAddr::V4(remote)) = (local, remote) {
            // IPv4 packets can originate from dual-stack IPv6 sockets. UDP
            // tables do not expose IPV6_V6ONLY, so a competing IPv6 wildcard
            // owner conservatively makes the decision ambiguous.
            let mapped = owner_once(
                SocketAddr::new(local.ip().to_ipv6_mapped().into(), local.port()),
                SocketAddr::new(remote.ip().to_ipv6_mapped().into(), remote.port()),
                proto,
            );
            lookup_failed = result.is_none() || mapped.is_none();
            return combine_families(result, mapped);
        }
        lookup_failed = result.is_none();
        result.unwrap_or(OwnerLookup::Unknown)
    };
    let mut result = lookup();
    for _ in 0..4 {
        if !matches!(result, OwnerLookup::Unknown | OwnerLookup::Unique(0)) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_micros(200));
        result = lookup();
    }
    if matches!(
        result,
        OwnerLookup::Unknown | OwnerLookup::Ambiguous | OwnerLookup::Unique(0)
    ) && crate::dns_broker::trace::allow(crate::dns_broker::trace::Category::Ownership)
    {
        let reason = if lookup_failed {
            "native_table_unavailable"
        } else {
            match result {
                OwnerLookup::Unknown => "successful_table_no_match",
                OwnerLookup::Unique(0) => "row_owner_unavailable",
                _ => "multiple_endpoint_owners",
            }
        };
        tracing::warn!(%local, %remote, proto, reason,
            elapsed_us = started.elapsed().as_micros() as u64, "split DNS owner lookup unresolved");
    }
    result
}

fn combine_families(first: Option<OwnerLookup>, second: Option<OwnerLookup>) -> OwnerLookup {
    let (Some(mut first), Some(second)) = (first, second) else {
        return OwnerLookup::Unknown;
    };
    first.merge(second);
    first
}

// None means the OS lookup failed; Some(Unknown) is a successful empty match.
// Failure cannot be merged away by a unique result from the other address family.
fn owner_once(local: SocketAddr, remote: SocketAddr, proto: u8) -> Option<OwnerLookup> {
    use windows::Win32::NetworkManagement::IpHelper::{
        MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID,
        MIB_UDP6TABLE_OWNER_PID,
    };
    use windows::Win32::Networking::WinSock::AF_INET6;
    let family = if local.is_ipv4() && remote.is_ipv4() {
        AF_INET
    } else if local.is_ipv6() && remote.is_ipv6() {
        AF_INET6
    } else {
        return None;
    };
    let (buffer, bytes) = owner_table(proto, family.0 as u32)?;
    let mut result = OwnerLookup::Unknown;
    match (local, remote, proto) {
        (SocketAddr::V4(local), SocketAddr::V4(remote), 6) => {
            let rows = table_rows::<MIB_TCPROW_OWNER_PID>(
                &buffer,
                bytes,
                std::mem::offset_of!(MIB_TCPTABLE_OWNER_PID, table),
            )?;
            for row in rows {
                if port_from_dword(row.dwLocalPort) == local.port()
                    && row.dwLocalAddr == u32::from(*local.ip()).to_be()
                    && port_from_dword(row.dwRemotePort) == remote.port()
                    && row.dwRemoteAddr == u32::from(*remote.ip()).to_be()
                {
                    result.add(row.dwOwningPid);
                }
            }
        }
        (SocketAddr::V4(local), _, 17) => {
            let rows = table_rows::<MIB_UDPROW_OWNER_PID>(
                &buffer,
                bytes,
                std::mem::offset_of!(MIB_UDPTABLE_OWNER_PID, table),
            )?;
            for row in rows {
                if port_from_dword(row.dwLocalPort) == local.port()
                    && (row.dwLocalAddr == 0 || row.dwLocalAddr == u32::from(*local.ip()).to_be())
                {
                    result.add(row.dwOwningPid);
                }
            }
        }
        (SocketAddr::V6(local), SocketAddr::V6(remote), 6) => {
            let rows = table_rows::<MIB_TCP6ROW_OWNER_PID>(
                &buffer,
                bytes,
                std::mem::offset_of!(MIB_TCP6TABLE_OWNER_PID, table),
            )?;
            for row in rows {
                if port_from_dword(row.dwLocalPort) == local.port()
                    && Ipv6Addr::from(row.ucLocalAddr) == *local.ip()
                    && port_from_dword(row.dwRemotePort) == remote.port()
                    && Ipv6Addr::from(row.ucRemoteAddr) == *remote.ip()
                {
                    result.add(row.dwOwningPid);
                }
            }
        }
        (SocketAddr::V6(local), _, 17) => {
            let rows = table_rows::<MIB_UDP6ROW_OWNER_PID>(
                &buffer,
                bytes,
                std::mem::offset_of!(MIB_UDP6TABLE_OWNER_PID, table),
            )?;
            for row in rows {
                let ip = Ipv6Addr::from(row.ucLocalAddr);
                if port_from_dword(row.dwLocalPort) == local.port()
                    && (ip.is_unspecified() || ip == *local.ip())
                {
                    result.add(row.dwOwningPid);
                }
            }
        }
        _ => {}
    }
    Some(result)
}

fn owner_table(proto: u8, family: u32) -> Option<(Vec<u64>, usize)> {
    use windows::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;
    let mut bytes = 16 * 1024u32;
    for _ in 0..4 {
        if bytes == 0 || bytes > 16 * 1024 * 1024 {
            return None;
        }
        let mut storage = vec![0u64; (bytes as usize).div_ceil(8)];
        let rc = unsafe {
            match proto {
                6 => GetExtendedTcpTable(
                    Some(storage.as_mut_ptr().cast()),
                    &mut bytes,
                    false,
                    family,
                    TCP_TABLE_OWNER_PID_ALL,
                    0,
                ),
                17 => GetExtendedUdpTable(
                    Some(storage.as_mut_ptr().cast()),
                    &mut bytes,
                    false,
                    family,
                    UDP_TABLE_OWNER_PID,
                    0,
                ),
                _ => return None,
            }
        };
        if rc == NO_ERROR.0 {
            return Some((storage, bytes as usize));
        }
        if rc != ERROR_INSUFFICIENT_BUFFER.0 {
            if crate::dns_broker::trace::allow(crate::dns_broker::trace::Category::Ownership) {
                tracing::warn!(proto, family, rc, "split DNS native owner table failed");
            }
            return None;
        }
    }
    None
}

fn table_rows<T>(storage: &[u64], bytes: usize, offset: usize) -> Option<&[T]> {
    if bytes < offset
        || bytes > std::mem::size_of_val(storage)
        || offset < 4
        || std::mem::align_of::<T>() > 8
        || !offset.is_multiple_of(std::mem::align_of::<T>())
    {
        return None;
    }
    let count = unsafe { *storage.as_ptr().cast::<u32>() } as usize;
    let end = offset.checked_add(count.checked_mul(std::mem::size_of::<T>())?)?;
    if end > bytes {
        return None;
    }
    Some(unsafe {
        std::slice::from_raw_parts(storage.as_ptr().cast::<u8>().add(offset).cast(), count)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_pid_is_unique_but_conflicting_pid_is_ambiguous() {
        let mut owner = OwnerLookup::Unknown;
        owner.add(10);
        owner.add(10);
        assert_eq!(owner, OwnerLookup::Unique(10));
        owner.add(20);
        owner.add(10);
        assert_eq!(owner, OwnerLookup::Ambiguous);
        let mut owner = OwnerLookup::Unique(10);
        owner.merge(OwnerLookup::Unknown);
        owner.merge(OwnerLookup::Unique(10));
        assert_eq!(owner, OwnerLookup::Unique(10));
        owner.merge(OwnerLookup::Unique(20));
        assert_eq!(owner, OwnerLookup::Ambiguous);
    }

    #[test]
    fn truncated_native_tables_are_rejected() {
        let mut storage = vec![0u64; 2];
        storage[0] = 99;
        assert!(table_rows::<u32>(&storage, 16, 4).is_none());
        storage[0] = 1;
        assert_eq!(table_rows::<u32>(&storage, 8, 4).unwrap().len(), 1);
        assert!(table_rows::<u32>(&storage, 7, 4).is_none());
        assert!(table_rows::<u32>(&storage, 100, 4).is_none());
    }

    #[test]
    fn failed_family_lookup_cannot_be_treated_as_successful_empty_table() {
        assert_eq!(
            combine_families(Some(OwnerLookup::Unique(10)), None),
            OwnerLookup::Unknown
        );
        assert_eq!(
            combine_families(None, Some(OwnerLookup::Unique(10))),
            OwnerLookup::Unknown
        );
        assert_eq!(
            combine_families(Some(OwnerLookup::Unique(10)), Some(OwnerLookup::Unknown)),
            OwnerLookup::Unique(10)
        );
        assert_eq!(
            combine_families(Some(OwnerLookup::Unique(10)), Some(OwnerLookup::Unique(20))),
            OwnerLookup::Ambiguous
        );
    }

    #[test]
    fn owned_udp_and_tcp_loopback_sockets_resolve_without_driver() {
        let pid = std::process::id();
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        assert_eq!(
            owner_for_tuple(
                udp.local_addr().unwrap(),
                "127.0.0.1:53".parse().unwrap(),
                17
            ),
            OwnerLookup::Unique(pid)
        );
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let stream = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (_accepted, _) = listener.accept().unwrap();
        assert_eq!(
            owner_for_tuple(stream.local_addr().unwrap(), stream.peer_addr().unwrap(), 6),
            OwnerLookup::Unique(pid)
        );
        assert_eq!(
            owner_for_tuple(
                stream.local_addr().unwrap(),
                "127.0.0.1:1".parse().unwrap(),
                6
            ),
            OwnerLookup::Unknown
        );
    }
}
