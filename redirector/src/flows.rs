use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, RwLock};

pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LocalEndpoint {
    pub addr: IpAddr,
    pub port: u16,
    pub proto: u8,
}

#[derive(Debug, Clone, Copy)]
pub struct FlowEntry {
    pub pid: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct SocketOwner {
    entry: FlowEntry,
    endpoint_id: u64,
}

pub type FlowTable = Arc<RwLock<HashMap<LocalEndpoint, SocketOwner>>>;

pub fn new() -> FlowTable {
    Arc::new(RwLock::new(HashMap::new()))
}

pub fn insert_socket(table: &FlowTable, key: LocalEndpoint, entry: FlowEntry, endpoint_id: u64) {
    table
        .write()
        .unwrap()
        .insert(key, SocketOwner { entry, endpoint_id });
}

pub fn lookup(table: &FlowTable, key: &LocalEndpoint) -> Option<FlowEntry> {
    table.read().unwrap().get(key).map(|owner| owner.entry)
}

pub fn close_socket(table: &FlowTable, endpoint_id: u64) {
    // CONNECT and BIND may report different local addresses for one socket.
    // Remove every event-derived entry for this endpoint, but not a newer bind
    // that has reused the same port. Packet-derived aliases are never cached.
    table
        .write()
        .unwrap()
        .retain(|_, owner| owner.endpoint_id != endpoint_id);
}

/// Lookup that falls back to a wildcard (0.0.0.0 / ::) local address. UDP
/// sockets that use sendto without an explicit bind end up registered against
/// the wildcard address even though their outbound packets carry the real LAN
/// source IP. Tries the exact (addr, port, proto) first, then the wildcard
/// variant.
pub fn lookup_with_wildcard(
    table: &FlowTable,
    addr: IpAddr,
    port: u16,
    proto: u8,
) -> Option<FlowEntry> {
    let exact = LocalEndpoint { addr, port, proto };
    if let Some(e) = lookup(table, &exact) {
        return Some(e);
    }
    let wildcard_addr = match addr {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    lookup(
        table,
        &LocalEndpoint {
            addr: wildcard_addr,
            port,
            proto,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wildcard_rebind_and_late_close_preserve_new_owner() {
        let table = new();
        let key = LocalEndpoint {
            addr: Ipv4Addr::UNSPECIFIED.into(),
            port: 40000,
            proto: PROTO_UDP,
        };
        let lan: IpAddr = Ipv4Addr::new(192, 168, 0, 2).into();
        insert_socket(&table, key, FlowEntry { pid: 10 }, 100);
        assert_eq!(
            lookup_with_wildcard(&table, lan, key.port, key.proto)
                .unwrap()
                .pid,
            10
        );
        close_socket(&table, 100);
        assert!(lookup_with_wildcard(&table, lan, key.port, key.proto).is_none());
        insert_socket(&table, key, FlowEntry { pid: 20 }, 200);
        close_socket(&table, 100);
        assert_eq!(
            lookup_with_wildcard(&table, lan, key.port, key.proto)
                .unwrap()
                .pid,
            20
        );
    }
    #[test]
    fn close_removes_all_addresses_for_endpoint() {
        let table = new();
        for addr in [Ipv4Addr::UNSPECIFIED, Ipv4Addr::LOCALHOST] {
            insert_socket(
                &table,
                LocalEndpoint {
                    addr: addr.into(),
                    port: 42,
                    proto: PROTO_UDP,
                },
                FlowEntry { pid: 10 },
                100,
            );
        }
        close_socket(&table, 100);
        assert!(table.read().unwrap().is_empty());
    }
}
