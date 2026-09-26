use std::net::Ipv4Addr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use windows::Win32::Foundation::{ERROR_NOT_FOUND, ERROR_OBJECT_ALREADY_EXISTS};
use windows::Win32::NetworkManagement::IpHelper::{
    CreateIpForwardEntry2, DeleteIpForwardEntry2, FreeMibTable, GetIpForwardTable2,
    InitializeIpForwardEntry, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2,
};
use windows::Win32::Networking::WinSock::{
    AF_INET, MIB_IPPROTO_NETMGMT, SOCKADDR_IN, SOCKADDR_INET,
};

use crate::adapter::VpnTarget;
use crate::session_binding::SessionSource;
use crate::shutdown::Shutdown;
use crate::status_server::StatusBus;

pub type VpnState = Arc<RwLock<Option<VpnTarget>>>;
const POLL_INTERVAL: Duration = Duration::from_millis(250);
const ROUTE_METRIC: u32 = 9999;

pub fn new() -> VpnState {
    Arc::new(RwLock::new(None))
}
pub fn current(state: &VpnState) -> Option<VpnTarget> {
    *state.read().unwrap()
}

/// This row includes the interface LUID so reuse of an interface index cannot
/// redirect cleanup to a different interface. No shell or localized output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Route {
    luid: u64,
    index: u32,
    destination: Ipv4Addr,
    prefix: u8,
    gateway: Ipv4Addr,
    metric: u32,
}
impl Route {
    fn same_key(&self, other: &Self) -> bool {
        self.luid == other.luid
            && self.index == other.index
            && self.destination == other.destination
            && self.prefix == other.prefix
            && self.gateway == other.gateway
    }
    fn is_default(&self) -> bool {
        self.prefix == 0 && self.destination.is_unspecified()
    }
}

trait RouteApi {
    fn list(&self) -> Result<Vec<Route>>;
    /// true only when this call created the row; false means it already exists.
    fn add(&self, route: Route) -> Result<bool>;
    fn delete(&self, route: Route) -> Result<()>;
}
struct WindowsRoutes;
impl RouteApi for WindowsRoutes {
    fn list(&self) -> Result<Vec<Route>> {
        let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
        unsafe { GetIpForwardTable2(AF_INET, &mut table) }
            .ok()
            .context("GetIpForwardTable2")?;
        if table.is_null() {
            bail!("GetIpForwardTable2 returned a null table");
        }
        let rows = unsafe {
            std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize)
        };
        let result = rows
            .iter()
            .filter_map(|row| unsafe {
                if row.DestinationPrefix.Prefix.si_family != AF_INET
                    || row.NextHop.si_family != AF_INET
                {
                    return None;
                }
                Some(Route {
                    luid: row.InterfaceLuid.Value,
                    index: row.InterfaceIndex,
                    destination: Ipv4Addr::from(
                        row.DestinationPrefix
                            .Prefix
                            .Ipv4
                            .sin_addr
                            .S_un
                            .S_addr
                            .to_ne_bytes(),
                    ),
                    prefix: row.DestinationPrefix.PrefixLength,
                    gateway: Ipv4Addr::from(row.NextHop.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes()),
                    metric: row.Metric,
                })
            })
            .collect();
        unsafe { FreeMibTable(table.cast()) };
        Ok(result)
    }
    fn add(&self, route: Route) -> Result<bool> {
        let rc = unsafe { CreateIpForwardEntry2(&native_row(route)) };
        if rc == ERROR_OBJECT_ALREADY_EXISTS {
            if self.list()?.iter().any(|row| row.same_key(&route)) {
                return Ok(false);
            }
            bail!("route creation reported a conflicting existing row");
        }
        rc.ok().context("CreateIpForwardEntry2")?;
        Ok(true)
    }
    fn delete(&self, route: Route) -> Result<()> {
        let rc = unsafe { DeleteIpForwardEntry2(&native_row(route)) };
        if rc == ERROR_NOT_FOUND {
            return Ok(());
        }
        rc.ok().context("DeleteIpForwardEntry2")
    }
}
fn native_ip(ip: Ipv4Addr) -> SOCKADDR_INET {
    let mut address = SOCKADDR_IN {
        sin_family: AF_INET,
        ..Default::default()
    };
    address.sin_addr.S_un.S_addr = u32::from_ne_bytes(ip.octets());
    SOCKADDR_INET { Ipv4: address }
}
fn native_row(route: Route) -> MIB_IPFORWARD_ROW2 {
    let mut row = MIB_IPFORWARD_ROW2::default();
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.InterfaceLuid.Value = route.luid;
    row.InterfaceIndex = route.index;
    row.DestinationPrefix.Prefix = native_ip(route.destination);
    row.DestinationPrefix.PrefixLength = route.prefix;
    row.SitePrefixLength = route.prefix;
    row.NextHop = native_ip(route.gateway);
    row.Metric = route.metric;
    row.Protocol = MIB_IPPROTO_NETMGMT;
    row.Loopback = false;
    row.AutoconfigureAddress = false;
    row.Publish = false;
    row.Immortal = false;
    row
}

struct Routes<A: RouteApi> {
    api: A,
    target: Option<VpnTarget>,
    owned: Option<Route>,
}
impl<A: RouteApi> Routes<A> {
    fn new(api: A) -> Self {
        Self {
            api,
            target: None,
            owned: None,
        }
    }
    fn cleanup(&mut self) -> Result<()> {
        if let Some(route) = self.owned {
            // Do not remove a route modified by another owner after our add.
            if self.api.list()?.contains(&route) {
                self.api.delete(route)?;
            }
            self.owned = None;
        }
        Ok(())
    }
    fn reconcile(&mut self, target: Option<VpnTarget>) -> Result<Option<VpnTarget>> {
        if self.target != target {
            self.cleanup()?;
            self.target = target;
        }
        let Some(target) = target else {
            return Ok(None);
        };
        let rows = self.api.list()?;
        if let Some(owned) = self.owned {
            if !rows.contains(&owned) {
                self.owned = None;
            }
        }
        let route = Route {
            luid: target.interface_luid,
            index: target.if_index,
            destination: Ipv4Addr::UNSPECIFIED,
            prefix: 0,
            gateway: target.gateway,
            metric: ROUTE_METRIC,
        };
        // A foreign default on this interface could win route selection even
        // for an interface-pinned socket. Do not publish ambiguous readiness.
        if rows.iter().any(|row| {
            row.index == target.if_index
                && row.luid == target.interface_luid
                && row.is_default()
                && row.gateway != target.gateway
        }) {
            bail!("VPN interface has a default route outside its current session gateway");
        }
        // An exact existing default is usable, but never becomes our property.
        if rows.iter().any(|row| row.same_key(&route)) {
            return Ok(Some(target));
        }
        if self.api.add(route)? {
            self.owned = Some(route);
        }
        // Read back before exposing a usable VPN target.
        if !self.api.list()?.iter().any(|row| row.same_key(&route)) {
            bail!("VPN route missing after creation");
        }
        Ok(Some(target))
    }
}
impl<A: RouteApi> Drop for Routes<A> {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            tracing::error!(%error, "could not remove owned VPN route");
        }
    }
}

pub async fn watcher(
    state: VpnState,
    bus: Arc<StatusBus>,
    shutdown: Shutdown,
    session: SessionSource,
) -> Result<()> {
    let mut routes = Routes::new(WindowsRoutes);
    while !shutdown.is_stopped() {
        let candidate = match session.current() {
            Ok(candidate) => candidate,
            Err(error) => {
                tracing::warn!(%error, "VPN session binding is not ready");
                None
            }
        };
        // Revoke the old generation before native route reconciliation. Missing,
        // malformed, exited-process and adapter errors also clean up owned rows.
        if current(&state) != candidate {
            *state.write().unwrap() = None;
            bus.vpn_up_since_ms.store(0, Ordering::Relaxed);
        }
        let ready = match routes.reconcile(candidate) {
            Ok(ready) => ready,
            Err(error) => {
                tracing::warn!(%error, "VPN route not ready; will retry");
                None
            }
        };
        if current(&state) != ready {
            bus.vpn_up_since_ms.store(
                if ready.is_some() { unix_millis() } else { 0 },
                Ordering::Relaxed,
            );
            *state.write().unwrap() = ready;
        }
        // Bounded shutdown even when no adapter or route event arrives.
        let until = tokio::time::Instant::now() + POLL_INTERVAL;
        while !shutdown.is_stopped() && tokio::time::Instant::now() < until {
            tokio::time::sleep_until(
                until.min(tokio::time::Instant::now() + Duration::from_millis(100)),
            )
            .await;
        }
    }
    *state.write().unwrap() = None;
    bus.vpn_up_since_ms.store(0, Ordering::Relaxed);
    routes.cleanup()
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
    use std::cell::{Cell, RefCell};
    #[derive(Default)]
    struct FakeRoutes {
        rows: RefCell<Vec<Route>>,
        fail_add: Cell<bool>,
        deleted: RefCell<Vec<Route>>,
    }
    impl RouteApi for FakeRoutes {
        fn list(&self) -> Result<Vec<Route>> {
            Ok(self.rows.borrow().clone())
        }
        fn add(&self, row: Route) -> Result<bool> {
            if self.fail_add.get() {
                bail!("simulated add failure");
            }
            if self.rows.borrow().iter().any(|r| r.same_key(&row)) {
                return Ok(false);
            }
            self.rows.borrow_mut().push(row);
            Ok(true)
        }
        fn delete(&self, row: Route) -> Result<()> {
            self.deleted.borrow_mut().push(row);
            self.rows.borrow_mut().retain(|r| !r.same_key(&row));
            Ok(())
        }
    }
    fn target() -> VpnTarget {
        VpnTarget {
            ipv4: Ipv4Addr::new(10, 8, 0, 2),
            if_index: 42,
            interface_luid: 1234,
            adapter_guid: [1; 16],
            session_id: [2; 16],
            gateway: Ipv4Addr::new(10, 8, 0, 1),
        }
    }
    fn peer() -> Route {
        Route {
            luid: 1234,
            index: 42,
            destination: Ipv4Addr::new(10, 8, 0, 1),
            prefix: 32,
            gateway: Ipv4Addr::new(10, 8, 0, 1),
            metric: 10,
        }
    }
    #[test]
    fn native_default_has_valid_fields_and_exact_identity() {
        let route = Route {
            destination: Ipv4Addr::UNSPECIFIED,
            prefix: 0,
            ..peer()
        };
        let row = native_row(route);
        assert_eq!(row.SitePrefixLength, 0);
        assert_eq!(row.Protocol, MIB_IPPROTO_NETMGMT);
        assert!(!row.Loopback && !row.Publish && !row.AutoconfigureAddress);
        assert_eq!(unsafe { row.InterfaceLuid.Value }, route.luid);
        assert_eq!(row.InterfaceIndex, route.index);
        assert_eq!(
            unsafe { row.NextHop.Ipv4.sin_addr.S_un.S_addr }.to_ne_bytes(),
            route.gateway.octets()
        );
    }
    #[test]
    fn authenticated_peer_needs_no_preexisting_route_and_retries_failed_add() {
        let mut routes = Routes::new(FakeRoutes::default());
        routes.api.fail_add.set(true);
        assert!(routes.reconcile(Some(target())).is_err());
        assert!(routes.owned.is_none());
        routes.api.fail_add.set(false);
        assert_eq!(routes.reconcile(Some(target())).unwrap(), Some(target()));
        assert!(routes.owned.is_some());
    }
    #[test]
    fn rejects_foreign_gateway_default_without_modifying_it() {
        let mut routes = Routes::new(FakeRoutes::default());
        let foreign = Route {
            destination: Ipv4Addr::UNSPECIFIED,
            prefix: 0,
            gateway: Ipv4Addr::new(10, 8, 0, 99),
            ..peer()
        };
        routes.api.rows.borrow_mut().push(foreign);
        assert!(routes.reconcile(Some(target())).is_err());
        assert!(routes.owned.is_none());
        routes.reconcile(None).unwrap();
        assert_eq!(*routes.api.rows.borrow(), vec![foreign]);
        assert!(routes.api.deleted.borrow().is_empty());
    }
    #[test]
    fn new_session_with_same_interface_and_ip_replaces_owned_route() {
        let mut routes = Routes::new(FakeRoutes::default());
        routes.reconcile(Some(target())).unwrap();
        let old = routes.owned.unwrap();
        let next = VpnTarget {
            session_id: [3; 16],
            ..target()
        };
        assert_eq!(routes.reconcile(Some(next)).unwrap(), Some(next));
        assert_eq!(*routes.api.deleted.borrow(), vec![old]);
        assert_eq!(routes.api.rows.borrow().len(), 1);
        assert!(routes.owned.is_some());
    }
    #[test]
    fn reused_index_does_not_borrow_or_delete_old_interface_route() {
        let mut routes = Routes::new(FakeRoutes::default());
        let stale = Route {
            luid: 999,
            destination: Ipv4Addr::UNSPECIFIED,
            prefix: 0,
            ..peer()
        };
        routes.api.rows.borrow_mut().push(stale);
        routes.reconcile(Some(target())).unwrap();
        assert_eq!(routes.owned.unwrap().luid, target().interface_luid);
        routes.reconcile(None).unwrap();
        assert_eq!(*routes.api.rows.borrow(), vec![stale]);
    }
    #[test]
    fn deletes_only_created_default_on_its_exact_interface() {
        let mut routes = Routes::new(FakeRoutes::default());
        let other = Route {
            index: 99,
            luid: 999,
            destination: Ipv4Addr::UNSPECIFIED,
            prefix: 0,
            ..peer()
        };
        routes.api.rows.borrow_mut().extend([peer(), other]);
        routes.reconcile(Some(target())).unwrap();
        let owned = routes.owned.unwrap();
        routes.reconcile(None).unwrap();
        assert_eq!(*routes.api.deleted.borrow(), vec![owned]);
        assert!(routes.api.rows.borrow().contains(&other));
    }
    #[test]
    fn never_owns_or_deletes_existing_default() {
        let mut routes = Routes::new(FakeRoutes::default());
        let existing = Route {
            destination: Ipv4Addr::UNSPECIFIED,
            prefix: 0,
            ..peer()
        };
        routes.api.rows.borrow_mut().push(existing);
        assert_eq!(routes.reconcile(Some(target())).unwrap(), Some(target()));
        assert!(routes.owned.is_none());
        routes.reconcile(None).unwrap();
        assert!(routes.api.deleted.borrow().is_empty());
    }
    #[test]
    fn repairs_route_removed_without_adapter_change() {
        let mut routes = Routes::new(FakeRoutes::default());
        routes.api.rows.borrow_mut().push(peer());
        routes.reconcile(Some(target())).unwrap();
        routes.api.rows.borrow_mut().retain(|r| !r.is_default());
        assert_eq!(routes.reconcile(Some(target())).unwrap(), Some(target()));
        assert!(routes.owned.is_some());
    }
}
