use super::*;
use crate::adapter::VpnTarget;
use std::net::Ipv4Addr;
use std::sync::Mutex;

pub(crate) fn lease() -> Lease {
    Lease {
        pid: 123,
        creation_time: 456,
        exe_path: "C:\\Apps\\Selected.exe".into(),
        dns: DnsSession {
            target: VpnTarget {
                ipv4: Ipv4Addr::new(10, 8, 0, 2),
                gateway: Ipv4Addr::new(10, 8, 0, 1),
                if_index: 8,
                interface_luid: 9,
                adapter_guid: [1; 16],
                session_id: [2; 16],
            },
            generation: [3; 16],
            servers: vec!["10.8.0.1:53".parse().unwrap()],
            open_vpn_pid: 999,
            open_vpn_creation_time: 777,
        },
    }
}

pub(crate) struct TestAuthority(pub Mutex<Option<Lease>>);
impl Authority for TestAuthority {
    fn decide(&self, owner: OwnerLookup) -> Decision {
        match self.0.lock().unwrap().clone() {
            Some(lease) if owner == OwnerLookup::Unique(lease.pid) => Decision::Tunnel(lease),
            _ => Decision::Drop(Fault::UnavailableSession),
        }
    }
}

pub(crate) fn permit() -> (Permit, Arc<TestAuthority>) {
    let lease = lease();
    let authority = Arc::new(TestAuthority(Mutex::new(Some(lease.clone()))));
    (Permit::new(lease, authority.clone()), authority)
}

fn process(_: u32) -> Option<crate::process::ProcessInfo> {
    Some(crate::process::ProcessInfo {
        exe_path: lease().exe_path,
        exe_name: "Selected.exe".into(),
        creation_time: 456,
    })
}

#[test]
fn selected_dns_is_fail_closed_before_any_general_vpn_fallback() {
    let selected = || Ok(vec![std::path::PathBuf::from("c:/apps/selected.exe")]);
    let result = decide_with(OwnerLookup::Unique(123), 10, process, selected, || None);
    assert!(matches!(result, Decision::Drop(Fault::UnavailableSession)));
    let result = decide_with(OwnerLookup::Unique(123), 10, process, selected, || {
        Some(lease().dns)
    });
    assert!(matches!(result, Decision::Tunnel(_)));
    let result = decide_with(
        OwnerLookup::Unique(123),
        10,
        process,
        || Ok(Vec::new()),
        || panic!("unselected DNS must not depend on VPN readiness"),
    );
    assert!(matches!(result, Decision::Pass));
    let result = decide_with(
        OwnerLookup::Unique(123),
        10,
        process,
        || anyhow::bail!("malformed current policy"),
        || Some(lease().dns),
    );
    assert!(matches!(result, Decision::Drop(Fault::UnavailablePolicy)));
}

#[test]
fn unknown_and_ambiguous_are_dropped_but_backend_is_excluded() {
    for (owner, fault) in [
        (OwnerLookup::Unknown, Fault::UnknownOwner),
        (OwnerLookup::Ambiguous, Fault::AmbiguousOwner),
    ] {
        let result = decide_with(owner, 10, |_| panic!(), || panic!(), || panic!());
        assert!(matches!(result, Decision::Drop(actual) if actual == fault));
    }
    assert!(matches!(
        decide_with(
            OwnerLookup::Unique(10),
            10,
            |_| panic!(),
            || panic!(),
            || panic!()
        ),
        Decision::Pass
    ));
}

#[tokio::test]
async fn generation_owner_adapter_and_session_changes_revoke_even_completed_work() {
    for change in 0..7 {
        let (permit, authority) = permit();
        let mut next = permit.lease.clone();
        match change {
            0 => next.dns.generation[0] ^= 1,
            1 => next.dns.target.session_id[0] ^= 1,
            2 => next.dns.target.interface_luid += 1,
            3 => next.dns.open_vpn_creation_time += 1,
            4 => next.creation_time += 1,
            5 => next.exe_path.push('x'),
            _ => next.dns.servers[0] = "10.8.0.3:53".parse().unwrap(),
        }
        let result = permit
            .guard(async {
                *authority.0.lock().unwrap() = Some(next);
                Ok(42)
            })
            .await;
        assert!(result.is_err(), "change {change} must revoke final result");
    }
}

#[tokio::test]
async fn revoked_idle_work_is_cancelled_without_waiting_for_transport_timeout() {
    let (permit, authority) = permit();
    let task =
        tokio::spawn(async move { permit.guard(std::future::pending::<Result<()>>()).await });
    tokio::task::yield_now().await;
    *authority.0.lock().unwrap() = None;
    assert!(tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap()
        .is_err());
}

#[test]
fn response_requires_current_socket_owner_even_while_original_process_stays_alive() {
    let (permit, _) = permit();
    assert!(permit.valid());
    assert!(permit.can_deliver_to(OwnerLookup::Unique(permit.lease.pid)));
    for owner in [
        OwnerLookup::Unique(permit.lease.pid + 1),
        OwnerLookup::Unknown,
        OwnerLookup::Ambiguous,
    ] {
        assert!(!permit.can_deliver_to(owner));
        assert!(
            permit.valid(),
            "the process/session lease alone still matches"
        );
    }
}

#[test]
fn inspect_covers_ipv6_loopback_and_fragment_bypasses_without_network() {
    let payload = [0; 12];
    let mut v4 = Vec::new();
    etherparse::PacketBuilder::ipv4([192, 0, 2, 2], [192, 0, 2, 53], 64)
        .udp(40000, 53)
        .write(&mut v4, &payload)
        .unwrap();
    assert!(matches!(
        inspect(&v4, false),
        Packet::Dns {
            supported: true,
            ..
        }
    ));
    assert!(matches!(
        inspect(&v4, true),
        Packet::Dns {
            supported: false,
            ..
        }
    ));
    let mut v6 = Vec::new();
    etherparse::PacketBuilder::ipv6([1; 16], [2; 16], 64)
        .udp(40000, 53)
        .write(&mut v6, &payload)
        .unwrap();
    assert!(matches!(
        inspect(&v6, false),
        Packet::Dns {
            supported: false,
            ..
        }
    ));
    v4[6] |= 0x20;
    assert_eq!(inspect(&v4, false), Packet::Unclassifiable);
    v4[9] = 1; // ICMP fragment is not DNS and must stay unchanged.
    assert_eq!(inspect(&v4, false), Packet::Other);
    let mut icmp6_fragment = vec![0; 56];
    icmp6_fragment[0] = 0x60;
    icmp6_fragment[4..6].copy_from_slice(&16u16.to_be_bytes());
    icmp6_fragment[6] = 44;
    icmp6_fragment[7] = 64;
    icmp6_fragment[40] = 58;
    icmp6_fragment[43] = 1;
    assert_eq!(inspect(&icmp6_fragment, false), Packet::Other);
    icmp6_fragment[40] = 17;
    assert_eq!(inspect(&icmp6_fragment, false), Packet::Unclassifiable);
    assert_eq!(inspect(&[0; 10], false), Packet::Unclassifiable);
    let mut other = Vec::new();
    etherparse::PacketBuilder::ipv4([192, 0, 2, 2], [192, 0, 2, 53], 64)
        .udp(40000, 443)
        .write(&mut other, &payload)
        .unwrap();
    assert_eq!(inspect(&other, false), Packet::Other);
}
