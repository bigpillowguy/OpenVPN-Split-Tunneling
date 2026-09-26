use super::*;
use serde_json::json;

fn snapshot() -> Value {
    json!({
        "version": 1,
        "sessionId": "10000000-0000-0000-0000-000000000001",
        "openVpnPid": 123,
        "openVpnCreationTime": 133999999999999999_u64,
        "openVpnExePath": "C:\\Program Files\\VpnClient\\OpenVPN\\openvpn.exe",
        "adapterGuid": "20000000-0000-0000-0000-000000000002",
        "interfaceIndex": 42,
        "ipv4": "10.8.0.2",
        "gateway": "10.8.0.1"
    })
}

fn binding() -> SessionBinding {
    SessionBinding::parse(&serde_json::to_vec(&snapshot()).unwrap()).unwrap()
}

fn process() -> ProcessInfo {
    ProcessInfo {
        exe_path: "C:\\Program Files\\VpnClient\\OpenVPN\\openvpn.exe".into(),
        exe_name: "openvpn.exe".into(),
        creation_time: 133999999999999999,
    }
}

fn adapter() -> Adapter {
    Adapter {
        friendly_name: "a custom name with no VPN heuristic".into(),
        description: "custom description".into(),
        adapter_name: "{20000000-0000-0000-0000-000000000002}".into(),
        addresses: vec![IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2))],
        is_up: true,
        if_index: 42,
        interface_luid: 1234,
    }
}

#[test]
fn exact_session_wins_with_two_vpns_and_identical_addresses() {
    let exact = adapter();
    let mut foreign = exact.clone();
    foreign.adapter_name = "{30000000-0000-0000-0000-000000000003}".into();
    foreign.if_index = 7;
    foreign.interface_luid = 77;
    foreign.description = "OpenVPN TAP-Windows".into();
    let target = binding()
        .validate(&[foreign, exact], Some(&process()))
        .unwrap();
    assert_eq!(target.if_index, 42);
    assert_eq!(target.interface_luid, 1234);
    assert_eq!(target.gateway, Ipv4Addr::new(10, 8, 0, 1));
}

#[test]
fn stale_process_pid_reuse_and_wrong_executable_revoke_binding() {
    let binding = binding();
    assert!(binding.validate(&[adapter()], None).is_err());
    let mut reused = process();
    reused.creation_time += 1;
    assert!(binding.validate(&[adapter()], Some(&reused)).is_err());
    let mut wrong = process();
    wrong.exe_path = "C:\\OtherOpenVPN\\openvpn.exe".into();
    assert!(binding.validate(&[adapter()], Some(&wrong)).is_err());
}

#[test]
fn disabled_missing_wrong_address_and_reused_adapter_index_are_rejected() {
    let binding = binding();
    assert!(binding.validate(&[], Some(&process())).is_err());
    let mut disabled = adapter();
    disabled.is_up = false;
    assert!(binding.validate(&[disabled], Some(&process())).is_err());
    let mut wrong_ip = adapter();
    wrong_ip.addresses = vec![IpAddr::V4(Ipv4Addr::new(10, 8, 0, 3))];
    assert!(binding.validate(&[wrong_ip], Some(&process())).is_err());
    let mut reused = adapter();
    reused.adapter_name = "30000000-0000-0000-0000-000000000003".into();
    assert!(binding.validate(&[reused], Some(&process())).is_err());
    let mut renumbered = adapter();
    renumbered.if_index += 1;
    assert!(binding.validate(&[renumbered], Some(&process())).is_err());
}

#[test]
fn new_session_id_changes_target_even_when_process_and_network_are_unchanged() {
    let old = binding().validate(&[adapter()], Some(&process())).unwrap();
    let mut value = snapshot();
    value["sessionId"] = json!("10000000-0000-0000-0000-000000000002");
    let next = SessionBinding::parse(&serde_json::to_vec(&value).unwrap())
        .unwrap()
        .validate(&[adapter()], Some(&process()))
        .unwrap();
    assert_ne!(old, next);
    assert_eq!(old.ipv4, next.ipv4);
    assert_eq!(old.if_index, next.if_index);
}

#[test]
fn malformed_or_incomplete_session_never_produces_target() {
    for (field, invalid) in [
        ("version", json!(2)),
        ("openVpnPid", json!(0)),
        ("openVpnCreationTime", json!(0)),
        ("openVpnCreationTime", json!("133999999999999999")),
        ("interfaceIndex", json!(4294967296_u64)),
        ("sessionId", json!("00000000-0000-0000-0000-000000000000")),
        ("adapterGuid", json!("not-a-guid")),
        ("openVpnExePath", json!("openvpn.exe")),
        ("gateway", json!("0.0.0.0")),
        ("gateway", json!("224.0.0.1")),
        ("gateway", json!("10.8.0.2")),
        ("gateway", json!("255.255.255.255")),
        ("ipv4", json!("127.0.0.1")),
    ] {
        let mut value = snapshot();
        value[field] = invalid;
        assert!(
            SessionBinding::parse(&serde_json::to_vec(&value).unwrap()).is_err(),
            "accepted {field}"
        );
    }
    let mut value = snapshot();
    value.as_object_mut().unwrap().remove("gateway");
    assert!(SessionBinding::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    assert!(SessionBinding::parse(b"{\"version\":1,").is_err());
}

#[test]
fn file_replacement_corruption_removal_and_size_limit_do_not_keep_old_binding() {
    struct TempFile(PathBuf);
    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let path = TempFile(std::env::temp_dir().join(format!(
        "vpn-binding-test-{}-{}.json", std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    )));
    assert!(read_snapshot(&path.0).unwrap().is_none());
    std::fs::write(&path.0, serde_json::to_vec(&snapshot()).unwrap()).unwrap();
    assert!(read_snapshot(&path.0).unwrap().is_some());
    std::fs::write(&path.0, b"invalid").unwrap();
    assert!(read_snapshot(&path.0).is_err());
    std::fs::write(&path.0, vec![b' '; (MAX_SNAPSHOT_BYTES + 1) as usize]).unwrap();
    assert!(read_snapshot(&path.0)
        .unwrap_err()
        .to_string()
        .contains("size limit"));
    std::fs::remove_file(&path.0).unwrap();
    assert!(read_snapshot(&path.0).unwrap().is_none());
}

#[test]
fn guid_case_and_braces_normalize_but_bad_separators_are_rejected() {
    assert_eq!(
        guid("{ABCDEF00-1234-5678-9012-3456789ABCDE}").unwrap(),
        guid("abcdef00-1234-5678-9012-3456789abcde").unwrap()
    );
    assert!(guid("abcdef0011234-5678-9012-3456789abcde").is_err());
    assert!(guid("{abcdef00-1234-5678-9012-3456789abcde").is_err());
}

#[test]
fn dns_metadata_is_optional_and_invalid_dns_does_not_invalidate_routing() {
    assert!(binding().dns_metadata().unwrap().is_none());
    let mut value = snapshot();
    value["dns"] = json!({"status":"ready","generation":"30000000-0000-0000-0000-000000000003","servers":[{"address":"10.8.0.1","port":53}]});
    let parse = |v: &Value| SessionBinding::parse(&serde_json::to_vec(v).unwrap()).unwrap();
    assert_eq!(
        parse(&value).dns_metadata().unwrap().unwrap().1,
        ["10.8.0.1:53".parse::<SocketAddrV4>().unwrap()]
    );
    for invalid in [
        "127.0.0.1",
        "169.254.1.1",
        "224.0.0.1",
        "240.0.0.1",
        "::1",
        "8.8.8.8/32",
        "1.2.3.04",
    ] {
        let mut bad = value.clone();
        bad["dns"]["servers"][0]["address"] = json!(invalid);
        assert!(parse(&bad).dns_metadata().is_err());
        assert!(parse(&bad).validate(&[adapter()], Some(&process())).is_ok());
    }
    for status in ["unknown", "not-provided", "invalid", "unsupported"] {
        let mut not_ready = value.clone();
        not_ready["dns"]["status"] = json!(status);
        assert!(parse(&not_ready).dns_metadata().unwrap().is_none());
    }
    for servers in [
        json!([]),
        json!([{"address":"10.8.0.1","port":5353}]),
        json!([{"address":"10.8.0.1","port":53},{"address":"10.8.0.1","port":53}]),
    ] {
        let mut bad = value.clone();
        bad["dns"]["servers"] = servers;
        assert!(parse(&bad).dns_metadata().is_err());
    }
}
