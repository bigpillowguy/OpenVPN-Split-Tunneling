use super::*;

const FIXTURE: &[u8] = include_bytes!("../../../tests/fixtures/dns-control-arm-v1.json");

fn command() -> Command {
    Command::parse(FIXTURE).unwrap()
}
fn dns() -> DnsSession {
    let mut dns = crate::split_dns::tests::lease().dns;
    dns.target.session_id = command().session;
    dns.generation = command().generation;
    dns
}
fn owner(_: u32) -> Option<ProcessInfo> {
    Some(ProcessInfo {
        exe_path: "C:\\Owned\\UI.exe".into(),
        exe_name: "UI.exe".into(),
        creation_time: command().owner.creation_time,
    })
}
fn apply(state: &mut State, command: Command, dns: Option<&DnsSession>) -> ControlResult<()> {
    state.apply(command, self::command().backend, dns, owner, || {})
}

#[test]
fn shared_csharp_fixture_preserves_guid_and_u64_fields() {
    let c = command();
    assert_eq!(c.revision, 9007199254740993);
    assert_eq!(c.owner.creation_time, 133000000000000001);
    assert_eq!(c.backend.creation_time, 133000000000000002);
    assert_eq!(
        c.lease,
        [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
            0xff, 0x00
        ]
    );
    assert!(c.armed);
    let mut state = State::default();
    apply(&mut state, c, Some(&dns())).unwrap();
    assert_eq!(state.acknowledgement.revision, c.revision);
}

#[test]
fn rejects_missing_wrong_type_zero_noncanonical_and_overflow_fields() {
    let original: Value = serde_json::from_slice(FIXTURE).unwrap();
    for (field, value) in [
        ("revision", serde_json::json!(0)),
        ("revision", serde_json::json!(1.25)),
        ("ownerPid", serde_json::json!(0)),
        ("backendPid", serde_json::json!(4294967296u64)),
        ("ownerCreationTime", serde_json::json!(0)),
        ("armed", serde_json::json!(1)),
        (
            "lease",
            serde_json::json!("112233445566778899aabbccddeeff00"),
        ),
        (
            "sessionId",
            serde_json::json!("00000000-0000-0000-0000-000000000000"),
        ),
    ] {
        let mut bad = original.clone();
        bad[field] = value;
        assert_eq!(
            Command::parse(&serde_json::to_vec(&bad).unwrap()),
            Err("control_invalid"),
            "field={field}"
        );
    }
    let mut missing = original;
    missing.as_object_mut().unwrap().remove("generation");
    assert!(Command::parse(&serde_json::to_vec(&missing).unwrap()).is_err());
}

#[test]
fn arm_requires_exact_backend_owner_and_current_session_generation() {
    let initial = command();
    let dns = dns();
    let mut state = State::default();
    let mut c = initial;
    c.backend.creation_time += 1;
    assert_eq!(
        apply(&mut state, c, Some(&dns)),
        Err("control_backend_mismatch")
    );
    assert_eq!(
        state.apply(
            initial,
            initial.backend,
            Some(&dns),
            |_| None,
            || panic!("must not clean up")
        ),
        Err("control_owner_unavailable")
    );
    let mut c = initial;
    c.owner.creation_time += 1;
    assert_eq!(
        apply(&mut state, c, Some(&dns)),
        Err("control_owner_mismatch")
    );
    assert_eq!(
        apply(&mut state, initial, None),
        Err("control_session_unavailable")
    );
    let mut c = initial;
    c.session[0] ^= 1;
    assert_eq!(
        apply(&mut state, c, Some(&dns)),
        Err("control_session_mismatch")
    );
    let mut c = initial;
    c.generation[0] ^= 1;
    assert_eq!(
        apply(&mut state, c, Some(&dns)),
        Err("control_session_mismatch")
    );
    assert_eq!(state.acknowledgement, Acknowledgement::default());
}

#[test]
fn cleanup_barrier_precedes_ack_and_replay_cannot_change_applied_state() {
    let c = command();
    let mut state = State::default();
    let aborted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        state.apply(c, c.backend, Some(&dns()), owner, || {
            panic!("cleanup did not finish")
        })
    }));
    assert!(aborted.is_err());
    assert_eq!(state.acknowledgement, Acknowledgement::default());
    apply(&mut state, c, Some(&dns())).unwrap();
    state
        .apply(
            c,
            c.backend,
            None,
            |_| panic!("identical command is not a new arm"),
            || panic!("replay cannot clear flows"),
        )
        .unwrap();
    let armed = state.acknowledgement;
    let mut conflict = c;
    conflict.armed = false;
    assert_eq!(
        apply(&mut state, conflict, None),
        Err("control_revision_conflict")
    );
    conflict.revision -= 1;
    assert_eq!(
        apply(&mut state, conflict, None),
        Err("control_stale_revision")
    );
    conflict.revision = c.revision + 1;
    conflict.lease[0] ^= 1;
    assert_eq!(
        apply(&mut state, conflict, None),
        Err("control_lease_mismatch")
    );
    assert_eq!(state.acknowledgement, armed);
}

#[test]
fn same_lease_off_works_after_vpn_or_owner_loss_and_new_arm_gets_new_epoch() {
    let c = command();
    let mut state = State::default();
    apply(&mut state, c, Some(&dns())).unwrap();
    let old = state.acknowledgement;
    let mut off = c;
    off.armed = false;
    off.revision += 1;
    state
        .apply(
            off,
            c.backend,
            None,
            |_| panic!("off must not depend on owner still being alive"),
            || {},
        )
        .unwrap();
    assert!(!state.acknowledgement.armed);
    off.revision += 1;
    apply(&mut state, off, None).unwrap();
    assert_eq!(
        apply(&mut state, c, Some(&dns())),
        Err("control_stale_revision")
    );
    let mut rearm = c;
    rearm.revision = off.revision + 1;
    rearm.lease[0] ^= 1;
    apply(&mut state, rearm, Some(&dns())).unwrap();
    assert!(state.acknowledgement.armed);
    assert_ne!(state.acknowledgement.revision, old.revision);
    assert_ne!(state.acknowledgement.lease, old.lease);
    let mut foreign_owner = rearm;
    foreign_owner.revision += 1;
    foreign_owner.owner.pid += 1;
    foreign_owner.armed = false;
    assert_eq!(
        apply(&mut state, foreign_owner, None),
        Err("control_owner_mismatch")
    );
}

#[test]
fn inactive_ack_can_confirm_off_for_unobserved_pending_lease() {
    let mut off = command();
    off.armed = false;
    let mut state = State::default();
    apply(&mut state, off, None).unwrap();
    let mut next = off;
    next.revision += 1;
    next.lease[0] ^= 1;
    apply(&mut state, next, None).unwrap();
    assert_eq!(state.acknowledgement.lease, Some(next.lease));
    assert!(!state.acknowledgement.armed);
}

#[test]
fn armed_command_cannot_authorize_reconnected_provider_generation() {
    let mut state = State::default();
    let mut dns = dns();
    apply(&mut state, command(), Some(&dns)).unwrap();
    assert!(state.acknowledgement.permits(&dns));
    dns.generation[0] ^= 1;
    assert!(!state.acknowledgement.permits(&dns));
    assert!(
        state.acknowledgement.armed,
        "provider loss cannot implicitly disarm capture"
    );
    dns.generation[0] ^= 1;
    dns.target.session_id[0] ^= 1;
    assert!(!state.acknowledgement.permits(&dns));
}

#[test]
fn missing_corrupt_or_oversized_file_never_disarms_an_applied_lease() {
    let resolver = Resolver::new();
    let identity = resolver.resolve(std::process::id()).unwrap();
    let path = std::env::temp_dir().join(format!(
        "vpn-dns-control-test-{}-{}.json",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let source = ControlSource::new(&path, &resolver).unwrap();
    assert_eq!(
        source.poll(None, &resolver, || panic!("missing initial must not apply")),
        Acknowledgement::default()
    );
    let mut file: Value = serde_json::from_slice(FIXTURE).unwrap();
    for name in ["ownerPid", "backendPid"] {
        file[name] = serde_json::json!(std::process::id());
    }
    for name in ["ownerCreationTime", "backendCreationTime"] {
        file[name] = serde_json::json!(identity.creation_time);
    }
    std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
    let armed = source.poll(Some(&dns()), &resolver, || {});
    assert!(armed.armed);
    assert!(armed.error.is_empty());
    for (input, error) in [
        (Some(vec![b'{']), "control_invalid"),
        (
            Some(vec![b'x'; MAX_BYTES as usize + 1]),
            "control_too_large",
        ),
        (None, "control_missing"),
    ] {
        match input {
            Some(bytes) => std::fs::write(&path, bytes).unwrap(),
            None => std::fs::remove_file(&path).unwrap(),
        }
        let retained = source.poll(None, &resolver, || {
            panic!("invalid input must not clear flows")
        });
        assert!(retained.armed);
        assert_eq!(retained.revision, armed.revision);
        assert_eq!(retained.lease, armed.lease);
        assert_eq!(retained.error, error);
    }
}
