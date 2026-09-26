use super::*;
use crate::adapter::VpnTarget;
use std::sync::Mutex;
use tokio::net::windows::named_pipe::ClientOptions;

fn lease(pid: u32) -> Lease {
    Lease {
        pid,
        creation_time: 1,
        exe_path: "C:\\selected.exe".into(),
        dns: DnsSession {
            target: VpnTarget {
                ipv4: "10.8.0.2".parse().unwrap(),
                if_index: 42,
                interface_luid: 123,
                adapter_guid: [1; 16],
                session_id: [2; 16],
                gateway: "10.8.0.1".parse().unwrap(),
            },
            generation: [3; 16],
            servers: vec!["10.8.0.1:53".parse().unwrap()],
            open_vpn_pid: 123,
            open_vpn_creation_time: 456,
        },
    }
}
struct TestAuthority(Mutex<Option<Lease>>);
impl Authority for TestAuthority {
    fn capture(&self, pid: u32) -> std::result::Result<Lease, u32> {
        self.0
            .lock()
            .unwrap()
            .clone()
            .filter(|l| l.pid == pid)
            .ok_or(ACCESS_DENIED)
    }
}

#[test]
fn rejects_foreign_pipe_names_and_selection_requires_exact_path() {
    assert!(pipe_path("VpnClient-Dns-0123456789abcdef0123456789abcdef").is_ok());
    for name in [
        "",
        r"\\other\pipe\test",
        "VpnClient-Dns-../x",
        "VpnClient-Dns-0123456789abcdef0123456789abcdef/x",
    ] {
        assert!(pipe_path(name).is_err());
    }
    assert!(selected(&["C:\\Selected.exe".into()], "c:/selected.exe"));
    assert!(!selected(
        &["C:\\Selected.exe".into()],
        "C:\\Other\\Selected.exe"
    ));
}

#[tokio::test]
async fn in_flight_results_revoke_for_every_identity_and_metadata_change() {
    for change in 0..8 {
        let old = lease(123);
        let authority = TestAuthority(Mutex::new(Some(old.clone())));
        let shutdown = Shutdown::new();
        let work = async {
            let mut now = old.clone();
            match change {
                0 => now.creation_time += 1,
                1 => now.dns.generation[0] ^= 1,
                2 => now.dns.target.interface_luid += 1,
                3 => now.dns.target.session_id[0] ^= 1,
                4 => now.dns.servers[0] = "10.8.0.9:53".parse().unwrap(),
                5 => now.dns.open_vpn_creation_time += 1,
                6 => {
                    *authority.0.lock().unwrap() = None;
                    return Ok(vec![1]);
                }
                _ => {
                    shutdown.stop();
                    return Ok(vec![1]);
                }
            }
            *authority.0.lock().unwrap() = Some(now);
            Ok(vec![1])
        };
        assert_eq!(
            guarded(work, &authority, &old, &shutdown).await,
            Err(CANCELLED)
        );
    }
}

#[tokio::test]
async fn removal_cancels_pending_transport_without_waiting_for_its_deadline() {
    let old = lease(123);
    let authority = TestAuthority(Mutex::new(Some(old.clone())));
    let revoke = async {
        tokio::time::sleep(Duration::from_millis(20)).await;
        *authority.0.lock().unwrap() = None;
    };
    let shutdown = Shutdown::new();
    let pending = guarded(std::future::pending(), &authority, &old, &shutdown);
    let (result, ()) = tokio::join!(
        tokio::time::timeout(Duration::from_secs(1), pending),
        revoke
    );
    assert_eq!(result.unwrap(), Err(CANCELLED));
}

fn unique_path() -> String {
    let suffix = format!(
        "{:032x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    pipe_path(&format!("VpnClient-Dns-{suffix}")).unwrap()
}

#[test]
fn pipe_client_child() {
    let Ok(path) = std::env::var("DNS_BROKER_TEST_PIPE") else {
        return;
    };
    let expected: u32 = std::env::var("DNS_BROKER_TEST_STATUS")
        .unwrap()
        .parse()
        .unwrap();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let mut client = ClientOptions::new().open(path).unwrap();
            let mut header = [0; 12];
            header[..4].copy_from_slice(&MAGIC.to_le_bytes());
            client.write_all(&header).await.unwrap();
            client.read_exact(&mut header).await.unwrap();
            assert_eq!(u32::from_le_bytes(header[..4].try_into().unwrap()), MAGIC);
            assert_eq!(
                u32::from_le_bytes(header[4..8].try_into().unwrap()),
                expected
            );
            assert_eq!(&header[8..], [0; 4]);
        });
}

#[tokio::test]
async fn real_pipe_authenticates_kernel_child_pid_and_first_instance_is_exclusive() {
    use std::os::windows::process::CommandExt;
    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    for allowed in [true, false] {
        let path = unique_path();
        let descriptor = security::SecurityDescriptor::new().unwrap();
        let pipe = descriptor.pipe(&path, true).unwrap();
        assert!(descriptor.pipe(&path, true).is_err());
        let expected = if allowed { 0 } else { ACCESS_DENIED };
        let mut child = Child(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "dns_broker::tests::pipe_client_child",
                    "--nocapture",
                ])
                .env("DNS_BROKER_TEST_PIPE", &path)
                .env("DNS_BROKER_TEST_STATUS", expected.to_string())
                .creation_flags(0x08000000)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap(),
        );
        let pid = child.0.id();
        tokio::time::timeout(Duration::from_secs(5), pipe.connect())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(security::client_pid(&pipe).unwrap(), pid);
        let auth = Arc::new(TestAuthority(Mutex::new(allowed.then(|| lease(pid)))));
        serve(pipe, auth, Shutdown::new()).await.unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                assert!(status.success(), "child failed: {status}");
                break;
            }
            assert!(tokio::time::Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

#[tokio::test]
async fn malformed_or_oversized_frames_are_rejected_without_allocating_their_claimed_length() {
    for (operation, length) in [(9u32, 0u32), (0, 12), (1, 4097), (1, u32::MAX)] {
        let path = unique_path();
        let descriptor = security::SecurityDescriptor::new().unwrap();
        let pipe = descriptor.pipe(&path, true).unwrap();
        let mut client = ClientOptions::new().open(&path).unwrap();
        pipe.connect().await.unwrap();
        let authority = Arc::new(TestAuthority(Mutex::new(Some(lease(std::process::id())))));
        let serving = tokio::spawn(serve(pipe, authority, Shutdown::new()));
        let mut header = [0; 12];
        header[..4].copy_from_slice(&MAGIC.to_le_bytes());
        header[4..8].copy_from_slice(&operation.to_le_bytes());
        header[8..].copy_from_slice(&length.to_le_bytes());
        client.write_all(&header).await.unwrap();
        client.read_exact(&mut header).await.unwrap();
        assert_eq!(
            u32::from_le_bytes(header[4..8].try_into().unwrap()),
            INVALID_PARAMETER
        );
        drop(client);
        serving.await.unwrap().unwrap();
    }
}
