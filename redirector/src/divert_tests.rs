//! These tests exchange packets only between in-memory smoltcp interfaces and
//! use loopback sockets for bridge I/O. They never open WinDivert or a VPN.

use super::*;
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::timeout;

const TEST_PID: u32 = 123;
const DEADLINE: Duration = Duration::from_secs(5);

fn stats() -> Stats {
    Stats::new(Arc::new(StatusBus::new()))
}

struct TcpPair {
    app_iface: Interface,
    proxy_iface: Interface,
    app_device: VirtualDevice,
    proxy_device: VirtualDevice,
    app_sockets: SocketSet<'static>,
    proxy_sockets: SocketSet<'static>,
    app: SocketHandle,
    proxy: SocketHandle,
    now_ms: i64,
}

impl TcpPair {
    fn new(proxy_rx: usize, proxy_tx: usize) -> Self {
        let app_ip = Ipv4Address::new(10, 0, 0, 1);
        let proxy_ip = Ipv4Address::new(10, 0, 0, 2);
        let mut app_device = VirtualDevice::new();
        let mut proxy_device = VirtualDevice::new();
        let mut app_iface = Self::interface(&mut app_device, app_ip);
        let proxy_iface = Self::interface(&mut proxy_device, proxy_ip);
        let mut app_sockets = SocketSet::new(Vec::new());
        let mut proxy_sockets = SocketSet::new(Vec::new());
        let mut app_socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; 65536]),
            tcp::SocketBuffer::new(vec![0; 65536]),
        );
        let mut proxy_socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; proxy_rx]),
            tcp::SocketBuffer::new(vec![0; proxy_tx]),
        );
        let endpoint = IpEndpoint::new(IpAddress::Ipv4(proxy_ip), 443);
        proxy_socket.listen(endpoint).unwrap();
        app_socket
            .connect(app_iface.context(), endpoint, 40000)
            .unwrap();
        let app = app_sockets.add(app_socket);
        let proxy = proxy_sockets.add(proxy_socket);
        let mut pair = Self {
            app_iface,
            proxy_iface,
            app_device,
            proxy_device,
            app_sockets,
            proxy_sockets,
            app,
            proxy,
            now_ms: 0,
        };
        pair.exchange(20);
        assert_eq!(pair.app().state(), tcp::State::Established);
        assert_eq!(pair.proxy().state(), tcp::State::Established);
        pair
    }

    fn interface(device: &mut VirtualDevice, ip: Ipv4Address) -> Interface {
        let mut iface = Interface::new(
            Config::new(HardwareAddress::Ip),
            device,
            smoltcp::time::Instant::from_millis(0),
        );
        iface.update_ip_addrs(|addrs| addrs.push(IpCidr::new(IpAddress::Ipv4(ip), 24)).unwrap());
        iface
    }

    fn app(&mut self) -> &mut tcp::Socket<'static> {
        self.app_sockets.get_mut(self.app)
    }

    fn proxy(&mut self) -> &mut tcp::Socket<'static> {
        self.proxy_sockets.get_mut(self.proxy)
    }

    fn exchange(&mut self, rounds: usize) {
        for _ in 0..rounds {
            let now = smoltcp::time::Instant::from_millis(self.now_ms);
            self.app_iface
                .poll(now, &mut self.app_device, &mut self.app_sockets);
            while let Some(packet) = self.app_device.pop_tx() {
                self.proxy_device.push_rx(packet);
            }
            self.proxy_iface
                .poll(now, &mut self.proxy_device, &mut self.proxy_sockets);
            while let Some(packet) = self.proxy_device.pop_tx() {
                self.app_device.push_rx(packet);
            }
            self.now_ms += 10;
        }
    }

    fn receive_at_app(&mut self, output: &mut Vec<u8>) {
        let mut buf = [0; 4096];
        while self.app().can_recv() {
            let n = self.app().recv_slice(&mut buf).unwrap();
            output.extend_from_slice(&buf[..n]);
        }
    }
}

#[test]
fn tcp_full_upload_queue_preserves_data_and_delays_fin_until_drained() {
    let mut pair = TcpPair::new(32768, 4096);
    let payload: Vec<u8> = (0..20000).map(|n| (n % 251) as u8).collect();
    assert_eq!(pair.app().send_slice(&payload).unwrap(), payload.len());
    pair.app().close();
    pair.exchange(100);
    assert_eq!(pair.proxy().state(), tcp::State::CloseWait);
    assert_eq!(pair.proxy().recv_queue(), payload.len());

    let (tx, mut rx) = mpsc::channel(1);
    tx.try_send(vec![255]).unwrap();
    let mut sender = Some(tx);
    let stats = stats();
    pump_tcp_app_to_remote(pair.proxy(), &mut sender, TEST_PID, &stats);
    assert_eq!(
        pair.proxy().recv_queue(),
        payload.len(),
        "full queue must not consume bytes"
    );
    assert!(sender.is_some(), "FIN must wait for buffered bytes");
    assert_eq!(rx.try_recv().unwrap(), vec![255]);

    let mut delivered = Vec::new();
    for _ in 0..5 {
        pump_tcp_app_to_remote(pair.proxy(), &mut sender, TEST_PID, &stats);
        while let Ok(data) = rx.try_recv() {
            delivered.extend(data);
        }
        if sender.is_none() {
            break;
        }
    }
    assert_eq!(delivered, payload);
    assert!(sender.is_none());
    assert_eq!(rx.try_recv(), Err(mpsc::error::TryRecvError::Disconnected));
    assert_eq!(
        stats.bus.bytes_out.load(Ordering::Relaxed),
        payload.len() as u64
    );
}

#[test]
fn tcp_partial_download_preserves_order_and_sends_fin_after_last_byte() {
    let mut pair = TcpPair::new(4096, 17);
    let first: Vec<u8> = (0..50).collect();
    let second: Vec<u8> = (100..137).collect();
    let expected: Vec<u8> = first.iter().chain(&second).copied().collect();
    let (tx, mut rx) = mpsc::channel(2);
    tx.try_send(first).unwrap();
    tx.try_send(second).unwrap();
    drop(tx);
    let mut pending = None;
    let stats = stats();

    pump_tcp_remote_to_app(pair.proxy(), &mut rx, &mut pending, TEST_PID, &stats);
    assert_eq!(pending.as_ref().unwrap().written, 17);
    assert_eq!(pair.proxy().send_queue(), 17);
    let mut delivered = Vec::new();
    for _ in 0..100 {
        pair.exchange(20);
        pair.receive_at_app(&mut delivered);
        pump_tcp_remote_to_app(pair.proxy(), &mut rx, &mut pending, TEST_PID, &stats);
        if !pair.app().may_recv() {
            break;
        }
    }
    assert_eq!(delivered, expected);
    assert!(pending.is_none());
    assert!(
        !pair.app().may_recv(),
        "remote EOF must follow the complete payload"
    );
    assert_eq!(
        stats.bus.bytes_in.load(Ordering::Relaxed),
        expected.len() as u64
    );
}

#[tokio::test]
async fn tcp_half_close_reaches_loopback_server_and_reply_reaches_smoltcp_app() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let dst = listener.local_addr().unwrap();
    let request = b"request whose response requires EOF".to_vec();
    let response = b"response after EOF".to_vec();
    let expected_request = request.clone();
    let expected_response = response.clone();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut received = Vec::new();
        socket.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, expected_request);
        socket.write_all(&expected_response).await.unwrap();
        socket.shutdown().await.unwrap();
    });
    let (tx, from_app) = mpsc::channel(1);
    let (to_app, mut rx) = mpsc::channel(1);
    let bridge = tokio::spawn(tcp_bridge(dst, None, from_app, to_app));
    let mut sender = Some(tx);
    let mut pending = None;
    let stats = stats();
    let mut pair = TcpPair::new(4096, 7);
    pair.app().send_slice(&request).unwrap();
    pair.app().close();
    let mut delivered = Vec::new();
    timeout(DEADLINE, async {
        loop {
            pair.exchange(20);
            pump_tcp_app_to_remote(pair.proxy(), &mut sender, TEST_PID, &stats);
            pump_tcp_remote_to_app(pair.proxy(), &mut rx, &mut pending, TEST_PID, &stats);
            pair.receive_at_app(&mut delivered);
            if !pair.app().may_recv() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(delivered, response);
    timeout(DEADLINE, bridge).await.unwrap().unwrap().unwrap();
    timeout(DEADLINE, server).await.unwrap().unwrap();
}

#[tokio::test]
async fn tcp_remote_half_close_still_allows_application_upload() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let dst = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        socket.shutdown().await.unwrap();
        let mut received = Vec::new();
        socket.read_to_end(&mut received).await.unwrap();
        received
    });
    let (tx, from_app) = mpsc::channel(1);
    let (to_app, mut rx) = mpsc::channel(1);
    let bridge = tokio::spawn(tcp_bridge(dst, None, from_app, to_app));
    assert!(timeout(DEADLINE, rx.recv()).await.unwrap().is_none());
    tx.send(b"after remote FIN".to_vec()).await.unwrap();
    drop(tx);
    assert_eq!(
        timeout(DEADLINE, server).await.unwrap().unwrap(),
        b"after remote FIN"
    );
    timeout(DEADLINE, bridge).await.unwrap().unwrap().unwrap();
}

#[tokio::test]
async fn dropping_tcp_worker_closes_socket_while_both_halves_are_idle() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let dst = listener.local_addr().unwrap();
    let (_tx, from_app) = mpsc::channel(1);
    let (to_app, _rx) = mpsc::channel(1);
    let worker = BridgeTask(tokio::spawn(async move {
        tcp_bridge(dst, None, from_app, to_app).await.unwrap();
    }));
    let (mut remote, _) = timeout(DEADLINE, listener.accept()).await.unwrap().unwrap();
    // Keep both channels alive: cancellation must release socket I/O itself.
    drop(worker);
    let mut buf = [0; 1];
    let result = timeout(DEADLINE, remote.read(&mut buf)).await.unwrap();
    assert!(
        matches!(result, Ok(0))
            || result.is_err_and(|e| e.kind() == std::io::ErrorKind::ConnectionReset)
    );
}

#[tokio::test]
async fn udp_empty_datagram_is_forwarded_and_does_not_close_flow() {
    let remote = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let dst = remote.local_addr().unwrap();
    let (tx, from_app) = mpsc::channel(1);
    let (to_app, mut rx) = mpsc::channel(1);
    let bridge = tokio::spawn(udp_bridge(dst, None, from_app, to_app));
    tx.send(Vec::new()).await.unwrap();
    let mut buf = [0; 32];
    let (n, peer) = timeout(DEADLINE, remote.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(n, 0);
    remote.send_to(&[], peer).await.unwrap();
    assert_eq!(
        timeout(DEADLINE, rx.recv()).await.unwrap(),
        Some(Vec::new())
    );
    remote.send_to(b"next", peer).await.unwrap();
    assert_eq!(
        timeout(DEADLINE, rx.recv()).await.unwrap(),
        Some(b"next".to_vec())
    );
    drop(tx);
    timeout(DEADLINE, bridge).await.unwrap().unwrap().unwrap();
    std::net::UdpSocket::bind(peer).expect("completed bridge must release its local port");
}

#[tokio::test]
async fn udp_closing_input_cancels_idle_receive_and_releases_socket() {
    let remote = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let (tx, from_app) = mpsc::channel(1);
    let (to_app, _rx) = mpsc::channel(1);
    let bridge = tokio::spawn(udp_bridge(
        remote.local_addr().unwrap(),
        None,
        from_app,
        to_app,
    ));
    tx.send(b"no response".to_vec()).await.unwrap();
    let mut buf = [0; 32];
    let (_, peer) = timeout(DEADLINE, remote.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    drop(tx);
    timeout(DEADLINE, bridge).await.unwrap().unwrap().unwrap();
    std::net::UdpSocket::bind(peer).expect("idle receive must not retain the socket");
}

#[tokio::test]
async fn dropping_udp_flow_aborts_worker_and_releases_socket() {
    let remote = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let dst = remote.local_addr().unwrap();
    let (tx, from_app) = mpsc::channel(1);
    let (to_app, rx) = mpsc::channel(1);
    let task = BridgeTask(tokio::spawn(async move {
        udp_bridge(dst, None, from_app, to_app).await.unwrap();
    }));
    let aborted = task.0.abort_handle();
    tx.send(b"no response".to_vec()).await.unwrap();
    let flow = UdpFlow {
        pid: TEST_PID,
        creation_time: 0,
        app_endpoint: (Ipv4Addr::LOCALHOST, 40000),
        original_dst: (Ipv4Addr::LOCALHOST, dst.port()),
        app_to_remote: tx,
        remote_to_app: rx,
        last_active: Instant::now(),
        _task: task,
    };
    let mut buf = [0; 32];
    let (_, peer) = timeout(DEADLINE, remote.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    drop(flow);
    timeout(DEADLINE, async {
        while !aborted.is_finished() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    std::net::UdpSocket::bind(peer).expect("flow owner must cancel pending socket I/O");
}

fn pending_flow(sockets: &mut SocketSet<'static>, since: Instant) -> (TcpKey, TcpFlow) {
    let mut socket = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; 64]),
        tcp::SocketBuffer::new(vec![0; 64]),
    );
    socket.listen(443).unwrap();
    let handle = sockets.add(socket);
    (
        TcpKey {
            src_ip: Ipv4Addr::LOCALHOST,
            src_port: 40000,
        },
        TcpFlow {
            handle,
            pid: TEST_PID,
            creation_time: 0,
            original_dst: "127.0.0.1:443".parse().unwrap(),
            state: TcpState::Pending { since },
            task: None,
        },
    )
}

#[tokio::test]
async fn pending_tcp_handshake_expires_and_releases_buffers() {
    let mut sockets = SocketSet::new(Vec::new());
    let (key, flow) = pending_flow(&mut sockets, Instant::now() - TCP_HANDSHAKE_TIMEOUT);
    let mut flows = HashMap::from([(key, flow)]);
    let stats = stats();
    service_tcp_flows(
        &mut flows,
        &mut sockets,
        &tokio::runtime::Handle::current(),
        None,
        &stats,
    );
    assert!(matches!(flows[&key].state, TcpState::Closed));
    service_tcp_flows(
        &mut flows,
        &mut sockets,
        &tokio::runtime::Handle::current(),
        None,
        &stats,
    );
    assert!(flows.is_empty());
    assert_eq!(sockets.iter().count(), 0);
    assert_eq!(stats.bridges_closed.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn already_closed_pending_tcp_is_removed_without_waiting_for_timeout() {
    let mut sockets = SocketSet::new(Vec::new());
    let (key, flow) = pending_flow(&mut sockets, Instant::now());
    sockets.get_mut::<tcp::Socket>(flow.handle).abort();
    let mut flows = HashMap::from([(key, flow)]);
    let stats = stats();
    for _ in 0..2 {
        service_tcp_flows(
            &mut flows,
            &mut sockets,
            &tokio::runtime::Handle::current(),
            None,
            &stats,
        );
    }
    assert!(flows.is_empty());
    assert_eq!(sockets.iter().count(), 0);
}

#[tokio::test]
async fn vpn_target_change_removes_flows_even_without_down_transition() {
    let mut sockets = SocketSet::new(Vec::new());
    let (key, mut flow) = pending_flow(&mut sockets, Instant::now());
    let task = BridgeTask(tokio::spawn(std::future::pending()));
    let aborted = task.0.abort_handle();
    flow.task = Some(task);
    let mut tcp_flows = HashMap::from([(key, flow)]);
    let mut udp_flows = HashMap::new();
    let stats = stats();
    let old_target = VpnTarget {
        ipv4: Ipv4Addr::new(10, 8, 0, 2),
        if_index: 5,
        interface_luid: 1234,
        adapter_guid: [1; 16],
        session_id: [2; 16],
        gateway: Ipv4Addr::new(10, 8, 0, 1),
    };
    let old = Some(old_target);
    let new = Some(VpnTarget {
        // A reconnect can reuse every address and interface field.
        session_id: [3; 16],
        ..old_target
    });
    on_vpn_change(
        old,
        old,
        &mut tcp_flows,
        &mut udp_flows,
        &mut sockets,
        &stats,
    );
    assert_eq!(
        tcp_flows.len(),
        1,
        "unchanged target must retain connections"
    );
    on_vpn_change(
        old,
        new,
        &mut tcp_flows,
        &mut udp_flows,
        &mut sockets,
        &stats,
    );
    assert!(tcp_flows.is_empty());
    assert_eq!(sockets.iter().count(), 0);
    timeout(DEADLINE, async {
        while !aborted.is_finished() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn flow_revalidation_removes_changed_process_identity_and_revoked_path() {
    let resolver = Resolver::new();
    let pid = std::process::id();
    let info = resolver.resolve(pid).unwrap();
    let paths = tunneled::new();
    tunneled::replace(&paths, vec![std::path::PathBuf::from(info.exe_path)]);
    let mut sockets = SocketSet::new(Vec::new());
    let (key, mut flow) = pending_flow(&mut sockets, Instant::now());
    flow.pid = pid;
    flow.creation_time = info.creation_time;
    let mut tcp_flows = HashMap::from([(key, flow)]);
    let mut udp_flows = HashMap::new();
    let stats = stats();

    revoke_invalid_flows(
        &resolver,
        &paths,
        &mut tcp_flows,
        &mut udp_flows,
        &mut sockets,
        &stats,
    );
    assert_eq!(
        tcp_flows.len(),
        1,
        "current listed process must retain its flow"
    );
    tcp_flows.get_mut(&key).unwrap().creation_time = info.creation_time.wrapping_add(1);
    revoke_invalid_flows(
        &resolver,
        &paths,
        &mut tcp_flows,
        &mut udp_flows,
        &mut sockets,
        &stats,
    );
    assert!(
        tcp_flows.is_empty(),
        "reused PID must not retain a previous process's flow"
    );

    let (key, mut flow) = pending_flow(&mut sockets, Instant::now());
    flow.pid = pid;
    flow.creation_time = info.creation_time;
    tcp_flows.insert(key, flow);
    tunneled::replace(&paths, Vec::new());
    revoke_invalid_flows(
        &resolver,
        &paths,
        &mut tcp_flows,
        &mut udp_flows,
        &mut sockets,
        &stats,
    );
    assert!(
        tcp_flows.is_empty(),
        "removing a configured path must revoke existing flows"
    );
    assert_eq!(sockets.iter().count(), 0);
}

fn tcp_request(port: u16, initial_syn: bool) -> TcpRequest {
    TcpRequest {
        key: TcpKey {
            src_ip: Ipv4Addr::new(10, 0, 0, 1),
            src_port: port,
        },
        pid: TEST_PID,
        creation_time: 0,
        destination: SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 443),
        initial_syn,
    }
}

#[test]
fn only_initial_syn_packets_allocate_a_tcp_listener() {
    for (flags, expected_initial_syn) in [
        (0x02, true),
        (0x42, true),
        (0x12, false),
        (0x03, false),
        (0x06, false),
        (0x10, false),
        (0x01, false),
        (0x04, false),
        (0, false),
    ] {
        let mut packet = vec![0; 40];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&40u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = PROTO_TCP;
        packet[12..16].copy_from_slice(&[10, 0, 0, 1]);
        packet[16..20].copy_from_slice(&[10, 0, 0, 2]);
        packet[20..22].copy_from_slice(&40000u16.to_be_bytes());
        packet[22..24].copy_from_slice(&443u16.to_be_bytes());
        packet[32] = 0x50;
        packet[33] = flags;
        let ParsedL4::Tcp { initial_syn, .. } = parse_ipv4_l4(&packet).unwrap() else {
            panic!("test packet must parse as TCP");
        };
        assert_eq!(initial_syn, expected_initial_syn, "flags={flags:#x}");
        let mut flows = HashMap::new();
        let mut sockets = SocketSet::new(Vec::new());
        let result = ensure_tcp_flow(&mut flows, &mut sockets, tcp_request(40000, initial_syn), 1);
        if expected_initial_syn {
            assert_eq!(result, TcpAdmission::Tunnel);
            assert_eq!(sockets.iter().count(), 1);
        } else {
            assert_eq!(result, TcpAdmission::PassThrough);
            assert!(flows.is_empty());
            assert_eq!(sockets.iter().count(), 0);
        }
    }
}

#[test]
fn tcp_capacity_rejects_new_syn_without_allocating_and_keeps_existing_flows() {
    let mut flows = HashMap::new();
    let mut sockets = SocketSet::new(Vec::new());
    assert_eq!(
        ensure_tcp_flow(&mut flows, &mut sockets, tcp_request(40000, true), 1),
        TcpAdmission::Tunnel
    );
    assert_eq!(
        ensure_tcp_flow(&mut flows, &mut sockets, tcp_request(40001, true), 1),
        TcpAdmission::Drop
    );
    assert_eq!(
        ensure_tcp_flow(&mut flows, &mut sockets, tcp_request(40000, false), 1),
        TcpAdmission::Tunnel
    );
    assert_eq!(
        ensure_tcp_flow(&mut flows, &mut sockets, tcp_request(40002, false), 1),
        TcpAdmission::PassThrough
    );
    assert_eq!(flows.len(), 1);
    assert_eq!(sockets.iter().count(), 1);
    let removed = flows.remove(&tcp_request(40000, true).key).unwrap();
    sockets.remove(removed.handle);
    assert_eq!(
        ensure_tcp_flow(&mut flows, &mut sockets, tcp_request(40001, true), 1),
        TcpAdmission::Tunnel
    );
    assert_eq!(flows.len(), 1);
    assert_eq!(sockets.iter().count(), 1);
}

#[tokio::test]
async fn udp_capacity_rejects_new_worker_and_keeps_existing_flow() {
    let mut flows = HashMap::new();
    let runtime = tokio::runtime::Handle::current();
    let stats = stats();
    let request = |port| UdpRequest {
        key: UdpKey {
            src_ip: Ipv4Addr::LOCALHOST,
            src_port: port,
            dst_ip: Ipv4Addr::LOCALHOST,
            dst_port: 9,
        },
        pid: TEST_PID,
        creation_time: 0,
        target: None,
    };
    assert!(ensure_udp_flow(&mut flows, request(40000), &runtime, &stats, 1).is_some());
    assert!(ensure_udp_flow(&mut flows, request(40001), &runtime, &stats, 1).is_none());
    assert!(ensure_udp_flow(&mut flows, request(40000), &runtime, &stats, 1).is_some());
    assert_eq!(flows.len(), 1);
    assert_eq!(stats.bridges_opened.load(Ordering::Relaxed), 1);
    flows.clear();
    assert!(ensure_udp_flow(&mut flows, request(40001), &runtime, &stats, 1).is_some());
    assert_eq!(stats.bridges_opened.load(Ordering::Relaxed), 2);
}
