//! These tests exchange packets only between in-memory smoltcp interfaces and
//! use loopback sockets for bridge I/O. They never open WinDivert or a VPN.

use super::*;
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::timeout;

const TEST_PID: u32 = 123;
const DEADLINE: Duration = Duration::from_secs(5);

fn raw_tcp(src: u16, dst: u16) -> Vec<u8> {
    let mut packet = vec![0; 40];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&40u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 6;
    packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
    packet[16..20].copy_from_slice(&[10, 0, 0, 1]);
    packet[20..22].copy_from_slice(&src.to_be_bytes());
    packet[22..24].copy_from_slice(&dst.to_be_bytes());
    packet[32] = 0x50;
    packet[33] = 4;
    packet
}

#[test]
fn inactive_dns_preserves_baseline_unknown_rst_and_generic_tcp53() {
    let packet = raw_tcp(53, 40000);
    let mut flows = HashMap::new();
    assert_eq!(
        tcp_output_interface(&packet, &flows, false, |_, _| panic!(
            "inactive must not attribute"
        )),
        Ok(None)
    );
    assert_eq!(
        tcp_output_interface(&packet, &flows, true, |_, _| panic!(
            "no flow cannot be authorized"
        )),
        Err(Fault::Revoked)
    );
    let mut sockets = SocketSet::new(Vec::new());
    let mut request = tcp_request(40000, true);
    request.destination.set_port(53);
    request.key.dst_port = 53;
    assert_eq!(
        ensure_tcp_flow(&mut flows, &mut sockets, request, 1),
        TcpAdmission::Tunnel
    );
    assert_eq!(
        tcp_output_interface(&packet, &flows, false, |_, _| panic!(
            "generic routing stays unchanged"
        )),
        Ok(None)
    );
    let normal = raw_tcp(443, 40000);
    assert_eq!(
        tcp_output_interface(&normal, &flows, true, |_, _| panic!("not DNS")),
        Ok(None)
    );
}

#[test]
fn control_transition_clears_dns_workers_sockets_and_queued_packets_before_off_ack() {
    use smoltcp::phy::{Device, RxToken, TxToken};
    let mut tcp = HashMap::new();
    let mut udp = HashMap::new();
    let mut sockets = SocketSet::new(Vec::new());
    let mut request = tcp_request(40000, true);
    request.destination.set_port(53);
    request.key.dst_port = 53;
    assert_eq!(
        ensure_tcp_flow(&mut tcp, &mut sockets, request, 4),
        TcpAdmission::Tunnel
    );
    assert_eq!(
        ensure_tcp_flow(&mut tcp, &mut sockets, tcp_request(40001, true), 4),
        TcpAdmission::Tunnel
    );
    let mut device = VirtualDevice::new();
    let now = smoltcp::time::Instant::from_millis(0);
    let dns_rx = raw_tcp(40000, 53);
    let normal_rx = raw_tcp(40001, 443);
    device.push_rx(dns_rx);
    device.push_rx(normal_rx.clone());
    let normal_tx = raw_tcp(443, 40001);
    for bytes in [raw_tcp(53, 40000), normal_tx.clone()] {
        device
            .transmit(now)
            .unwrap()
            .consume(bytes.len(), |packet| packet.copy_from_slice(&bytes));
    }
    clear_port53_flows(&mut tcp, &mut udp, &mut sockets, &mut device, &stats());
    assert_eq!(tcp.len(), 1);
    assert_eq!(sockets.iter().count(), 1);
    assert!(tcp.keys().all(|key| key.dst_port != 53));
    assert_eq!(device.pop_tx(), Some(normal_tx));
    assert!(device.pop_tx().is_none());
    let (rx, _) = device.receive(now).unwrap();
    assert_eq!(rx.consume(|packet| packet.to_vec()), normal_rx);
    assert!(device.receive(now).is_none());
}

#[test]
fn inactive_extra_capture_reinjects_ipv6_loopback_and_fragments_without_dns_policy() {
    let mut v4 = build_udp_packet(
        Ipv4Addr::new(192, 0, 2, 1),
        40000,
        Ipv4Addr::new(192, 0, 2, 53),
        53,
        &[0; 12],
    )
    .unwrap();
    assert!(!is_extra_dns_capture(&v4, false));
    assert!(is_extra_dns_capture(&v4, true));
    v4[6] |= 0x20;
    assert!(is_extra_dns_capture(&v4, false));
    let mut v6 = Vec::new();
    etherparse::PacketBuilder::ipv6([1; 16], [2; 16], 64)
        .udp(40000, 53)
        .write(&mut v6, &[0; 12])
        .unwrap();
    assert!(is_extra_dns_capture(&v6, false));
}

#[tokio::test]
async fn dns_udp_reply_uses_original_inbound_interface_and_counts_only_accepted_injection() {
    let (permit, _) = crate::split_dns::tests::permit();
    let (app_to_remote, _) = mpsc::channel(1);
    let (_, remote_to_app) = mpsc::channel(1);
    let mut captured = unsafe { WinDivertAddress::<NetworkLayer>::new() };
    captured.set_outbound(true);
    captured.set_interface_index(17);
    captured.set_subinterface_index(3);
    let mut flow = UdpFlow {
        pid: permit.lease.pid,
        creation_time: permit.lease.creation_time,
        app_endpoint: (Ipv4Addr::new(192, 168, 1, 63), 49664),
        original_dst: (Ipv4Addr::new(8, 8, 8, 8), 53),
        dns: Some(permit),
        reply_interface: ReplyInterface::captured(&captured),
        app_to_remote,
        remote_to_app,
        last_active: Instant::now(),
        _task: BridgeTask(tokio::spawn(std::future::pending())),
    };
    let mut response = crate::dns_broker::wire::test_query();
    response[2] = 0x81;
    response[3] = 0x83; // Preserve a provider NXDOMAIN; never invent one.
    let stats = stats();
    assert!(!deliver_udp_response(
        &flow,
        &response,
        &stats,
        |packet, interface| {
            let address = injection_address(interface);
            assert!(!address.outbound());
            assert_eq!(address.interface_index(), 17);
            assert_eq!(address.subinterface_index(), 3);
            assert!(!address.ip_checksum() && !address.udp_checksum());
            let parsed = SlicedPacket::from_ip(&packet).unwrap();
            let Some(NetSlice::Ipv4(ip)) = parsed.net else {
                panic!("IPv4 required")
            };
            assert_eq!(ip.header().source_addr(), flow.original_dst.0);
            assert_eq!(ip.header().destination_addr(), flow.app_endpoint.0);
            let Some(TransportSlice::Udp(udp)) = parsed.transport else {
                panic!("UDP required")
            };
            assert_eq!((udp.source_port(), udp.destination_port()), (53, 49664));
            assert_eq!(udp.payload(), response);
            false // Failed native injection must not be presented as bytes delivered.
        }
    ));
    assert_eq!(stats.bus.bytes_in.load(Ordering::Relaxed), 0);
    assert!(deliver_udp_response(&flow, &response, &stats, |_, _| true));
    assert_eq!(
        stats.bus.bytes_in.load(Ordering::Relaxed),
        response.len() as u64
    );
    flow.reply_interface = None;
    assert!(!deliver_udp_response(
        &flow,
        &response,
        &stats,
        |_, _| panic!("missing interface must block")
    ));
    assert_eq!(
        stats.bus.bytes_in.load(Ordering::Relaxed),
        response.len() as u64
    );
}

#[test]
fn dns_tcp_preserves_captured_interface_and_general_injection_stays_unchanged() {
    let mut flows = HashMap::new();
    let mut sockets = SocketSet::new(Vec::new());
    let mut request = tcp_request(40000, true);
    request.dns = Some(crate::split_dns::tests::permit().0);
    request.reply_interface = Some(ReplyInterface {
        index: 17,
        subindex: 3,
    });
    let key = request.key;
    assert_eq!(
        ensure_tcp_flow(&mut flows, &mut sockets, request, 1),
        TcpAdmission::Tunnel
    );
    let address = injection_address(flows[&key].reply_interface);
    assert!(!address.outbound());
    assert_eq!(
        (address.interface_index(), address.subinterface_index()),
        (17, 3)
    );
    let general = injection_address(None);
    assert!(general.outbound());
    assert!(ReplyInterface::captured(&general).is_none());
}

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
        dns: None,
        reply_interface: None,
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
            dst_ip: Ipv4Addr::LOCALHOST,
            dst_port: 443,
        },
        TcpFlow {
            handle,
            pid: TEST_PID,
            creation_time: 0,
            original_dst: "127.0.0.1:443".parse().unwrap(),
            dns: None,
            reply_interface: None,
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
            dst_ip: Ipv4Addr::new(10, 0, 0, 2),
            dst_port: 443,
        },
        pid: TEST_PID,
        creation_time: 0,
        destination: SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 443),
        initial_syn,
        dns: None,
        reply_interface: None,
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
        dns: None,
        reply_interface: None,
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

#[test]
fn selected_dns_midstream_is_dropped_and_tcp_keys_include_original_destination() {
    let (permit, _) = crate::split_dns::tests::permit();
    let mut request = tcp_request(40000, false);
    request.dns = Some(permit.clone());
    let mut flows = HashMap::new();
    let mut sockets = SocketSet::new(Vec::new());
    assert_eq!(
        ensure_tcp_flow(&mut flows, &mut sockets, request, 2),
        TcpAdmission::Drop
    );
    assert!(flows.is_empty());
    let mut first = tcp_request(40000, true);
    first.dns = Some(permit.clone());
    let mut second = tcp_request(40000, true);
    second.dns = Some(permit);
    second.destination = "192.0.2.3:53".parse().unwrap();
    second.key.dst_ip = *second.destination.ip();
    second.key.dst_port = 53;
    assert_eq!(
        ensure_tcp_flow(&mut flows, &mut sockets, first, 2),
        TcpAdmission::Tunnel
    );
    assert_eq!(
        ensure_tcp_flow(&mut flows, &mut sockets, second, 2),
        TcpAdmission::Tunnel
    );
    assert_eq!(flows.len(), 2);
}

#[test]
fn udp_packet_length_is_bounded_and_reply_keeps_original_endpoint() {
    let remote = Ipv4Addr::new(192, 0, 2, 53);
    let app = Ipv4Addr::new(192, 0, 2, 10);
    assert!(build_udp_packet(remote, 53, app, 40000, &vec![0; 65508]).is_none());
    let packet = build_udp_packet(remote, 53, app, 40000, &vec![0; 65507]).unwrap();
    assert_eq!(packet.len(), 65535);
    assert_eq!(u16::from_be_bytes(packet[2..4].try_into().unwrap()), 65535);
    assert!(
        matches!(parse_ipv4_l4(&packet), Some(ParsedL4::Udp { src_ip, src_port:53, dst_ip, dst_port:40000 }) if src_ip == remote && dst_ip == app)
    );
}

#[test]
fn dns_generation_revoke_closes_only_dns_flows() {
    let stats = stats();
    let mut sockets = SocketSet::new(Vec::new());
    let mut flows = HashMap::new();
    let mut udp = HashMap::new();
    let mut dns = tcp_request(40000, true);
    dns.dns = Some(crate::split_dns::tests::permit().0);
    let regular = tcp_request(40001, true);
    assert_eq!(
        ensure_tcp_flow(&mut flows, &mut sockets, dns, 10),
        TcpAdmission::Tunnel
    );
    assert_eq!(
        ensure_tcp_flow(&mut flows, &mut sockets, regular, 10),
        TcpAdmission::Tunnel
    );
    remove_dns_flows(&mut flows, &mut udp, &mut sockets, &stats);
    assert_eq!(flows.len(), 1);
    assert_eq!(sockets.iter().count(), 1);
    assert!(flows.values().all(|flow| flow.dns.is_none()));
}

fn permit_for(servers: Vec<SocketAddrV4>) -> (Permit, Arc<crate::split_dns::tests::TestAuthority>) {
    let mut lease = crate::split_dns::tests::lease();
    lease.dns.servers = servers;
    let authority = Arc::new(crate::split_dns::tests::TestAuthority(
        std::sync::Mutex::new(Some(lease.clone())),
    ));
    (Permit::new(lease, authority.clone()), authority)
}

#[tokio::test]
async fn transparent_dns_udp_keeps_tc_and_original_client_id_and_address() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let SocketAddr::V4(endpoint) = server.local_addr().unwrap() else {
        unreachable!()
    };
    let tcp_trap = TcpListener::bind(endpoint).await.unwrap();
    let (permit, _) = permit_for(vec![endpoint]);
    let (tx, from_app) = mpsc::channel(2);
    let (to_app, mut rx) = mpsc::channel(2);
    let bridge = tokio::spawn(udp_dns_bridge_bound(
        permit,
        crate::dns_broker::transport::Binding::loopback(),
        from_app,
        to_app,
    ));
    let query = crate::dns_broker::wire::test_query();
    tx.send(query.clone()).await.unwrap();
    let mut packet = [0; 4096];
    let (size, peer) = timeout(DEADLINE, server.recv_from(&mut packet))
        .await
        .unwrap()
        .unwrap();
    packet[2] |= 0x82; // QR + TC, no implicit TCP exchange by our UDP bridge.
    server.send_to(&packet[..size], peer).await.unwrap();
    let reply = timeout(DEADLINE, rx.recv()).await.unwrap().unwrap();
    assert_eq!(&reply[..2], &query[..2]);
    assert_ne!(reply[2] & 2, 0);
    assert!(timeout(Duration::from_millis(50), tcp_trap.accept())
        .await
        .is_err());
    let raw = build_udp_packet(
        "192.0.2.53".parse().unwrap(),
        53,
        "192.0.2.10".parse().unwrap(),
        40000,
        &reply,
    )
    .unwrap();
    assert_eq!(extract_udp_payload(&raw).unwrap(), reply);
    assert!(
        matches!(parse_ipv4_l4(&raw),Some(ParsedL4::Udp {src_ip,src_port:53,..}) if src_ip == Ipv4Addr::new(192,0,2,53))
    );
    drop(tx);
    timeout(DEADLINE, bridge).await.unwrap().unwrap().unwrap();
}

#[tokio::test]
async fn dns_tcp_retries_only_provider_connects_and_preserves_framing_half_close() {
    let closed = tokio::net::TcpSocket::new_v4().unwrap();
    closed.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let SocketAddr::V4(first) = closed.local_addr().unwrap() else {
        unreachable!()
    };
    let SocketAddr::V4(second) = server.local_addr().unwrap() else {
        unreachable!()
    };
    let (permit, _) = permit_for(vec![first, second]);
    let (tx, from_app) = mpsc::channel(8);
    let (to_app, mut rx) = mpsc::channel(8);
    let bridge = tokio::spawn(tcp_dns_bridge_bound(
        permit,
        crate::dns_broker::transport::Binding::loopback(),
        from_app,
        to_app,
    ));
    let query = crate::dns_broker::wire::test_query();
    let mut framed = Vec::new();
    for _ in 0..2 {
        framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
        framed.extend_from_slice(&query);
    }
    for chunk in framed.chunks(11) {
        tx.send(chunk.to_vec()).await.unwrap();
    }
    drop(tx);
    let (mut stream, _) = timeout(DEADLINE, server.accept()).await.unwrap().unwrap();
    let mut received = Vec::new();
    timeout(DEADLINE, stream.read_to_end(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received, framed);
    for chunk in received.chunks(7) {
        stream.write_all(chunk).await.unwrap();
    }
    stream.shutdown().await.unwrap();
    let mut result = Vec::new();
    while let Some(chunk) = timeout(DEADLINE, rx.recv()).await.unwrap() {
        result.extend(chunk);
    }
    assert_eq!(result, framed);
    timeout(DEADLINE, bridge).await.unwrap().unwrap().unwrap();
}

#[tokio::test]
async fn dns_tcp_idle_revocation_closes_owned_socket() {
    let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let SocketAddr::V4(endpoint) = server.local_addr().unwrap() else {
        unreachable!()
    };
    let (permit, authority) = permit_for(vec![endpoint]);
    let (_tx, from_app) = mpsc::channel(1);
    let (to_app, _rx) = mpsc::channel(1);
    let bridge = tokio::spawn(tcp_dns_bridge_bound(
        permit,
        crate::dns_broker::transport::Binding::loopback(),
        from_app,
        to_app,
    ));
    let (mut stream, _) = timeout(DEADLINE, server.accept()).await.unwrap().unwrap();
    *authority.0.lock().unwrap() = None;
    assert!(timeout(Duration::from_secs(1), bridge)
        .await
        .unwrap()
        .unwrap()
        .is_err());
    assert_eq!(
        timeout(DEADLINE, stream.read(&mut [0; 1]))
            .await
            .unwrap()
            .unwrap(),
        0
    );
}
