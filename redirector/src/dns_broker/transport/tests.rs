use super::*;
use tokio::net::TcpListener;

fn reply(query: &[u8], truncated: bool) -> Vec<u8> {
    let mut answer = query.to_vec();
    answer[2] = if truncated { 0x83 } else { 0x81 };
    answer[3] = 0x83;
    answer
}

#[tokio::test]
async fn transparent_udp_preserves_positive_answer_and_edns_metadata() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let SocketAddr::V4(endpoint) = server.local_addr().unwrap() else {
        unreachable!()
    };
    let opt = [0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0]; // EDNS UDP size1232.
    let answer_rr = [0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 9];
    let mut query = wire::test_query();
    query[11] = 1;
    query.extend_from_slice(&opt);
    let task = tokio::spawn(async move {
        let mut request = [0; 4096];
        let (size, peer) = server.recv_from(&mut request).await.unwrap();
        let mut response = request[..size - opt.len()].to_vec();
        response[2] = 0x81;
        response[3] = 0x80;
        response[7] = 1;
        response.extend_from_slice(&answer_rr);
        response.extend_from_slice(&opt);
        server.send_to(&response, peer).await.unwrap();
    });
    let question = wire::query(&query).unwrap();
    let response = exchange_datagram(
        Binding::loopback(),
        &[endpoint],
        &query,
        &question,
        QueryTrace::new(std::process::id(), question.kind()),
    )
    .await
    .unwrap();
    assert_eq!(&response[..2], &query[..2]);
    assert_eq!(wire::response_header(&response), Some((0, false, 1)));
    assert_eq!(
        &response[query.len() - opt.len()..response.len() - opt.len()],
        &answer_rr
    );
    assert!(response.ends_with(&opt));
    task.await.unwrap();
}

#[tokio::test]
async fn udp_ignores_wrong_id_and_question_and_restores_client_id() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoint = match server.local_addr().unwrap() {
        SocketAddr::V4(s) => s,
        _ => unreachable!(),
    };
    let task = tokio::spawn(async move {
        let mut bytes = [0; 4096];
        let (n, peer) = server.recv_from(&mut bytes).await.unwrap();
        let correct = reply(&bytes[..n], false);
        let mut wrong = correct.clone();
        wrong[0] ^= 1;
        server.send_to(&wrong, peer).await.unwrap();
        wrong = correct.clone();
        wrong[13] = b'x';
        server.send_to(&wrong, peer).await.unwrap();
        server.send_to(&correct, peer).await.unwrap();
    });
    let q = wire::test_query();
    let result = exchange(
        Binding::loopback(),
        &[endpoint],
        &q,
        &wire::query(&q).unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(&result[..2], &q[..2]);
    assert_eq!(result[3], 0x83);
    task.await.unwrap();
}

#[tokio::test]
async fn truncation_uses_tcp_same_provider_with_dns_length_framing() {
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoint = match udp.local_addr().unwrap() {
        SocketAddr::V4(s) => s,
        _ => unreachable!(),
    };
    let tcp = TcpListener::bind(endpoint).await.unwrap();
    let task = tokio::spawn(async move {
        let mut bytes = [0; 4096];
        let (n, peer) = udp.recv_from(&mut bytes).await.unwrap();
        udp.send_to(&reply(&bytes[..n], true), peer).await.unwrap();
        let (mut stream, _) = tcp.accept().await.unwrap();
        let size = stream.read_u16().await.unwrap();
        let mut query = vec![0; usize::from(size)];
        stream.read_exact(&mut query).await.unwrap();
        assert_eq!(query, &bytes[..n]);
        let answer = reply(&query, false);
        stream.write_u16(answer.len() as u16).await.unwrap();
        // Deliberate fragmentation exercises read_exact rather than a single read.
        for chunk in answer.chunks(3) {
            stream.write_all(chunk).await.unwrap();
        }
    });
    let q = wire::test_query();
    let result = exchange(
        Binding::loopback(),
        &[endpoint],
        &q,
        &wire::query(&q).unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(result, reply(&q, false));
    task.await.unwrap();
}

#[tokio::test]
async fn silent_provider_times_out_without_other_resolver() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoint = match server.local_addr().unwrap() {
        SocketAddr::V4(s) => s,
        _ => unreachable!(),
    };
    let q = wire::test_query();
    assert_eq!(
        exchange(
            Binding::loopback(),
            &[endpoint],
            &q,
            &wire::query(&q).unwrap()
        )
        .await,
        Err(TIMEOUT)
    );
    let mut bytes = [0; 4096];
    server.try_recv_from(&mut bytes).unwrap();
    assert_eq!(
        server.try_recv_from(&mut bytes).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[tokio::test]
async fn connected_udp_rejects_spoofed_source_even_with_correct_question_and_id() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoint = match server.local_addr().unwrap() {
        SocketAddr::V4(s) => s,
        _ => unreachable!(),
    };
    let task = tokio::spawn(async move {
        let mut bytes = [0; 4096];
        let (n, peer) = server.recv_from(&mut bytes).await.unwrap();
        let attacker = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        attacker
            .send_to(&reply(&bytes[..n], false), peer)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut legitimate = reply(&bytes[..n], false);
        legitimate[3] = 0x82;
        server.send_to(&legitimate, peer).await.unwrap();
    });
    let q = wire::test_query();
    let result = exchange(
        Binding::loopback(),
        &[endpoint],
        &q,
        &wire::query(&q).unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(result[3], 0x82);
    task.await.unwrap();
}
