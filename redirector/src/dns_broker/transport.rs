use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::windows::io::AsRawSocket;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, UdpSocket};
use windows::Win32::Networking::WinSock::{setsockopt, WSAGetLastError, IPPROTO_IP, SOCKET};
use windows::Win32::Security::Cryptography::{BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG};

use super::{wire, SERVER_FAILURE, TIMEOUT};
use crate::adapter::VpnTarget;

#[derive(Clone, Copy)]
pub struct Binding {
    source: Ipv4Addr,
    interface: Option<u32>,
}
impl Binding {
    pub fn vpn(target: VpnTarget) -> Self {
        Self {
            source: target.ipv4,
            interface: Some(target.if_index),
        }
    }
    #[cfg(test)]
    pub fn loopback() -> Self {
        Self {
            source: Ipv4Addr::LOCALHOST,
            interface: None,
        }
    }
    fn pin(&self, socket: &impl AsRawSocket) -> Result<(), u32> {
        if let Some(index) = self.interface {
            let bytes = index.to_be().to_ne_bytes();
            let result = unsafe {
                setsockopt(
                    SOCKET(socket.as_raw_socket() as usize),
                    IPPROTO_IP.0,
                    31,
                    Some(&bytes),
                )
            };
            if result != 0 {
                tracing::debug!(
                    code = unsafe { WSAGetLastError() }.0,
                    "DNS interface pin failed"
                );
                return Err(SERVER_FAILURE);
            }
        }
        Ok(())
    }
}

pub async fn exchange(
    binding: Binding,
    servers: &[SocketAddrV4],
    request: &[u8],
    question: &wire::Question,
) -> Result<Vec<u8>, u32> {
    let mut random = [0; 2];
    unsafe { BCryptGenRandom(None, &mut random, BCRYPT_USE_SYSTEM_PREFERRED_RNG) }
        .ok()
        .map_err(|_| SERVER_FAILURE)?;
    let id = u16::from_ne_bytes(random);
    let mut query = request.to_vec();
    query[..2].copy_from_slice(&id.to_be_bytes());
    let mut last = SERVER_FAILURE;
    for server in servers {
        let attempt = tokio::time::timeout(
            Duration::from_secs(2),
            one(binding, *server, &query, id, question),
        )
        .await;
        match attempt {
            Ok(Ok(mut response)) => {
                response[..2].copy_from_slice(&request[..2]);
                return Ok(response);
            }
            Ok(Err(status)) => last = status,
            Err(_) => last = TIMEOUT,
        }
    }
    Err(last)
}

async fn one(
    binding: Binding,
    server: SocketAddrV4,
    query: &[u8],
    id: u16,
    question: &wire::Question,
) -> Result<Vec<u8>, u32> {
    let socket = UdpSocket::bind(SocketAddrV4::new(binding.source, 0))
        .await
        .map_err(|_| SERVER_FAILURE)?;
    binding.pin(&socket)?;
    // Connected UDP restricts response source to the exact provider endpoint.
    socket.connect(server).await.map_err(|_| SERVER_FAILURE)?;
    socket.send(query).await.map_err(|_| SERVER_FAILURE)?;
    let mut response = vec![0; wire::MAX_RESPONSE];
    for _ in 0..16 {
        let received = socket
            .recv(&mut response)
            .await
            .map_err(|_| SERVER_FAILURE)?;
        match wire::response(&response[..received], id, question) {
            Ok(wire::Response::Complete) => {
                response.truncate(received);
                return Ok(response);
            }
            Ok(wire::Response::Truncated) => {
                return tcp(binding, server, query, id, question).await
            }
            Err(()) => {} // Ignore mismatched IDs/questions, with bounded work/deadline.
        }
    }
    Err(SERVER_FAILURE)
}

async fn tcp(
    binding: Binding,
    server: SocketAddrV4,
    query: &[u8],
    id: u16,
    question: &wire::Question,
) -> Result<Vec<u8>, u32> {
    let socket = TcpSocket::new_v4().map_err(|_| SERVER_FAILURE)?;
    socket
        .bind(SocketAddr::V4(SocketAddrV4::new(binding.source, 0)))
        .map_err(|_| SERVER_FAILURE)?;
    binding.pin(&socket)?;
    let mut stream = socket
        .connect(SocketAddr::V4(server))
        .await
        .map_err(|_| SERVER_FAILURE)?;
    stream
        .write_u16(query.len() as u16)
        .await
        .map_err(|_| SERVER_FAILURE)?;
    stream.write_all(query).await.map_err(|_| SERVER_FAILURE)?;
    let length = usize::from(stream.read_u16().await.map_err(|_| SERVER_FAILURE)?);
    if length < 12 {
        return Err(SERVER_FAILURE);
    }
    let mut response = vec![0; length];
    stream
        .read_exact(&mut response)
        .await
        .map_err(|_| SERVER_FAILURE)?;
    match wire::response(&response, id, question) {
        Ok(wire::Response::Complete) => Ok(response),
        _ => Err(SERVER_FAILURE),
    }
}

#[cfg(test)]
mod tests;
