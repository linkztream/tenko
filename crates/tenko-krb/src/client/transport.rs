//! The KDC and change-password transport: UDP with the TCP fallback of RFC 4120 section
//! 7.2.2 (a four-octet big-endian length before each message), with a timeout per
//! attempt and the servers the caller lists (identity plan section 3.1: found through
//! `_kerberos._tcp.<realm>` or listed by the operator; the crate resolves nothing).
//!
//! A request larger than the UDP limit goes over TCP directly (MIT's
//! `udp_preference_limit`, 1,465 octets, since a TGS request with an AD ticket rarely fits
//! a datagram); a UDP answer of `KRB_ERR_RESPONSE_TOO_BIG`, a UDP failure or a UDP
//! timeout is retried over TCP to the same server before the next server is tried. A TCP
//! answer longer than [`MAX_REPLY_LEN`] is refused, and its octets are read as they come,
//! never into a buffer sized by the length the server announced.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    time::timeout,
};

use super::ClientError;
use crate::der::{KrbError, tag};

/// The largest answer read over TCP.
pub const MAX_REPLY_LEN: usize = 1 << 20;
/// The largest UDP datagram.
const MAX_DATAGRAM: usize = 65_535;
/// `KRB_ERR_RESPONSE_TOO_BIG`.
pub const KRB_ERR_RESPONSE_TOO_BIG: i32 = 52;

/// How the client reaches its servers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportConfig {
    /// The timeout of one attempt (one UDP exchange or one TCP connection and exchange).
    pub timeout: Duration,
    /// Requests larger than this go over TCP directly.
    pub udp_limit: usize,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(3),
            udp_limit: 1465,
        }
    }
}

fn is_too_big(reply: &[u8]) -> bool {
    reply.first() == Some(&tag::application(30))
        && KrbError::decode(reply).is_ok_and(|e| e.error_code == KRB_ERR_RESPONSE_TOO_BIG)
}

fn unspecified(peer: SocketAddr) -> SocketAddr {
    match peer.ip() {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    }
}

fn io(error: &std::io::Error) -> ClientError {
    ClientError::Io(error.kind())
}

/// One UDP attempt; `None` when the request is larger than the UDP limit and goes over
/// TCP instead. The request is built once, for the socket's own address.
async fn udp(
    config: &TransportConfig,
    server: SocketAddr,
    build: &mut (dyn FnMut(IpAddr) -> Result<Vec<u8>, ClientError> + Send),
) -> Result<Option<Vec<u8>>, ClientError> {
    let attempt = async {
        let socket = UdpSocket::bind(unspecified(server))
            .await
            .map_err(|e| io(&e))?;
        socket.connect(server).await.map_err(|e| io(&e))?;
        let request = build(socket.local_addr().map_err(|e| io(&e))?.ip())?;
        if request.len() > config.udp_limit {
            return Ok(None);
        }
        socket.send(&request).await.map_err(|e| io(&e))?;
        let mut buffer = vec![0_u8; MAX_DATAGRAM];
        let len = socket.recv(&mut buffer).await.map_err(|e| io(&e))?;
        buffer.truncate(len);
        Ok(Some(buffer))
    };
    timeout(config.timeout, attempt)
        .await
        .unwrap_or(Err(ClientError::Timeout))
}

async fn tcp(
    config: &TransportConfig,
    server: SocketAddr,
    build: &mut (dyn FnMut(IpAddr) -> Result<Vec<u8>, ClientError> + Send),
) -> Result<Vec<u8>, ClientError> {
    let attempt = async {
        let mut stream = TcpStream::connect(server).await.map_err(|e| io(&e))?;
        let request = build(stream.local_addr().map_err(|e| io(&e))?.ip())?;
        let len = u32::try_from(request.len())
            .ok()
            .filter(|len| len & 0x8000_0000 == 0)
            .ok_or(ClientError::Reply("the request is too large"))?;
        let mut framed = Vec::with_capacity(4 + request.len());
        framed.extend_from_slice(&len.to_be_bytes());
        framed.extend_from_slice(&request);
        stream.write_all(&framed).await.map_err(|e| io(&e))?;
        let mut prefix = [0_u8; 4];
        stream.read_exact(&mut prefix).await.map_err(|e| io(&e))?;
        // The high bit is reserved (RFC 4120 section 7.2.2); a server never sets it.
        let len = usize::try_from(u32::from_be_bytes(prefix))
            .ok()
            .filter(|len| *len <= MAX_REPLY_LEN && prefix[0] & 0x80 == 0)
            .ok_or(ClientError::Reply("the answer is too large"))?;
        let mut reply = Vec::new();
        (&mut stream)
            .take(u64::try_from(len).unwrap_or(0))
            .read_to_end(&mut reply)
            .await
            .map_err(|e| io(&e))?;
        if reply.len() != len {
            return Err(ClientError::Reply(
                "the connection closed inside the answer",
            ));
        }
        Ok(reply)
    };
    timeout(config.timeout, attempt)
        .await
        .unwrap_or(Err(ClientError::Timeout))
}

/// Sends a request built for the local address of the socket (the change-password
/// request names it) to the first server that answers.
///
/// # Errors
///
/// [`ClientError::Unreachable`] when no server answered; an error of `build`.
pub async fn exchange(
    config: &TransportConfig,
    servers: &[SocketAddr],
    mut build: impl FnMut(IpAddr) -> Result<Vec<u8>, ClientError> + Send,
) -> Result<Vec<u8>, ClientError> {
    let mut last = None;
    for server in servers {
        if config.udp_limit > 0 {
            match udp(config, *server, &mut build).await {
                Ok(Some(reply)) if !is_too_big(&reply) => return Ok(reply),
                // Too large to send, too big an answer, or no answer: TCP to the same
                // server.
                Ok(_) | Err(ClientError::Timeout | ClientError::Io(_)) => {}
                Err(error) => return Err(error),
            }
        }
        match tcp(config, *server, &mut build).await {
            Ok(reply) => return Ok(reply),
            Err(error @ (ClientError::Timeout | ClientError::Io(_))) => last = Some(error),
            Err(error) => return Err(error),
        }
    }
    Err(ClientError::Unreachable {
        servers: servers.len(),
        last: last.map(|e| e.to_string()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::der::PrincipalName;

    fn config() -> TransportConfig {
        TransportConfig {
            timeout: Duration::from_millis(300),
            udp_limit: 1465,
        }
    }

    fn too_big() -> Vec<u8> {
        KrbError {
            ctime: None,
            cusec: None,
            stime: 0,
            susec: 0,
            error_code: KRB_ERR_RESPONSE_TOO_BIG,
            crealm: None,
            cname: None,
            realm: "CORP.EXAMPLE.TEST".into(),
            sname: PrincipalName::new(2, &["krbtgt", "CORP.EXAMPLE.TEST"]),
            e_text: None,
            e_data: None,
        }
        .encode()
    }

    /// A server on one port for UDP and TCP: UDP answers `udp` (or nothing), TCP answers
    /// `tcp` with the length prefix.
    async fn server(udp_answer: Option<Vec<u8>>, tcp_answer: Vec<u8>) -> SocketAddr {
        let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("tcp");
        let addr = tcp_listener.local_addr().expect("addr");
        let udp_socket = UdpSocket::bind(addr).await.expect("udp on the same port");
        tokio::spawn(async move {
            let mut buffer = vec![0_u8; 65_535];
            while let Ok((_, peer)) = udp_socket.recv_from(&mut buffer).await {
                if let Some(answer) = &udp_answer {
                    let _ = udp_socket.send_to(answer, peer).await;
                }
            }
        });
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = tcp_listener.accept().await {
                let answer = tcp_answer.clone();
                tokio::spawn(async move {
                    let mut prefix = [0_u8; 4];
                    if stream.read_exact(&mut prefix).await.is_err() {
                        return;
                    }
                    let mut request =
                        vec![0_u8; usize::try_from(u32::from_be_bytes(prefix)).expect("len")];
                    let _ = stream.read_exact(&mut request).await;
                    let mut out = u32::try_from(answer.len())
                        .expect("len")
                        .to_be_bytes()
                        .to_vec();
                    out.extend_from_slice(&answer);
                    let _ = stream.write_all(&out).await;
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn udp_answers_and_the_tcp_fallback() {
        let request = |_: IpAddr| Ok(b"request".to_vec());
        // UDP answers.
        let addr = server(Some(b"udp answer".to_vec()), b"tcp answer".to_vec()).await;
        assert_eq!(
            exchange(&config(), &[addr], request).await.expect("udp"),
            b"udp answer"
        );
        // KRB_ERR_RESPONSE_TOO_BIG over UDP: TCP.
        let addr = server(Some(too_big()), b"tcp answer".to_vec()).await;
        assert_eq!(
            exchange(&config(), &[addr], request).await.expect("tcp"),
            b"tcp answer"
        );
        // No UDP answer: TCP after the timeout.
        let addr = server(None, b"tcp answer".to_vec()).await;
        assert_eq!(
            exchange(&config(), &[addr], request).await.expect("tcp"),
            b"tcp answer"
        );
        // A large request: TCP directly.
        let addr = server(Some(b"udp answer".to_vec()), b"tcp answer".to_vec()).await;
        let large = |_: IpAddr| Ok(vec![0_u8; 2000]);
        assert_eq!(
            exchange(&config(), &[addr], large).await.expect("tcp"),
            b"tcp answer"
        );
        // A server that is not there, then one that is.
        let dead: SocketAddr = "127.0.0.1:9".parse().expect("addr");
        let addr = server(Some(b"udp answer".to_vec()), b"tcp answer".to_vec()).await;
        assert_eq!(
            exchange(&config(), &[dead, addr], request)
                .await
                .expect("second"),
            b"udp answer"
        );
        let error = exchange(&config(), &[dead], request)
            .await
            .expect_err("unreachable");
        assert!(
            matches!(error, ClientError::Unreachable { servers: 1, .. }),
            "{error}"
        );
    }

    #[tokio::test]
    async fn an_announced_length_above_the_bound_is_refused() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("tcp");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let _ = stream.write_all(&0x7fff_ffff_u32.to_be_bytes()).await;
            }
        });
        let large = |_: IpAddr| Ok(vec![0_u8; 2000]);
        let error = exchange(&config(), &[addr], large)
            .await
            .expect_err("refused");
        assert_eq!(error, ClientError::Reply("the answer is too large"));
    }
}
