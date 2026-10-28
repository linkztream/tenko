//! Free loopback ports for the tests that start a [`Server`] on real sockets.
//!
//! A server asked for port 0 takes a UDP port from the system and binds TCP on the same
//! number, which another test's outgoing connection can hold already (under a loaded gate
//! that is `AddrInUse`). [`free_port`] instead draws from a pool below the ephemeral ranges
//! of Linux (32768 and up), Windows and macOS (49152 and up), checks TCP and UDP on both
//! loopback families and never hands a port out twice in a process; [`start_on_free_port`]
//! starts again on a new port when the bind still loses a race with another process.

use std::{
    collections::HashSet,
    hash::BuildHasher as _,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, UdpSocket},
    sync::{
        Mutex, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
};

use tenko_dns::{
    catalog::CatalogHandle,
    server::{Hooks, Server, ServerConfig},
};

/// The ports [`free_port`] hands out.
const PORT_POOL: std::ops::Range<u16> = 20_000..32_000;

/// How often a pick is tried before the helper gives up (a pool full of ports in use is a
/// broken machine, not a race).
const PORT_PICKS: u32 = 500;

/// How often a server start is tried before the test fails.
const START_ATTEMPTS: u32 = 20;

/// Whether `port` can be bound on the loopback for TCP and for UDP right now, on IPv4 and,
/// where the machine has it, on IPv6.
fn is_free(port: u16) -> bool {
    let v4 = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok()
        && UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).is_ok();
    // A machine without IPv6 on the loopback cannot bind at all: that is no reason to skip.
    let v6_usable = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).is_ok();
    v4 && (!v6_usable
        || (TcpListener::bind((Ipv6Addr::LOCALHOST, port)).is_ok()
            && UdpSocket::bind((Ipv6Addr::LOCALHOST, port)).is_ok()))
}

/// A free loopback port, for TCP and UDP alike, that no other call of this process handed
/// out and that is not in an ephemeral range.
pub fn free_port() -> u16 {
    static PICKS: AtomicU64 = AtomicU64::new(0);
    static HANDED_OUT: Mutex<Option<HashSet<u16>>> = Mutex::new(None);
    let span = u64::from(PORT_POOL.end - PORT_POOL.start);
    for _ in 0..PORT_PICKS {
        // Random per process (the hasher's keys) and different on every call.
        let draw = std::hash::RandomState::new().hash_one(PICKS.fetch_add(1, Ordering::Relaxed));
        let port = PORT_POOL.start + u16::try_from(draw % span).expect("below the pool's end");
        let mut handed_out = HANDED_OUT.lock().unwrap_or_else(PoisonError::into_inner);
        let handed_out = handed_out.get_or_insert_with(HashSet::new);
        if handed_out.contains(&port) || !is_free(port) {
            continue;
        }
        handed_out.insert(port);
        return port;
    }
    panic!("no free loopback port in {PORT_POOL:?} after {PORT_PICKS} picks");
}

/// Starts an authoritative server on a free port: `config` builds the configuration for the
/// port picked. An `AddrInUse` from the start (another process took the port between the
/// pick and the bind) starts again on a new port; any other error fails the test.
pub async fn start_on_free_port(
    config: impl Fn(u16) -> ServerConfig,
    catalog: &CatalogHandle,
) -> Server {
    for attempt in 1..=START_ATTEMPTS {
        match Server::start_authoritative(config(free_port()), catalog.clone(), Hooks::default())
            .await
        {
            Ok(server) => return server,
            Err(error)
                if error.kind() == std::io::ErrorKind::AddrInUse && attempt < START_ATTEMPTS =>
            {
                eprintln!(
                    "start attempt {attempt} of {START_ATTEMPTS}: the port was taken between \
                     the pick and the bind; picking another port"
                );
            }
            Err(error) => panic!("start (attempt {attempt} of {START_ATTEMPTS}): {error}"),
        }
    }
    unreachable!("the loop returns or panics");
}

/// The loopback addresses a test listens on for `port`.
pub fn loopback(port: u16, ipv6: bool) -> Vec<SocketAddr> {
    let mut listen = vec![SocketAddr::from((Ipv4Addr::LOCALHOST, port))];
    if ipv6 {
        listen.push(SocketAddr::from((Ipv6Addr::LOCALHOST, port)));
    }
    listen
}
