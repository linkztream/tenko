//! Free loopback ports for the tests that start a [`Server`] on real sockets.
//!
//! A server asked for port 0 takes a UDP port from the system and binds TCP on the same
//! number, which another test's outgoing connection can hold already (under a loaded gate
//! that is `AddrInUse`). The port therefore comes from `tenko_core::testing::free_port`, a
//! pool below the ephemeral ranges that is checked for TCP and UDP on both loopback families
//! and never handed out twice in a process; [`start_on_free_port`] starts again on a new
//! port when the bind still loses a race with another process.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use tenko_core::testing::free_port;
use tenko_dns::{
    catalog::CatalogHandle,
    server::{Hooks, Server, ServerConfig},
};

/// How often a server start is tried before the test fails.
const START_ATTEMPTS: u32 = 20;

/// Starts an authoritative server on a free port: `config` builds the configuration for the
/// port picked. An `AddrInUse` from the start (another process took the port between the
/// pick and the bind) or a `PermissionDenied` (Windows excludes the port for one of the
/// transports) starts again on a new port; any other error fails the test.
pub async fn start_on_free_port(
    config: impl Fn(u16) -> ServerConfig,
    catalog: &CatalogHandle,
) -> Server {
    for attempt in 1..=START_ATTEMPTS {
        match Server::start_authoritative(
            config(free_port().release()),
            catalog.clone(),
            Hooks::default(),
        )
        .await
        {
            Ok(server) => return server,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::AddrInUse | std::io::ErrorKind::PermissionDenied
                ) && attempt < START_ATTEMPTS =>
            {
                eprintln!(
                    "start attempt {attempt} of {START_ATTEMPTS}: the port was taken or is excluded between \
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
