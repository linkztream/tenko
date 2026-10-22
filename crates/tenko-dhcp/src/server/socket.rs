//! The listener sockets (plan section 2.5, ADR 0009's layout): blocking UDP sockets through
//! `socket2`, the safe socket API the DNS role uses, one per worker with `SO_REUSEPORT` on
//! Linux and one shared by the workers elsewhere.
//!
//! The receiving interface and address come from the binding, not from `IP_PKTINFO`:
//! `socket2` 0.6 has no safe way to ask for that control message, and no binding needs it.
//!
//! - **Relay mode** binds the unicast address on port 67. Only relayed and unicast
//!   datagrams reach it (renewals of clients on other links included), and the address it
//!   is bound to is the receiving address.
//! - **Direct mode on Linux** binds `0.0.0.0` on port 67 with `SO_BINDTODEVICE` to the
//!   listener's interface (and `SO_REUSEADDR`, so that several interfaces can each have
//!   one), which receives the broadcasts of that link; the configured address is the
//!   interface's address. Without an interface name the socket hears every link, which is
//!   right only on a host with one.
//! - **Direct mode elsewhere** (Windows) binds the interface's unicast address, on which
//!   Windows delivers the broadcasts arriving on that interface.
//!
//! Every socket may send broadcasts (`SO_BROADCAST`).
//!
//! WP7.5: a direct listener has one socket that its workers share, whatever the layout.
//! Linux hands a broadcast to every socket of a `SO_REUSEPORT` group (only unicast is spread
//! over the group), so one socket per worker would answer every broadcast request once per
//! worker; `tests/direct_linux.rs` asserts that each DISCOVER is answered once.

use std::{
    io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket},
    sync::Arc,
    time::Duration,
};

use socket2::{Domain, Protocol, Socket, Type};

use super::{Listen, SocketLayout};
use crate::v4::engine::ListenMode;

/// How often a blocked worker wakes to look at the stop flag.
pub const STOP_POLL: Duration = Duration::from_millis(200);

/// The sockets of one listener.
#[derive(Debug)]
pub(crate) struct Bound {
    /// The address bound (the port the system chose for port 0).
    pub(crate) address: SocketAddrV4,
    /// The listener's address: the receiving address the engine selects by.
    pub(crate) local: Ipv4Addr,
    pub(crate) sockets: Vec<Arc<UdpSocket>>,
}

#[cfg(target_os = "linux")]
fn set_reuse_port(socket: &Socket) -> io::Result<()> {
    socket.set_reuse_port(true)
}

#[cfg(not(target_os = "linux"))]
fn set_reuse_port(_socket: &Socket) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "SO_REUSEPORT spreading is a Linux feature; use the shared socket layout",
    ))
}

#[cfg(target_os = "linux")]
fn direct_address(listen: &Listen, socket: &Socket) -> io::Result<SocketAddrV4> {
    socket.set_reuse_address(true)?;
    if let Some(interface) = &listen.interface {
        socket.bind_device(Some(interface.as_bytes()))?;
    }
    Ok(SocketAddrV4::new(
        Ipv4Addr::UNSPECIFIED,
        listen.address.port(),
    ))
}

#[cfg(not(target_os = "linux"))]
#[allow(
    clippy::unnecessary_wraps,
    reason = "the Linux variant sets socket options that fail"
)]
fn direct_address(listen: &Listen, _socket: &Socket) -> io::Result<SocketAddrV4> {
    Ok(listen.address)
}

fn bind_one(
    listen: &Listen,
    port: u16,
    reuse: bool,
    buffers: (usize, usize),
) -> io::Result<(UdpSocket, SocketAddrV4)> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    // The buffer sizes are wishes: the system caps them (net.core.rmem_max on Linux).
    if buffers.0 > 0 {
        let _ = socket.set_recv_buffer_size(buffers.0);
    }
    if buffers.1 > 0 {
        let _ = socket.set_send_buffer_size(buffers.1);
    }
    socket.set_broadcast(true)?;
    if reuse {
        set_reuse_port(&socket)?;
    }
    let mut address = match listen.mode {
        ListenMode::Relay => listen.address,
        ListenMode::Direct => direct_address(listen, &socket)?,
    };
    address.set_port(port);
    socket.bind(&SocketAddr::V4(address).into())?;
    let socket: UdpSocket = socket.into();
    socket.set_read_timeout(Some(STOP_POLL))?;
    let bound = match socket.local_addr()? {
        SocketAddr::V4(bound) => bound,
        SocketAddr::V6(_) => return Err(io::Error::other("an IPv4 socket bound IPv6")),
    };
    Ok((socket, bound))
}

/// Binds the sockets of one listener: one per worker with `SO_REUSEPORT`, else one.
pub(crate) fn bind(
    listen: &Listen,
    workers: usize,
    layout: SocketLayout,
    buffers: (usize, usize),
) -> io::Result<Bound> {
    // WP7.5: a broadcast reaches every socket of a reuse-port group: one per direct listener.
    let reuse = layout == SocketLayout::ReusePort && listen.mode == ListenMode::Relay;
    let (first, bound) = bind_one(listen, listen.address.port(), reuse, buffers)?;
    let mut sockets = vec![Arc::new(first)];
    if reuse {
        for _ in 1..workers.max(1) {
            sockets.push(Arc::new(bind_one(listen, bound.port(), true, buffers)?.0));
        }
    }
    Ok(Bound {
        address: bound,
        local: *listen.address.ip(),
        sockets,
    })
}
