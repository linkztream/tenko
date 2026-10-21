//! The raw link-layer channel the raw-socket methods share: one Ethernet socket on the
//! probe's interface that sends frames and hands back the frames it receives, and the
//! interface facts (name, MAC, addresses) the methods build their frames from.
//!
//! The real channel is Linux only and goes through `pnet_datalink` (`AF_PACKET`), a safe
//! wrapper: no `unsafe` enters this workspace. It needs `CAP_NET_RAW`. The socket I/O runs
//! on a dedicated thread that owns the non-`Send` sender and receiver; the methods talk to
//! it over channels, so they stay async and honour their deadlines. A [`MockLink`] feeds
//! crafted frames to the methods' unit tests, so the sweep, the SYN scan, the rate limit
//! and the kill switch are tested without a socket.

use std::{
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use tenko_core::MacAddr;

use crate::error::ScanError;

/// The interface a raw channel runs on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkInterface {
    /// The interface name (`eth0`), for notes and the interface override.
    pub name: String,
    /// The interface's own MAC address, the source of the frames the methods send.
    pub mac: MacAddr,
    /// The interface's first IPv4 address, the source address of ARP and SYN frames.
    pub ipv4: Option<Ipv4Addr>,
    /// The interface's IPv6 addresses.
    pub ipv6: Vec<Ipv6Addr>,
}

/// A raw Ethernet channel: send a frame, or take the next received frame.
#[async_trait]
pub trait RawLink: Send + Sync + fmt::Debug {
    /// The interface the channel runs on.
    fn interface(&self) -> &LinkInterface;

    /// Sends one Ethernet frame.
    ///
    /// # Errors
    ///
    /// `scan.io` when the frame could not be sent.
    async fn send(&self, frame: &[u8]) -> Result<(), ScanError>;

    /// The next received frame, or `None` when `timeout` passed with none.
    ///
    /// # Errors
    ///
    /// `scan.io` when the channel failed.
    async fn recv(&self, timeout: Duration) -> Result<Option<Vec<u8>>, ScanError>;
}

/// Opens a raw channel on an interface. The methods hold a factory, not a channel, so the
/// socket is opened at run time (when the capability and the interface are known) and the
/// tests inject a mock.
#[async_trait]
pub trait LinkFactory: Send + Sync + fmt::Debug {
    /// The interfaces that can carry a raw channel (up, with a MAC, not loopback).
    fn interfaces(&self) -> Vec<LinkInterface>;

    /// Opens a channel on `interface`.
    ///
    /// # Errors
    ///
    /// `scan.unavailable` without the capability, `scan.io` when the socket fails.
    async fn open(&self, interface: &LinkInterface) -> Result<Arc<dyn RawLink>, ScanError>;
}

/// Picks the interface a method runs on: the one named by `override_name` when given, else
/// the one whose IPv4 network holds `prefer_ipv4` (the probe's address on the segment),
/// else the first interface with an IPv4 address, else the first interface.
pub fn choose_interface(
    interfaces: &[LinkInterface],
    override_name: Option<&str>,
    prefer_ipv4: Option<Ipv4Addr>,
) -> Option<LinkInterface> {
    if let Some(name) = override_name {
        return interfaces.iter().find(|i| i.name == name).cloned();
    }
    if let Some(target) = prefer_ipv4
        && let Some(found) = interfaces
            .iter()
            .find(|i| i.ipv4.is_some_and(|addr| same_network(addr, target)))
    {
        return Some(found.clone());
    }
    interfaces
        .iter()
        .find(|i| i.ipv4.is_some())
        .or_else(|| interfaces.first())
        .cloned()
}

/// A coarse same-network test (a /24) for choosing the interface when no override is set;
/// the exact prefix is not known here, and the probe is one per segment.
fn same_network(a: Ipv4Addr, b: Ipv4Addr) -> bool {
    a.octets()[..3] == b.octets()[..3]
}

#[cfg(target_os = "linux")]
pub use platform::HostLinkFactory;

#[cfg(target_os = "linux")]
mod platform {
    use std::{
        net::IpAddr,
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, Ordering},
            mpsc,
        },
        thread::JoinHandle,
        time::Duration,
    };

    use async_trait::async_trait;
    use pnet_datalink::{Channel, Config, NetworkInterface};
    use tenko_core::MacAddr;
    use tokio::sync::mpsc as tokio_mpsc;

    use super::{LinkFactory, LinkInterface, RawLink};
    use crate::error::ScanError;

    /// How long the reader blocks before it checks the stop flag and the send queue again.
    const READ_TIMEOUT: Duration = Duration::from_millis(50);
    /// Most frames held for the methods before the newest are dropped. A busy segment can
    /// fill this between the method's reads, so the active methods re-send (ARP sweep) or
    /// keep listening past the window (the passive methods).
    const RECV_CAPACITY: usize = 16384;

    /// Opens real `AF_PACKET` channels through `pnet_datalink`.
    #[derive(Debug, Default)]
    pub struct HostLinkFactory;

    fn to_interface(iface: &NetworkInterface) -> Option<LinkInterface> {
        let mac = iface.mac?;
        let mut ipv4 = None;
        let mut ipv6 = Vec::new();
        for ip in &iface.ips {
            match ip.ip() {
                IpAddr::V4(v4) if ipv4.is_none() && !v4.is_loopback() => ipv4 = Some(v4),
                IpAddr::V6(v6) if !v6.is_loopback() => ipv6.push(v6),
                _ => {}
            }
        }
        Some(LinkInterface {
            name: iface.name.clone(),
            mac: MacAddr::new(mac.octets()),
            ipv4,
            ipv6,
        })
    }

    #[async_trait]
    impl LinkFactory for HostLinkFactory {
        fn interfaces(&self) -> Vec<LinkInterface> {
            pnet_datalink::interfaces()
                .iter()
                .filter(|iface| iface.is_up() && !iface.is_loopback() && iface.mac.is_some())
                .filter_map(to_interface)
                .collect()
        }

        async fn open(&self, interface: &LinkInterface) -> Result<Arc<dyn RawLink>, ScanError> {
            let interface = interface.clone();
            tokio::task::spawn_blocking(move || HostLink::open(interface))
                .await
                .map_err(|error| ScanError::io(format!("the raw channel task failed: {error}")))?
                .map(|link| Arc::new(link) as Arc<dyn RawLink>)
        }
    }

    /// A running `AF_PACKET` channel: a reader thread owns the socket, the methods talk to it
    /// over channels.
    #[derive(Debug)]
    pub struct HostLink {
        interface: LinkInterface,
        send_tx: Mutex<Option<mpsc::Sender<Vec<u8>>>>,
        recv_rx: tokio::sync::Mutex<tokio_mpsc::Receiver<Vec<u8>>>,
        stop: Arc<AtomicBool>,
        worker: Mutex<Option<JoinHandle<()>>>,
    }

    impl HostLink {
        fn open(interface: LinkInterface) -> Result<Self, ScanError> {
            let native = pnet_datalink::interfaces()
                .into_iter()
                .find(|iface| iface.name == interface.name)
                .ok_or_else(|| ScanError::io(format!("interface {} is gone", interface.name)))?;
            let config = Config {
                read_timeout: Some(READ_TIMEOUT),
                ..Config::default()
            };
            let (mut tx, mut rx) = match pnet_datalink::channel(&native, config) {
                Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
                Ok(_) => return Err(ScanError::io("the raw channel is not an Ethernet channel")),
                Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                    return Err(ScanError::unavailable(
                        "opening a raw socket needs CAP_NET_RAW",
                    ));
                }
                Err(error) => {
                    return Err(ScanError::io(format!("cannot open a raw socket: {error}")));
                }
            };
            let (send_tx, send_rx) = mpsc::channel::<Vec<u8>>();
            let (recv_tx, recv_rx) = tokio_mpsc::channel::<Vec<u8>>(RECV_CAPACITY);
            let stop = Arc::new(AtomicBool::new(false));
            let worker_stop = Arc::clone(&stop);
            let worker = std::thread::Builder::new()
                .name("tenko-raw-link".to_owned())
                .spawn(move || {
                    while !worker_stop.load(Ordering::Relaxed) {
                        while let Ok(frame) = send_rx.try_recv() {
                            // A frame that cannot be sent is lost; the method counts replies.
                            let _ = tx.send_to(&frame, None);
                        }
                        match rx.next() {
                            Ok(frame) => {
                                let _ = recv_tx.try_send(frame.to_vec());
                            }
                            Err(error)
                                if error.kind() == std::io::ErrorKind::TimedOut
                                    || error.kind() == std::io::ErrorKind::WouldBlock => {}
                            Err(_) => break,
                        }
                    }
                })
                .map_err(|error| ScanError::io(format!("cannot start the raw reader: {error}")))?;
            Ok(Self {
                interface,
                send_tx: Mutex::new(Some(send_tx)),
                recv_rx: tokio::sync::Mutex::new(recv_rx),
                stop,
                worker: Mutex::new(Some(worker)),
            })
        }
    }

    impl Drop for HostLink {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            // Drop the send side so the reader's queue closes.
            if let Ok(mut guard) = self.send_tx.lock() {
                guard.take();
            }
            if let Ok(mut guard) = self.worker.lock()
                && let Some(handle) = guard.take()
            {
                let _ = handle.join();
            }
        }
    }

    #[async_trait]
    impl RawLink for HostLink {
        fn interface(&self) -> &LinkInterface {
            &self.interface
        }

        async fn send(&self, frame: &[u8]) -> Result<(), ScanError> {
            let sender = {
                let guard = self
                    .send_tx
                    .lock()
                    .map_err(|_| ScanError::io("the raw channel is poisoned"))?;
                guard.clone()
            };
            sender
                .ok_or_else(|| ScanError::io("the raw channel is closed"))?
                .send(frame.to_vec())
                .map_err(|_| ScanError::io("the raw reader is gone"))
        }

        async fn recv(&self, timeout: Duration) -> Result<Option<Vec<u8>>, ScanError> {
            let mut rx = self.recv_rx.lock().await;
            // A closed channel and a timeout both mean no frame now.
            Ok(tokio::time::timeout(timeout, rx.recv())
                .await
                .ok()
                .flatten())
        }
    }
}

#[cfg(test)]
pub use mock::{MockLink, MockLinkFactory};

#[cfg(test)]
mod mock {
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
        time::Duration,
    };

    use async_trait::async_trait;
    use tenko_core::MacAddr;

    use super::{LinkFactory, LinkInterface, RawLink};
    use crate::error::ScanError;

    /// A link that records what the method sent and hands out received frames, so the
    /// senders and listeners are tested without a socket. Each frame carries a gate: it is
    /// handed out only once at least that many frames have been sent, so a reply follows
    /// its request (an ARP reply after the request, a SYN-ACK after the SYN).
    #[derive(Debug)]
    pub struct MockLink {
        interface: LinkInterface,
        sent: Mutex<Vec<Vec<u8>>>,
        incoming: Mutex<VecDeque<(usize, Vec<u8>)>>,
    }

    impl MockLink {
        /// A mock whose `incoming` frames are available at once (gate 0).
        pub fn new(incoming: Vec<Vec<u8>>) -> Self {
            Self::scripted(incoming.into_iter().map(|frame| (0, frame)).collect())
        }

        /// A mock whose frames are gated: `(gate, frame)` is handed out once `gate` frames
        /// have been sent.
        pub fn scripted(incoming: Vec<(usize, Vec<u8>)>) -> Self {
            Self {
                interface: default_interface(),
                sent: Mutex::new(Vec::new()),
                incoming: Mutex::new(incoming.into()),
            }
        }

        /// The frames the method sent, in order.
        ///
        /// # Panics
        ///
        /// Panics when the mock's lock is poisoned.
        pub fn sent(&self) -> Vec<Vec<u8>> {
            self.sent.lock().expect("lock").clone()
        }
    }

    /// The documentation interface used by the mock: MAC `00:00:5e:00:53:05`, IPv4
    /// `192.0.2.5`.
    pub fn default_interface() -> LinkInterface {
        LinkInterface {
            name: "test0".to_owned(),
            mac: MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, 0x05]),
            ipv4: Some(std::net::Ipv4Addr::new(192, 0, 2, 5)),
            ipv6: vec!["2001:db8::5".parse().expect("ipv6")],
        }
    }

    #[async_trait]
    impl RawLink for MockLink {
        fn interface(&self) -> &LinkInterface {
            &self.interface
        }

        async fn send(&self, frame: &[u8]) -> Result<(), ScanError> {
            self.sent.lock().expect("lock").push(frame.to_vec());
            Ok(())
        }

        async fn recv(&self, _timeout: Duration) -> Result<Option<Vec<u8>>, ScanError> {
            let sent = self.sent.lock().expect("lock").len();
            let mut incoming = self.incoming.lock().expect("lock");
            match incoming.front() {
                Some((gate, _)) if *gate <= sent => Ok(incoming.pop_front().map(|(_, f)| f)),
                _ => Ok(None),
            }
        }
    }

    /// A factory that opens [`MockLink`]s.
    #[derive(Debug)]
    pub struct MockLinkFactory {
        link: Mutex<Option<Arc<dyn RawLink>>>,
        interfaces: Vec<LinkInterface>,
    }

    impl MockLinkFactory {
        /// A factory that hands out `link` once.
        pub fn new(link: Arc<dyn RawLink>) -> Self {
            let interfaces = vec![link.interface().clone()];
            Self {
                link: Mutex::new(Some(link)),
                interfaces,
            }
        }
    }

    #[async_trait]
    impl LinkFactory for MockLinkFactory {
        fn interfaces(&self) -> Vec<LinkInterface> {
            self.interfaces.clone()
        }

        async fn open(&self, _interface: &LinkInterface) -> Result<Arc<dyn RawLink>, ScanError> {
            self.link
                .lock()
                .expect("lock")
                .clone()
                .ok_or_else(|| ScanError::io("the mock link was already opened"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iface(name: &str, ipv4: Option<Ipv4Addr>) -> LinkInterface {
        LinkInterface {
            name: name.to_owned(),
            mac: MacAddr::new([0, 0, 0x5e, 0, 0x53, 1]),
            ipv4,
            ipv6: Vec::new(),
        }
    }

    #[test]
    fn the_override_wins_then_the_matching_network_then_the_first() {
        let interfaces = vec![
            iface("eth0", Some(Ipv4Addr::new(10, 0, 0, 1))),
            iface("eth1", Some(Ipv4Addr::new(192, 0, 2, 5))),
        ];
        assert_eq!(
            choose_interface(&interfaces, Some("eth1"), None)
                .unwrap()
                .name,
            "eth1"
        );
        assert_eq!(
            choose_interface(&interfaces, None, Some(Ipv4Addr::new(192, 0, 2, 9)))
                .unwrap()
                .name,
            "eth1"
        );
        assert_eq!(
            choose_interface(&interfaces, None, None).unwrap().name,
            "eth0"
        );
        assert!(choose_interface(&interfaces, Some("absent"), None).is_none());
    }
}
