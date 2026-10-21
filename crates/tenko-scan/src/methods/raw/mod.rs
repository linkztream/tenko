//! The raw-socket methods (WP3.14): `arp_sweep`, `tcp_syn`, `os_fingerprint`, passive
//! `lldp` (with CDP) and `dhcp_snoop`. They send and listen at the link layer through one
//! safe Ethernet channel ([`link`]); the frame parsers and builders are in
//! [`crate::frame`]. On Linux they need `CAP_NET_RAW`; on Windows they answer `unsupported`
//! because raw sockets need Npcap, which Tenko does not bundle (docs/scanning.md section
//! 9). Every method honours the shared rate limiter and the kill switch, and none blocks
//! the scheduler's other methods.

pub mod arp;
pub mod dhcp_snoop;
pub mod fingerprint;
pub mod link;
pub mod lldp;
pub mod syn;

use std::{net::Ipv4Addr, sync::Arc};

use ipnet::IpNet;

pub use arp::ArpSweep;
pub use dhcp_snoop::DhcpSnoop;
pub use lldp::LldpListen;
pub use syn::{OsFingerprintScan, TcpSynScan};

use crate::{capability::Capabilities, error::ScanError, method::Availability, scope::Scope};
use link::{LinkFactory, LinkInterface, RawLink, choose_interface};

/// Whether this host can run the raw-socket methods, and how to open a channel when it
/// can. The methods hold this instead of a channel, so the socket opens at run time.
#[derive(Clone)]
pub struct RawSupport {
    factory: Option<Arc<dyn LinkFactory>>,
    reason: String,
}

impl std::fmt::Debug for RawSupport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawSupport")
            .field("capable", &self.factory.is_some())
            .field("reason", &self.reason)
            .finish()
    }
}

impl RawSupport {
    /// Detects support from the host's capabilities. On Linux a channel opens when
    /// `CAP_NET_RAW` is present; on Windows the methods are always unsupported.
    pub fn detect(capabilities: &Capabilities) -> Self {
        #[cfg(target_os = "linux")]
        {
            if capabilities.raw_sockets {
                Self {
                    factory: Some(Arc::new(link::HostLinkFactory)),
                    reason: String::new(),
                }
            } else {
                Self {
                    factory: None,
                    reason: format!("needs raw sockets: {}", capabilities.raw_detail),
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = capabilities;
            Self {
                factory: None,
                reason: "raw sockets need Npcap, which Tenko does not bundle \
                         (docs/scanning.md section 9)"
                    .to_owned(),
            }
        }
    }

    /// A support backed by a test factory.
    #[cfg(test)]
    pub fn mock(factory: Arc<dyn LinkFactory>) -> Self {
        Self {
            factory: Some(factory),
            reason: String::new(),
        }
    }

    /// Whether a channel can be opened.
    fn availability(&self) -> Availability {
        if self.factory.is_some() {
            Availability::Ready
        } else {
            Availability::Unavailable(self.reason.clone())
        }
    }

    /// Opens a channel on the interface chosen for `scope`, honouring the `override_name`.
    async fn open(
        &self,
        scope: &Scope,
        override_name: Option<&str>,
    ) -> Result<Arc<dyn RawLink>, ScanError> {
        let factory = self
            .factory
            .as_ref()
            .ok_or_else(|| ScanError::unavailable(self.reason.clone()))?;
        let interfaces = factory.interfaces();
        if interfaces.is_empty() {
            return Err(ScanError::io(
                "no usable network interface for a raw socket",
            ));
        }
        // Without an override, the interface whose own address lies in the scope wins; the
        // coarse network match of `choose_interface` is the fallback.
        let in_scope = override_name
            .is_none()
            .then(|| {
                interfaces
                    .iter()
                    .find(|i| {
                        i.ipv4
                            .is_some_and(|ip| scope.contains(std::net::IpAddr::V4(ip)))
                    })
                    .cloned()
            })
            .flatten();
        let interface = in_scope
            .or_else(|| choose_interface(&interfaces, override_name, scope_ipv4(scope)))
            .ok_or_else(|| match override_name {
                Some(name) => ScanError::config(format!("scan: interface `{name}` was not found")),
                None => ScanError::io("no interface matched the scope for a raw socket"),
            })?;
        factory.open(&interface).await
    }
}

/// The first IPv4 address of the scope's prefixes, to prefer the interface on that segment.
fn scope_ipv4(scope: &Scope) -> Option<Ipv4Addr> {
    scope.prefixes().iter().find_map(|net| match net {
        IpNet::V4(v4) => Some(v4.addr()),
        IpNet::V6(_) => None,
    })
}

/// The source addresses a method builds its frames from: the interface's MAC and IPv4.
/// Returns an error when the interface has no IPv4 address, which the active methods need.
fn source_ipv4(interface: &LinkInterface) -> Result<Ipv4Addr, ScanError> {
    interface.ipv4.ok_or_else(|| {
        ScanError::io(format!(
            "interface {} has no IPv4 address for the sweep",
            interface.name
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::IcmpSupport;

    fn unsupported() -> Capabilities {
        Capabilities {
            raw_sockets: false,
            raw_detail: "CAP_NET_RAW is missing".to_owned(),
            icmp: IcmpSupport::PingCommand,
        }
    }

    #[test]
    fn without_the_capability_every_method_says_why() {
        let support = RawSupport::detect(&unsupported());
        let Availability::Unavailable(reason) = support.availability() else {
            panic!("a method without the capability is not ready");
        };
        if cfg!(target_os = "linux") {
            assert!(reason.contains("CAP_NET_RAW"), "{reason}");
        } else {
            assert!(reason.contains("Npcap"), "{reason}");
        }
    }
}
