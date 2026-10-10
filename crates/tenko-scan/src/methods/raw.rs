//! The methods that need raw sockets: `arp_sweep`, `tcp_syn`, `os_fingerprint` and `lldp`.
//! They are declared so the scheduler, the status and the configuration know them, and
//! they stay unavailable until a later package implements them. The status still shows
//! whether this host could run them (`CAP_NET_RAW` on Linux, Npcap on Windows).

use async_trait::async_trait;

use crate::{
    capability::Capabilities,
    error::ScanError,
    method::{Availability, Method, MethodKind, MethodOutput, RunContext},
};

/// A declared raw-socket method.
#[derive(Debug, Clone)]
pub struct RawSocketMethod {
    kind: MethodKind,
    capable: bool,
    detail: String,
}

impl RawSocketMethod {
    /// The method `kind` on a host with `capabilities`.
    pub fn new(kind: MethodKind, capabilities: &Capabilities) -> Self {
        Self {
            kind,
            capable: capabilities.raw_sockets,
            detail: capabilities.raw_detail.clone(),
        }
    }
}

#[async_trait]
impl Method for RawSocketMethod {
    fn kind(&self) -> MethodKind {
        self.kind
    }

    fn availability(&self) -> Availability {
        let host = if self.capable {
            "this host has raw sockets"
        } else {
            self.detail.as_str()
        };
        Availability::Unavailable(format!(
            "needs raw sockets and is not implemented yet ({host})"
        ))
    }

    async fn run(&self, _ctx: &RunContext) -> Result<MethodOutput, ScanError> {
        Err(ScanError::unavailable(format!(
            "{} needs raw sockets and is not implemented yet",
            self.kind
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::IcmpSupport;

    #[test]
    fn raw_methods_say_why_they_do_not_run() {
        let capabilities = Capabilities {
            raw_sockets: false,
            raw_detail: "CAP_NET_RAW is missing".to_owned(),
            icmp: IcmpSupport::PingCommand,
        };
        let method = RawSocketMethod::new(MethodKind::TcpSyn, &capabilities);
        let Availability::Unavailable(reason) = method.availability() else {
            panic!("a raw method is never ready yet");
        };
        assert!(reason.contains("CAP_NET_RAW is missing"), "{reason}");
    }
}
