//! DHCP service: DHCPv4 and DHCPv6, failover, relay agent handling, and dynamic DNS updates.
//!
//! Today the crate holds the DHCPv4 wire codec ([`v4`]): a view over a received message
//! with typed options (RFC 2131, RFC 2132 and the option RFCs the server needs) and a
//! builder that writes a reply into a caller's buffer. Neither allocates. The server, the
//! lease store and DHCPv6 land in later Phase 3 packages (see `docs/ROADMAP.md`);
//! `docs/dhcp.md` section 1 describes the wire format.

pub mod v4;

/// Name of this crate as declared in its manifest.
pub const CRATE_NAME: &str = "tenko-dhcp";

/// Returns the version of this crate as declared in its manifest.
pub const fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_matches_manifest() {
        assert_eq!(CRATE_NAME, env!("CARGO_PKG_NAME"));
        assert!(version().starts_with(|c: char| c.is_ascii_digit()));
    }
}
