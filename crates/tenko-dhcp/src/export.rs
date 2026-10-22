//! Exports of the DHCP configuration and its leases for another server (MIG-16, decisions
//! P3-Q10 and P3-Q17): leaving Tenko is never blocked by a format only Tenko reads.
//!
//! | Module | What |
//! |---|---|
//! | [`kea`] | Kea 2.6: the `Dhcp4` configuration, the memfile lease file, a `DhcpDdns` skeleton and the loss report |
//!
//! The DHCPv6 half (`Dhcp6`) follows with the DHCPv6 server (WP9.1). `docs/dhcp.md`
//! section 18 describes the export.

pub mod kea;
