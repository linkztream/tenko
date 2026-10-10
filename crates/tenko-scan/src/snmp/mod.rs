//! SNMPv3 polling of switches (SCAN-05).
//!
//! A switch knows which MAC address sits behind which port, which neighbours it has and
//! which addresses it has resolved. [`poll`] reads those tables over SNMPv3 with the
//! user-based security model and returns them as one [`DeviceTables`]; nothing is scanned.
//!
//! | Module | Contents |
//! |---|---|
//! | [`ber`] | BER encoding and decoding, object identifiers, values |
//! | [`message`] | the SNMPv3 message and its PDUs (RFC 3412) |
//! | [`usm`] | keys, authentication and privacy of the user-based model (RFC 3414, 3826, 7860) |
//! | [`client`] | the UDP client: engine discovery, `get`, `walk` |
//!
//! Supported security: no authentication, HMAC-SHA-1-96 and HMAC-SHA-2 (RFC 7860)
//! authentication, and AES-128-CFB privacy. MD5 and DES are not supported and a device
//! that only offers them is refused with a clear error.

pub mod ber;
pub mod client;
pub mod message;
pub(crate) mod mib;
pub mod usm;

#[cfg(test)]
pub(crate) mod testing;
#[cfg(test)]
mod tests;

use std::{collections::BTreeMap, fmt, net::IpAddr, net::SocketAddr, str::FromStr, time::Duration};

use serde::{Deserialize, Serialize};
use tenko_core::MacAddr;
use zeroize::Zeroizing;

use crate::{error::ScanError, limit::Pacer, method::Cancel};

pub use ber::{Oid, Value, VarBind};
pub use client::{Client, Walk};

/// The authentication protocol of a user (RFC 3414, RFC 7860).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthProtocol {
    /// HMAC-SHA-1-96 (RFC 3414); 12 octets of digest.
    Sha1,
    /// HMAC-SHA-224 (RFC 7860); 16 octets.
    Sha224,
    /// HMAC-SHA-256 (RFC 7860); 24 octets.
    Sha256,
    /// HMAC-SHA-384 (RFC 7860); 32 octets.
    Sha384,
    /// HMAC-SHA-512 (RFC 7860); 48 octets.
    Sha512,
}

impl AuthProtocol {
    /// Every supported protocol.
    pub const ALL: [AuthProtocol; 5] = [
        AuthProtocol::Sha1,
        AuthProtocol::Sha224,
        AuthProtocol::Sha256,
        AuthProtocol::Sha384,
        AuthProtocol::Sha512,
    ];

    /// The name in the configuration.
    pub const fn name(self) -> &'static str {
        match self {
            AuthProtocol::Sha1 => "sha1",
            AuthProtocol::Sha224 => "sha224",
            AuthProtocol::Sha256 => "sha256",
            AuthProtocol::Sha384 => "sha384",
            AuthProtocol::Sha512 => "sha512",
        }
    }
}

impl fmt::Display for AuthProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for AuthProtocol {
    type Err = ScanError;

    /// Parses the name of a protocol, ignoring case, hyphens and underscores
    /// (`SHA-256`, `sha_256` and `sha256` are the same). MD5 gets a message of its own.
    fn from_str(text: &str) -> Result<Self, ScanError> {
        let key: String = text
            .chars()
            .filter(|c| *c != '-' && *c != '_' && !c.is_whitespace())
            .collect::<String>()
            .to_ascii_lowercase();
        match key.as_str() {
            "sha" | "sha1" | "hmacsha1" | "hmacsha96" => Ok(AuthProtocol::Sha1),
            "sha224" | "hmacsha224" => Ok(AuthProtocol::Sha224),
            "sha256" | "hmacsha256" => Ok(AuthProtocol::Sha256),
            "sha384" | "hmacsha384" => Ok(AuthProtocol::Sha384),
            "sha512" | "hmacsha512" => Ok(AuthProtocol::Sha512),
            "md5" | "hmacmd5" | "hmacmd596" => Err(ScanError::config(
                "MD5 authentication is not supported; use sha1, sha224, sha256, sha384 or sha512",
            )),
            _ => Err(ScanError::config(format!(
                "unknown SNMP authentication protocol {text:?}; use sha1, sha224, sha256, sha384 or sha512"
            ))),
        }
    }
}

/// The privacy protocol of a user (RFC 3826).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivProtocol {
    /// AES-128 in CFB mode with a 128-bit feedback.
    Aes128,
}

impl PrivProtocol {
    /// The name in the configuration.
    pub const fn name(self) -> &'static str {
        match self {
            PrivProtocol::Aes128 => "aes128",
        }
    }
}

impl fmt::Display for PrivProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for PrivProtocol {
    type Err = ScanError;

    /// Parses the name of a protocol, ignoring case, hyphens and underscores. DES and
    /// the AES variants other than AES-128 get messages of their own.
    fn from_str(text: &str) -> Result<Self, ScanError> {
        let key: String = text
            .chars()
            .filter(|c| *c != '-' && *c != '_' && !c.is_whitespace())
            .collect::<String>()
            .to_ascii_lowercase();
        match key.as_str() {
            "aes" | "aes128" | "cfbaes128" => Ok(PrivProtocol::Aes128),
            "des" | "cbcdes" | "3des" | "des3" | "3desede" | "cbc3desede" => Err(
                ScanError::config("DES and 3DES privacy are not supported; use aes128"),
            ),
            "aes192" | "aes256" => Err(ScanError::config(
                "only AES-128 privacy is supported; use aes128",
            )),
            _ => Err(ScanError::config(format!(
                "unknown SNMP privacy protocol {text:?}; use aes128"
            ))),
        }
    }
}

/// The credentials of an SNMPv3 user.
///
/// Privacy requires authentication (RFC 3414). Passwords are at least eight characters.
/// `Debug` shows the user and the protocols and never a password.
#[derive(Clone)]
pub struct Credentials {
    /// The user name (`msgUserName`), at most 32 octets.
    pub user: String,
    /// The authentication protocol and password; `None` for no authentication.
    pub auth: Option<(AuthProtocol, Zeroizing<String>)>,
    /// The privacy protocol and password; `None` for no privacy.
    pub privacy: Option<(PrivProtocol, Zeroizing<String>)>,
    /// The context name; empty is the default context.
    pub context: String,
}

impl Credentials {
    /// A user without authentication and privacy.
    pub fn no_auth(user: impl Into<String>) -> Self {
        Self {
            user: user.into(),
            auth: None,
            privacy: None,
            context: String::new(),
        }
    }

    /// A user with authentication and without privacy.
    pub fn auth_no_priv(
        user: impl Into<String>,
        protocol: AuthProtocol,
        password: impl Into<String>,
    ) -> Self {
        Self {
            auth: Some((protocol, Zeroizing::new(password.into()))),
            ..Self::no_auth(user)
        }
    }

    /// A user with authentication and privacy.
    pub fn auth_priv(
        user: impl Into<String>,
        auth_protocol: AuthProtocol,
        auth_password: impl Into<String>,
        priv_protocol: PrivProtocol,
        priv_password: impl Into<String>,
    ) -> Self {
        Self {
            privacy: Some((priv_protocol, Zeroizing::new(priv_password.into()))),
            ..Self::auth_no_priv(user, auth_protocol, auth_password)
        }
    }

    /// The same credentials for another context.
    #[must_use]
    pub fn with_context(mut self, context: impl Into<String>) -> Self {
        self.context = context.into();
        self
    }

    /// Checks the credentials without sending anything. The messages never contain a
    /// password.
    ///
    /// # Errors
    /// `scan.config`: privacy without authentication, a password shorter than eight
    /// characters, a user name over 32 octets or a context name over 255 octets.
    pub fn validate(&self) -> Result<(), ScanError> {
        if self.user.len() > 32 {
            return Err(ScanError::config(
                "the SNMP user name is longer than 32 octets",
            ));
        }
        if self.context.len() > 255 {
            return Err(ScanError::config(
                "the SNMP context name is longer than 255 octets",
            ));
        }
        if self.privacy.is_some() && self.auth.is_none() {
            return Err(ScanError::config(
                "SNMP privacy requires authentication (RFC 3414)",
            ));
        }
        if self.auth.is_some() && self.user.is_empty() {
            return Err(ScanError::config(
                "an SNMP user with authentication needs a user name",
            ));
        }
        if let Some((_, password)) = &self.auth {
            usm::check_password(password).map_err(|error| {
                ScanError::config(format!("the SNMP authentication password: {error}"))
            })?;
        }
        if let Some((_, password)) = &self.privacy {
            usm::check_password(password).map_err(|error| {
                ScanError::config(format!("the SNMP privacy password: {error}"))
            })?;
        }
        Ok(())
    }
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("user", &self.user)
            .field("auth", &self.auth.as_ref().map(|(protocol, _)| protocol))
            .field(
                "privacy",
                &self.privacy.as_ref().map(|(protocol, _)| protocol),
            )
            .field("context", &self.context)
            .finish()
    }
}

/// How a poll talks to the device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PollOptions {
    /// How long to wait for the answer to one datagram.
    pub timeout: Duration,
    /// How many times a datagram is sent again when no answer comes.
    pub retries: u32,
    /// `max-repetitions` of a `GetBulk` request.
    pub max_repetitions: u32,
    /// The most rows of one table walk; a longer table is cut and the result marked
    /// truncated.
    pub max_rows: usize,
}

impl Default for PollOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(2),
            retries: 2,
            max_repetitions: 20,
            max_rows: 20_000,
        }
    }
}

/// An interface of the device (`ifTable`, `ifXTable`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Interface {
    /// `ifName`.
    pub name: Option<String>,
    /// `ifDescr`.
    pub descr: Option<String>,
    /// `ifAlias`, the description an administrator gave the port.
    pub alias: Option<String>,
    /// `ifPhysAddress`; `None` when empty or all zero.
    pub mac: Option<MacAddr>,
}

/// An entry of the ARP or neighbour table of the device.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ArpEntry {
    /// The interface the entry was learned on.
    pub if_index: u32,
    /// The IPv4 or IPv6 address.
    pub ip: IpAddr,
    /// Its MAC address.
    pub mac: MacAddr,
}

/// An entry of the forwarding database of a bridge.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FdbEntry {
    /// The MAC address.
    pub mac: MacAddr,
    /// The VLAN (the filtering database id of the Q-BRIDGE table when it is 1 to 4094);
    /// `None` for the VLAN-unaware table.
    pub vlan: Option<u16>,
    /// The bridge port the address was learned on.
    pub bridge_port: u32,
    /// The interface of that port, when the base port table maps it.
    pub if_index: Option<u32>,
}

/// A neighbour announced through LLDP.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LldpNeighbour {
    /// The local port: the port id of `lldpLocPortTable`, or its description when the
    /// id is a MAC or network address.
    pub local_port: Option<String>,
    /// The chassis id of the neighbour, formatted by its subtype.
    pub remote_chassis: Option<String>,
    /// The port id of the neighbour, formatted by its subtype.
    pub remote_port: Option<String>,
    /// The port description of the neighbour.
    pub remote_port_desc: Option<String>,
    /// The system name of the neighbour.
    pub remote_sys_name: Option<String>,
}

/// What a poll of one device returned.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DeviceTables {
    /// `sysDescr`.
    pub sys_descr: Option<String>,
    /// `sysName`.
    pub sys_name: Option<String>,
    /// `sysObjectID`, dotted.
    pub sys_object_id: Option<String>,
    /// The interfaces by `ifIndex`.
    pub interfaces: BTreeMap<u32, Interface>,
    /// The ARP and neighbour entries, sorted, without duplicates.
    pub arp: Vec<ArpEntry>,
    /// The forwarding database, sorted, without duplicates.
    pub fdb: Vec<FdbEntry>,
    /// The LLDP neighbours, in table order.
    pub lldp: Vec<LldpNeighbour>,
    /// A walk hit [`PollOptions::max_rows`] and some table is cut.
    pub truncated: bool,
    /// One line for every table that could not be read completely.
    pub failures: Vec<String>,
}

/// Reads the tables of the device at `target` over SNMPv3.
///
/// Every datagram takes a permit of `pacer` first and `cancel` stops the poll between
/// datagrams. A table that the device does not have is empty; a table that fails
/// part-way adds a line to [`DeviceTables::failures`] and keeps the rows read so far.
///
/// # Errors
/// `scan.config` for unusable credentials; `scan.snmp.timeout` when the device does not
/// answer discovery; `scan.snmp.auth` when it refuses the user (also later, mid-poll);
/// `scan.snmp.protocol` for answers that break the protocol; `scan.io` for socket errors;
/// `scan.cancelled` when `cancel` fires.
pub async fn poll(
    target: SocketAddr,
    credentials: &Credentials,
    options: &PollOptions,
    pacer: &Pacer,
    cancel: &Cancel,
) -> Result<DeviceTables, ScanError> {
    let mut client = Client::connect(target, credentials, options, pacer, cancel).await?;
    client.discover().await?;
    mib::read_tables(&mut client, options).await
}
