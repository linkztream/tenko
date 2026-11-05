//! The envelope a mirrored source pushes (`docs/plans/windows-takeover-plan.md` sections
//! 2.1 and 3.1, ADR 0033; MIG-01, MIG-08).
//!
//! A mirrored source is pushed to, never polled: a scheduled exporter on the source's own
//! host (the Windows DHCP exporter of `deploy/windows/mirror/` first) turns what it reads
//! into the source-neutral [`DhcpIr`] and a [`LossReport`] and sends them as one
//! [`MirrorSnapshot`] to `PUT /migrate/mirrors/{id}/snapshot`. The envelope is strict: an
//! unknown field, a value that does not parse or a bound that is passed refuses the whole
//! push with the path of the first error (422 `migrate.mirror.invalid`), and nothing of a
//! refused push is stored. The fixture `tests/fixtures/mirror/snapshot.json` is the
//! contract between the exporter and this crate: its field names are the envelope's.
//!
//! The bounds of section 2.1 live here so that the push route, the exporter's tests and
//! the fixture agree: a body of at most [`MAX_BODY_BYTES`] (gzip allowed,
//! [`MAX_INFLATED_BYTES`] inflated), at most [`MAX_SCOPES`] scopes, [`MAX_RESERVATIONS`]
//! reservations and [`MAX_LEASES`] leases.

use std::{borrow::Cow, collections::BTreeMap, fmt, str::FromStr};

use ipnet::IpNet;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use utoipa::{
    PartialSchema, ToSchema,
    openapi::{ObjectBuilder, RefOr, Schema, Type},
};

use super::{
    LossReport,
    dhcp::{DhcpIr, IrClientId, IrLeaseState, IrOption, IrRange},
};
use crate::{Coded, codec::key::KeyCodec, error::InvalidValue, timestamp::Timestamp};

/// The envelope format this build reads and writes.
pub const FORMAT: u16 = 1;

/// The largest push body on the wire, compressed or not: 8 MiB.
pub const MAX_BODY_BYTES: usize = 8 << 20;

/// The largest push body after inflating a gzip body: 32 MiB.
pub const MAX_INFLATED_BYTES: usize = 32 << 20;

/// The most scopes one snapshot carries.
pub const MAX_SCOPES: usize = 1_000;

/// The most reservations one snapshot carries, over every scope.
pub const MAX_RESERVATIONS: usize = 10_000;

/// The most leases one snapshot carries.
pub const MAX_LEASES: usize = 100_000;

/// The most loss entries one snapshot carries.
pub const MAX_LOSSES: usize = 10_000;

/// The longest server name the origin may carry (a DNS name, RFC 1035).
pub const MAX_SERVER_LEN: usize = 253;

/// The longest adapter name and adapter version.
pub const MAX_ADAPTER_LEN: usize = 64;

/// The longest host name a lease may carry (Windows stores up to 255 characters).
pub const MAX_HOSTNAME_LEN: usize = 255;

/// The longest text form of one option value.
pub const MAX_OPTION_VALUE_LEN: usize = 4_096;

/// The longest detail of a loss entry.
pub const MAX_LOSS_DETAIL_LEN: usize = 4_096;

/// The longest label of a source kind.
pub const MAX_KIND_LEN: usize = 32;

/// The label of a source kind: `[a-z0-9-]{1,32}`, never an enumeration of products, so that
/// an exporter for any server can push the same IR under its own label (`windows-dhcp` for
/// the exporter of `deploy/windows/mirror/`).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourceKindLabel(String);

impl SourceKindLabel {
    /// The label of the Windows DHCP exporter.
    pub const WINDOWS_DHCP: &'static str = "windows-dhcp";

    /// Validates a label.
    ///
    /// # Errors
    ///
    /// [`InvalidValue`] when the label is empty, longer than [`MAX_KIND_LEN`] or holds a
    /// character outside `a-z`, `0-9` and `-`.
    pub fn new(label: &str) -> Result<Self, InvalidValue> {
        if label.is_empty() || label.len() > MAX_KIND_LEN {
            return Err(InvalidValue::new(
                "source kind",
                label,
                "1 to 32 characters",
            ));
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(InvalidValue::new(
                "source kind",
                label,
                "lowercase letters, digits and hyphens only",
            ));
        }
        Ok(Self(label.to_owned()))
    }

    /// The label.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SourceKindLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SourceKindLabel({:?})", self.0)
    }
}

impl fmt::Display for SourceKindLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for SourceKindLabel {
    type Err = InvalidValue;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl Serialize for SourceKindLabel {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SourceKindLabel {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::new(&text).map_err(serde::de::Error::custom)
    }
}

impl PartialSchema for SourceKindLabel {
    fn schema() -> RefOr<Schema> {
        RefOr::T(Schema::Object(
            ObjectBuilder::new()
                .schema_type(Type::String)
                .description(Some(
                    "The label of a source kind: lowercase letters, digits and hyphens, 1 to \
                     32 characters (windows-dhcp)",
                ))
                .pattern(Some("^[a-z0-9-]{1,32}$"))
                .build(),
        ))
    }
}

impl ToSchema for SourceKindLabel {}

impl KeyCodec for SourceKindLabel {
    fn encode_key(&self, out: &mut Vec<u8>) {
        self.0.encode_key(out);
    }
    fn decode_key(input: &mut &[u8]) -> Result<Self, crate::codec::key::KeyError> {
        let text = String::decode_key(input)?;
        Self::new(&text).map_err(|_| crate::codec::key::KeyError::Invalid("source kind"))
    }
}

/// Where a snapshot comes from: the kind of source, the server it was read from and the
/// adapter that produced it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct MirrorOrigin {
    /// The kind of source (`windows-dhcp`).
    pub kind: SourceKindLabel,
    /// The server the adapter read, as it names itself (a host name).
    pub server: String,
    /// The adapter's name (`Tenko-DhcpMirror.ps1`).
    pub adapter: String,
    /// The adapter's version.
    pub adapter_version: String,
}

/// One push of a mirrored source: the IR of the whole source at `taken_at`, with the loss
/// report of what the adapter could not map (plan section 3.1).
///
/// `sequence` increases strictly from push to push of one mirror; an older or equal one is
/// a replay (409 `migrate.mirror.sequence`). `taken_at` is the source host's clock when the
/// data was read: a lease's remaining time is computed against it, so clock skew between the
/// source and the node shortens or lengthens no lease.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct MirrorSnapshot {
    /// The envelope format; this build reads [`FORMAT`].
    pub format: u16,
    /// The push sequence, from 1, strictly increasing per mirror.
    pub sequence: u64,
    /// When the adapter read the source, by the source host's clock, in UTC.
    pub taken_at: Timestamp,
    /// Where the snapshot comes from.
    pub source: MirrorOrigin,
    /// The DHCP content of the source.
    pub dhcp: DhcpIr,
    /// What the adapter could not map.
    pub losses: LossReport,
}

/// Why a snapshot was refused: the path of the first field that does not validate, in
/// the envelope's JSON (`dhcp.scopes[0].ranges[1].last`), and the reason (422
/// `migrate.mirror.invalid`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotInvalid {
    /// The path of the first error.
    pub path: String,
    /// The reason, in English.
    pub reason: Cow<'static, str>,
}

impl SnapshotInvalid {
    fn new(path: impl Into<String>, reason: impl Into<Cow<'static, str>>) -> Self {
        Self {
            path: path.into(),
            reason: reason.into(),
        }
    }
}

impl fmt::Display for SnapshotInvalid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the snapshot is invalid at {}: {}",
            self.path, self.reason
        )
    }
}

impl std::error::Error for SnapshotInvalid {}

impl Coded for SnapshotInvalid {
    fn code(&self) -> &'static str {
        crate::migrate::codes::MIRROR_INVALID
    }

    fn http_status(&self) -> u16 {
        422
    }

    fn params(&self) -> BTreeMap<&'static str, String> {
        BTreeMap::from([
            ("path", self.path.clone()),
            ("reason", self.reason.to_string()),
        ])
    }

    fn title(&self) -> &'static str {
        "Invalid snapshot"
    }
}

/// Whether `text` is one line of printable text (no control character).
fn is_plain(text: &str) -> bool {
    !text.chars().any(char::is_control)
}

fn check_text(
    path: &str,
    text: &str,
    max: usize,
    what: &'static str,
) -> Result<(), SnapshotInvalid> {
    if text.is_empty() {
        return Err(SnapshotInvalid::new(path, format!("{what} is empty")));
    }
    if text.chars().count() > max {
        return Err(SnapshotInvalid::new(
            path,
            format!("{what} is longer than {max} characters"),
        ));
    }
    if !is_plain(text) {
        return Err(SnapshotInvalid::new(
            path,
            format!("{what} holds a control character"),
        ));
    }
    Ok(())
}

fn check_client(path: &str, client: &IrClientId) -> Result<(), SnapshotInvalid> {
    match (&client.mac, &client.client_id) {
        (None, None) => Err(SnapshotInvalid::new(
            path,
            "a client needs a MAC address or a client identifier",
        )),
        (_, Some(id)) if id.0.is_empty() => Err(SnapshotInvalid::new(
            format!("{path}.client_id"),
            "a client identifier is not empty",
        )),
        (_, Some(id)) if id.0.len() > crate::dhcp::lease::MAX_CLIENT_ID => {
            Err(SnapshotInvalid::new(
                format!("{path}.client_id"),
                "a client identifier has at most 255 octets",
            ))
        }
        _ => Ok(()),
    }
}

fn check_options(path: &str, options: &[IrOption]) -> Result<(), SnapshotInvalid> {
    for (index, option) in options.iter().enumerate() {
        let path = format!("{path}[{index}]");
        if option.code == 0 || option.code > 254 {
            return Err(SnapshotInvalid::new(
                format!("{path}.code"),
                "an option code is 1 to 254",
            ));
        }
        if option.values.is_empty() {
            return Err(SnapshotInvalid::new(
                format!("{path}.values"),
                "an option carries at least one value",
            ));
        }
        for (position, value) in option.values.iter().enumerate() {
            if value.chars().count() > MAX_OPTION_VALUE_LEN {
                return Err(SnapshotInvalid::new(
                    format!("{path}.values[{position}]"),
                    "an option value is at most 4,096 characters",
                ));
            }
        }
    }
    Ok(())
}

fn check_range(path: &str, range: &IrRange, scope: &IpNet) -> Result<(), SnapshotInvalid> {
    if !scope.contains(&range.first) || !scope.contains(&range.last) {
        return Err(SnapshotInvalid::new(path, "the range is outside the scope"));
    }
    if range.first > range.last {
        return Err(SnapshotInvalid::new(
            path,
            "the first address is after the last",
        ));
    }
    Ok(())
}

impl MirrorSnapshot {
    /// Checks the envelope beyond what parsing checks: the format, the sequence, the bounds
    /// of section 2.1, the texts of the origin, and the content of the IR (scopes that are
    /// networks named once, ranges and exclusions inside their scope, reservations and
    /// leases inside their scope with a client identity, leases of a scope the snapshot
    /// holds in a state the mirror carries, options with a code and a value, superscopes,
    /// policies and failover relationships that name scopes the snapshot holds, bounded
    /// loss entries). Values that have a Tenko type (addresses, networks, MAC addresses,
    /// host names, times) were checked when they parsed.
    ///
    /// # Errors
    ///
    /// [`SnapshotInvalid`] with the path of the first error.
    #[allow(
        clippy::too_many_lines,
        reason = "one rule per field, read top to bottom"
    )]
    pub fn validate(&self) -> Result<(), SnapshotInvalid> {
        if self.format != FORMAT {
            return Err(SnapshotInvalid::new(
                "format",
                format!("unsupported envelope format; this build reads {FORMAT}"),
            ));
        }
        if self.sequence == 0 {
            return Err(SnapshotInvalid::new("sequence", "the sequence starts at 1"));
        }
        check_text(
            "source.server",
            &self.source.server,
            MAX_SERVER_LEN,
            "the server name",
        )?;
        check_text(
            "source.adapter",
            &self.source.adapter,
            MAX_ADAPTER_LEN,
            "the adapter name",
        )?;
        check_text(
            "source.adapter_version",
            &self.source.adapter_version,
            MAX_ADAPTER_LEN,
            "the adapter version",
        )?;

        let dhcp = &self.dhcp;
        if dhcp.scopes.len() > MAX_SCOPES {
            return Err(SnapshotInvalid::new(
                "dhcp.scopes",
                format!("more than {MAX_SCOPES} scopes"),
            ));
        }
        check_options("dhcp.server_options", &dhcp.server_options)?;
        for (index, def) in dhcp.option_defs.iter().enumerate() {
            if def.code == 0 || def.code > 254 {
                return Err(SnapshotInvalid::new(
                    format!("dhcp.option_defs[{index}].code"),
                    "an option code is 1 to 254",
                ));
            }
            check_text(
                &format!("dhcp.option_defs[{index}].name"),
                &def.name,
                MAX_OPTION_VALUE_LEN,
                "the name",
            )?;
        }
        for (index, class) in dhcp.classes.iter().enumerate() {
            check_text(
                &format!("dhcp.classes[{index}].name"),
                &class.name,
                MAX_OPTION_VALUE_LEN,
                "the name",
            )?;
        }

        let mut scopes: BTreeMap<IpNet, usize> = BTreeMap::new();
        let mut reservations = 0usize;
        for (index, scope) in dhcp.scopes.iter().enumerate() {
            let path = format!("dhcp.scopes[{index}]");
            if scope.cidr.trunc() != scope.cidr {
                return Err(SnapshotInvalid::new(
                    format!("{path}.cidr"),
                    "the scope is not a network address",
                ));
            }
            if scopes.insert(scope.cidr, index).is_some() {
                return Err(SnapshotInvalid::new(
                    format!("{path}.cidr"),
                    "the scope appears twice",
                ));
            }
            for (position, range) in scope.ranges.iter().enumerate() {
                check_range(&format!("{path}.ranges[{position}]"), range, &scope.cidr)?;
            }
            for (position, range) in scope.exclusions.iter().enumerate() {
                check_range(
                    &format!("{path}.exclusions[{position}]"),
                    range,
                    &scope.cidr,
                )?;
            }
            check_options(&format!("{path}.options"), &scope.options)?;
            reservations += scope.reservations.len();
            if reservations > MAX_RESERVATIONS {
                return Err(SnapshotInvalid::new(
                    format!("{path}.reservations"),
                    format!("more than {MAX_RESERVATIONS} reservations in the snapshot"),
                ));
            }
            let mut addresses = BTreeMap::new();
            for (position, reservation) in scope.reservations.iter().enumerate() {
                let path = format!("{path}.reservations[{position}]");
                if !scope.cidr.contains(&reservation.ip) {
                    return Err(SnapshotInvalid::new(
                        format!("{path}.ip"),
                        "the reservation is outside the scope",
                    ));
                }
                if addresses.insert(reservation.ip, position).is_some() {
                    return Err(SnapshotInvalid::new(
                        format!("{path}.ip"),
                        "the address is reserved twice",
                    ));
                }
                check_client(&format!("{path}.client"), &reservation.client)?;
                check_options(&format!("{path}.options"), &reservation.options)?;
            }
        }

        for (index, superscope) in dhcp.superscopes.iter().enumerate() {
            let path = format!("dhcp.superscopes[{index}]");
            check_text(
                &format!("{path}.name"),
                &superscope.name,
                MAX_OPTION_VALUE_LEN,
                "the name",
            )?;
            for (position, member) in superscope.scopes.iter().enumerate() {
                if !scopes.contains_key(member) {
                    return Err(SnapshotInvalid::new(
                        format!("{path}.scopes[{position}]"),
                        "the snapshot holds no such scope",
                    ));
                }
            }
        }
        for (index, policy) in dhcp.policies.iter().enumerate() {
            let path = format!("dhcp.policies[{index}]");
            check_text(
                &format!("{path}.name"),
                &policy.name,
                MAX_OPTION_VALUE_LEN,
                "the name",
            )?;
            if let Some(scope) = &policy.scope
                && !scopes.contains_key(scope)
            {
                return Err(SnapshotInvalid::new(
                    format!("{path}.scope"),
                    "the snapshot holds no such scope",
                ));
            }
            check_options(&format!("{path}.options"), &policy.options)?;
        }
        for (index, failover) in dhcp.failover.iter().enumerate() {
            let path = format!("dhcp.failover[{index}]");
            for (position, member) in failover.scopes.iter().enumerate() {
                if !scopes.contains_key(member) {
                    return Err(SnapshotInvalid::new(
                        format!("{path}.scopes[{position}]"),
                        "the snapshot holds no such scope",
                    ));
                }
            }
        }

        if dhcp.leases.len() > MAX_LEASES {
            return Err(SnapshotInvalid::new(
                "dhcp.leases",
                format!("more than {MAX_LEASES} leases"),
            ));
        }
        let mut leased = BTreeMap::new();
        for (index, lease) in dhcp.leases.iter().enumerate() {
            let path = format!("dhcp.leases[{index}]");
            if !scopes.contains_key(&lease.scope) {
                return Err(SnapshotInvalid::new(
                    format!("{path}.scope"),
                    "the snapshot holds no such scope",
                ));
            }
            if !lease.scope.contains(&lease.ip) {
                return Err(SnapshotInvalid::new(
                    format!("{path}.ip"),
                    "the lease is outside its scope",
                ));
            }
            if leased.insert(lease.ip, index).is_some() {
                return Err(SnapshotInvalid::new(
                    format!("{path}.ip"),
                    "the address is leased twice",
                ));
            }
            check_client(&format!("{path}.client"), &lease.client)?;
            match lease.state {
                IrLeaseState::Active if lease.expires.is_none() => {
                    return Err(SnapshotInvalid::new(
                        format!("{path}.expires"),
                        "an active lease carries its end",
                    ));
                }
                IrLeaseState::Other => {
                    return Err(SnapshotInvalid::new(
                        format!("{path}.state"),
                        "a lease in another state belongs in the loss report",
                    ));
                }
                _ => {}
            }
            if let Some(hostname) = &lease.hostname {
                check_text(
                    &format!("{path}.hostname"),
                    hostname,
                    MAX_HOSTNAME_LEN,
                    "the host name",
                )?;
            }
        }

        if self.losses.entries.len() > MAX_LOSSES {
            return Err(SnapshotInvalid::new(
                "losses.entries",
                format!("more than {MAX_LOSSES} loss entries"),
            ));
        }
        for (index, entry) in self.losses.entries.iter().enumerate() {
            let path = format!("losses.entries[{index}]");
            check_text(
                &format!("{path}.code"),
                &entry.code,
                crate::names::MAX_NAME_LEN,
                "the code",
            )?;
            if entry.detail.chars().count() > MAX_LOSS_DETAIL_LEN {
                return Err(SnapshotInvalid::new(
                    format!("{path}.detail"),
                    "the detail is longer than 4,096 characters",
                ));
            }
        }
        Ok(())
    }

    /// The scopes of the snapshot, by network.
    pub fn scope(&self, cidr: &IpNet) -> Option<&super::dhcp::IrScope> {
        self.dhcp.scopes.iter().find(|scope| scope.cidr == *cidr)
    }

    /// How many reservations the snapshot holds, over every scope.
    pub fn reservation_count(&self) -> usize {
        self.dhcp
            .scopes
            .iter()
            .map(|scope| scope.reservations.len())
            .sum()
    }
}
