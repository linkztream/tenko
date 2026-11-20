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
    LossReport, SourceLocation,
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

/// The most items of each smaller list of a snapshot: custom option definitions, classes,
/// policies, superscopes, failover relationships, the options of one level, the ranges and
/// exclusions of one scope, the conditions of a policy and the values of one option or
/// condition.
pub const MAX_ITEMS: usize = 1_000;

/// The most MAC filter entries one snapshot carries.
pub const MAX_FILTERS: usize = 10_000;

/// The longest sheet or column of a source location: the location of a loss entry is its key,
/// which an acknowledgment stores.
pub const MAX_LOCATION_LEN: usize = 256;

/// The most array elements one push body holds over every list, counted before it is parsed
/// (`tenko_migrate::mirror::body`): the bounds above summed with room for the options and
/// values of every level, so that no list of the body is allocated past what this bound
/// allows.
pub const MAX_ELEMENTS: usize = 262_144;

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

/// Checks a free text: at most `max` characters and no control character, so that it is one
/// line wherever it is shown, logged or printed in a terminal; empty only with `empty`.
fn check_line(
    path: &str,
    text: &str,
    max: usize,
    what: &'static str,
    empty: bool,
) -> Result<(), SnapshotInvalid> {
    if text.is_empty() && !empty {
        return Err(SnapshotInvalid::new(path, format!("{what} is empty")));
    }
    if text.chars().count() > max {
        return Err(SnapshotInvalid::new(
            path,
            format!("{what} is longer than {max} characters"),
        ));
    }
    if text.chars().any(char::is_control) {
        return Err(SnapshotInvalid::new(
            path,
            format!("{what} holds a control character"),
        ));
    }
    Ok(())
}

/// A text that must not be empty.
fn check_text(
    path: &str,
    text: &str,
    max: usize,
    what: &'static str,
) -> Result<(), SnapshotInvalid> {
    check_line(path, text, max, what, false)
}

/// An optional free text of at most [`MAX_OPTION_VALUE_LEN`] characters.
fn check_free(
    path: &str,
    text: Option<&String>,
    what: &'static str,
) -> Result<(), SnapshotInvalid> {
    text.map_or(Ok(()), |text| {
        check_line(path, text, MAX_OPTION_VALUE_LEN, what, true)
    })
}

fn check_count(path: &str, len: usize, max: usize) -> Result<(), SnapshotInvalid> {
    if len > max {
        return Err(SnapshotInvalid::new(path, format!("more than {max} items")));
    }
    Ok(())
}

fn check_location(path: &str, location: &SourceLocation) -> Result<(), SnapshotInvalid> {
    for (field, text) in [("sheet", &location.sheet), ("column", &location.column)] {
        if let Some(text) = text {
            check_line(
                &format!("{path}.{field}"),
                text,
                MAX_LOCATION_LEN,
                "a location",
                true,
            )?;
        }
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
    check_count(path, options.len(), MAX_ITEMS)?;
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
        check_count(&format!("{path}.values"), option.values.len(), MAX_ITEMS)?;
        for (position, value) in option.values.iter().enumerate() {
            check_line(
                &format!("{path}.values[{position}]"),
                value,
                MAX_OPTION_VALUE_LEN,
                "an option value",
                true,
            )?;
        }
        check_free(
            &format!("{path}.vendor_class"),
            option.vendor_class.as_ref(),
            "a class",
        )?;
        check_free(
            &format!("{path}.user_class"),
            option.user_class.as_ref(),
            "a class",
        )?;
        check_location(&format!("{path}.origin"), &option.origin)?;
    }
    Ok(())
}

fn check_ranges(path: &str, ranges: &[IrRange], scope: &IpNet) -> Result<(), SnapshotInvalid> {
    check_count(path, ranges.len(), MAX_ITEMS)?;
    for (position, range) in ranges.iter().enumerate() {
        let path = format!("{path}[{position}]");
        if !scope.contains(&range.first) || !scope.contains(&range.last) {
            return Err(SnapshotInvalid::new(path, "the range is outside the scope"));
        }
        if range.first > range.last {
            return Err(SnapshotInvalid::new(
                path,
                "the first address is after the last",
            ));
        }
    }
    Ok(())
}

fn check_members(
    path: &str,
    members: &[IpNet],
    scopes: &BTreeMap<IpNet, usize>,
) -> Result<(), SnapshotInvalid> {
    check_count(path, members.len(), MAX_SCOPES)?;
    for (position, member) in members.iter().enumerate() {
        if !scopes.contains_key(member) {
            return Err(SnapshotInvalid::new(
                format!("{path}[{position}]"),
                "the snapshot holds no such scope",
            ));
        }
    }
    Ok(())
}

impl MirrorSnapshot {
    /// Checks the envelope beyond what parsing checks: the format, the sequence, the bounds
    /// of section 2.1 and a bound on every other list ([`MAX_ITEMS`], [`MAX_FILTERS`]),
    /// every free text one line of bounded length without a control character, and the
    /// content of the IR (scopes that are networks named once, ranges and exclusions inside
    /// their scope, reservations and leases inside their scope with a client identity,
    /// leases of a scope the snapshot holds in a state the mirror carries, options with a
    /// code and a value, superscopes, policies and failover relationships that name scopes
    /// the snapshot holds, bounded loss entries). Values that have a Tenko type (addresses,
    /// networks, MAC addresses, host names, times) were checked when they parsed.
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
        check_count("dhcp.scopes", dhcp.scopes.len(), MAX_SCOPES)?;
        check_options("dhcp.server_options", &dhcp.server_options)?;
        check_count("dhcp.option_defs", dhcp.option_defs.len(), MAX_ITEMS)?;
        for (index, def) in dhcp.option_defs.iter().enumerate() {
            let path = format!("dhcp.option_defs[{index}]");
            if def.code == 0 || def.code > 254 {
                return Err(SnapshotInvalid::new(
                    format!("{path}.code"),
                    "an option code is 1 to 254",
                ));
            }
            check_text(
                &format!("{path}.name"),
                &def.name,
                MAX_OPTION_VALUE_LEN,
                "the name",
            )?;
            check_free(
                &format!("{path}.vendor_class"),
                def.vendor_class.as_ref(),
                "a class",
            )?;
            check_free(
                &format!("{path}.description"),
                def.description.as_ref(),
                "a description",
            )?;
            check_location(&format!("{path}.origin"), &def.origin)?;
        }
        check_count("dhcp.classes", dhcp.classes.len(), MAX_ITEMS)?;
        for (index, class) in dhcp.classes.iter().enumerate() {
            let path = format!("dhcp.classes[{index}]");
            check_text(
                &format!("{path}.name"),
                &class.name,
                MAX_OPTION_VALUE_LEN,
                "the name",
            )?;
            check_free(
                &format!("{path}.description"),
                class.description.as_ref(),
                "a description",
            )?;
            check_location(&format!("{path}.origin"), &class.origin)?;
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
            check_free(&format!("{path}.name"), scope.name.as_ref(), "a name")?;
            check_free(
                &format!("{path}.description"),
                scope.description.as_ref(),
                "a description",
            )?;
            check_free(
                &format!("{path}.superscope"),
                scope.superscope.as_ref(),
                "a name",
            )?;
            check_location(&format!("{path}.origin"), &scope.origin)?;
            check_ranges(&format!("{path}.ranges"), &scope.ranges, &scope.cidr)?;
            check_ranges(
                &format!("{path}.exclusions"),
                &scope.exclusions,
                &scope.cidr,
            )?;
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
                check_free(
                    &format!("{path}.source_name"),
                    reservation.source_name.as_ref(),
                    "a name",
                )?;
                check_free(
                    &format!("{path}.description"),
                    reservation.description.as_ref(),
                    "a description",
                )?;
                check_location(&format!("{path}.origin"), &reservation.origin)?;
                check_options(&format!("{path}.options"), &reservation.options)?;
            }
        }

        check_count("dhcp.superscopes", dhcp.superscopes.len(), MAX_ITEMS)?;
        for (index, superscope) in dhcp.superscopes.iter().enumerate() {
            let path = format!("dhcp.superscopes[{index}]");
            check_text(
                &format!("{path}.name"),
                &superscope.name,
                MAX_OPTION_VALUE_LEN,
                "the name",
            )?;
            check_location(&format!("{path}.origin"), &superscope.origin)?;
            check_members(&format!("{path}.scopes"), &superscope.scopes, &scopes)?;
        }
        check_count("dhcp.policies", dhcp.policies.len(), MAX_ITEMS)?;
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
            check_count(
                &format!("{path}.conditions"),
                policy.conditions.len(),
                MAX_ITEMS,
            )?;
            for (position, condition) in policy.conditions.iter().enumerate() {
                let path = format!("{path}.conditions[{position}].values");
                check_count(&path, condition.values.len(), MAX_ITEMS)?;
                for (at, value) in condition.values.iter().enumerate() {
                    check_line(
                        &format!("{path}[{at}]"),
                        value,
                        MAX_OPTION_VALUE_LEN,
                        "a value",
                        true,
                    )?;
                }
            }
            check_count(&format!("{path}.ranges"), policy.ranges.len(), MAX_ITEMS)?;
            check_options(&format!("{path}.options"), &policy.options)?;
            check_free(
                &format!("{path}.description"),
                policy.description.as_ref(),
                "a description",
            )?;
            check_location(&format!("{path}.origin"), &policy.origin)?;
        }
        check_count("dhcp.filters", dhcp.filters.len(), MAX_FILTERS)?;
        for (index, filter) in dhcp.filters.iter().enumerate() {
            let path = format!("dhcp.filters[{index}]");
            check_free(
                &format!("{path}.description"),
                filter.description.as_ref(),
                "a description",
            )?;
            check_location(&format!("{path}.origin"), &filter.origin)?;
        }
        check_count("dhcp.failover", dhcp.failover.len(), MAX_ITEMS)?;
        for (index, failover) in dhcp.failover.iter().enumerate() {
            let path = format!("dhcp.failover[{index}]");
            check_line(
                &format!("{path}.name"),
                &failover.name,
                MAX_OPTION_VALUE_LEN,
                "the name",
                true,
            )?;
            check_line(
                &format!("{path}.partner"),
                &failover.partner,
                MAX_OPTION_VALUE_LEN,
                "the partner",
                true,
            )?;
            check_location(&format!("{path}.origin"), &failover.origin)?;
            check_members(&format!("{path}.scopes"), &failover.scopes, &scopes)?;
        }

        check_count("dhcp.leases", dhcp.leases.len(), MAX_LEASES)?;
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
            check_location(&format!("{path}.origin"), &lease.origin)?;
        }

        check_count("losses.entries", self.losses.entries.len(), MAX_LOSSES)?;
        for (index, entry) in self.losses.entries.iter().enumerate() {
            let path = format!("losses.entries[{index}]");
            check_text(
                &format!("{path}.code"),
                &entry.code,
                crate::names::MAX_NAME_LEN,
                "the code",
            )?;
            check_line(
                &format!("{path}.detail"),
                &entry.detail,
                MAX_LOSS_DETAIL_LEN,
                "the detail",
                true,
            )?;
            check_location(&format!("{path}.location"), &entry.location)?;
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
