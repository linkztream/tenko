//! The IPAM part of the migration intermediate representation (ADR 0006, MIG-01).
//!
//! Every source adapter (the spreadsheet import first, other IPAM systems in Phase 4)
//! produces an [`Ir`] plus a [`LossReport`] listing what it could not map. The IR uses the
//! validated value types of the model, so anything that does not parse becomes a loss
//! entry instead of silently wrong data. References between IR items are by natural key
//! (CIDR, VLAN id, host name), because the source has no Tenko identifiers.
//!
//! The DHCP part (Phase 3, WP7.0) is [`dhcp::DhcpIr`], produced beside the [`Ir`] by DHCP
//! sources.

use std::{borrow::Cow, collections::BTreeMap, fmt, net::IpAddr};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

// WP7.0: the DHCP part of the IR.
pub mod dhcp;

use crate::{
    ipam::{AssignmentMode, Status},
    net::{Fqdn, HostName, MacAddr},
};

/// Where in the source an item came from: sheet, row and column for spreadsheets, a path or
/// object name for other sources.
#[derive(
    Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
pub struct SourceLocation {
    /// Sheet, file or object collection.
    #[serde(default)]
    pub sheet: Option<String>,
    /// Row number, 1-based as shown by spreadsheet programs.
    #[serde(default)]
    pub row: Option<u32>,
    /// Column letter or header.
    #[serde(default)]
    pub column: Option<String>,
}

impl fmt::Display for SourceLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = Vec::new();
        if let Some(sheet) = &self.sheet {
            parts.push(sheet.clone());
        }
        if let Some(row) = self.row {
            parts.push(format!("row {row}"));
        }
        if let Some(column) = &self.column {
            parts.push(format!("column {column}"));
        }
        if parts.is_empty() {
            f.write_str("(unknown location)")
        } else {
            f.write_str(&parts.join(", "))
        }
    }
}

/// A network (prefix) from the source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct IrNetwork {
    /// The network.
    #[schema(value_type = String, example = "192.0.2.0/24")]
    pub cidr: IpNet,
    /// Name or label.
    #[serde(default)]
    pub name: Option<String>,
    /// VLAN id.
    #[serde(default)]
    pub vlan: Option<u16>,
    /// Site name.
    #[serde(default)]
    pub site: Option<String>,
    /// Status.
    #[serde(default)]
    pub status: Option<Status>,
    /// Free text.
    #[serde(default)]
    pub description: Option<String>,
    /// Tags.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Unmapped columns kept as custom field candidates, by header.
    #[serde(default)]
    pub custom: BTreeMap<String, String>,
    /// Origin in the source.
    #[serde(default)]
    pub origin: SourceLocation,
}

/// A VLAN from the source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct IrVlan {
    /// VLAN id.
    pub vid: u16,
    /// Name.
    #[serde(default)]
    pub name: Option<String>,
    /// Site name.
    #[serde(default)]
    pub site: Option<String>,
    /// Free text.
    #[serde(default)]
    pub description: Option<String>,
    /// Origin in the source.
    #[serde(default)]
    pub origin: SourceLocation,
}

/// A host from the source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct IrHost {
    /// Host name (the natural key addresses refer to).
    pub name: HostName,
    /// Assignment mode, when the source says.
    #[serde(default)]
    pub mode: Option<AssignmentMode>,
    /// MAC addresses.
    #[serde(default)]
    pub macs: Vec<MacAddr>,
    /// Site name.
    #[serde(default)]
    pub site: Option<String>,
    /// Free text.
    #[serde(default)]
    pub description: Option<String>,
    /// Tags.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Unmapped columns kept as custom field candidates, by header.
    #[serde(default)]
    pub custom: BTreeMap<String, String>,
    /// Origin in the source.
    #[serde(default)]
    pub origin: SourceLocation,
}

/// An address from the source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct IrAddress {
    /// The address.
    #[schema(value_type = String, example = "192.0.2.10")]
    pub ip: IpAddr,
    /// Intended DNS name.
    #[serde(default)]
    pub dns_name: Option<Fqdn>,
    /// The host the address belongs to, by name.
    #[serde(default)]
    pub host: Option<HostName>,
    /// MAC address of the interface carrying the address.
    #[serde(default)]
    pub mac: Option<MacAddr>,
    /// Status.
    #[serde(default)]
    pub status: Option<Status>,
    /// Free text.
    #[serde(default)]
    pub description: Option<String>,
    /// Tags.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Unmapped columns kept as custom field candidates, by header.
    #[serde(default)]
    pub custom: BTreeMap<String, String>,
    /// Origin in the source.
    #[serde(default)]
    pub origin: SourceLocation,
}

/// The IPAM content of a migration source.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Ir {
    /// Networks.
    #[serde(default)]
    pub networks: Vec<IrNetwork>,
    /// VLANs.
    #[serde(default)]
    pub vlans: Vec<IrVlan>,
    /// Hosts.
    #[serde(default)]
    pub hosts: Vec<IrHost>,
    /// Addresses.
    #[serde(default)]
    pub addresses: Vec<IrAddress>,
}

impl Ir {
    /// Whether the IR holds nothing.
    pub fn is_empty(&self) -> bool {
        self.networks.is_empty()
            && self.vlans.is_empty()
            && self.hosts.is_empty()
            && self.addresses.is_empty()
    }
}

/// What a source adapter could not map (MIG-01).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct LossReport {
    /// One entry per lost or transformed item.
    #[serde(default)]
    pub entries: Vec<LossEntry>,
}

impl LossReport {
    /// Whether nothing was lost.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Records a loss.
    pub fn push(
        &mut self,
        location: SourceLocation,
        code: &'static str,
        detail: impl Into<String>,
    ) {
        self.entries.push(LossEntry {
            location,
            code: Cow::Borrowed(code),
            detail: detail.into(),
        });
    }
}

/// One lost or transformed item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct LossEntry {
    /// Where in the source.
    pub location: SourceLocation,
    /// Stable code, for example `import.cell.invalid_ip`.
    #[schema(value_type = String)]
    pub code: Cow<'static, str>,
    /// English explanation with the offending value.
    pub detail: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{from_cbor, to_cbor};

    #[test]
    fn ir_and_loss_report_round_trip() {
        let origin = SourceLocation {
            sheet: Some("LAN".to_owned()),
            row: Some(12),
            column: Some("C".to_owned()),
        };
        let ir = Ir {
            networks: vec![],
            vlans: vec![],
            hosts: vec![],
            addresses: vec![IrAddress {
                ip: "198.51.100.7".parse().expect("ip"),
                dns_name: Some(Fqdn::new("nas.example.test").expect("name")),
                host: Some(HostName::new("nas").expect("name")),
                mac: Some("00:00:5e:00:53:07".parse().expect("mac")),
                status: Some(Status::Active),
                description: None,
                tags: vec!["storage".to_owned()],
                custom: BTreeMap::new(),
                origin: origin.clone(),
            }],
        };
        assert!(!ir.is_empty());
        assert_eq!(
            from_cbor::<Ir>(&to_cbor(&ir).expect("cbor")).expect("cbor"),
            ir
        );

        let mut report = LossReport::default();
        report.push(
            origin,
            "import.cell.invalid_ip",
            "`198.51.100.300` is not an address",
        );
        assert_eq!(
            report.entries[0].location.to_string(),
            "LAN, row 12, column C"
        );
        let json = serde_json::to_string(&report).expect("json");
        assert_eq!(
            serde_json::from_str::<LossReport>(&json).expect("json"),
            report
        );
    }
}
