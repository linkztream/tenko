//! The stored value of a `dhcp.history` row (ADR 0031): the lean event of one lease change.
//!
//! The key of a row is the time, the VRF and the address. Its value used to be a whole
//! [`LeaseEvent`] in CBOR (about 250 octets with the client's host name); since ADR 0031 it
//! is [`HistoryRow::Lean`], a CBOR byte string of about 60 octets with what the change
//! was and to whom: the event, the state after it and its end, the scope, the client
//! identity (hardware type, `chaddr` and, when present, the client identifier), the node and
//! the revision of the lease row the change wrote. The names, the fingerprint and the DDNS
//! state are not copied: they are in the lease row at that revision, and the history read
//! joins them from the lease row while it still has them ([`HistoryNames`]).
//!
//! Rows written by earlier versions are CBOR maps of the whole event and still decode
//! ([`HistoryRow::Full`]); a reader cannot tell the two apart by anything but the shape of
//! the value. The encoding of a lean value is versioned by its first octet.
//!
//! | Octets | Field |
//! |---|---|
//! | 1 | version, 1 |
//! | 1 | the event ([`LeaseEventKind`]) |
//! | 1 | the state after it ([`BindingState`]) |
//! | 1 | flags: 1 a client identifier follows, 2 a revision follows |
//! | 8 | the end of the state, nanoseconds since the Unix epoch, big endian |
//! | 16 | the scope |
//! | 1 to 10 | the node, unsigned LEB128 |
//! | 1 to 10 | the revision of the lease row, unsigned LEB128, when flagged |
//! | 1 | the hardware type |
//! | 1 + n | `chaddr`: its length and its octets |
//! | 1 + n | the client identifier, when flagged: its length and its octets |

use std::{fmt, net::Ipv4Addr};

use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, MapAccess, Visitor},
};
use utoipa::ToSchema;

use super::lease::{BindingState, ClientKey, LeaseEvent, LeaseEventKind};
use crate::{
    id::{NodeId, PrefixId, Revision, VrfId},
    serde_util::HexBytes,
    timestamp::Timestamp,
};

/// The version octet of a lean value.
const VERSION: u8 = 1;
/// Flag: a client identifier follows.
const HAS_CLIENT_ID: u8 = 1;
/// Flag: a revision follows.
const HAS_REVISION: u8 = 2;

/// Where the host name of a history item comes from when the history is read (ADR 0031).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum HistoryNames {
    /// The history row holds them itself (a row written before ADR 0031).
    Stored,
    /// The lease row still is the one the change wrote: the names are those of the change.
    Lease,
    /// The lease row has changed since but still belongs to the same client: the names are
    /// the row's as they are now.
    LeaseNow,
    /// The lease row belongs to another client or is gone: the names are not known.
    Unknown,
}

/// The lean value of one history row (ADR 0031): everything of a [`LeaseEvent`] but its
/// key and the names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeanEvent {
    /// What happened.
    pub kind: LeaseEventKind,
    /// The state after the event.
    pub state: BindingState,
    /// The end of that state.
    pub ends: Timestamp,
    /// The scope.
    pub scope: PrefixId,
    /// The client.
    pub client: ClientKey,
    /// The node that wrote the lease row.
    pub node: NodeId,
    /// The revision of the lease row the change wrote; none when the history row was
    /// written in the same batch as the lease row (its own revision is the row's then).
    pub revision: Option<Revision>,
}

/// The stored value of a `dhcp.history` row: lean since ADR 0031, the whole event before.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoryRow {
    /// A row written since ADR 0031.
    Lean(LeanEvent),
    /// A row written by an earlier version: the whole event, with the host name.
    Full(LeaseEvent),
}

impl HistoryRow {
    /// The lean row of `event` (its key fields and its host name are not stored).
    pub fn of(event: &LeaseEvent) -> Self {
        HistoryRow::Lean(LeanEvent {
            kind: event.kind,
            state: event.state,
            ends: event.ends,
            scope: event.scope,
            client: event.client.clone(),
            node: event.node,
            revision: event.revision,
        })
    }

    /// The event of the row with the key `(at, vrf, addr)` and the row's own store
    /// revision `stored`. A lean event has no host name and names the lease row's revision
    /// (`stored` when the lease row was written in the same batch); a full one keeps its
    /// own fields and says so in [`LeaseEvent::names`].
    pub fn into_event(self, key: (Timestamp, VrfId, Ipv4Addr), stored: Revision) -> LeaseEvent {
        let (at, vrf, addr) = key;
        match self {
            HistoryRow::Lean(lean) => LeaseEvent {
                at,
                kind: lean.kind,
                addr,
                vrf,
                scope: lean.scope,
                client: lean.client,
                state: lean.state,
                ends: lean.ends,
                hostname: None,
                node: lean.node,
                revision: Some(lean.revision.unwrap_or(stored)),
                names: None,
            },
            HistoryRow::Full(mut event) => {
                event.names = Some(HistoryNames::Stored);
                event
            }
        }
    }

    /// The octets of a lean value (the payload of its CBOR byte string).
    fn encode(lean: &LeanEvent) -> Vec<u8> {
        let mut out = Vec::with_capacity(48);
        out.push(VERSION);
        out.push(kind_code(lean.kind));
        out.push(state_code(lean.state));
        let client_id = lean.client.client_id.as_ref().map(|id| id.0.as_slice());
        let mut flags = 0;
        if client_id.is_some() {
            flags |= HAS_CLIENT_ID;
        }
        if lean.revision.is_some() {
            flags |= HAS_REVISION;
        }
        out.push(flags);
        let nanos = i64::try_from(lean.ends.unix_nanos()).unwrap_or(i64::MAX);
        out.extend_from_slice(&nanos.to_be_bytes());
        out.extend_from_slice(lean.scope.uuid().as_bytes());
        leb128(lean.node.0, &mut out);
        if let Some(revision) = lean.revision {
            leb128(revision.0, &mut out);
        }
        out.push(lean.client.htype);
        let chaddr = lean.client.chaddr.0.as_slice();
        let chaddr = &chaddr[..chaddr.len().min(usize::from(u8::MAX))];
        out.push(u8::try_from(chaddr.len()).unwrap_or(u8::MAX));
        out.extend_from_slice(chaddr);
        if let Some(id) = client_id {
            let id = &id[..id.len().min(usize::from(u8::MAX))];
            out.push(u8::try_from(id.len()).unwrap_or(u8::MAX));
            out.extend_from_slice(id);
        }
        out
    }

    /// A lean value from its octets.
    fn decode(bytes: &[u8]) -> Result<LeanEvent, String> {
        let mut reader = Reader { bytes, at: 0 };
        let version = reader.byte()?;
        if version != VERSION {
            return Err(format!("unknown history row version {version}"));
        }
        let kind = kind_of(reader.byte()?)?;
        let state = state_of(reader.byte()?)?;
        let flags = reader.byte()?;
        let nanos = i64::from_be_bytes(reader.array::<8>()?);
        let ends = Timestamp::from_unix_nanos(i128::from(nanos)).map_err(|e| e.to_string())?;
        let scope = PrefixId::from_uuid(uuid::Uuid::from_bytes(reader.array::<16>()?));
        let node = NodeId(reader.leb128()?);
        let revision = if flags & HAS_REVISION == 0 {
            None
        } else {
            Some(Revision(reader.leb128()?))
        };
        let htype = reader.byte()?;
        let len = usize::from(reader.byte()?);
        let chaddr = reader.take(len)?.to_vec();
        let client_id = if flags & HAS_CLIENT_ID == 0 {
            None
        } else {
            let len = usize::from(reader.byte()?);
            Some(HexBytes(reader.take(len)?.to_vec()))
        };
        if reader.at != bytes.len() {
            return Err("trailing octets after a history row".to_owned());
        }
        Ok(LeanEvent {
            kind,
            state,
            ends,
            scope,
            client: ClientKey {
                htype,
                chaddr: HexBytes(chaddr),
                client_id,
            },
            node,
            revision,
        })
    }
}

impl Serialize for HistoryRow {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            HistoryRow::Lean(lean) => serializer.serialize_bytes(&HistoryRow::encode(lean)),
            HistoryRow::Full(event) => event.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for HistoryRow {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct RowVisitor;

        impl<'de> Visitor<'de> for RowVisitor {
            type Value = HistoryRow;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a lean history row (octets) or a lease event (a map)")
            }

            fn visit_bytes<E: de::Error>(self, bytes: &[u8]) -> Result<HistoryRow, E> {
                HistoryRow::decode(bytes)
                    .map(HistoryRow::Lean)
                    .map_err(E::custom)
            }

            fn visit_byte_buf<E: de::Error>(self, bytes: Vec<u8>) -> Result<HistoryRow, E> {
                self.visit_bytes(&bytes)
            }

            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<HistoryRow, A::Error> {
                LeaseEvent::deserialize(de::value::MapAccessDeserializer::new(map))
                    .map(HistoryRow::Full)
            }
        }

        deserializer.deserialize_any(RowVisitor)
    }
}

/// The code of an event in a lean value.
const fn kind_code(kind: LeaseEventKind) -> u8 {
    match kind {
        LeaseEventKind::Granted => 0,
        LeaseEventKind::Renewed => 1,
        LeaseEventKind::Rebound => 2,
        LeaseEventKind::Released => 3,
        LeaseEventKind::Declined => 4,
        LeaseEventKind::Expired => 5,
        LeaseEventKind::Reclaimed => 6,
        LeaseEventKind::Conflict => 7,
    }
}

fn kind_of(code: u8) -> Result<LeaseEventKind, String> {
    Ok(match code {
        0 => LeaseEventKind::Granted,
        1 => LeaseEventKind::Renewed,
        2 => LeaseEventKind::Rebound,
        3 => LeaseEventKind::Released,
        4 => LeaseEventKind::Declined,
        5 => LeaseEventKind::Expired,
        6 => LeaseEventKind::Reclaimed,
        7 => LeaseEventKind::Conflict,
        other => return Err(format!("unknown lease event code {other}")),
    })
}

/// The code of a binding state in a lean value.
const fn state_code(state: BindingState) -> u8 {
    match state {
        BindingState::Free => 0,
        BindingState::Active => 1,
        BindingState::Expired => 2,
        BindingState::Released => 3,
        BindingState::Abandoned => 4,
        BindingState::Reset => 5,
        BindingState::Backup => 6,
    }
}

fn state_of(code: u8) -> Result<BindingState, String> {
    Ok(match code {
        0 => BindingState::Free,
        1 => BindingState::Active,
        2 => BindingState::Expired,
        3 => BindingState::Released,
        4 => BindingState::Abandoned,
        5 => BindingState::Reset,
        6 => BindingState::Backup,
        other => return Err(format!("unknown binding state code {other}")),
    })
}

/// Appends `value` as unsigned LEB128.
fn leb128(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let low = u8::try_from(value & 0x7f).unwrap_or(0);
        value >>= 7;
        if value == 0 {
            out.push(low);
            return;
        }
        out.push(low | 0x80);
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], String> {
        let end = self
            .at
            .checked_add(len)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| "a history row ends early".to_owned())?;
        let out = &self.bytes[self.at..end];
        self.at = end;
        Ok(out)
    }

    fn byte(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], String> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    fn leb128(&mut self) -> Result<u64, String> {
        let mut value = 0u64;
        for shift in (0..64).step_by(7) {
            let byte = self.byte()?;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err("an integer of a history row is too long".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{from_cbor, to_cbor};

    fn event(client_id: Option<Vec<u8>>, revision: Option<Revision>) -> LeaseEvent {
        LeaseEvent {
            at: "2026-10-31T08:00:00.123456789Z".parse().expect("time"),
            kind: LeaseEventKind::Renewed,
            addr: "192.0.2.50".parse().expect("addr"),
            vrf: VrfId::generate(),
            scope: PrefixId::generate(),
            client: ClientKey {
                htype: 1,
                chaddr: HexBytes(vec![0x00, 0x00, 0x5e, 0x00, 0x53, 0x01]),
                client_id: client_id.map(HexBytes),
            },
            state: BindingState::Active,
            ends: "2026-10-31T09:00:00.5Z".parse().expect("time"),
            hostname: Some("laptop".to_owned()),
            node: NodeId(3),
            revision,
            names: None,
        }
    }

    #[test]
    fn a_lean_row_round_trips_and_stays_small() {
        for (client_id, revision) in [
            (None, Some(Revision(1_234_567))),
            (Some(vec![1, 0, 0, 0x5e, 0, 0x53, 1]), Some(Revision(9))),
            (None, None),
        ] {
            let event = event(client_id, revision);
            let row = HistoryRow::of(&event);
            let bytes = to_cbor(&row).expect("cbor");
            assert!(bytes.len() <= 64, "{} octets", bytes.len());
            let back: HistoryRow = from_cbor(&bytes).expect("decode");
            assert_eq!(back, row);
            let decoded = back.into_event((event.at, event.vrf, event.addr), Revision(77));
            assert_eq!(decoded.hostname, None, "a lean row keeps no names");
            assert_eq!(decoded.revision, Some(revision.unwrap_or(Revision(77))));
            assert_eq!(
                LeaseEvent {
                    hostname: None,
                    revision: decoded.revision,
                    ..event
                },
                decoded
            );
        }
    }

    #[test]
    fn a_row_of_an_earlier_version_still_decodes() {
        // The value earlier versions wrote: the whole event as a CBOR map.
        let event = event(None, None);
        let bytes = to_cbor(&event).expect("cbor");
        let row: HistoryRow = from_cbor(&bytes).expect("decode");
        assert_eq!(row, HistoryRow::Full(event.clone()));
        let decoded = row.into_event((event.at, event.vrf, event.addr), Revision(5));
        assert_eq!(decoded.hostname.as_deref(), Some("laptop"));
        assert_eq!(decoded.names, Some(HistoryNames::Stored));
        assert_eq!(decoded.revision, None);
    }

    #[test]
    fn a_damaged_lean_row_is_refused() {
        let row = HistoryRow::of(&event(None, Some(Revision(3))));
        let HistoryRow::Lean(lean) = &row else {
            unreachable!("a lean row");
        };
        let octets = HistoryRow::encode(lean);
        for cut in 0..octets.len() {
            assert!(HistoryRow::decode(&octets[..cut]).is_err(), "cut at {cut}");
        }
        let mut versioned = octets.clone();
        versioned[0] = 2;
        assert!(HistoryRow::decode(&versioned).is_err());
        let mut longer = octets;
        longer.push(0);
        assert!(HistoryRow::decode(&longer).is_err());
    }
}
