//! What a request tells the matcher (plan section 2.4): the fields classes and policies
//! test, borrowed from the received message or from the effective view's query.

use crate::v4::{LengthPrefixed, Message, RelayAgentInfo, code};

/// The fields of a request that classes and policies test. Every field borrows its octets;
/// building the facts of a received message walks its options once and allocates nothing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Facts<'a> {
    /// The Ethernet address (`htype` 1, six octets of `chaddr`).
    pub mac: Option<[u8; 6]>,
    /// Option 61 as sent (the type octet and the identifier).
    pub client_id: Option<&'a [u8]>,
    /// Option 60, the vendor class identifier.
    pub vendor_class: Option<&'a [u8]>,
    /// Option 77 as sent: RFC 3004's length-prefixed classes, or one plain string as
    /// Windows and iPXE send it.
    pub user_class: Option<&'a [u8]>,
    /// Sub-option 1 of option 82.
    pub circuit_id: Option<&'a [u8]>,
    /// Sub-option 2 of option 82.
    pub remote_id: Option<&'a [u8]>,
    /// Option 93 as sent: architecture types of two octets each (RFC 4578).
    pub architectures: Option<&'a [u8]>,
    /// Option 12, the host name.
    pub host_name: Option<&'a [u8]>,
}

impl<'a> Facts<'a> {
    /// The facts of a received request. An option sent in several instances (RFC 3396) or
    /// with a malformed length counts as absent: a class never matches on half a value.
    pub fn of(message: &Message<'a>) -> Self {
        let mut facts = Self {
            mac: message.mac().ok(),
            ..Self::default()
        };
        let mut split = [false; 7];
        for option in message.options() {
            let Ok(option) = option else { break };
            let (slot, index) = match option.code {
                code::CLIENT_IDENTIFIER => (&mut facts.client_id, 0),
                code::VENDOR_CLASS_IDENTIFIER => (&mut facts.vendor_class, 1),
                code::USER_CLASS => (&mut facts.user_class, 2),
                code::CLIENT_ARCHITECTURE => (&mut facts.architectures, 3),
                code::HOST_NAME => (&mut facts.host_name, 4),
                code::RELAY_AGENT_INFORMATION => (&mut facts.circuit_id, 5),
                _ => continue,
            };
            if slot.is_some() {
                split[index] = true;
            }
            *slot = Some(option.data);
        }
        for (index, slot) in [
            &mut facts.client_id,
            &mut facts.vendor_class,
            &mut facts.user_class,
            &mut facts.architectures,
            &mut facts.host_name,
        ]
        .into_iter()
        .enumerate()
        {
            if split[index] || slot.is_some_and(<[u8]>::is_empty) {
                *slot = None;
            }
        }
        if facts
            .architectures
            .is_some_and(|data| !data.len().is_multiple_of(2))
        {
            facts.architectures = None;
        }
        // The relay agent information sat in the circuit-id slot during the walk.
        let relay = facts
            .circuit_id
            .take()
            .filter(|_| !split[5])
            .and_then(|data| RelayAgentInfo::parse(data).ok());
        if let Some(info) = relay {
            facts.circuit_id = info.circuit_id();
            facts.remote_id = info.remote_id();
        }
        facts
    }

    /// Whether option 93 lists the architecture type `kind`.
    pub fn has_architecture(&self, kind: u16) -> bool {
        self.architectures.is_some_and(|data| {
            data.as_chunks::<2>()
                .0
                .iter()
                .any(|octets| u16::from_be_bytes(*octets) == kind)
        })
    }

    /// The first architecture type of option 93.
    pub fn architecture(&self) -> Option<u16> {
        self.architectures
            .and_then(|data| data.first_chunk::<2>())
            .map(|octets| u16::from_be_bytes(*octets))
    }

    /// Whether option 77 holds the user class `value`: the whole option as sent, or one of
    /// its RFC 3004 instances.
    pub fn has_user_class(&self, value: &[u8]) -> bool {
        let Some(data) = self.user_class else {
            return false;
        };
        data == value
            || LengthPrefixed::parse(data)
                .is_some_and(|classes| classes.into_iter().any(|class| class == value))
    }
}
