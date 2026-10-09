//! Authenticator data (WebAuthn Level 3, section 6.1).

use ciborium::Value;

use super::{WebAuthnError, cose::CoseKey};

/// Longest credential id the specification allows.
pub const MAX_CREDENTIAL_ID_LEN: usize = 1023;

const MALFORMED: WebAuthnError = WebAuthnError::Malformed("authenticator data");

/// The flags byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Flags(pub u8);

impl Flags {
    /// User present (UP).
    pub const USER_PRESENT: u8 = 0x01;
    /// User verified (UV).
    pub const USER_VERIFIED: u8 = 0x04;
    /// Backup eligible (BE).
    pub const BACKUP_ELIGIBLE: u8 = 0x08;
    /// Backup state (BS).
    pub const BACKUP_STATE: u8 = 0x10;
    /// Attested credential data included (AT).
    pub const ATTESTED: u8 = 0x40;
    /// Extension data included (ED).
    pub const EXTENSIONS: u8 = 0x80;

    /// Whether the user was present.
    pub const fn user_present(self) -> bool {
        self.0 & Self::USER_PRESENT != 0
    }

    /// Whether the user was verified.
    pub const fn user_verified(self) -> bool {
        self.0 & Self::USER_VERIFIED != 0
    }

    /// Whether the credential may be backed up (a synced passkey).
    pub const fn backup_eligible(self) -> bool {
        self.0 & Self::BACKUP_ELIGIBLE != 0
    }

    /// Whether the credential is currently backed up.
    pub const fn backup_state(self) -> bool {
        self.0 & Self::BACKUP_STATE != 0
    }

    /// Whether attested credential data follows.
    pub const fn attested(self) -> bool {
        self.0 & Self::ATTESTED != 0
    }

    /// Whether extension data follows.
    pub const fn extensions(self) -> bool {
        self.0 & Self::EXTENSIONS != 0
    }
}

/// The attested credential data of a registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestedCredential {
    /// The authenticator model (AAGUID).
    pub aaguid: [u8; 16],
    /// The credential id.
    pub credential_id: Vec<u8>,
    /// The credential public key, exactly as encoded by the authenticator.
    pub public_key_cbor: Vec<u8>,
    /// The parsed public key.
    pub public_key: CoseKey,
}

/// Parsed authenticator data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatorData {
    /// SHA-256 of the RP ID.
    pub rp_id_hash: [u8; 32],
    /// The flags.
    pub flags: Flags,
    /// The signature counter.
    pub sign_count: u32,
    /// The attested credential data (registrations only).
    pub attested: Option<AttestedCredential>,
}

impl AuthenticatorData {
    /// Parses authenticator data. Extensions are decoded to find their end and are
    /// otherwise ignored; trailing bytes are refused.
    ///
    /// # Errors
    ///
    /// [`WebAuthnError::Malformed`] or the errors of [`CoseKey::parse`].
    pub fn parse(raw: &[u8]) -> Result<Self, WebAuthnError> {
        if raw.len() < 37 {
            return Err(MALFORMED);
        }
        let (head, mut rest) = raw.split_at(37);
        let mut rp_id_hash = [0_u8; 32];
        rp_id_hash.copy_from_slice(&head[..32]);
        let flags = Flags(head[32]);
        let sign_count = u32::from_be_bytes([head[33], head[34], head[35], head[36]]);

        let attested = if flags.attested() {
            if rest.len() < 18 {
                return Err(MALFORMED);
            }
            let (aaguid, after) = rest.split_at(16);
            let (length, after) = after.split_at(2);
            let length = usize::from(u16::from_be_bytes([length[0], length[1]]));
            if length == 0 || length > MAX_CREDENTIAL_ID_LEN || after.len() < length {
                return Err(MALFORMED);
            }
            let (credential_id, after) = after.split_at(length);
            let mut reader = after;
            let value: Value = ciborium::de::from_reader(&mut reader).map_err(|_| MALFORMED)?;
            let consumed = after.len() - reader.len();
            let public_key = CoseKey::from_value(&value)?;
            rest = reader;
            Some(AttestedCredential {
                aaguid: aaguid.try_into().map_err(|_| MALFORMED)?,
                credential_id: credential_id.to_vec(),
                public_key_cbor: after[..consumed].to_vec(),
                public_key,
            })
        } else {
            None
        };

        if flags.extensions() {
            let mut reader = rest;
            let value: Value = ciborium::de::from_reader(&mut reader).map_err(|_| MALFORMED)?;
            if !matches!(value, Value::Map(_)) {
                return Err(MALFORMED);
            }
            rest = reader;
        }
        if !rest.is_empty() {
            return Err(MALFORMED);
        }
        Ok(Self {
            rp_id_hash,
            flags,
            sign_count,
            attested,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_an_assertion_without_attested_data() {
        let mut raw = vec![7_u8; 32];
        raw.push(Flags::USER_PRESENT | Flags::USER_VERIFIED);
        raw.extend_from_slice(&42_u32.to_be_bytes());
        let data = AuthenticatorData::parse(&raw).expect("parse");
        assert_eq!(data.rp_id_hash, [7; 32]);
        assert!(data.flags.user_present());
        assert!(data.flags.user_verified());
        assert!(!data.flags.backup_eligible());
        assert_eq!(data.sign_count, 42);
        assert!(data.attested.is_none());
    }

    #[test]
    fn refuses_short_and_trailing_data() {
        assert!(AuthenticatorData::parse(&[0; 36]).is_err());
        let mut raw = vec![0_u8; 37];
        raw.push(0);
        assert!(AuthenticatorData::parse(&raw).is_err());
        // AT set without attested data.
        let mut raw = vec![0_u8; 37];
        raw[32] = Flags::ATTESTED;
        assert!(AuthenticatorData::parse(&raw).is_err());
    }

    #[test]
    fn skips_extensions() {
        let mut raw = vec![0_u8; 32];
        raw.push(Flags::USER_PRESENT | Flags::EXTENSIONS);
        raw.extend_from_slice(&0_u32.to_be_bytes());
        // {"credProtect": 2}
        raw.extend_from_slice(&[
            0xa1, 0x6b, b'c', b'r', b'e', b'd', b'P', b'r', b'o', b't', b'e', b'c', b't', 0x02,
        ]);
        let data = AuthenticatorData::parse(&raw).expect("parse");
        assert!(data.flags.extensions());
        raw.push(0);
        assert!(AuthenticatorData::parse(&raw).is_err());
    }
}
