//! The DHCID record (RFC 4701): who a name belongs to.
//!
//! The RDATA is the identifier type (two octets), the digest type (one octet, 1 for
//! SHA-256) and the SHA-256 digest of the client's identifier followed by the FQDN in
//! canonical wire form (lowercase, uncompressed). The identifier of a DHCPv4 client:
//!
//! | Type | When | Identifier |
//! |---|---|---|
//! | 0 | no option 61 | `htype` and the `hlen` octets of `chaddr` |
//! | 1 | option 61 | the option's data (its type octet and the identifier) |
//! | 2 | option 61 of type 255 (RFC 4361) | the DUID after the type octet and the IAID |
//!
//! The same client asking for the same name always gets the same DHCID, a different client
//! a different one, and the record says nothing about the client to a reader.

use sha2::{Digest, Sha256};
use tenko_core::{dhcp::ClientKey, dns::DnsName};

/// The record type of the DHCID record.
pub const RTYPE: u16 = 49;

/// The digest type SHA-256 (RFC 4701, section 3.4).
pub const DIGEST_SHA256: u8 = 1;

/// The identifier type of `htype` and `chaddr`.
pub const ID_CHADDR: u16 = 0;
/// The identifier type of option 61.
pub const ID_CLIENT_ID: u16 = 1;
/// The identifier type of a DUID.
pub const ID_DUID: u16 = 2;

/// The identifier type and the identifier octets of a client.
pub fn identifier(client: &ClientKey) -> (u16, Vec<u8>) {
    match client.client_id.as_ref().map(|id| id.0.as_slice()) {
        // RFC 4361: type 255, a four-octet IAID, then the DUID.
        Some([255, _, _, _, _, duid @ ..]) if !duid.is_empty() => (ID_DUID, duid.to_vec()),
        Some(id) if !id.is_empty() => (ID_CLIENT_ID, id.to_vec()),
        _ => {
            let mut out = Vec::with_capacity(1 + client.chaddr.0.len());
            out.push(client.htype);
            out.extend_from_slice(&client.chaddr.0);
            (ID_CHADDR, out)
        }
    }
}

/// The DHCID RDATA of `client` for `fqdn`.
pub fn dhcid(client: &ClientKey, fqdn: &DnsName) -> Vec<u8> {
    let (kind, id) = identifier(client);
    let mut hasher = Sha256::new();
    hasher.update(&id);
    hasher.update(fqdn.to_wire());
    let digest = hasher.finalize();
    let mut out = Vec::with_capacity(3 + digest.len());
    out.extend_from_slice(&kind.to_be_bytes());
    out.push(DIGEST_SHA256);
    out.extend_from_slice(&digest);
    out
}

#[cfg(test)]
mod tests {
    use tenko_core::serde_util::HexBytes;

    use super::*;

    fn base64(bytes: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
            for i in 0..4 {
                if i <= chunk.len() {
                    out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize]));
                } else {
                    out.push('=');
                }
            }
        }
        out
    }

    fn name(text: &str) -> DnsName {
        DnsName::new(text).expect("name")
    }

    // The examples of RFC 4701, section 3.6.
    #[test]
    fn the_examples_of_the_rfc() {
        let duid = ClientKey {
            htype: 1,
            chaddr: HexBytes(vec![1, 2, 3, 4, 5, 6]),
            client_id: Some(HexBytes(
                [
                    &[255u8, 0, 0, 0, 1][..],
                    &[0, 1, 0, 6, 0x41, 0x2d, 0xf1, 0x66, 1, 2, 3, 4, 5, 6],
                ]
                .concat(),
            )),
        };
        assert_eq!(
            base64(&dhcid(&duid, &name("chi6.example.com"))),
            "AAIBY2/AuCccgoJbsaxcQc9TUapptP69lOjxfNuVAA2kjEA="
        );
        let client_id = ClientKey {
            htype: 1,
            chaddr: HexBytes(vec![7, 8, 9, 10, 11, 12]),
            client_id: Some(HexBytes(vec![1, 7, 8, 9, 10, 11, 12])),
        };
        assert_eq!(
            base64(&dhcid(&client_id, &name("chi.example.com"))),
            "AAEBOSD+XR3Os/0LozeXVqcNc7FwCfQdWL3b/NaiUDlW2No="
        );
        let chaddr = ClientKey {
            htype: 1,
            chaddr: HexBytes(vec![1, 2, 3, 4, 5, 6]),
            client_id: None,
        };
        assert_eq!(
            base64(&dhcid(&chaddr, &name("client.example.com"))),
            "AAABxLmlskllE0MVjd57zHcWmEH3pCQ6VytcKD//7es/deY="
        );
    }

    #[test]
    fn the_name_and_the_client_both_count() {
        let a = ClientKey {
            htype: 1,
            chaddr: HexBytes(vec![0, 0, 0x5e, 0, 0x53, 1]),
            client_id: None,
        };
        let b = ClientKey {
            chaddr: HexBytes(vec![0, 0, 0x5e, 0, 0x53, 2]),
            ..a.clone()
        };
        let host = name("host.example.test");
        assert_eq!(dhcid(&a, &host), dhcid(&a, &name("HOST.example.test.")));
        assert_ne!(dhcid(&a, &host), dhcid(&b, &host));
        assert_ne!(dhcid(&a, &host), dhcid(&a, &name("other.example.test")));
        assert_eq!(dhcid(&a, &host).len(), 35);
    }
}
