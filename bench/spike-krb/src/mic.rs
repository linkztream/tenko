//! RFC 4121 MIC tokens over `aws-lc-rs`: the per-message signature of GSS-TSIG (RFC 3645),
//! computed by Tenko itself whatever Kerberos library establishes the context.
//!
//! The token is a 16-octet header (`04 04`, flags, five `ff` octets, the sequence number)
//! and HMAC-SHA1-96 over the data followed by the header, under `Kc = DK(key, usage || 0x99)`
//! with usage 25 for the initiator and 23 for the acceptor (RFC 4121, section 4.2.6.1;
//! RFC 3961, section 5.1; RFC 3962, section 4).

use aws_lc_rs::cipher::{AES_128, AES_256, EncryptingKey, EncryptionContext, UnboundCipherKey};
use aws_lc_rs::constant_time::verify_slices_are_equal;
use aws_lc_rs::hmac;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::acceptor::Enctype;

/// Key usage of tokens sent by the acceptor.
pub const ACCEPTOR_SIGN: u32 = 23;
/// Key usage of tokens sent by the initiator.
pub const INITIATOR_SIGN: u32 = 25;

/// Flag: the token was sent by the acceptor.
pub const FLAG_SENT_BY_ACCEPTOR: u8 = 0x01;
/// Flag: the token is a wrap token with confidentiality (never set on a MIC).
pub const FLAG_SEALED: u8 = 0x02;
/// Flag: the key is an acceptor subkey.
pub const FLAG_ACCEPTOR_SUBKEY: u8 = 0x04;

const TOKEN_ID: [u8; 2] = [0x04, 0x04];
const FILLER: [u8; 5] = [0xff; 5];
/// Header and HMAC-SHA1-96.
pub const TOKEN_LEN: usize = 16 + 12;

/// The header of a MIC token after decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub flags: u8,
    pub seq: u64,
}

/// Why a MIC did not verify.
#[derive(Debug, PartialEq, Eq)]
pub enum MicError {
    /// Wrong length or token identifier.
    Malformed,
    /// A flag the direction or the token type forbids.
    Flags,
    /// The checksum does not match.
    Checksum,
}

/// RFC 3961 n-fold: stretches or shrinks `input` to `out_len` octets by 13-bit rotations
/// and ones'-complement addition.
pub fn nfold(input: &[u8], out_len: usize) -> Vec<u8> {
    let in_len = input.len();
    let lcm = in_len * out_len / gcd(in_len, out_len);
    let mut out = vec![0u8; out_len];
    let mut carry: u32 = 0;
    // The concatenation of the rotated copies, taken as big-endian numbers added with
    // end-around carry, as in RFC 3961, appendix A.
    let bytes = |i: usize| -> u8 {
        let copy = i / in_len;
        let rotate = (13 * copy) % (in_len * 8);
        let pos = i % in_len;
        let byte_shift = rotate / 8;
        let bit_shift = rotate % 8;
        let a = input[(pos + in_len - byte_shift) % in_len];
        if bit_shift == 0 {
            a
        } else {
            let b = input[(pos + 2 * in_len - byte_shift - 1) % in_len];
            (a >> bit_shift) | (b << (8 - bit_shift))
        }
    };
    for i in (0..out_len).rev() {
        let mut sum: u32 = u32::from(out[i]) + carry;
        let mut j = i;
        while j < lcm {
            sum += u32::from(bytes(j));
            j += out_len;
        }
        out[i] = (sum & 0xff) as u8;
        carry = sum >> 8;
    }
    // Add the final carry end-around.
    let mut i = out_len;
    while carry != 0 && i > 0 {
        i -= 1;
        let sum = u32::from(out[i]) + carry;
        out[i] = (sum & 0xff) as u8;
        carry = sum >> 8;
    }
    out
}

fn gcd(mut a: usize, mut b: usize) -> usize {
    while b != 0 {
        let t = a % b;
        a = b;
        b = t;
    }
    a
}

fn aes_block(key: &[u8], enctype: Enctype, block: &mut [u8; 16]) {
    let alg = match enctype {
        Enctype::Aes128 => &AES_128,
        Enctype::Aes256 => &AES_256,
    };
    let unbound = UnboundCipherKey::new(alg, key).expect("key length checked by the caller");
    let ecb = EncryptingKey::ecb(unbound).expect("AES supports ECB");
    ecb.less_safe_encrypt(block, EncryptionContext::None)
        .expect("one block, no padding");
}

/// RFC 3961 derived key `DK(key, constant)` for the AES enctypes: `DR` is the AES block
/// function fed back on itself (CBC-CTS of one block is the block function), and
/// random-to-key is the identity.
pub fn derive_key(key: &[u8], enctype: Enctype, constant: &[u8]) -> Vec<u8> {
    assert_eq!(
        key.len(),
        enctype.key_len(),
        "key length does not match the enctype"
    );
    let mut block: [u8; 16] = nfold(constant, 16).try_into().expect("16 octets");
    let mut out = Vec::with_capacity(enctype.key_len());
    while out.len() < enctype.key_len() {
        aes_block(key, enctype, &mut block);
        out.extend_from_slice(&block);
    }
    out.truncate(enctype.key_len());
    out
}

/// A MIC key for one direction: `Kc` derived once per context, as TSIG keys are today.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MicKey {
    #[zeroize(skip)]
    hmac: hmac::Key,
    #[zeroize(skip)]
    usage: u32,
}

impl MicKey {
    /// Derives `Kc` for `usage` (23 or 25) from the context key.
    pub fn new(context_key: &[u8], enctype: Enctype, usage: u32) -> Self {
        let mut constant = usage.to_be_bytes().to_vec();
        constant.push(0x99);
        let mut kc = derive_key(context_key, enctype, &constant);
        let hmac = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &kc);
        kc.zeroize();
        MicKey { hmac, usage }
    }

    /// The flags a sender under this key sets: the acceptor bit from the usage, the subkey
    /// bit when the context key is an acceptor subkey.
    pub fn sender_flags(&self, acceptor_subkey: bool) -> u8 {
        let mut flags = if self.usage == ACCEPTOR_SIGN {
            FLAG_SENT_BY_ACCEPTOR
        } else {
            0
        };
        if acceptor_subkey {
            flags |= FLAG_ACCEPTOR_SUBKEY;
        }
        flags
    }

    /// Signs `data` with sequence number `seq`; allocates nothing beyond the token.
    pub fn sign(&self, flags: u8, seq: u64, data: &[u8]) -> [u8; TOKEN_LEN] {
        let header = header(flags, seq);
        let mut ctx = hmac::Context::with_key(&self.hmac);
        ctx.update(data);
        ctx.update(&header);
        let tag = ctx.sign();
        let mut token = [0u8; TOKEN_LEN];
        token[..16].copy_from_slice(&header);
        token[16..].copy_from_slice(&tag.as_ref()[..12]);
        token
    }

    /// Verifies `token` over `data`. The caller checks the sequence number against its
    /// window; this checks the format, the direction flag and the checksum.
    pub fn verify(&self, token: &[u8], data: &[u8]) -> Result<Header, MicError> {
        if token.len() != TOKEN_LEN || token[..2] != TOKEN_ID || token[3..8] != FILLER {
            return Err(MicError::Malformed);
        }
        let flags = token[2];
        let from_acceptor = flags & FLAG_SENT_BY_ACCEPTOR != 0;
        // A key for usage 25 verifies tokens the initiator sent, and the other way round.
        let expect_acceptor = self.usage == ACCEPTOR_SIGN;
        if from_acceptor != expect_acceptor || flags & FLAG_SEALED != 0 {
            return Err(MicError::Flags);
        }
        let seq = u64::from_be_bytes(token[8..16].try_into().expect("8 octets"));
        let mut ctx = hmac::Context::with_key(&self.hmac);
        ctx.update(data);
        ctx.update(&token[..16]);
        let tag = ctx.sign();
        verify_slices_are_equal(&tag.as_ref()[..12], &token[16..])
            .map_err(|_| MicError::Checksum)?;
        Ok(Header { flags, seq })
    }
}

fn header(flags: u8, seq: u64) -> [u8; 16] {
    let mut h = [0u8; 16];
    h[..2].copy_from_slice(&TOKEN_ID);
    h[2] = flags;
    h[3..8].copy_from_slice(&FILLER);
    h[8..].copy_from_slice(&seq.to_be_bytes());
    h
}

/// The two MIC keys of one context, as Tenko's TSIG keyring would hold them.
pub struct ContextMicKeys {
    /// Verifies what the initiator sends (usage 25).
    pub initiator: MicKey,
    /// Signs what the acceptor sends (usage 23).
    pub acceptor: MicKey,
}

impl ContextMicKeys {
    /// Derives both keys from the context key.
    pub fn new(context_key: &[u8], enctype: Enctype) -> Self {
        ContextMicKeys {
            initiator: MicKey::new(context_key, enctype, INITIATOR_SIGN),
            acceptor: MicKey::new(context_key, enctype, ACCEPTOR_SIGN),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use picky_krb::crypto::aes::{AesSize, checksum_sha_aes};

    #[test]
    fn nfold_rfc3961_vectors() {
        // RFC 3961, appendix A.
        assert_eq!(
            nfold(b"012345", 8),
            [0xbe, 0x07, 0x26, 0x31, 0x27, 0x6b, 0x19, 0x55]
        );
        assert_eq!(
            nfold(b"password", 7),
            [0x78, 0xa0, 0x7b, 0x6c, 0xaf, 0x85, 0xfa]
        );
        assert_eq!(
            nfold(b"Rough Consensus, and Running Code", 8),
            [0xbb, 0x6e, 0xd3, 0x08, 0x70, 0xb7, 0xf0, 0xe0]
        );
        assert_eq!(
            nfold(b"password", 21),
            [
                0x59, 0xe4, 0xa8, 0xca, 0x7c, 0x03, 0x85, 0xc3, 0xc3, 0x7b, 0x3f, 0x6d, 0x20, 0x00,
                0x24, 0x7c, 0xb6, 0xe6, 0xbd, 0x5b, 0x3e
            ]
        );
        assert_eq!(
            nfold(b"kerberos", 16),
            [
                0x6b, 0x65, 0x72, 0x62, 0x65, 0x72, 0x6f, 0x73, 0x7b, 0x9b, 0x5b, 0x2b, 0x93, 0x13,
                0x2b, 0x93
            ]
        );
    }

    #[test]
    fn checksum_matches_picky_krb_for_both_key_sizes() {
        let data = b"the TSIG digest data of an update";
        for (enctype, aes) in [
            (Enctype::Aes128, AesSize::Aes128),
            (Enctype::Aes256, AesSize::Aes256),
        ] {
            let mut key = vec![0u8; enctype.key_len()];
            for (i, b) in key.iter_mut().enumerate() {
                *b = (i as u8).wrapping_mul(37).wrapping_add(11);
            }
            for usage in [INITIATOR_SIGN, ACCEPTOR_SIGN] {
                let mic = MicKey::new(&key, enctype, usage);
                let flags = mic.sender_flags(true);
                let token = mic.sign(flags, 0x1234_5678, data);
                let mut payload = data.to_vec();
                payload.extend_from_slice(&token[..16]);
                let expected = checksum_sha_aes(&key, usage as i32, &payload, &aes).unwrap();
                assert_eq!(
                    &token[16..],
                    expected.as_slice(),
                    "{enctype:?} usage {usage}"
                );
                assert_eq!(
                    mic.verify(&token, data),
                    Ok(Header {
                        flags,
                        seq: 0x1234_5678
                    })
                );
                let mut bad = token;
                bad[20] ^= 1;
                assert_eq!(mic.verify(&bad, data), Err(MicError::Checksum));
                let other = MicKey::new(
                    &key,
                    enctype,
                    if usage == INITIATOR_SIGN {
                        ACCEPTOR_SIGN
                    } else {
                        INITIATOR_SIGN
                    },
                );
                assert_eq!(other.verify(&token, data), Err(MicError::Flags));
            }
        }
    }
}
