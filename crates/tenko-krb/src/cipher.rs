//! RFC 3961 and RFC 3962 for `aes128-cts-hmac-sha1-96` (17) and `aes256-cts-hmac-sha1-96`
//! (18), Tenko's own code over the AES block function, HMAC-SHA1 and PBKDF2 of `aws-lc-rs`
//! (ADR 0026 point 1, CON-03).
//!
//! - [`nfold`] and [`derive_key`]: the n-fold of RFC 3961 section 5.1 and `DK(key,
//!   constant)` with the AES block function fed back on itself (`random-to-key` is the
//!   identity for AES).
//! - [`string_to_key`]: PBKDF2-HMAC-SHA1 with the iteration count (4,096 unless the KDC
//!   says otherwise), then `DK(tkey, "kerberos")` (RFC 3962 section 4).
//! - [`cts_encrypt`] and [`cts_decrypt`]: CBC with ciphertext stealing, the last two blocks
//!   swapped (RFC 3962 section 5), over unpadded CBC and ECB.
//! - [`encrypt`] and [`decrypt`]: a 16-octet random confounder, the CTS ciphertext under
//!   `Ke = DK(key, usage || 0xAA)` and HMAC-SHA1-96 under `Ki = DK(key, usage || 0x55)`,
//!   checked in constant time before any plaintext is returned.
//! - [`checksum`] and [`verify_checksum`]: `hmac-sha1-96-aes128` (15) and
//!   `hmac-sha1-96-aes256` (16) under `Kc = DK(key, usage || 0x99)`.
//!
//! RC4, DES and 3DES are not implemented (ADR 0026 point 3): any other encryption type is a
//! [`CipherError::UnsupportedEnctype`].

use std::num::NonZeroU32;

use aws_lc_rs::{
    cipher::{
        AES_128, AES_256, DecryptingKey, DecryptionContext, EncryptingKey, EncryptionContext,
        UnboundCipherKey,
    },
    constant_time::verify_slices_are_equal,
    hmac,
    iv::FixedLength,
    pbkdf2,
};
use tenko_core::dns::EncryptionType;
use zeroize::{Zeroize, Zeroizing};

use crate::der::EncryptionKey;

/// The AES block length.
pub const BLOCK_LEN: usize = 16;
/// The confounder's length: one block.
pub const CONFOUNDER_LEN: usize = 16;
/// The truncated HMAC-SHA1 of the encryption and checksum types.
pub const HMAC_LEN: usize = 12;
/// The shortest ciphertext: a confounder and the HMAC.
pub const MIN_CIPHERTEXT_LEN: usize = CONFOUNDER_LEN + HMAC_LEN;
/// The default PBKDF2 iteration count of RFC 3962 section 4.
pub const DEFAULT_ITERATIONS: u32 = 4096;
/// The largest iteration count Tenko derives a key with. A KDC's `s2kparams` arrive before
/// the KDC is authenticated, so the count bounds the work an answer can ask for (about a
/// second of PBKDF2-HMAC-SHA1).
pub const MAX_ITERATIONS: u32 = 1 << 20;

/// The checksum type `hmac-sha1-96-aes128`.
pub const CKSUM_HMAC_SHA1_96_AES128: i32 = 15;
/// The checksum type `hmac-sha1-96-aes256`.
pub const CKSUM_HMAC_SHA1_96_AES256: i32 = 16;

/// The key usage numbers of RFC 4120 section 7.5.1, RFC 4121 section 2 and [MS-PAC].
pub mod usage {
    /// `PA-ENC-TIMESTAMP`, encrypted with the client's key.
    pub const PA_ENC_TIMESTAMP: u32 = 1;
    /// The ticket's `enc-part`, under the service key.
    pub const TICKET: u32 = 2;
    /// The AS-REP's `enc-part`, under the client's key.
    pub const AS_REP_ENC_PART: u32 = 3;
    /// The checksum of a TGS request's body in its authenticator.
    pub const TGS_REQ_AUTH_CKSUM: u32 = 6;
    /// A TGS request's authenticator, under the TGT's session key.
    pub const TGS_REQ_AUTHENTICATOR: u32 = 7;
    /// The TGS-REP's `enc-part`, under the TGT's session key.
    pub const TGS_REP_ENC_PART_SESSION: u32 = 8;
    /// The TGS-REP's `enc-part`, under the authenticator's subkey.
    pub const TGS_REP_ENC_PART_SUBKEY: u32 = 9;
    /// An AP-REQ's authenticator, under the ticket's session key.
    pub const AP_REQ_AUTHENTICATOR: u32 = 11;
    /// The AP-REP's `enc-part`, under the ticket's session key.
    pub const AP_REP_ENC_PART: u32 = 12;
    /// A `KRB-PRIV`'s `enc-part`.
    pub const KRB_PRIV_ENC_PART: u32 = 13;
    /// The signatures of the PAC ([MS-PAC] section 2.8, the "non-Kerberos checksum salt").
    pub const PAC_CHECKSUM: u32 = 17;
    /// GSS-API tokens sent by the acceptor (MIC).
    pub const ACCEPTOR_SIGN: u32 = 23;
    /// GSS-API tokens sent by the initiator (MIC).
    pub const INITIATOR_SIGN: u32 = 25;
}

/// Why a cryptographic operation was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CipherError {
    /// An encryption type other than 17 and 18 (RC4, DES and 3DES are never accepted).
    #[error("encryption type {0} is not aes128-cts-hmac-sha1-96 or aes256-cts-hmac-sha1-96")]
    UnsupportedEnctype(i32),
    /// A checksum type other than 15 and 16, or one that does not match the key.
    #[error("checksum type {0} is not hmac-sha1-96 for this key")]
    UnsupportedChecksum(i32),
    /// A key of the wrong length for its type.
    #[error("a key of {0} octets does not match its encryption type")]
    KeyLength(usize),
    /// A ciphertext shorter than a confounder and the HMAC.
    #[error("the ciphertext is too short")]
    Truncated,
    /// The integrity check failed: the wrong key, or the ciphertext was changed.
    #[error("the integrity check failed")]
    Integrity,
    /// A checksum that does not verify.
    #[error("the checksum does not verify")]
    Checksum,
    /// An iteration count of 0 or above [`MAX_ITERATIONS`], or `s2kparams` that are not
    /// four octets.
    #[error("the string-to-key parameters are refused")]
    Iterations,
    /// The AES library or the random generator failed.
    #[error("the cryptographic library failed")]
    Library,
}

/// The encryption type of an RFC 3961 number.
///
/// # Errors
///
/// [`CipherError::UnsupportedEnctype`] for anything but 17 and 18.
pub fn enctype(number: i32) -> Result<EncryptionType, CipherError> {
    EncryptionType::from_number(number).ok_or(CipherError::UnsupportedEnctype(number))
}

/// The key length of an encryption type.
pub const fn key_len(etype: EncryptionType) -> usize {
    match etype {
        EncryptionType::Aes128CtsHmacSha1 => 16,
        EncryptionType::Aes256CtsHmacSha1 => 32,
    }
}

/// The checksum type that goes with an encryption type.
pub const fn checksum_type(etype: EncryptionType) -> i32 {
    match etype {
        EncryptionType::Aes128CtsHmacSha1 => CKSUM_HMAC_SHA1_96_AES128,
        EncryptionType::Aes256CtsHmacSha1 => CKSUM_HMAC_SHA1_96_AES256,
    }
}

/// A key of one of the two AES encryption types. The octets are zeroed on drop and never
/// printed.
#[derive(Clone, PartialEq, Eq)]
pub struct Key {
    etype: EncryptionType,
    bytes: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Key({:?})", self.etype)
    }
}

impl Key {
    /// A key from its type and octets.
    ///
    /// # Errors
    ///
    /// [`CipherError::KeyLength`] when the length does not match the type.
    pub fn new(etype: EncryptionType, bytes: &[u8]) -> Result<Self, CipherError> {
        if bytes.len() != key_len(etype) {
            return Err(CipherError::KeyLength(bytes.len()));
        }
        Ok(Self {
            etype,
            bytes: Zeroizing::new(bytes.to_vec()),
        })
    }

    /// A key from an `EncryptionKey` on the wire.
    ///
    /// # Errors
    ///
    /// [`CipherError::UnsupportedEnctype`] or [`CipherError::KeyLength`].
    pub fn from_wire(key: &EncryptionKey) -> Result<Self, CipherError> {
        Self::new(enctype(key.keytype)?, &key.value)
    }

    /// A fresh random key of `etype` (a subkey, a session key in tests).
    ///
    /// # Errors
    ///
    /// [`CipherError::Library`] when the random generator fails.
    pub fn random(etype: EncryptionType) -> Result<Self, CipherError> {
        let mut bytes = Zeroizing::new(vec![0_u8; key_len(etype)]);
        aws_lc_rs::rand::fill(&mut bytes).map_err(|_| CipherError::Library)?;
        Ok(Self { etype, bytes })
    }

    /// The `EncryptionKey` for the wire.
    pub fn to_wire(&self) -> EncryptionKey {
        EncryptionKey {
            keytype: self.etype.number(),
            value: self.bytes.clone(),
        }
    }

    /// The encryption type.
    pub const fn etype(&self) -> EncryptionType {
        self.etype
    }

    /// The key octets.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

// ---------------------------------------------------------------------------------------
// n-fold and the derived keys

/// RFC 3961 section 5.1 n-fold: `input` stretched or shrunk to `out_len` octets by 13-bit
/// rotations and ones'-complement addition.
///
/// # Panics
///
/// When `input` or `out_len` is empty (every caller passes a constant).
pub fn nfold(input: &[u8], out_len: usize) -> Vec<u8> {
    assert!(!input.is_empty() && out_len > 0, "n-fold of nothing");
    let in_len = input.len();
    let lcm = in_len * out_len / gcd(in_len, out_len);
    let mut out = vec![0_u8; out_len];
    // Octet `i` of the concatenation of the copies of the input, each rotated right by 13
    // bits more than the one before.
    let octet = |i: usize| -> u8 {
        let copy = i / in_len;
        let rotate = (13 * copy) % (in_len * 8);
        let pos = i % in_len;
        let octet_shift = rotate / 8;
        let bit_shift = rotate % 8;
        let a = input[(pos + in_len - octet_shift) % in_len];
        if bit_shift == 0 {
            a
        } else {
            let b = input[(pos + 2 * in_len - octet_shift - 1) % in_len];
            (a >> bit_shift) | (b << (8 - bit_shift))
        }
    };
    let mut carry: u32 = 0;
    for i in (0..out_len).rev() {
        let mut sum: u32 = carry;
        let mut j = i;
        while j < lcm {
            sum += u32::from(octet(j));
            j += out_len;
        }
        out[i] = sum.to_le_bytes()[0];
        carry = sum >> 8;
    }
    // The end-around carry.
    while carry != 0 {
        for octet in out.iter_mut().rev() {
            let sum = u32::from(*octet) + carry;
            *octet = sum.to_le_bytes()[0];
            carry = sum >> 8;
            if carry == 0 {
                break;
            }
        }
    }
    out
}

const fn gcd(mut a: usize, mut b: usize) -> usize {
    while b != 0 {
        let t = a % b;
        a = b;
        b = t;
    }
    a
}

fn aes_algorithm(etype: EncryptionType) -> &'static aws_lc_rs::cipher::Algorithm {
    match etype {
        EncryptionType::Aes128CtsHmacSha1 => &AES_128,
        EncryptionType::Aes256CtsHmacSha1 => &AES_256,
    }
}

fn encrypting(key: &[u8], etype: EncryptionType, cbc: bool) -> Result<EncryptingKey, CipherError> {
    let unbound =
        UnboundCipherKey::new(aes_algorithm(etype), key).map_err(|_| CipherError::Library)?;
    if cbc {
        EncryptingKey::cbc(unbound)
    } else {
        EncryptingKey::ecb(unbound)
    }
    .map_err(|_| CipherError::Library)
}

fn decrypting(key: &[u8], etype: EncryptionType, cbc: bool) -> Result<DecryptingKey, CipherError> {
    let unbound =
        UnboundCipherKey::new(aes_algorithm(etype), key).map_err(|_| CipherError::Library)?;
    if cbc {
        DecryptingKey::cbc(unbound)
    } else {
        DecryptingKey::ecb(unbound)
    }
    .map_err(|_| CipherError::Library)
}

/// RFC 3961 section 5.1 `DK(key, constant)` for AES: `DR` is the AES block function applied
/// to `n-fold(constant, 16)` and then to its own output until the key length is filled.
///
/// # Errors
///
/// [`CipherError::Library`] when the AES library fails.
pub fn derive_key(key: &Key, constant: &[u8]) -> Result<Key, CipherError> {
    let ecb = encrypting(key.as_bytes(), key.etype, false)?;
    let mut block = Zeroizing::new([0_u8; BLOCK_LEN]);
    block.copy_from_slice(&nfold(constant, BLOCK_LEN));
    let len = key_len(key.etype);
    let mut out = Zeroizing::new(Vec::with_capacity(len));
    while out.len() < len {
        ecb.less_safe_encrypt(&mut block[..], EncryptionContext::None)
            .map_err(|_| CipherError::Library)?;
        let take = (len - out.len()).min(BLOCK_LEN);
        out.extend_from_slice(&block[..take]);
    }
    Key::new(key.etype, &out)
}

/// The key `DK(key, usage || kind)` of one usage: `0x99` for checksums, `0xAA` for
/// encryption, `0x55` for the integrity HMAC.
///
/// # Errors
///
/// [`CipherError::Library`] when the AES library fails.
pub fn usage_key(key: &Key, usage: u32, kind: u8) -> Result<Key, CipherError> {
    let mut constant = [0_u8; 5];
    constant[..4].copy_from_slice(&usage.to_be_bytes());
    constant[4] = kind;
    derive_key(key, &constant)
}

/// The constant byte of a checksum key.
pub const KIND_CHECKSUM: u8 = 0x99;
/// The constant byte of an encryption key.
pub const KIND_ENCRYPTION: u8 = 0xaa;
/// The constant byte of an integrity key.
pub const KIND_INTEGRITY: u8 = 0x55;

// ---------------------------------------------------------------------------------------
// string-to-key

/// The iteration count of `s2kparams`: four octets, big-endian (RFC 3962 section 4); absent:
/// [`DEFAULT_ITERATIONS`].
///
/// # Errors
///
/// [`CipherError::Iterations`] when the parameters are not four octets or the count is 0 or
/// above [`MAX_ITERATIONS`].
pub fn iterations(s2kparams: Option<&[u8]>) -> Result<u32, CipherError> {
    let Some(params) = s2kparams else {
        return Ok(DEFAULT_ITERATIONS);
    };
    let bytes: [u8; 4] = params.try_into().map_err(|_| CipherError::Iterations)?;
    let count = u32::from_be_bytes(bytes);
    if count == 0 || count > MAX_ITERATIONS {
        return Err(CipherError::Iterations);
    }
    Ok(count)
}

/// RFC 3962 section 4 string-to-key: `DK(PBKDF2-HMAC-SHA1(password, salt, iterations),
/// "kerberos")`. The password is its UTF-8 octets ([MS-KILE] section 3.1.5.2 for AD).
///
/// # Errors
///
/// [`CipherError::Iterations`] for a count of 0 or above [`MAX_ITERATIONS`];
/// [`CipherError::Library`] when the AES library fails.
pub fn string_to_key(
    etype: EncryptionType,
    password: &[u8],
    salt: &[u8],
    iterations: u32,
) -> Result<Key, CipherError> {
    if iterations > MAX_ITERATIONS {
        return Err(CipherError::Iterations);
    }
    let count = NonZeroU32::new(iterations).ok_or(CipherError::Iterations)?;
    let mut tkey = Zeroizing::new(vec![0_u8; key_len(etype)]);
    pbkdf2::derive(pbkdf2::PBKDF2_HMAC_SHA1, count, salt, password, &mut tkey);
    derive_key(&Key::new(etype, &tkey)?, b"kerberos")
}

// ---------------------------------------------------------------------------------------
// AES-CTS

fn zero_iv() -> FixedLength<BLOCK_LEN> {
    FixedLength::from([0_u8; BLOCK_LEN])
}

/// RFC 3962 section 5 CBC with ciphertext stealing and a zero IV, in place: one block is
/// plain CBC; longer input is CBC over the input padded with zeros, the last two blocks
/// swapped and the result cut to the input's length (the stolen octets are the padding).
///
/// # Errors
///
/// [`CipherError::Truncated`] for input shorter than one block;
/// [`CipherError::KeyLength`] or [`CipherError::Library`] for a bad key.
pub fn cts_encrypt(key: &Key, data: &mut [u8]) -> Result<(), CipherError> {
    let len = data.len();
    if len < BLOCK_LEN {
        return Err(CipherError::Truncated);
    }
    let cbc = encrypting(key.as_bytes(), key.etype, true)?;
    let blocks = len.div_ceil(BLOCK_LEN);
    let mut buf = Zeroizing::new(vec![0_u8; blocks * BLOCK_LEN]);
    buf[..len].copy_from_slice(data);
    cbc.less_safe_encrypt(&mut buf, EncryptionContext::Iv128(zero_iv()))
        .map_err(|_| CipherError::Library)?;
    if blocks > 1 {
        let (head, last) = buf.split_at_mut((blocks - 1) * BLOCK_LEN);
        head[(blocks - 2) * BLOCK_LEN..].swap_with_slice(last);
    }
    data.copy_from_slice(&buf[..len]);
    Ok(())
}

/// The inverse of [`cts_encrypt`], in place.
///
/// # Errors
///
/// As [`cts_encrypt`].
pub fn cts_decrypt(key: &Key, data: &mut [u8]) -> Result<(), CipherError> {
    let len = data.len();
    if len < BLOCK_LEN {
        return Err(CipherError::Truncated);
    }
    let blocks = len.div_ceil(BLOCK_LEN);
    let mut buf = Zeroizing::new(vec![0_u8; blocks * BLOCK_LEN]);
    if blocks == 1 {
        buf.copy_from_slice(data);
    } else {
        // The octets: C1 .. C(n-2), then Cn in full, then the first r octets of C(n-1).
        let tail = len - (blocks - 1) * BLOCK_LEN;
        let full = (blocks - 2) * BLOCK_LEN;
        buf[..full].copy_from_slice(&data[..full]);
        let mut last = Zeroizing::new([0_u8; BLOCK_LEN]);
        last.copy_from_slice(&data[full..full + BLOCK_LEN]);
        // D = AES^-1(Cn) = (Pn || 0) xor C(n-1): its octets past r are those of C(n-1).
        let mut d = Zeroizing::new(*last);
        decrypting(key.as_bytes(), key.etype, false)?
            .decrypt(&mut d[..], DecryptionContext::None)
            .map_err(|_| CipherError::Library)?;
        let previous = &mut buf[full..full + BLOCK_LEN];
        previous[..tail].copy_from_slice(&data[full + BLOCK_LEN..]);
        previous[tail..].copy_from_slice(&d[tail..]);
        buf[full + BLOCK_LEN..].copy_from_slice(&last[..]);
    }
    decrypting(key.as_bytes(), key.etype, true)?
        .decrypt(&mut buf, DecryptionContext::Iv128(zero_iv()))
        .map_err(|_| CipherError::Library)?;
    data.copy_from_slice(&buf[..len]);
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Encryption and checksums

fn hmac_sha1_96(key: &Key, parts: &[&[u8]]) -> [u8; HMAC_LEN] {
    let hmac_key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, key.as_bytes());
    let mut context = hmac::Context::with_key(&hmac_key);
    for part in parts {
        context.update(part);
    }
    let tag = context.sign();
    let mut out = [0_u8; HMAC_LEN];
    out.copy_from_slice(&tag.as_ref()[..HMAC_LEN]);
    out
}

/// Encrypts `plaintext` for `usage` with a fresh random confounder.
///
/// # Errors
///
/// [`CipherError::Library`] when the random generator or AES fails.
pub fn encrypt(key: &Key, usage: u32, plaintext: &[u8]) -> Result<Vec<u8>, CipherError> {
    let mut confounder = Zeroizing::new([0_u8; CONFOUNDER_LEN]);
    aws_lc_rs::rand::fill(&mut confounder[..]).map_err(|_| CipherError::Library)?;
    encrypt_with_confounder(key, usage, &confounder, plaintext)
}

/// Encrypts with a given confounder: for the test vectors only, since a confounder must
/// be random.
///
/// # Errors
///
/// As [`encrypt`].
pub fn encrypt_with_confounder(
    key: &Key,
    usage: u32,
    confounder: &[u8; CONFOUNDER_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, CipherError> {
    let ke = usage_key(key, usage, KIND_ENCRYPTION)?;
    let ki = usage_key(key, usage, KIND_INTEGRITY)?;
    let mut out = Vec::with_capacity(CONFOUNDER_LEN + plaintext.len() + HMAC_LEN);
    out.extend_from_slice(confounder);
    out.extend_from_slice(plaintext);
    let mac = hmac_sha1_96(&ki, &[&out]);
    if let Err(error) = cts_encrypt(&ke, &mut out) {
        out.zeroize();
        return Err(error);
    }
    out.extend_from_slice(&mac);
    Ok(out)
}

/// Decrypts `ciphertext` for `usage`. The HMAC is checked in constant time and no
/// plaintext is returned unless it matches.
///
/// # Errors
///
/// [`CipherError::Truncated`] for less than [`MIN_CIPHERTEXT_LEN`] octets,
/// [`CipherError::Integrity`] when the HMAC does not match (the wrong key or a changed
/// ciphertext), [`CipherError::Library`] when AES fails.
pub fn decrypt(
    key: &Key,
    usage: u32,
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CipherError> {
    if ciphertext.len() < MIN_CIPHERTEXT_LEN {
        return Err(CipherError::Truncated);
    }
    let (body, mac) = ciphertext.split_at(ciphertext.len() - HMAC_LEN);
    let ke = usage_key(key, usage, KIND_ENCRYPTION)?;
    let ki = usage_key(key, usage, KIND_INTEGRITY)?;
    let mut plain = Zeroizing::new(body.to_vec());
    cts_decrypt(&ke, &mut plain)?;
    let expected = hmac_sha1_96(&ki, &[&plain]);
    verify_slices_are_equal(&expected, mac).map_err(|_| CipherError::Integrity)?;
    plain.drain(..CONFOUNDER_LEN);
    Ok(plain)
}

/// Decrypts an `EncryptedData`, checking that its type is the key's.
///
/// # Errors
///
/// [`CipherError::UnsupportedEnctype`] when the types differ or are not AES, else as
/// [`decrypt`].
pub fn decrypt_data(
    key: &Key,
    usage: u32,
    data: &crate::der::EncryptedData,
) -> Result<Zeroizing<Vec<u8>>, CipherError> {
    if data.etype != key.etype.number() {
        return Err(CipherError::UnsupportedEnctype(data.etype));
    }
    decrypt(key, usage, &data.cipher)
}

/// Encrypts into an `EncryptedData` of the key's type, without a key version.
///
/// # Errors
///
/// As [`encrypt`].
pub fn encrypt_data(
    key: &Key,
    usage: u32,
    plaintext: &[u8],
) -> Result<crate::der::EncryptedData, CipherError> {
    Ok(crate::der::EncryptedData {
        etype: key.etype.number(),
        kvno: None,
        cipher: encrypt(key, usage, plaintext)?,
    })
}

/// The `hmac-sha1-96-aes*` checksum of `data` for `usage`.
///
/// # Errors
///
/// [`CipherError::Library`] when AES fails.
pub fn checksum(key: &Key, usage: u32, data: &[u8]) -> Result<[u8; HMAC_LEN], CipherError> {
    let kc = usage_key(key, usage, KIND_CHECKSUM)?;
    Ok(hmac_sha1_96(&kc, &[data]))
}

/// Verifies a checksum of type `cksumtype` over `data` in constant time. The type must be
/// the one that goes with the key's encryption type.
///
/// # Errors
///
/// [`CipherError::UnsupportedChecksum`] for another type, [`CipherError::Checksum`] when
/// it does not match.
pub fn verify_checksum(
    key: &Key,
    usage: u32,
    cksumtype: i32,
    data: &[u8],
    expected: &[u8],
) -> Result<(), CipherError> {
    if cksumtype != checksum_type(key.etype) {
        return Err(CipherError::UnsupportedChecksum(cksumtype));
    }
    let computed = checksum(key, usage, data)?;
    verify_slices_are_equal(&computed, expected).map_err(|_| CipherError::Checksum)
}

/// The salts of string-to-key for Active Directory accounts ([MS-KILE] section 3.1.5.2,
/// identity plan section 3.1).
pub mod salt {
    use tenko_core::dns::{KrbAccount, PrincipalName};

    /// The default salt of RFC 4120 section 4, which [MS-KILE] keeps for user accounts:
    /// the realm, then each component of the name as it is written
    /// (`CORP.EXAMPLE.TESTalice`).
    pub fn principal(principal: &PrincipalName) -> String {
        let mut out = principal.realm().as_str().to_owned();
        for component in principal.components() {
            out.push_str(component);
        }
        out
    }

    /// The salt of the service account: for a computer account (a name ending in `$`) the
    /// rule of [MS-KILE] that `tenko-core` computes (the realm in upper case, `host`, the
    /// name in lower case without the `$`, a dot, the realm in lower case:
    /// `CORP.EXAMPLE.TESThosttenko-dns.corp.example.test`), for a user account the realm
    /// and the name.
    pub fn account(account: &KrbAccount) -> String {
        account
            .computer_salt()
            .unwrap_or_else(|| format!("{}{}", account.realm.as_str(), account.name))
    }
}

#[cfg(test)]
mod tests;
