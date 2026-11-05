//! RFC 4121 MIC tokens over the context key: the per-message signature of GSS-TSIG
//! (RFC 3645 section 5, DNS-28) and of the SPNEGO `mechListMIC`.
//!
//! A token is a 16-octet header (`04 04`, the flags, five `ff` octets, the sender's 64-bit
//! sequence number) and HMAC-SHA1-96 over the data followed by the header, under
//! `Kc = DK(context key, usage || 0x99)`, with usage 25 for what the initiator sends and 23
//! for what the acceptor sends (RFC 4121 section 4.2.6.1, RFC 3961 section 5.3).
//!
//! The two keys are derived once per context ([`ContextMicKeys::new`]); signing and
//! verifying then allocate nothing and compute one HMAC, as TSIG does. The data may be fed
//! in pieces ([`MicKey::begin`]), so that the TSIG module hands over its digest data as it
//! writes it. Checksums are compared in constant time. The receiver checks the sequence
//! number against its own window; this module checks the format and the flags.

use aws_lc_rs::{constant_time::verify_slices_are_equal, hmac};

use crate::cipher::{self, CipherError, Key, usage};

/// Flag: the token was sent by the acceptor.
pub const FLAG_SENT_BY_ACCEPTOR: u8 = 0x01;
/// Flag: a wrap token with confidentiality; never set on a MIC.
pub const FLAG_SEALED: u8 = 0x02;
/// Flag: the context key is the acceptor's subkey.
pub const FLAG_ACCEPTOR_SUBKEY: u8 = 0x04;

/// The token identifier of a MIC token.
pub const TOKEN_ID: [u8; 2] = [0x04, 0x04];
const FILLER: [u8; 5] = [0xff; 5];
/// The header's length.
pub const HEADER_LEN: usize = 16;
/// A MIC token's length: the header and HMAC-SHA1-96.
pub const TOKEN_LEN: usize = HEADER_LEN + cipher::HMAC_LEN;

/// The header of a verified token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// The flags.
    pub flags: u8,
    /// The sender's sequence number.
    pub seq: u64,
}

/// Why a MIC token did not verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MicError {
    /// Not 28 octets, or not the MIC token identifier and filler.
    #[error("not a MIC token")]
    Malformed,
    /// The direction flag is not the sender's, the sealed flag is set, or the
    /// acceptor-subkey flag does not match the context.
    #[error("the token's flags do not match the context")]
    Flags,
    /// The checksum does not match.
    #[error("the MIC does not verify")]
    Checksum,
}

/// The MIC key of one direction.
pub struct MicKey {
    hmac: hmac::Key,
    sent_by_acceptor: bool,
    acceptor_subkey: bool,
}

impl std::fmt::Debug for MicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MicKey")
            .field("sent_by_acceptor", &self.sent_by_acceptor)
            .field("acceptor_subkey", &self.acceptor_subkey)
            .finish_non_exhaustive()
    }
}

/// A MIC being computed over data fed in pieces.
pub struct MicContext<'a> {
    key: &'a MicKey,
    context: hmac::Context,
}

impl MicContext<'_> {
    /// Feeds data.
    pub fn update(&mut self, data: &[u8]) {
        self.context.update(data);
    }

    /// The token for the data fed, with the sender's flags and `seq`.
    pub fn sign(mut self, seq: u64) -> [u8; TOKEN_LEN] {
        let header = header(self.key.flags(), seq);
        self.context.update(&header);
        let tag = self.context.sign();
        let mut token = [0_u8; TOKEN_LEN];
        token[..HEADER_LEN].copy_from_slice(&header);
        token[HEADER_LEN..].copy_from_slice(&tag.as_ref()[..cipher::HMAC_LEN]);
        token
    }

    /// Verifies `token` over the data fed.
    ///
    /// # Errors
    ///
    /// A [`MicError`].
    pub fn verify(mut self, token: &[u8]) -> Result<Header, MicError> {
        let parsed = self.key.check_header(token)?;
        self.context.update(&token[..HEADER_LEN]);
        let tag = self.context.sign();
        verify_slices_are_equal(&tag.as_ref()[..cipher::HMAC_LEN], &token[HEADER_LEN..])
            .map_err(|_| MicError::Checksum)?;
        Ok(parsed)
    }
}

impl MicKey {
    /// The key of the sender `usage` (23 for the acceptor, 25 for the initiator) over the
    /// context key; `acceptor_subkey` says whether the context key is the acceptor's
    /// subkey, which sets [`FLAG_ACCEPTOR_SUBKEY`] in both directions.
    ///
    /// # Errors
    ///
    /// [`CipherError::Library`] when AES fails.
    pub fn new(
        context_key: &Key,
        sent_by_acceptor: bool,
        acceptor_subkey: bool,
    ) -> Result<Self, CipherError> {
        let key_usage = if sent_by_acceptor {
            usage::ACCEPTOR_SIGN
        } else {
            usage::INITIATOR_SIGN
        };
        let kc = cipher::usage_key(context_key, key_usage, cipher::KIND_CHECKSUM)?;
        Ok(Self {
            hmac: hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, kc.as_bytes()),
            sent_by_acceptor,
            acceptor_subkey,
        })
    }

    /// The flags a sender under this key sets.
    pub const fn flags(&self) -> u8 {
        let mut flags = 0;
        if self.sent_by_acceptor {
            flags |= FLAG_SENT_BY_ACCEPTOR;
        }
        if self.acceptor_subkey {
            flags |= FLAG_ACCEPTOR_SUBKEY;
        }
        flags
    }

    /// Starts a MIC over data fed in pieces.
    pub fn begin(&self) -> MicContext<'_> {
        MicContext {
            key: self,
            context: hmac::Context::with_key(&self.hmac),
        }
    }

    /// The token over `data` with sequence number `seq`.
    pub fn sign(&self, seq: u64, data: &[u8]) -> [u8; TOKEN_LEN] {
        let mut context = self.begin();
        context.update(data);
        context.sign(seq)
    }

    /// Verifies `token` over `data`.
    ///
    /// # Errors
    ///
    /// A [`MicError`].
    pub fn verify(&self, token: &[u8], data: &[u8]) -> Result<Header, MicError> {
        let mut context = self.begin();
        context.update(data);
        context.verify(token)
    }

    fn check_header(&self, token: &[u8]) -> Result<Header, MicError> {
        if token.len() != TOKEN_LEN || token[..2] != TOKEN_ID || token[3..8] != FILLER {
            return Err(MicError::Malformed);
        }
        let flags = token[2];
        // Unknown flag bits are ignored (RFC 4121 section 4.2.2).
        if (flags & FLAG_SENT_BY_ACCEPTOR != 0) != self.sent_by_acceptor
            || flags & FLAG_SEALED != 0
            || (flags & FLAG_ACCEPTOR_SUBKEY != 0) != self.acceptor_subkey
        {
            return Err(MicError::Flags);
        }
        let mut seq = [0_u8; 8];
        seq.copy_from_slice(&token[8..HEADER_LEN]);
        Ok(Header {
            flags,
            seq: u64::from_be_bytes(seq),
        })
    }
}

fn header(flags: u8, seq: u64) -> [u8; HEADER_LEN] {
    let mut h = [0_u8; HEADER_LEN];
    h[..2].copy_from_slice(&TOKEN_ID);
    h[2] = flags;
    h[3..8].copy_from_slice(&FILLER);
    h[8..].copy_from_slice(&seq.to_be_bytes());
    h
}

/// The two MIC keys of an acceptor's context, as the TSIG keyring holds them.
#[derive(Debug)]
pub struct ContextMicKeys {
    /// Verifies what the initiator sends (usage 25).
    pub initiator: MicKey,
    /// Signs what the acceptor sends (usage 23).
    pub acceptor: MicKey,
}

impl ContextMicKeys {
    /// Derives both keys from the context key.
    ///
    /// # Errors
    ///
    /// [`CipherError::Library`] when AES fails.
    pub fn new(context_key: &Key, acceptor_subkey: bool) -> Result<Self, CipherError> {
        Ok(Self {
            initiator: MicKey::new(context_key, false, acceptor_subkey)?,
            acceptor: MicKey::new(context_key, true, acceptor_subkey)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use tenko_core::dns::EncryptionType;

    use super::*;
    use crate::fixtures;

    /// DNS-28: the recorded MICs both ways under the context key MIT ended with: MIT's two
    /// MICs verify with Tenko's code, with consecutive sequence numbers, and the MIC Tenko
    /// computes for the acceptor's message is octet for octet the one MIT's
    /// `gss_verify_mic` accepted.
    #[test]
    fn dns_28_recorded_mics_verify_both_ways() {
        for f in fixtures::all() {
            let etype = if f.ctxkey.len() == 16 {
                EncryptionType::Aes128CtsHmacSha1
            } else {
                EncryptionType::Aes256CtsHmacSha1
            };
            let key = Key::new(etype, &f.ctxkey).expect("context key");
            let keys = ContextMicKeys::new(&key, true).expect("keys");
            let first = keys
                .initiator
                .verify(&f.initmic, &f.msg)
                .unwrap_or_else(|e| panic!("{}: {e}", f.name));
            assert_eq!(first.flags, FLAG_ACCEPTOR_SUBKEY, "{}", f.name);
            let second = keys.initiator.verify(&f.initmic2, &f.msg2).expect("second");
            assert_eq!(second.seq, first.seq + 1, "{}", f.name);
            assert_eq!(
                keys.initiator.verify(&f.initmic, &f.msg2),
                Err(MicError::Checksum)
            );
            let seq = u64::from_be_bytes(f.accmic[8..16].try_into().expect("seq"));
            assert_eq!(
                keys.acceptor.sign(seq, &f.accmsg).to_vec(),
                f.accmic,
                "{}",
                f.name
            );
            assert_eq!(
                keys.acceptor.verify(&f.accmic, &f.accmsg).map(|h| h.seq),
                Ok(seq)
            );
        }
    }

    #[test]
    fn tokens_sign_and_verify_both_ways_in_pieces() {
        for etype in [
            EncryptionType::Aes128CtsHmacSha1,
            EncryptionType::Aes256CtsHmacSha1,
        ] {
            let key = Key::random(etype).expect("key");
            let keys = ContextMicKeys::new(&key, true).expect("keys");
            let token = keys.acceptor.sign(7, b"the TSIG digest data");
            assert_eq!(token[2], FLAG_SENT_BY_ACCEPTOR | FLAG_ACCEPTOR_SUBKEY);
            // The peer's view: its "acceptor" key verifies what the acceptor sent.
            let peer = ContextMicKeys::new(&key, true).expect("peer");
            let mut context = peer.acceptor.begin();
            context.update(b"the TSIG ");
            context.update(b"digest data");
            assert_eq!(context.verify(&token), Ok(Header { flags: 5, seq: 7 }));
            // The wrong direction, a changed octet, a wrong length, the sealed flag.
            assert_eq!(
                peer.initiator.verify(&token, b"the TSIG digest data"),
                Err(MicError::Flags)
            );
            let mut changed = token;
            changed[20] ^= 1;
            assert_eq!(
                peer.acceptor.verify(&changed, b"the TSIG digest data"),
                Err(MicError::Checksum)
            );
            assert_eq!(
                peer.acceptor.verify(&token, b"other data"),
                Err(MicError::Checksum)
            );
            assert_eq!(
                peer.acceptor.verify(&token[..27], b"x"),
                Err(MicError::Malformed)
            );
            let mut sealed = token;
            sealed[2] |= FLAG_SEALED;
            assert_eq!(peer.acceptor.verify(&sealed, b"x"), Err(MicError::Flags));
            let mut filler = token;
            filler[5] = 0;
            assert_eq!(
                peer.acceptor.verify(&filler, b"x"),
                Err(MicError::Malformed)
            );
            // The subkey flag must match the context.
            let no_subkey = ContextMicKeys::new(&key, false).expect("keys");
            assert_eq!(
                no_subkey.acceptor.verify(&token, b"the TSIG digest data"),
                Err(MicError::Flags)
            );
            // An unknown flag bit is ignored, but it is covered by the checksum.
            let mut extra = token;
            extra[2] |= 0x80;
            assert_eq!(
                peer.acceptor.verify(&extra, b"the TSIG digest data"),
                Err(MicError::Checksum)
            );
        }
    }
}
