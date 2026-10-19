//! RRSIG records (RFC 4034, section 3): making one, and deciding whether one already in
//! the zone can stay.
//!
//! A signature's inception is one hour before the signing time, so that validators whose
//! clock is behind still accept it. Its expiration is `signature_validity_days` after the
//! signing time less a random jitter of up to half of `resign_before_days`, so that the
//! signatures of a zone signed at once expire, and are renewed, spread over days instead
//! of in one pass.

use tenko_core::{
    Timestamp,
    dns::{DnsName, DnssecPolicy, Rdata, RecordData, Rtype},
};

use super::{
    canonical::{RrsigHead, rrsig_labels, signed_data, slices},
    crypto::{CryptoError, verify},
    keys::LoadedKey,
};

/// How far before the signing time a signature's inception lies.
pub const INCEPTION_OFFSET_SECS: u32 = 3600;

/// How far in the future an inception may lie for a signature to be kept (clock skew).
pub const FUTURE_SKEW_SECS: u32 = 300;

/// Seconds of a day.
pub const DAY_SECS: u32 = 86_400;

/// The extra time a re-sign pass of the timer renews ahead of the due time, so that the
/// next pass of a zone waits about a day.
pub const RENEW_SLACK_SECS: u32 = DAY_SECS;

/// Seconds since 1970 modulo 2^32: the time fields of an RRSIG.
pub fn unix32(at: Timestamp) -> u32 {
    let seconds = at.unix_nanos().div_euclid(1_000_000_000);
    u32::try_from(seconds.rem_euclid(1 << 32)).unwrap_or_default()
}

/// The time of an RRSIG time field, taken in the 68-year window around `now` (RFC 4034,
/// section 3.1.5).
pub fn time_of(field: u32, now: Timestamp) -> Timestamp {
    let delta = i64::from(i32::from_ne_bytes(
        field.wrapping_sub(unix32(now)).to_ne_bytes(),
    ));
    let seconds = now.unix_nanos().div_euclid(1_000_000_000) + i128::from(delta);
    Timestamp::from_unix_nanos(seconds * 1_000_000_000).unwrap_or(now)
}

/// Signed seconds from `now` to `field` in serial arithmetic.
pub fn seconds_until(field: u32, now: u32) -> i64 {
    i64::from(i32::from_ne_bytes(field.wrapping_sub(now).to_ne_bytes()))
}

/// The times of one signing pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Times {
    /// Now.
    pub now: u32,
    /// The validity of a new signature, in seconds.
    pub validity: u32,
    /// The largest jitter taken off a new signature's expiration, in seconds.
    pub spread: u32,
    /// A signature with less than this left is renewed, in seconds.
    pub renew: u32,
}

impl Times {
    /// The times of a pass at `now` under `policy`; `ahead` renews up to
    /// [`RENEW_SLACK_SECS`] before the due time (the passes of the timer).
    pub fn new(now: Timestamp, policy: &DnssecPolicy, ahead: bool) -> Self {
        let validity = u32::from(policy.signature_validity_days).saturating_mul(DAY_SECS);
        let resign = u32::from(policy.resign_before_days).saturating_mul(DAY_SECS);
        Self {
            now: unix32(now),
            validity,
            spread: resign / 2,
            renew: if ahead {
                resign.saturating_add(RENEW_SLACK_SECS).min(validity)
            } else {
                resign
            },
        }
    }

    fn expiration(&self) -> u32 {
        let jitter = if self.spread == 0 {
            0
        } else {
            let mut bytes = [0u8; 4];
            let _ = aws_lc_rs::rand::fill(&mut bytes);
            u32::from_be_bytes(bytes) % self.spread
        };
        self.now.wrapping_add(self.validity).wrapping_sub(jitter)
    }
}

/// A new RRSIG over the RRset of `owner` and `rtype` with `key`, signed for the zone at
/// `apex`.
///
/// # Errors
///
/// [`CryptoError`] when the signature fails.
pub fn rrsig(
    key: &LoadedKey,
    apex: &DnsName,
    owner: &DnsName,
    rtype: Rtype,
    ttl: u32,
    rdata: &[Rdata],
    times: &Times,
) -> Result<Rdata, CryptoError> {
    let head = RrsigHead {
        type_covered: rtype,
        algorithm: key.meta.algorithm.number(),
        labels: rrsig_labels(owner),
        original_ttl: ttl,
        expiration: times.expiration(),
        inception: times.now.wrapping_sub(INCEPTION_OFFSET_SECS),
        key_tag: key.meta.key_tag,
        signer: apex,
    };
    let data = signed_data(&head, owner, rtype, slices(rdata));
    let signature = key.pair.sign(&data)?;
    let wire = head.with_signature(&signature);
    Rdata::from_wire(tenko_core::dns::Rtype::RRSIG, &wire)
        .map_err(|_| CryptoError("the signature does not form an RRSIG"))
}

/// The fields of a stored RRSIG that decide whether it can stay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigFields {
    /// The type covered.
    pub type_covered: Rtype,
    /// The algorithm number.
    pub algorithm: u8,
    /// The labels.
    pub labels: u8,
    /// The original TTL.
    pub original_ttl: u32,
    /// The expiration.
    pub expiration: u32,
    /// The inception.
    pub inception: u32,
    /// The key tag.
    pub key_tag: u16,
}

/// The fields of RRSIG record data, if it is one.
pub fn fields(rdata: &Rdata) -> Option<SigFields> {
    let bytes = rdata.as_bytes();
    if bytes.len() < 18 {
        return None;
    }
    let u32_at =
        |at: usize| u32::from_be_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]);
    Some(SigFields {
        type_covered: Rtype(u16::from_be_bytes([bytes[0], bytes[1]])),
        algorithm: bytes[2],
        labels: bytes[3],
        original_ttl: u32_at(4),
        expiration: u32_at(8),
        inception: u32_at(12),
        key_tag: u16::from_be_bytes([bytes[16], bytes[17]]),
    })
}

/// Whether a stored signature can stay for the RRset of `owner` and `rtype` with `ttl`,
/// made by `key`: same key, algorithm, labels and TTL, inception not in the future, and
/// more than the renewal time left.
pub fn keeps(
    sig: &SigFields,
    key: &LoadedKey,
    owner: &DnsName,
    rtype: Rtype,
    ttl: u32,
    times: &Times,
) -> bool {
    sig.type_covered == rtype
        && sig.key_tag == key.meta.key_tag
        && sig.algorithm == key.meta.algorithm.number()
        && sig.labels == rrsig_labels(owner)
        && sig.original_ttl == ttl
        && seconds_until(sig.inception, times.now) <= i64::from(FUTURE_SKEW_SECS)
        && seconds_until(sig.expiration, times.now) > i64::from(times.renew)
}

/// Whether a stored signature verifies over the RRset with `key`'s public key.
pub fn verifies(
    sig_rdata: &Rdata,
    key: &LoadedKey,
    apex: &DnsName,
    owner: &DnsName,
    rtype: Rtype,
    rdata: &[Rdata],
) -> bool {
    let Ok(RecordData::Rrsig {
        type_covered,
        algorithm,
        labels,
        original_ttl,
        expiration,
        inception,
        key_tag,
        signer,
        signature,
    }) = sig_rdata.decode(Rtype::RRSIG)
    else {
        return false;
    };
    if &signer != apex {
        return false;
    }
    let head = RrsigHead {
        type_covered,
        algorithm,
        labels,
        original_ttl,
        expiration,
        inception,
        key_tag,
        signer: &signer,
    };
    let data = signed_data(&head, owner, rtype, slices(rdata));
    verify(algorithm, &key.public_key, &data, &signature.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_fields_wrap_around_now() {
        let now = Timestamp::from_unix_nanos(1_792_238_400 * 1_000_000_000).expect("now");
        let field = unix32(now).wrapping_add(3600);
        assert_eq!(time_of(field, now).saturating_since(now).as_secs(), 3600);
        assert_eq!(seconds_until(field, unix32(now)), 3600);
        assert_eq!(
            seconds_until(unix32(now).wrapping_sub(10), unix32(now)),
            -10
        );
    }

    #[test]
    fn the_timer_renews_ahead() {
        let now = Timestamp::from_unix_nanos(1_792_238_400 * 1_000_000_000).expect("now");
        let policy = DnssecPolicy::default();
        let plain = Times::new(now, &policy, false);
        let ahead = Times::new(now, &policy, true);
        assert_eq!(plain.renew, 7 * DAY_SECS);
        assert_eq!(ahead.renew, 8 * DAY_SECS);
        for _ in 0..100 {
            let expiration = plain.expiration();
            let left = seconds_until(expiration, plain.now);
            assert!(left <= i64::from(14 * DAY_SECS));
            assert!(left > i64::from(14 * DAY_SECS - plain.spread));
        }
    }
}
