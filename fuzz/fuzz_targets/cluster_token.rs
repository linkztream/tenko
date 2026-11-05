#![no_main]

//! The enrollment token a node presents to a controller, from the enrollment request and from
//! the command line: `tnk2.<id>.<secret>.<fingerprint>` and `tnk1.<id>.<secret>`. Any text
//! parses or is refused; the text of a parsed token reads back to the same token, with the
//! same id, fingerprint and digest, and spells the input again up to the case of the id; the
//! digest a controller looks the token up by is computed; the secret stays out of the debug
//! form. The hexadecimal forms of a CA fingerprint (`--ca-fingerprint`) and of a stored digest
//! are read on the same text and read back from their rendering.

use libfuzzer_sys::fuzz_target;
use tenko_cluster::token::{
    CaFingerprint, EnrollmentToken, LEGACY_TOKEN_PREFIX, LEGACY_TOKEN_TEXT_LEN, TOKEN_PREFIX,
    TOKEN_TEXT_LEN, TokenDigest,
};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    if let Ok(fingerprint) = CaFingerprint::from_hex(text) {
        let hex = fingerprint.to_hex();
        assert_eq!(hex.len(), 64);
        assert_eq!(hex, fingerprint.to_string());
        assert_eq!(CaFingerprint::from_hex(&hex), Ok(fingerprint));
        assert!(hex.eq_ignore_ascii_case(text));
    }
    if let Ok(digest) = TokenDigest::from_hex(text) {
        let hex = digest.to_hex();
        assert_eq!(TokenDigest::from_hex(&hex), Ok(digest));
        assert!(hex.eq_ignore_ascii_case(text));
        let json = serde_json::to_string(&digest).expect("a digest serializes");
        let read: TokenDigest = serde_json::from_str(&json).expect("a digest reads back");
        assert_eq!(read, digest);
    }

    let Ok(token) = EnrollmentToken::parse(text) else {
        return;
    };
    let rendered = token.to_text();
    let (prefix, len) = if token.ca_fingerprint().is_some() {
        (TOKEN_PREFIX, TOKEN_TEXT_LEN)
    } else {
        (LEGACY_TOKEN_PREFIX, LEGACY_TOKEN_TEXT_LEN)
    };
    assert_eq!(rendered.len(), len);
    assert!(rendered.starts_with(prefix));
    assert!(rendered.is_ascii());
    // The parser is strict: a token that parses is the canonical spelling, except that the
    // id is read in either case and rendered in lowercase.
    assert!(rendered.eq_ignore_ascii_case(text.trim_ascii()));

    let again = EnrollmentToken::parse(&rendered).expect("a rendered token parses");
    assert_eq!(again.id(), token.id());
    assert_eq!(again.ca_fingerprint(), token.ca_fingerprint());
    assert_eq!(*again.to_text(), *rendered);

    // The digest the controller stores and looks the token up by, equal for the token and
    // its round trip, in both comparisons.
    let digest = token.digest();
    assert_eq!(again.digest(), digest);
    assert!(digest.matches(&again));
    assert!(again.digest().matches(&token));
    assert_eq!(TokenDigest::from_hex(&digest.to_hex()), Ok(digest));

    if let Some(fingerprint) = token.ca_fingerprint() {
        let hex = fingerprint.to_hex();
        assert_eq!(CaFingerprint::from_hex(&hex), Ok(fingerprint));
        assert_eq!(hex, fingerprint.to_string());
        // The digest does not depend on the fingerprint: the same id and secret as a
        // `tnk1` token match the same digest.
        let legacy = format!(
            "{LEGACY_TOKEN_PREFIX}{}",
            &rendered[TOKEN_PREFIX.len()..LEGACY_TOKEN_TEXT_LEN]
        );
        let legacy =
            EnrollmentToken::parse(&legacy).expect("the tnk1 spelling of a tnk2 token parses");
        assert_eq!(legacy.ca_fingerprint(), None);
        assert!(digest.matches(&legacy));
    }

    // The secret never leaves through the debug form.
    let secret = rendered
        .split('.')
        .nth(2)
        .expect("a token has a secret part");
    let debug = format!("{token:?}");
    assert!(!debug.contains(secret));
    assert!(debug.contains(&token.id().to_string()));
});
