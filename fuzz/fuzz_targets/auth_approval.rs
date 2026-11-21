#![no_main]

//! What the approval routes read from a takeover script without a credential (ADR 0038): the
//! body of `POST /auth/approvals` (`tenko_auth::approval::parse_request`: the size bound, the
//! strict JSON, the client's reported names, the P-256 key and Tenko's limits on the plan) and
//! the body of `POST /auth/approvals/{id}/collect` (`parse_collect`). The first octet picks the
//! parser (even: the request, odd: the collect); the rest is the body. An accepted request has
//! a 65-octet key, the SHA-256 of the body as its hash, and a plan within the limits.

use libfuzzer_sys::fuzz_target;
use sha2::{Digest, Sha256};

fuzz_target!(|data: &[u8]| {
    let Some((&pick, body)) = data.split_first() else {
        return;
    };
    if pick % 2 == 1 {
        let _ = tenko_auth::approval::parse_collect(body);
        return;
    }
    if let Ok((request, key, hash)) = tenko_auth::approval::parse_request(body) {
        assert_eq!(key.len(), 65);
        assert_eq!(hash, <[u8; 32]>::from(Sha256::digest(body)));
        assert!(tenko_auth::approval::check_plan(&request.plan).is_ok());
    }
});
