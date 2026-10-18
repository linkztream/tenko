#![no_main]

//! The parsers in front of the query path of DoT and DoH: the PROXY protocol version 2
//! header and `X-Forwarded-For` of the reverse-proxy mode, the `dns` parameter of a DoH
//! `GET` with its base64url, and the TTL walk behind `Cache-Control`.

use libfuzzer_sys::fuzz_target;
use tenko_dns::tls::{doh, proxy};

fuzz_target!(|data: &[u8]| {
    if let Ok((_, len)) = proxy::parse(data) {
        assert!(len >= proxy::FIXED_LEN && len <= data.len());
    }
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = proxy::forwarded_for(text);
        if let Some(param) = doh::dns_param(text) {
            let mut out = Vec::new();
            if doh::decode_base64url(param, &mut out) {
                assert!(out.len() <= param.len());
            }
        }
    }
    assert!(doh::max_age(data) <= 0x7fff_ffff);
});
