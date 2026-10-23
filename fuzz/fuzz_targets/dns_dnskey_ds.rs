#![no_main]

use libfuzzer_sys::fuzz_target;
use tenko_dns::{dnssec::crypto, validate::rrset::Key};

// The first octet is the length of the DNSKEY record data, the rest is it and then a DS
// record's data. The key parses or not, its tag is a function of its octets, the DS
// matches only when the tag, the algorithm and a supported digest agree, and nothing
// panics on any split.
fuzz_target!(|data: &[u8]| {
    let [len, rest @ ..] = data else {
        return;
    };
    let split = usize::from(*len).min(rest.len());
    let (dnskey, ds) = rest.split_at(split);
    let zone = b"\x07example\x04test\x00";
    let tag = crypto::key_tag(dnskey);
    if let Some(key) = Key::parse(dnskey) {
        assert_eq!(key.key_tag, tag);
        assert_eq!(key.public_key.len(), dnskey.len() - 4);
        let _ = key.usable();
        let _ = key.sep();
        let _ = key.revoked();
    }
    let matches = crypto::ds_matches(zone, dnskey, ds);
    if matches {
        assert!(ds.len() >= 4);
        assert_eq!(u16::from_be_bytes([ds[0], ds[1]]), tag);
        assert_eq!(dnskey.get(3), Some(&ds[2]));
        assert!(crypto::supported_digest(ds[3]));
        assert_eq!(
            crypto::ds_digest(ds[3], zone, dnskey).as_deref(),
            Some(&ds[4..])
        );
    }
    if let Some(digest_type) = ds.get(3) {
        let digest = crypto::ds_digest(*digest_type, zone, dnskey);
        assert_eq!(digest.is_some(), crypto::supported_digest(*digest_type));
    }
    // A signature over the data with the key never verifies for a key that does not parse.
    if Key::parse(dnskey).is_none() {
        assert!(!crypto::verify(13, dnskey, ds, ds));
    }
});
