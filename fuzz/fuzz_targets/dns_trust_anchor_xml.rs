#![no_main]

use libfuzzer_sys::fuzz_target;
use tenko_dns::anchors::xml;

// The input is a trust anchor file (RFC 7958). It parses or is refused with a reason;
// nothing panics, and a file that parses has a zone and key digests whose DS record data
// carry the fields they were read with.
fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    match xml::parse(text) {
        Ok(file) => {
            assert!(!file.id.is_empty());
            assert!(file.digests.len() <= xml::MAX_DIGESTS);
            for digest in &file.digests {
                let rdata = digest.ds_rdata();
                assert_eq!(u16::from_be_bytes([rdata[0], rdata[1]]), digest.key_tag);
                assert_eq!(rdata[2], digest.algorithm);
                assert_eq!(rdata[3], digest.digest_type);
                assert_eq!(&rdata[4..], digest.digest.as_slice());
            }
        }
        Err(error) => assert!(!error.0.is_empty()),
    }
});
