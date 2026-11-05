#![no_main]

use libfuzzer_sys::fuzz_target;
use tenko_dns::anchors::text;

// The input is the presentation form of a trust anchor key as `POST /dns/trust-anchors`
// and `tenko dns trust-anchor add` take it: a DS record's data (`20326 8 2 E06D...`) or a
// DNSKEY record's data (`257 3 8 AwEA...`). Each parses or is refused with a reason;
// nothing panics, also on text that holds characters of several octets, and data that
// parses writes back as a presentation form that parses to the same data.
fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };
    match text::parse_ds(input) {
        Ok(rdata) => {
            assert!(rdata.len() > 4);
            let again = text::parse_ds(&text::ds_text(&rdata)).expect("the DS form parses");
            assert_eq!(again, rdata);
        }
        Err(error) => assert!(!error.as_coded_error().detail.is_empty()),
    }
    match text::parse_dnskey(input) {
        Ok(rdata) => {
            assert!(rdata.len() > 4);
            let again =
                text::parse_dnskey(&text::dnskey_text(&rdata)).expect("the DNSKEY form parses");
            assert_eq!(again, rdata);
        }
        Err(error) => assert!(!error.as_coded_error().detail.is_empty()),
    }
});
