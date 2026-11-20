//! Fuzzes the push body of a mirrored source (`tenko_migrate::mirror::body::decode`): the
//! bounds, the gzip inflation, the strict parse of the envelope with the JSON path of the first
//! error, and the checks of the parsed snapshot. The first octet is control: its low bit says
//! `Content-Encoding: gzip`; the rest is the body. A body that decodes validates, serializes to
//! JSON that decodes to the same snapshot, and hashes the same on both sides; a refusal is a
//! 413 or a 422.
#![no_main]

use libfuzzer_sys::fuzz_target;
use tenko_core::Coded;
use tenko_migrate::mirror::{body, service::content_hashes};

fuzz_target!(|data: &[u8]| {
    let Some((control, rest)) = data.split_first() else {
        return;
    };
    match body::decode(rest, control & 1 == 1) {
        Ok(snapshot) => {
            snapshot.validate().expect("a decoded snapshot validates");
            let json = serde_json::to_vec(&snapshot).expect("serializes");
            let again = body::decode(&json, false).expect("its JSON decodes");
            assert_eq!(again, snapshot);
            assert_eq!(
                content_hashes(&again).expect("hash"),
                content_hashes(&snapshot).expect("hash")
            );
        }
        Err(error) => assert!(matches!(error.http_status(), 413 | 422), "{error}"),
    }
    let _ = body::json_path(rest, usize::from(*control), rest.len() / 2);
});
