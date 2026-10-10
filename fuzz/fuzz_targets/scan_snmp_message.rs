#![no_main]

use libfuzzer_sys::fuzz_target;
use tenko_scan::snmp::message::{MessageData, decode_message, decode_scoped_pdu};

fuzz_target!(|data: &[u8]| {
    // The input as a datagram: the structure of the message, then its scoped PDU. An
    // encrypted message has no readable scoped PDU, so the octets are read as if they
    // were the decrypted plaintext.
    if let Ok(message) = decode_message(data) {
        let scoped = match &message.data {
            MessageData::Plain(scoped) => Some(scoped.clone()),
            MessageData::Encrypted(octets) => decode_scoped_pdu(octets).ok(),
        };
        // What decoded must encode again and decode to the same value.
        if let Some(scoped) = scoped {
            let encoded = scoped.encode().expect("a decoded scoped PDU encodes");
            assert_eq!(decode_scoped_pdu(&encoded), Ok(scoped));
        }
    }
    // The input as the plaintext of an encrypted message.
    let _ = decode_scoped_pdu(data);
});
