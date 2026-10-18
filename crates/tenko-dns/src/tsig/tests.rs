use super::*;
use crate::wire::{MAX_MESSAGE_LEN, write_query};

fn name(text: &str) -> DnsName {
    DnsName::new(text).expect("name")
}

fn key(algorithm: TsigAlgorithm) -> TsigKey {
    TsigKey::new(
        &name("transfer.example.test"),
        algorithm,
        b"0123456789abcdef0123456789abcdef",
    )
}

fn ring(algorithm: TsigAlgorithm) -> Keyring {
    Keyring::new([key(algorithm)])
}

const NOW: u64 = 1_790_000_000;

fn signed_query(ring: &Keyring, at: u64) -> (Vec<u8>, Mac) {
    let mut out = Vec::new();
    write_query(&mut out, 0x1234, "example.test", 252, None);
    let mut signer = Signer::request(ring.by_name(&name("transfer.example.test")).expect("key"));
    assert!(signer.sign(&mut out, at, 0, &[], MAX_MESSAGE_LEN));
    (out, signer.last_mac().expect("mac"))
}

/// The MAC of a request computed from the bytes RFC 8945 section 4.3 lists, written out
/// by hand: the unsigned message, then the TSIG variables.
fn expected_request_mac(unsigned: &[u8], at: u64) -> Vec<u8> {
    let mut data = unsigned.to_vec();
    data.extend_from_slice(b"\x08transfer\x07example\x04test\x00");
    data.extend_from_slice(&[0x00, 0xff]); // class ANY
    data.extend_from_slice(&[0, 0, 0, 0]); // TTL
    data.extend_from_slice(b"\x0bhmac-sha256\x00");
    data.extend_from_slice(&at.to_be_bytes()[2..]);
    data.extend_from_slice(&FUDGE.to_be_bytes());
    data.extend_from_slice(&[0, 0]); // error
    data.extend_from_slice(&[0, 0]); // other length
    let key = hmac::Key::new(hmac::HMAC_SHA256, b"0123456789abcdef0123456789abcdef");
    hmac::sign(&key, &data).as_ref().to_vec()
}

#[test]
fn a_signed_request_carries_the_mac_of_the_rfc_variables() {
    let ring = ring(TsigAlgorithm::HmacSha256);
    let mut unsigned = Vec::new();
    write_query(&mut unsigned, 0x1234, "example.test", 252, None);
    let (signed, mac) = signed_query(&ring, NOW);
    assert_eq!(
        mac.as_bytes(),
        expected_request_mac(&unsigned, NOW).as_slice()
    );
    let tsig = find(&signed).expect("parse").expect("tsig");
    assert_eq!(tsig.record_start, unsigned.len());
    assert_eq!(tsig.original_id, 0x1234);
    assert_eq!(tsig.fudge, FUDGE);
    assert_eq!(tsig.mac, mac.as_bytes());
    assert_eq!(wire::parse_header(&signed).expect("header").arcount, 1);
}

#[test]
fn every_algorithm_signs_and_verifies() {
    for algorithm in [
        TsigAlgorithm::HmacSha256,
        TsigAlgorithm::HmacSha384,
        TsigAlgorithm::HmacSha512,
        TsigAlgorithm::HmacSha1,
    ] {
        let ring = ring(algorithm);
        let (signed, mac) = signed_query(&ring, NOW);
        assert_eq!(mac.as_bytes().len(), mac_len(algorithm));
        let tsig = find(&signed).expect("parse").expect("tsig");
        let verified = verify_request(&ring, &signed, &tsig, NOW + 10).expect("verifies");
        assert_eq!(verified.mac, mac);
        assert_eq!(algorithm_of(algorithm_wire(algorithm)), Some(algorithm));
    }
}

#[test]
fn a_changed_message_an_unknown_key_and_a_late_clock_are_refused() {
    let ring = ring(TsigAlgorithm::HmacSha256);
    let (mut signed, _) = signed_query(&ring, NOW);
    let tsig = find(&signed).expect("parse").expect("tsig");
    let other = Keyring::new([TsigKey::new(
        &name("other.example.test"),
        TsigAlgorithm::HmacSha256,
        b"secret-secret-secret",
    )]);
    let refused = verify_request(&other, &signed, &tsig, NOW).expect_err("badkey");
    assert_eq!(refused.error, TsigError::BadKey);
    let wrong_algorithm = Keyring::new([key(TsigAlgorithm::HmacSha512)]);
    let refused = verify_request(&wrong_algorithm, &signed, &tsig, NOW).expect_err("badkey");
    assert_eq!(refused.error, TsigError::BadKey);
    let refused = verify_request(&ring, &signed, &tsig, NOW + 301).expect_err("badtime");
    assert_eq!(refused.error, TsigError::BadTime);
    assert!(refused.key.is_some(), "a BADTIME answer is signed");
    // One flipped bit of the question.
    signed[13] ^= 0x20;
    let tsig = find(&signed).expect("parse").expect("tsig");
    let refused = verify_request(&ring, &signed, &tsig, NOW).expect_err("badsig");
    assert_eq!(refused.error, TsigError::BadSig);
}

#[test]
fn a_truncated_mac_is_taken_down_to_half_the_hash() {
    let ring = ring(TsigAlgorithm::HmacSha256);
    let mut unsigned = Vec::new();
    write_query(&mut unsigned, 0x1234, "example.test", 252, None);
    let full = expected_request_mac(&unsigned, NOW);
    for (len, ok) in [(16, true), (15, false), (32, true)] {
        let mut message = unsigned.clone();
        let record = TsigRecord {
            key: b"\x08transfer\x07example\x04test\x00",
            algorithm: b"\x0bhmac-sha256\x00",
            time_signed: NOW,
            fudge: FUDGE,
            mac: &full[..len],
            original_id: 0x1234,
            error: 0,
            other: &[],
        };
        assert!(wire::append_tsig(&mut message, &record, MAX_MESSAGE_LEN));
        let tsig = find(&message).expect("parse").expect("tsig");
        let result = verify_request(&ring, &message, &tsig, NOW);
        assert_eq!(result.is_ok(), ok, "length {len}");
        if !ok {
            assert_eq!(result.expect_err("short").error, TsigError::Truncated);
        }
    }
}

/// An answer with one TXT record at the root holding `body`.
fn answer(id: u16, body: u8) -> Vec<u8> {
    let mut out = vec![0u8; HEADER_LEN];
    out[..2].copy_from_slice(&id.to_be_bytes());
    out[2] = 0x84;
    out[7] = 1;
    out.extend_from_slice(&[0, 0, 16, 0, 1, 0, 0, 0, 60, 0, 2, 1, body]);
    out
}

#[test]
fn a_chain_of_answers_verifies_with_unsigned_messages_between() {
    let ring = ring(TsigAlgorithm::HmacSha256);
    let (query, request_mac) = signed_query(&ring, NOW);
    let tsig = find(&query).expect("parse").expect("tsig");
    let verified = verify_request(&ring, &query, &tsig, NOW).expect("request");
    let mut signer = Signer::answer(Arc::clone(&verified.key), verified.mac);
    let mut messages = Vec::new();
    for index in 0..5u8 {
        let mut message = answer(0x1234, index);
        // The third message goes out unsigned.
        if index == 2 {
            signer.leave_unsigned(&message);
        } else {
            assert!(signer.sign(&mut message, NOW + 1, 0, &[], MAX_MESSAGE_LEN));
        }
        messages.push(message);
    }
    let mut chain = Verifier::new(ring.get(tsig.key).expect("key"), request_mac);
    for message in &messages {
        chain.verify(message, NOW + 2).expect("chain");
    }
    assert!(chain.complete());
    // A message swapped in the middle breaks the chain.
    let mut swapped = Verifier::new(ring.get(tsig.key).expect("key"), request_mac);
    swapped.verify(&messages[0], NOW).expect("first");
    assert_eq!(swapped.verify(&messages[3], NOW), Err(TsigError::BadSig));
    // The first answer must be signed.
    let mut unsigned = Verifier::new(ring.get(tsig.key).expect("key"), request_mac);
    assert_eq!(
        unsigned.verify(&answer(0x1234, 9), NOW),
        Err(TsigError::Unsigned)
    );
}

#[test]
fn refusals_carry_the_error_and_badtime_the_server_time() {
    let ring = ring(TsigAlgorithm::HmacSha256);
    let (query, request_mac) = signed_query(&ring, NOW);
    let tsig = find(&query).expect("parse").expect("tsig");
    let refused = verify_request(&ring, &query, &tsig, NOW + 1000).expect_err("late");
    let mut out = answer(0x1234, 0);
    assert!(refusal_tsig(
        &mut out,
        &refused,
        &tsig,
        NOW + 1000,
        MAX_MESSAGE_LEN
    ));
    let answered = find(&out).expect("parse").expect("tsig");
    assert_eq!(answered.error, error::BADTIME);
    assert_eq!(answered.time_signed, NOW);
    assert_eq!(answered.other, &(NOW + 1000).to_be_bytes()[2..]);
    // The client verifies the BADTIME answer's MAC and sees the server's error.
    let mut verifier = Verifier::new(ring.get(tsig.key).expect("key"), request_mac);
    assert_eq!(
        verifier.verify(&out, NOW),
        Err(TsigError::Peer(error::BADTIME))
    );
    let other = Keyring::default();
    let refused = verify_request(&other, &query, &tsig, NOW).expect_err("badkey");
    let mut out = answer(0x1234, 0);
    assert!(refusal_tsig(
        &mut out,
        &refused,
        &tsig,
        NOW,
        MAX_MESSAGE_LEN
    ));
    let answered = find(&out).expect("parse").expect("tsig");
    assert_eq!((answered.error, answered.mac.len()), (error::BADKEY, 0));
}

#[test]
fn a_tsig_record_must_be_the_last() {
    let ring = ring(TsigAlgorithm::HmacSha256);
    let (mut signed, _) = signed_query(&ring, NOW);
    // Append an OPT record after the TSIG record.
    signed.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0]);
    let arcount = u16::from_be_bytes([signed[10], signed[11]]) + 1;
    signed[10..12].copy_from_slice(&arcount.to_be_bytes());
    assert_eq!(find(&signed), Err(TsigFormError::Record));
    assert_eq!(find(&[0u8; 4]), Err(TsigFormError::Message));
    let mut plain = Vec::new();
    write_query(&mut plain, 1, "example.test", 1, Some(1232));
    assert_eq!(find(&plain), Ok(None));
}
