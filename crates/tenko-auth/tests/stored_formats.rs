//! The stored bytes of the records an end of an account's access touches, pinned: a record
//! of an account whose access never ended keeps the bytes it had before the generations
//! existed, a later field is read past, and a change of the encoding fails here first.
//! Never regenerate these values: a difference is a change of a stored format.

use std::fmt::Debug;

use serde::{Serialize, de::DeserializeOwned};
use tenko_auth::{
    encoding::hex_encode as hex,
    model::{
        ACCESS_ENDS, KNOWN_DEVICES, KnownDeviceRecord, SCOPED_TOKENS, SESSIONS, ScopedTokenRecord,
        SessionRecord, TOKENS, TokenGrant, TokenRecord, USERS, UserRecord,
    },
    roles::RoleName,
};
use tenko_core::{AuthStrength, Timestamp, UserId, codec::KeyCodec, table::TableDef};

fn at() -> Timestamp {
    "2026-11-12T10:00:00Z".parse().expect("a time")
}

fn user_id() -> UserId {
    "0190f2a0-0000-7000-8000-000000000001"
        .parse()
        .expect("an id")
}

/// `map` with one more entry, `"later": 1`, as a later build might write it.
fn with_later_field(map: &[u8]) -> Vec<u8> {
    let (count, entries) = match map[0] {
        header @ 0xa0..=0xb7 => (usize::from(header - 0xa0), &map[1..]),
        0xb8 => (usize::from(map[1]), &map[2..]),
        other => panic!("not a CBOR map: {other:#x}"),
    };
    let count = u8::try_from(count + 1).expect("a small map");
    let mut out = if count < 24 {
        vec![0xa0 + count]
    } else {
        vec![0xb8, count]
    };
    out.extend_from_slice(entries);
    out.extend_from_slice(&[0x65, b'l', b'a', b't', b'e', b'r', 0x01]);
    out
}

/// `value` encodes to `golden`, decodes from it, and decodes from it with a later field.
fn pinned<K: KeyCodec, V: Serialize + DeserializeOwned + PartialEq + Debug>(
    table: &TableDef<K, V>,
    value: &V,
    golden: &str,
) {
    let bytes = table.encode(value).expect("encodes");
    assert_eq!(
        hex(&bytes),
        golden,
        "the stored bytes of {} changed",
        table.name()
    );
    assert_eq!(&table.decode(&bytes).expect("decodes"), value);
    assert_eq!(
        &table
            .decode(&with_later_field(&bytes))
            .expect("a record with a later field decodes"),
        value,
        "{}",
        table.name()
    );
}

/// The key a generation is stored under: absent from the bytes of a credential, or an
/// account, that no end of access touched.
fn names_a_generation(golden: &str) -> bool {
    golden.contains(&hex(b"generation"))
}

#[test]
fn a_user_record_keeps_its_bytes_until_its_access_ends() {
    let mut user = UserRecord::new(
        "ada".to_owned(),
        "Ada".to_owned(),
        vec![RoleName::Operator],
        at(),
    );
    user.id = user_id();
    let never = "b0626964500190f2a0000070008000000000000001646e616d65636164616c646973706c61795f6e616d656341646165726f6c657381686f70657261746f726870617373776f7264f664746f7470f66e7265636f766572795f636f646573806864697361626c6564f46b627265616b5f676c617373f4646c6f636bf6781870617373776f72645f6368616e67655f7265717569726564f4686c616e6775616765f66a637265617465645f617474323032362d31312d31325431303a30303a30305a646b696e6466706572736f6e656f776e6572f66b756e6c6f636b65645f6174f6";
    assert!(!names_a_generation(never));
    pinned(&USERS, &user, never);
    user.sessions_generation = 2;
    user.tokens_generation = 1;
    pinned(
        &USERS,
        &user,
        "b2626964500190f2a0000070008000000000000001646e616d65636164616c646973706c61795f6e616d656341646165726f6c657381686f70657261746f726870617373776f7264f664746f7470f66e7265636f766572795f636f646573806864697361626c6564f46b627265616b5f676c617373f4646c6f636bf6781870617373776f72645f6368616e67655f7265717569726564f4686c616e6775616765f66a637265617465645f617474323032362d31312d31325431303a30303a30305a646b696e6466706572736f6e656f776e6572f66b756e6c6f636b65645f6174f67373657373696f6e735f67656e65726174696f6e0271746f6b656e735f67656e65726174696f6e01",
    );
}

#[test]
fn a_session_record_is_pinned() {
    let mut session = SessionRecord {
        id: "0190f2a0-0000-7000-8000-000000000002"
            .parse()
            .expect("an id"),
        user: user_id(),
        strength: AuthStrength::Password,
        created_at: at(),
        authenticated_at: at(),
        expires_at: at(),
        idle_expires_at: at(),
        last_seen_at: at(),
        source_ip: None,
        user_agent: None,
        break_glass: false,
        mfa_enrollment_required: false,
        source: tenko_auth::directory::SessionSource::Local,
        directory_checked_at: None,
        generation: 0,
    };
    let never = "ac626964500190f2a00000700080000000000000026475736572500190f2a000007000800000000000000168737472656e6774686870617373776f72646a637265617465645f617474323032362d31312d31325431303a30303a30305a7061757468656e746963617465645f617474323032362d31312d31325431303a30303a30305a6a657870697265735f617474323032362d31312d31325431303a30303a30305a6f69646c655f657870697265735f617474323032362d31312d31325431303a30303a30305a6c6c6173745f7365656e5f617474323032362d31312d31325431303a30303a30305a69736f757263655f6970f66a757365725f6167656e74f66b627265616b5f676c617373f4776d66615f656e726f6c6c6d656e745f7265717569726564f4";
    assert!(!names_a_generation(never));
    pinned(&SESSIONS, &session, never);
    session.generation = 2;
    pinned(
        &SESSIONS,
        &session,
        "ad626964500190f2a00000700080000000000000026475736572500190f2a000007000800000000000000168737472656e6774686870617373776f72646a637265617465645f617474323032362d31312d31325431303a30303a30305a7061757468656e746963617465645f617474323032362d31312d31325431303a30303a30305a6a657870697265735f617474323032362d31312d31325431303a30303a30305a6f69646c655f657870697265735f617474323032362d31312d31325431303a30303a30305a6c6c6173745f7365656e5f617474323032362d31312d31325431303a30303a30305a69736f757263655f6970f66a757365725f6167656e74f66b627265616b5f676c617373f4776d66615f656e726f6c6c6d656e745f7265717569726564f46a67656e65726174696f6e02",
    );
}

#[test]
fn a_known_device_record_is_pinned() {
    let mut device = KnownDeviceRecord {
        id: "0190f2a0-0000-7000-8000-000000000003"
            .parse()
            .expect("an id"),
        user: user_id(),
        known_since: at(),
        issued_at: at(),
        expires_at: at(),
        password_changed_at: Some(at()),
        failures: 1,
        generation: 0,
    };
    let never = "a7626964500190f2a00000700080000000000000036475736572500190f2a00000700080000000000000016b6b6e6f776e5f73696e636574323032362d31312d31325431303a30303a30305a696973737565645f617474323032362d31312d31325431303a30303a30305a6a657870697265735f617474323032362d31312d31325431303a30303a30305a7370617373776f72645f6368616e6765645f617474323032362d31312d31325431303a30303a30305a686661696c7572657301";
    assert!(!names_a_generation(never));
    pinned(&KNOWN_DEVICES, &device, never);
    device.generation = 2;
    pinned(
        &KNOWN_DEVICES,
        &device,
        "a8626964500190f2a00000700080000000000000036475736572500190f2a00000700080000000000000016b6b6e6f776e5f73696e636574323032362d31312d31325431303a30303a30305a696973737565645f617474323032362d31312d31325431303a30303a30305a6a657870697265735f617474323032362d31312d31325431303a30303a30305a7370617373776f72645f6368616e6765645f617474323032362d31312d31325431303a30303a30305a686661696c75726573016a67656e65726174696f6e02",
    );
}

#[test]
fn a_personal_token_record_is_pinned() {
    let mut token = TokenRecord {
        id: "0190f2a0-0000-7000-8000-000000000004"
            .parse()
            .expect("an id"),
        owner: user_id(),
        name: "automation".to_owned(),
        created_at: at(),
        expires_at: Some(at()),
        last_used_at: None,
        issued_with: AuthStrength::Password,
        prefix: "tnk_abcdefgh".to_owned(),
        generation: 0,
    };
    let never = "a8626964500190f2a0000070008000000000000004656f776e6572500190f2a0000070008000000000000001646e616d656a6175746f6d6174696f6e6a637265617465645f617474323032362d31312d31325431303a30303a30305a6a657870697265735f617474323032362d31312d31325431303a30303a30305a6c6c6173745f757365645f6174f66b6973737565645f776974686870617373776f7264667072656669786c746e6b5f6162636465666768";
    assert!(!names_a_generation(never));
    pinned(&TOKENS, &token, never);
    token.generation = 1;
    pinned(
        &TOKENS,
        &token,
        "a9626964500190f2a0000070008000000000000004656f776e6572500190f2a0000070008000000000000001646e616d656a6175746f6d6174696f6e6a637265617465645f617474323032362d31312d31325431303a30303a30305a6a657870697265735f617474323032362d31312d31325431303a30303a30305a6c6c6173745f757365645f6174f66b6973737565645f776974686870617373776f7264667072656669786c746e6b5f61626364656667686a67656e65726174696f6e01",
    );
}

#[test]
fn a_scoped_token_record_is_pinned() {
    let mut token = ScopedTokenRecord {
        id: "0190f2a0-0000-7000-8000-000000000005"
            .parse()
            .expect("an id"),
        owner: user_id(),
        name: "automation".to_owned(),
        created_at: at(),
        created_by: user_id(),
        expires_at: Some(at()),
        last_used_at: None,
        issued_with: AuthStrength::Password,
        prefix: "tnk_abcdefgh".to_owned(),
        grants: vec![TokenGrant {
            role: RoleName::Viewer,
            scope: None,
        }],
        scopes: Vec::new(),
        generation: 0,
    };
    let never = "ab626964500190f2a0000070008000000000000005656f776e6572500190f2a0000070008000000000000001646e616d656a6175746f6d6174696f6e6a637265617465645f617474323032362d31312d31325431303a30303a30305a6a637265617465645f6279500190f2a00000700080000000000000016a657870697265735f617474323032362d31312d31325431303a30303a30305a6c6c6173745f757365645f6174f66b6973737565645f776974686870617373776f7264667072656669786c746e6b5f6162636465666768666772616e747381a164726f6c65667669657765726673636f70657380";
    assert!(!names_a_generation(never));
    pinned(&SCOPED_TOKENS, &token, never);
    token.generation = 1;
    pinned(
        &SCOPED_TOKENS,
        &token,
        "ac626964500190f2a0000070008000000000000005656f776e6572500190f2a0000070008000000000000001646e616d656a6175746f6d6174696f6e6a637265617465645f617474323032362d31312d31325431303a30303a30305a6a637265617465645f6279500190f2a00000700080000000000000016a657870697265735f617474323032362d31312d31325431303a30303a30305a6c6c6173745f757365645f6174f66b6973737565645f776974686870617373776f7264667072656669786c746e6b5f6162636465666768666772616e747381a164726f6c65667669657765726673636f706573806a67656e65726174696f6e01",
    );
}

#[test]
fn an_unfinished_end_is_pinned() {
    let bytes = ACCESS_ENDS.encode(&at()).expect("encodes");
    assert_eq!(
        hex(&bytes),
        "74323032362d31312d31325431303a30303a30305a",
        "the stored bytes of auth.access_ends changed"
    );
    assert_eq!(ACCESS_ENDS.decode(&bytes).expect("decodes"), at());
    assert_eq!(
        hex(&ACCESS_ENDS.key(&user_id())),
        "0190f2a0000070008000000000000001"
    );
}
