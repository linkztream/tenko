//! The PAC reader against the PACs of the recorded tickets.

use super::*;
use crate::{
    cipher::{self, usage},
    der::{
        self, ApReq, AuthorizationData, EncTicketPart, InitialContextToken, KrbToken, NegTokenInit,
        oid,
    },
    fixtures,
};

/// The service key, the decrypted ticket and its PAC octets of a fixture.
pub(crate) fn ticket_pac(f: &fixtures::Fixture) -> (Key, EncTicketPart, Vec<u8>) {
    let outer = InitialContextToken::decode(&f.init0).expect("token");
    let mech_token = if outer.mech == oid::SPNEGO {
        NegTokenInit::decode_initial(&f.init0)
            .expect("init")
            .mech_token
            .expect("t")
            .to_vec()
    } else {
        f.init0.clone()
    };
    let inner = InitialContextToken::decode(&mech_token).expect("inner");
    let req = ApReq::decode(KrbToken::decode(inner.inner).expect("krb").message).expect("AP-REQ");
    let enc = &req.ticket.enc_part;
    let (etype, _, key) = f
        .keys
        .iter()
        .find(|(e, k, _)| *e == enc.etype && Some(*k) == enc.kvno)
        .expect("key");
    let key = Key::new(cipher::enctype(*etype).expect("aes"), key).expect("key");
    let plain = cipher::decrypt_data(&key, usage::TICKET, enc).expect("ticket");
    let ticket = EncTicketPart::decode(&plain).expect("EncTicketPart");
    let ad = ticket.authorization_data.as_ref().expect("ad");
    let inner = AuthorizationData::decode(&ad.0[0].ad_data).expect("if-relevant");
    assert_eq!(inner.0[0].ad_type, der::ad_type::WIN2K_PAC);
    let pac = inner.0[0].ad_data.clone();
    (key, ticket, pac)
}

const DOMAIN: &str = "S-1-5-21-2622792684-1183831692-3139652611";

fn sid(text: &str) -> Sid {
    Sid::parse(text).expect("sid")
}

/// DNS-28: the PACs of the recorded Samba and MIT tickets verify with the service key, and
/// the Samba PAC gives alice's SIDs.
#[test]
fn dns_28_recorded_pacs_verify_and_give_the_sids() {
    for f in fixtures::all() {
        let (key, ticket, pac) = ticket_pac(&f);
        let read = verify(&pac, &key, "alice", ticket.authtime)
            .unwrap_or_else(|e| panic!("{}: {e}", f.name));
        assert_eq!(
            (read.client_name.as_str(), read.client_authtime),
            ("alice", ticket.authtime)
        );
        if f.name.starts_with("mit") {
            assert_eq!(
                read.logon, None,
                "{}: MIT writes no logon information",
                f.name
            );
            continue;
        }
        let logon = read.logon.expect("Samba writes the logon information");
        assert_eq!(logon.effective_name, "alice");
        assert_eq!(logon.logon_domain_name, "CORP");
        assert_eq!(logon.logon_domain_sid, sid(DOMAIN));
        assert_eq!(logon.user_sid, sid(&format!("{DOMAIN}-1103")));
        assert_eq!(logon.primary_group_sid, sid(&format!("{DOMAIN}-513")));
        assert_eq!(logon.group_sids, [sid(&format!("{DOMAIN}-513"))]);
        assert_eq!(
            logon.extra_sids,
            [sid("S-1-18-1"), sid("S-1-5-21-0-0-0-497")]
        );
        assert_eq!(
            logon.groups(),
            [
                sid(&format!("{DOMAIN}-513")),
                sid("S-1-18-1"),
                sid("S-1-5-21-0-0-0-497")
            ]
        );
        assert_eq!(read_unverified(&pac).expect("read").as_ref(), Some(&logon));
    }
}

#[test]
fn a_changed_pac_or_another_key_is_refused() {
    let all = fixtures::all();
    let samba = all
        .iter()
        .find(|f| f.name == "samba-aes256-krb5")
        .expect("samba");
    let (key, ticket, pac) = ticket_pac(samba);
    // Another key of the same type, and a key of the other type.
    let other = Key::new(key.etype(), &vec![7; cipher::key_len(key.etype())]).expect("key");
    assert_eq!(
        verify(&pac, &other, "alice", ticket.authtime),
        Err(PacError::Signature(CipherError::Checksum))
    );
    let aes128 =
        Key::new(tenko_core::dns::EncryptionType::Aes128CtsHmacSha1, &[7; 16]).expect("key");
    assert_eq!(
        verify(&pac, &aes128, "alice", ticket.authtime),
        Err(PacError::Signature(CipherError::UnsupportedChecksum(16)))
    );
    // A changed octet anywhere outside the two signatures' data.
    let bufs = buffers(&pac).expect("buffers");
    let signatures: Vec<std::ops::Range<usize>> = bufs
        .iter()
        .filter(|b| {
            matches!(
                b.kind,
                buffer_type::SERVER_CHECKSUM | buffer_type::PRIVSVR_CHECKSUM
            )
        })
        .map(|b| b.offset + 4..b.offset + b.size)
        .collect();
    for index in 0..pac.len() {
        if signatures.iter().any(|r| r.contains(&index)) {
            continue;
        }
        let mut changed = pac.clone();
        changed[index] ^= 0x01;
        assert!(
            verify(&changed, &key, "alice", ticket.authtime).is_err(),
            "octet {index}"
        );
    }
    // The client information must match the ticket.
    assert_eq!(
        verify(&pac, &key, "bob", ticket.authtime),
        Err(PacError::ClientMismatch)
    );
    assert_eq!(
        verify(&pac, &key, "ALICE", ticket.authtime).map(|p| p.client_name),
        Ok("alice".into())
    );
    assert_eq!(
        verify(&pac, &key, "alice", ticket.authtime + 1),
        Err(PacError::ClientMismatch)
    );
    // Every truncation is refused, never a panic.
    for len in 0..pac.len() {
        assert!(verify(&pac[..len], &key, "alice", ticket.authtime).is_err());
        let _ = read_unverified(&pac[..len]);
    }
}

#[test]
fn malformed_headers_are_refused() {
    let all = fixtures::all();
    let (key, ticket, pac) = ticket_pac(&all[0]);
    let check = |bytes: &[u8]| verify(bytes, &key, "alice", ticket.authtime);
    let set_u32 = |bytes: &mut Vec<u8>, at: usize, value: u32| {
        bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    };
    let mut zero = pac.clone();
    set_u32(&mut zero, 0, 0);
    assert_eq!(check(&zero), Err(PacError::Malformed("cBuffers")));
    let mut many = pac.clone();
    set_u32(&mut many, 0, u32::try_from(MAX_BUFFERS).expect("small") + 1);
    assert_eq!(check(&many), Err(PacError::Malformed("cBuffers")));
    let mut version = pac.clone();
    set_u32(&mut version, 4, 1);
    assert_eq!(check(&version), Err(PacError::Malformed("Version")));
    let mut unaligned = pac.clone();
    let first = u32_at(&pac, 16).expect("offset");
    set_u32(&mut unaligned, 16, first + 1);
    assert_eq!(check(&unaligned), Err(PacError::Malformed("Offset")));
    let mut beyond = pac.clone();
    set_u32(&mut beyond, 12, 0xffff);
    assert_eq!(check(&beyond), Err(PacError::Malformed("Offset")));
    // The server signature's buffer renamed: missing, and the client information twice.
    let bufs = buffers(&pac).expect("buffers");
    let server = bufs
        .iter()
        .position(|b| b.kind == buffer_type::SERVER_CHECKSUM)
        .expect("server");
    let mut no_server = pac.clone();
    set_u32(&mut no_server, 8 + server * 16, 99);
    assert_eq!(
        check(&no_server),
        Err(PacError::Buffer(buffer_type::SERVER_CHECKSUM))
    );
    let mut twice = pac.clone();
    set_u32(&mut twice, 8 + server * 16, buffer_type::CLIENT_INFO);
    assert_eq!(
        check(&twice),
        Err(PacError::Buffer(buffer_type::CLIENT_INFO))
    );
}

/// A logon information structure written per [MS-PAC] section 2.5, with empty names, for the
/// paths the recorded PACs do not reach.
fn ndr_logon(
    groups: &[u32],
    extra: &[&Sid],
    resource: Option<(&Sid, &[u32])>,
    flags: u32,
) -> Vec<u8> {
    let mut out = vec![
        1, 0x10, 8, 0, 0xcc, 0xcc, 0xcc, 0xcc, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    let u32s = |out: &mut Vec<u8>, values: &[u32]| {
        for v in values {
            out.extend_from_slice(&v.to_le_bytes());
        }
    };
    let rpc_sid = |out: &mut Vec<u8>, sid: &Sid| {
        u32s(
            out,
            &[u32::try_from(sid.sub_authorities().len()).expect("count")],
        );
        out.extend_from_slice(&sid.to_bytes());
    };
    let empty_string = [0_u32];
    u32s(&mut out, &[0x0002_0000]);
    out.extend_from_slice(&[0; 48]);
    for _ in 0..6 {
        u32s(&mut out, &empty_string);
        u32s(&mut out, &[0]);
    }
    out.extend_from_slice(&[0; 4]);
    let count = |n: usize| u32::try_from(n).expect("count");
    u32s(
        &mut out,
        &[
            1104,
            513,
            count(groups.len()),
            u32::from(!groups.is_empty()),
            flags,
        ],
    );
    out.extend_from_slice(&[0; 16]);
    u32s(&mut out, &[0, 0, 0, 0, 1]);
    out.extend_from_slice(&[0; 8]);
    u32s(&mut out, &[0x10, 0]);
    out.extend_from_slice(&[0; 16]);
    u32s(
        &mut out,
        &[0, 0, count(extra.len()), u32::from(!extra.is_empty())],
    );
    let (resource_sid, resource_rids) = resource.map_or((None, &[][..]), |(s, r)| (Some(s), r));
    u32s(
        &mut out,
        &[
            u32::from(resource_sid.is_some()),
            count(resource_rids.len()),
            u32::from(!resource_rids.is_empty()),
        ],
    );
    if !groups.is_empty() {
        u32s(&mut out, &[count(groups.len())]);
        for rid in groups {
            u32s(&mut out, &[*rid, 7]);
        }
    }
    rpc_sid(&mut out, &sid(DOMAIN));
    if !extra.is_empty() {
        u32s(&mut out, &[count(extra.len())]);
        for _ in extra {
            u32s(&mut out, &[0x0002_0010, 7]);
        }
        for s in extra {
            rpc_sid(&mut out, s);
            while out.len() % 4 != 0 {
                out.push(0);
            }
        }
    }
    if let Some(s) = resource_sid {
        rpc_sid(&mut out, s);
    }
    if !resource_rids.is_empty() {
        u32s(&mut out, &[count(resource_rids.len())]);
        for rid in resource_rids {
            u32s(&mut out, &[*rid, 7]);
        }
    }
    out
}

#[test]
fn logon_information_with_resource_groups_and_many_groups() {
    let resource_domain = sid("S-1-5-21-1-2-3");
    let other = sid("S-1-5-21-9-8-7-1000");
    let groups: Vec<u32> = (1000..1300).collect();
    let data = ndr_logon(
        &groups,
        &[&other],
        Some((&resource_domain, &[555, 556])),
        LOGON_RESOURCE_GROUPS | 0x20,
    );
    let logon = logon_info(&data).expect("logon info");
    assert_eq!(logon.user_sid, sid(&format!("{DOMAIN}-1104")));
    assert_eq!(logon.group_sids.len(), 300);
    assert_eq!(logon.extra_sids, std::slice::from_ref(&other));
    assert_eq!(
        logon.resource_group_sids,
        [sid("S-1-5-21-1-2-3-555"), sid("S-1-5-21-1-2-3-556")]
    );
    assert_eq!(logon.groups().len(), 1 + 300 + 1 + 2);
    // Without the D flag the resource groups are not taken.
    let data = ndr_logon(&[], &[], Some((&resource_domain, &[555])), 0);
    assert_eq!(logon_info(&data).expect("logon").resource_group_sids, []);
    // A count above the bound or beyond the octets is refused before allocating.
    let mut huge = ndr_logon(&[513], &[], None, 0);
    let at = huge.len() - (8 + 4) - (4 + 8 + 16);
    huge[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(logon_info(&huge).is_err());
    let data = ndr_logon(
        &groups,
        &[&other],
        Some((&resource_domain, &[555, 556])),
        LOGON_RESOURCE_GROUPS,
    );
    for len in 0..data.len() {
        assert!(logon_info(&data[..len]).is_err(), "prefix {len}");
    }
}
