//! A Kerberos initiator and a settable clock for the tests of GSS-TSIG (this crate's and
//! the acceptance tests'), over the codec and cipher of `tenko-krb`. Built only for tests
//! and with the `testing` feature; never in a release build.
//!
//! [`Initiator`] makes a ticket under a service key and an AP-REQ with the RFC 4121
//! checksum, raw or inside SPNEGO, as a Windows or MIT client would, and reads the
//! acceptor's AP-REP back into an initiator's [`GssContext`] that signs with
//! [`crate::tsig::Signer`] and verifies with [`crate::tsig::Verifier`]. [`pair`] makes the
//! two sides of a context directly, and [`Tkey::adopt`] puts the acceptor's side into a
//! node's table, so that the ownership rules can be tested with any SIDs.

use std::{
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicI64, Ordering},
    },
};

use tenko_core::dns::{EncryptionType, KeyVersionState, PrincipalName, Realm, Sid};
use tenko_krb::{
    acceptor::{Clock, KrbTime},
    cipher::{self, Key, usage},
    der::{
        ApRep, ApReq, Authenticator, Checksum, EncApRepPart, EncTicketPart, InitialContextToken,
        KrbToken, NegTokenInit, NegTokenResp, PrincipalName as WirePrincipal, Ticket,
        TransitedEncoding, gss::tok_id, name_type, oid,
    },
    keys::{KeyEntry, KeySet},
    mic::ContextMicKeys,
};

use super::{ContextParts, GssContext, GssIdentity, Role, Tkey};
use crate::name::NameBuf;

/// The realm of the tests.
pub const REALM: &str = "CORP.EXAMPLE.TEST";

/// The SPN of the tests' node.
pub const SPN: &str = "DNS/ns1.corp.example.test";

/// A clock the test moves.
#[derive(Debug)]
pub struct TestClock(AtomicI64);

impl TestClock {
    /// A clock at `secs`.
    pub fn new(secs: i64) -> Arc<Self> {
        Arc::new(Self(AtomicI64::new(secs)))
    }

    /// Sets the time.
    pub fn set(&self, secs: i64) {
        self.0.store(secs, Ordering::Relaxed);
    }

    /// The time.
    pub fn secs(&self) -> i64 {
        self.0.load(Ordering::Relaxed)
    }
}

impl Clock for TestClock {
    fn now(&self) -> KrbTime {
        KrbTime::from_secs(self.secs())
    }
}

/// A key whose octets follow from `seed`.
pub fn key(etype: EncryptionType, seed: u8) -> Key {
    let bytes: Vec<u8> = (0..cipher::key_len(etype))
        .map(|i| {
            u8::try_from(i % 256)
                .unwrap_or(0)
                .wrapping_mul(97)
                .wrapping_add(seed)
        })
        .collect();
    Key::new(etype, &bytes).unwrap_or_else(|_| unreachable!("a key of its own length"))
}

/// The service account's key set of the tests: `tenko-dns$@CORP.EXAMPLE.TEST`, `key`
/// at version `kvno`.
pub fn key_set(key: &Key, kvno: u32) -> KeySet {
    let principal = PrincipalName::parse("tenko-dns$@CORP.EXAMPLE.TEST")
        .unwrap_or_else(|_| unreachable!("a valid principal"));
    KeySet::new(vec![KeyEntry {
        principal,
        kvno,
        state: KeyVersionState::Current,
        key: key.clone(),
    }])
    .unwrap_or_else(|_| unreachable!("one entry"))
}

/// The realm of the tests.
pub fn realm() -> Realm {
    Realm::new(REALM).unwrap_or_else(|_| unreachable!("a valid realm"))
}

/// What an initiator puts in its AP-REQ.
#[derive(Debug, Clone)]
pub struct Initiator {
    /// The service key the ticket is encrypted in.
    pub service_key: Key,
    /// Its version.
    pub kvno: u32,
    /// The session key.
    pub session: Key,
    /// The initiator's subkey.
    pub subkey: Key,
    /// The initiator's first sequence number.
    pub seq: u32,
    /// The authenticator's time (Unix seconds).
    pub now: i64,
    /// Microseconds of the authenticator.
    pub cusec: u32,
    /// The ticket's end (Unix seconds).
    pub ticket_end: i64,
    /// The client principal's components, in `CORP.EXAMPLE.TEST`.
    pub client: Vec<String>,
    /// The SPN asked for.
    pub spn: Vec<String>,
}

impl Initiator {
    /// A Windows-shaped initiator for `client` (`pc01$`): mutual, replay, sequence and
    /// integrity, a subkey, an AP-REQ dated `now`, a ticket of ten hours.
    pub fn new(service_key: Key, kvno: u32, client: &str, now: i64) -> Self {
        let etype = service_key.etype();
        Self {
            service_key,
            kvno,
            session: key(etype, 0x11),
            subkey: key(etype, 0x22),
            seq: 0x0123_4567,
            now,
            cusec: 123_456,
            ticket_end: now + 10 * 3_600,
            client: vec![client.to_owned()],
            spn: SPN.split('/').map(str::to_owned).collect(),
        }
    }

    /// The client principal.
    pub fn principal(&self) -> PrincipalName {
        PrincipalName::parse(&format!("{}@{REALM}", self.client.join("/")))
            .unwrap_or_else(|_| unreachable!("a valid principal"))
    }

    fn ticket(&self) -> Ticket {
        let part = EncTicketPart {
            flags: 0x40a1_0000,
            key: self.session.to_wire(),
            crealm: REALM.to_owned(),
            cname: WirePrincipal {
                name_type: name_type::PRINCIPAL,
                components: self.client.clone(),
            },
            transited: TransitedEncoding {
                tr_type: 1,
                contents: vec![],
            },
            authtime: self.now - 60,
            starttime: Some(self.now - 60),
            endtime: self.ticket_end,
            renew_till: None,
            caddr: None,
            authorization_data: None,
        };
        let mut enc = cipher::encrypt_data(&self.service_key, usage::TICKET, &part.encode())
            .unwrap_or_else(|_| unreachable!("AES encrypts"));
        enc.kvno = Some(self.kvno);
        Ticket {
            realm: REALM.to_owned(),
            sname: WirePrincipal {
                name_type: name_type::SRV_INST,
                components: self.spn.clone(),
            },
            enc_part: enc,
        }
    }

    fn ap_req(&self) -> Vec<u8> {
        let mut checksum = 16_u32.to_le_bytes().to_vec();
        checksum.extend_from_slice(&[0; 16]);
        checksum.extend_from_slice(&0x3e_u32.to_le_bytes());
        let auth = Authenticator {
            crealm: REALM.to_owned(),
            cname: WirePrincipal {
                name_type: name_type::PRINCIPAL,
                components: self.client.clone(),
            },
            cksum: Some(Checksum {
                cksumtype: 0x8003,
                checksum,
            }),
            cusec: self.cusec,
            ctime: self.now,
            subkey: Some(self.subkey.to_wire()),
            seq_number: Some(self.seq),
            authorization_data: None,
        };
        let authenticator =
            cipher::encrypt_data(&self.session, usage::AP_REQ_AUTHENTICATOR, &auth.encode())
                .unwrap_or_else(|_| unreachable!("AES encrypts"));
        ApReq {
            ap_options: 0x2000_0000,
            ticket: self.ticket(),
            authenticator,
        }
        .encode()
    }

    /// The raw Kerberos token (what MIT's `nsupdate -g` may send).
    pub fn raw_token(&self) -> Vec<u8> {
        KrbToken::encode(oid::KRB5, tok_id::AP_REQ, &self.ap_req())
    }

    /// The SPNEGO token with Windows' list (Microsoft's Kerberos OID first, then the
    /// standard one, `NegoEx` and NTLM) and the optimistic Kerberos token.
    pub fn spnego_token(&self) -> Vec<u8> {
        let token = KrbToken::encode(oid::MS_KRB5, tok_id::AP_REQ, &self.ap_req());
        NegTokenInit {
            mech_types: vec![oid::MS_KRB5, oid::KRB5, oid::NEGOEX, oid::NTLMSSP],
            mech_types_der: &[],
            req_flags: None,
            mech_token: Some(&token),
            mech_list_mic: None,
        }
        .encode_initial()
    }

    /// An SPNEGO token that offers NTLM only.
    pub fn ntlm_only_token() -> Vec<u8> {
        NegTokenInit {
            mech_types: vec![oid::NTLMSSP],
            mech_types_der: &[],
            req_flags: None,
            mech_token: Some(b"NTLMSSP\0\x01\0\0\0"),
            mech_list_mic: None,
        }
        .encode_initial()
    }

    /// Reads the acceptor's last token (raw, or a `negTokenResp` around the AP-REP) and
    /// makes the initiator's side of the context named `name` (lowercase wire form) with
    /// the server at `server`.
    ///
    /// # Panics
    ///
    /// When the token is not an AP-REP that decrypts under the session key.
    pub fn finish(&self, name: &[u8], token: &[u8], server: IpAddr) -> Arc<GssContext> {
        let (subkey, acceptor_seq) = self.ap_rep(token);
        self.context(name, &subkey, acceptor_seq, 0, server)
    }

    /// The acceptor subkey and sequence number of the AP-REP in `token` (raw, or a
    /// `negTokenResp` around it).
    ///
    /// # Panics
    ///
    /// When the token is not an AP-REP that decrypts under the session key.
    pub fn ap_rep(&self, token: &[u8]) -> (Key, u32) {
        let inner = match NegTokenResp::decode(token) {
            Ok(resp) => resp.response_token.expect("the AP-REP in the negTokenResp"),
            Err(_) => token,
        };
        let outer = InitialContextToken::decode(inner).expect("the AP-REP token");
        let krb = KrbToken::decode(outer.inner).expect("a Kerberos token");
        assert_eq!(krb.tok_id, tok_id::AP_REP, "an AP-REP");
        let rep = ApRep::decode(krb.message).expect("AP-REP");
        let plain = cipher::decrypt_data(&self.session, usage::AP_REP_ENC_PART, &rep.enc_part)
            .expect("the AP-REP decrypts under the session key");
        let part = EncApRepPart::decode(&plain).expect("EncAPRepPart");
        assert_eq!(
            (part.ctime, part.cusec),
            (self.now, self.cusec),
            "mutual authentication"
        );
        let subkey = Key::from_wire(&part.subkey.expect("an acceptor subkey")).expect("AES");
        (
            subkey,
            part.seq_number.expect("the acceptor's sequence number"),
        )
    }

    /// The initiator's side of the context named `name` under the acceptor `subkey`, when
    /// each side already used `mics` sequence numbers for the SPNEGO `mechListMIC`.
    ///
    /// # Panics
    ///
    /// When `name` is not a wire name.
    pub fn context(
        &self,
        name: &[u8],
        subkey: &Key,
        acceptor_seq: u32,
        mics: u64,
        server: IpAddr,
    ) -> Arc<GssContext> {
        let keys = ContextMicKeys::new(subkey, true).expect("MIC keys");
        Arc::new(GssContext::new(ContextParts {
            name: NameBuf::from_wire(name).expect("a key name"),
            identity: GssIdentity {
                principal: self.principal(),
                sid: None,
                groups: Vec::new(),
            },
            keys,
            role: Role::Initiator,
            send_seq: u64::from(self.seq) + mics,
            receive_seq: u64::from(acceptor_seq) + mics,
            client: server,
            established: u64::try_from(self.now).unwrap_or(0),
            expires: u64::try_from(self.ticket_end).unwrap_or(0),
        }))
    }
}

/// The two sides of one context named `name` (lowercase wire form) for `identity`, from
/// `client`, valid from `now` for an hour: the acceptor's, for [`Tkey::adopt`], and the
/// initiator's, for the client.
///
/// # Panics
///
/// When `name` is not a wire name or `principal` not a principal.
pub fn pair(
    name: &[u8],
    principal: &str,
    sid: Option<Sid>,
    groups: Vec<Sid>,
    client: IpAddr,
    now: u64,
) -> (Arc<GssContext>, Arc<GssContext>) {
    let context_key = Key::random(EncryptionType::Aes256CtsHmacSha1).expect("a random key");
    let identity = GssIdentity {
        principal: PrincipalName::parse(principal).expect("a principal"),
        sid,
        groups,
    };
    let side = |role, send_seq, receive_seq| {
        Arc::new(GssContext::new(ContextParts {
            name: NameBuf::from_wire(name).expect("a key name"),
            identity: identity.clone(),
            keys: ContextMicKeys::new(&context_key, true).expect("MIC keys"),
            role,
            send_seq,
            receive_seq,
            client,
            established: now,
            expires: now + 3_600,
        }))
    };
    (
        side(Role::Acceptor, 1_000, 5_000),
        side(Role::Initiator, 5_000, 1_000),
    )
}

impl Tkey {
    /// Puts an established context into the table, as a completed negotiation would.
    pub fn adopt(&self, context: Arc<GssContext>) {
        let now = self.now();
        let mut table = self.table();
        table.insert(context, self.settings.contexts_max, now);
        table.gauges();
    }
}
