//! An initiator for the tests, over Tenko's own codec and cipher: tickets under a service
//! key, AP-REQs with the RFC 4121 checksum, raw or inside SPNEGO, and the AP-REP check.

use tenko_core::dns::EncryptionType;

use crate::{
    cipher::{self, Key, usage},
    der::{
        ApRep, ApReq, Authenticator, Checksum, EncApRepPart, EncTicketPart, EncryptedData,
        InitialContextToken, KrbToken, NegTokenInit, PrincipalName, Ticket, TransitedEncoding,
        gss::tok_id, name_type,
    },
};

pub(crate) const REALM: &str = "CORP.EXAMPLE.TEST";
pub(crate) const SPN: &str = "DNS/tenko.corp.example.test";
pub(crate) const NOW: i64 = 1_793_867_714;

/// What the initiator puts in its AP-REQ.
pub(crate) struct Initiator {
    pub service_key: Key,
    pub kvno: Option<u32>,
    pub session: Key,
    pub subkey: Option<Key>,
    pub seq: u32,
    pub now: i64,
    pub ticket_start: i64,
    pub ticket_end: i64,
    pub ticket_flags: u32,
    pub gss_flags: u32,
    pub ap_options: u32,
    pub cusec: u32,
    pub realm: String,
    pub spn: Vec<String>,
    pub client: Vec<String>,
    pub authenticator_client: Option<Vec<String>>,
    pub authenticator_name_type: Option<i32>,
    pub checksum: Option<Checksum>,
}

pub(crate) fn key(etype: EncryptionType, seed: u8) -> Key {
    let bytes: Vec<u8> = (0..cipher::key_len(etype))
        .map(|i| {
            u8::try_from(i % 256)
                .expect("small")
                .wrapping_mul(97)
                .wrapping_add(seed)
        })
        .collect();
    Key::new(etype, &bytes).expect("key")
}

pub(crate) fn gss_checksum(flags: u32) -> Checksum {
    let mut data = 16_u32.to_le_bytes().to_vec();
    data.extend_from_slice(&[0; 16]);
    data.extend_from_slice(&flags.to_le_bytes());
    Checksum {
        cksumtype: 0x8003,
        checksum: data,
    }
}

impl Initiator {
    /// A Windows-shaped initiator: mutual, replay, sequence and integrity flags, a subkey,
    /// an AP-REQ dated `now`, a ticket valid for ten hours.
    pub(crate) fn new(service_key: Key, kvno: u32, now: i64) -> Self {
        let etype = service_key.etype();
        Self {
            service_key,
            kvno: Some(kvno),
            session: key(etype, 0x11),
            subkey: Some(key(etype, 0x22)),
            seq: 0x0123_4567,
            now,
            ticket_start: now - 60,
            ticket_end: now + 10 * 3600,
            ticket_flags: 0x40a1_0000,
            gss_flags: 0x3e,
            ap_options: 0x2000_0000,
            cusec: 123_456,
            realm: REALM.into(),
            spn: SPN.split('/').map(str::to_owned).collect(),
            client: vec!["pc01$".into()],
            authenticator_client: None,
            authenticator_name_type: None,
            checksum: None,
        }
    }

    pub(crate) fn ticket(&self) -> Ticket {
        let part = EncTicketPart {
            flags: self.ticket_flags,
            key: self.session.to_wire(),
            crealm: self.realm.clone(),
            cname: PrincipalName {
                name_type: name_type::PRINCIPAL,
                components: self.client.clone(),
            },
            transited: TransitedEncoding {
                tr_type: 1,
                contents: vec![],
            },
            authtime: self.ticket_start,
            starttime: Some(self.ticket_start),
            endtime: self.ticket_end,
            renew_till: None,
            caddr: None,
            authorization_data: None,
        };
        let mut enc = cipher::encrypt_data(&self.service_key, usage::TICKET, &part.encode())
            .expect("encrypt");
        enc.kvno = self.kvno;
        Ticket {
            realm: self.realm.clone(),
            sname: PrincipalName {
                name_type: name_type::SRV_INST,
                components: self.spn.clone(),
            },
            enc_part: enc,
        }
    }

    pub(crate) fn ap_req(&self) -> Vec<u8> {
        let auth = Authenticator {
            crealm: self.realm.clone(),
            cname: PrincipalName {
                name_type: self.authenticator_name_type.unwrap_or(name_type::PRINCIPAL),
                components: self
                    .authenticator_client
                    .clone()
                    .unwrap_or_else(|| self.client.clone()),
            },
            cksum: Some(
                self.checksum
                    .clone()
                    .unwrap_or_else(|| gss_checksum(self.gss_flags)),
            ),
            cusec: self.cusec,
            ctime: self.now,
            subkey: self.subkey.as_ref().map(Key::to_wire),
            seq_number: Some(self.seq),
            authorization_data: None,
        };
        let authenticator: EncryptedData =
            cipher::encrypt_data(&self.session, usage::AP_REQ_AUTHENTICATOR, &auth.encode())
                .expect("encrypt");
        ApReq {
            ap_options: self.ap_options,
            ticket: self.ticket(),
            authenticator,
        }
        .encode()
    }

    /// The raw GSS token under `mech`.
    pub(crate) fn token(&self, mech: &[u8]) -> Vec<u8> {
        KrbToken::encode(mech, tok_id::AP_REQ, &self.ap_req())
    }

    /// A `negTokenInit` over `mechs` with `mech_token` and an optional MIC.
    pub(crate) fn spnego(
        mechs: &[&[u8]],
        mech_token: Option<&[u8]>,
        mic: Option<&[u8]>,
    ) -> Vec<u8> {
        NegTokenInit {
            mech_types: mechs.to_vec(),
            mech_types_der: &[],
            req_flags: None,
            mech_token,
            mech_list_mic: mic,
        }
        .encode_initial()
    }

    /// Checks an AP-REP token: its OID and its encrypted part under the session key.
    pub(crate) fn check_ap_rep(&self, token: &[u8], mech: &[u8]) -> (Key, u32) {
        let outer = InitialContextToken::decode(token).expect("AP-REP token");
        assert_eq!(outer.mech, mech, "the AP-REP carries the request's OID");
        let inner = KrbToken::decode(outer.inner).expect("krb token");
        assert_eq!(inner.tok_id, tok_id::AP_REP);
        let rep = ApRep::decode(inner.message).expect("AP-REP");
        let plain = cipher::decrypt_data(&self.session, usage::AP_REP_ENC_PART, &rep.enc_part)
            .expect("decrypts");
        let part = EncApRepPart::decode(&plain).expect("EncAPRepPart");
        assert_eq!((part.ctime, part.cusec), (self.now, self.cusec));
        let subkey = Key::from_wire(&part.subkey.expect("acceptor subkey")).expect("aes");
        assert_eq!(subkey.etype(), self.session.etype());
        let seq = part.seq_number.expect("sequence number");
        assert!(seq < 1 << 30);
        (subkey, seq)
    }
}
