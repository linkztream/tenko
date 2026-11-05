//! An initiator written over `picky-krb` for the tests: it makes tickets under the service
//! key, AP-REQs with the RFC 4121 checksum, wraps them raw or in SPNEGO, and checks the
//! AP-REP. Its MICs come from `picky-krb`'s checksum, independent of `mic.rs`.

use picky_asn1::bit_string::BitString;
use picky_asn1::wrapper::{
    BitStringAsn1, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2,
    ExplicitContextTag3, ExplicitContextTag4, ExplicitContextTag5, ExplicitContextTag6,
    ExplicitContextTag7, GeneralizedTimeAsn1, IntegerAsn1, ObjectIdentifierAsn1, OctetStringAsn1,
    Optional,
};
use picky_asn1_x509::oids;
use picky_krb::constants::gss_api::{AP_REP_TOKEN_ID, AP_REQ_TOKEN_ID};
use picky_krb::constants::key_usages::{AP_REP_ENC, AP_REQ_AUTHENTICATOR, TICKET_REP};
use picky_krb::constants::types::{AP_REQ_MSG_TYPE, NT_PRINCIPAL, NT_SRV_INST};
use picky_krb::crypto::CipherSuite;
use picky_krb::crypto::aes::{AesSize, checksum_sha_aes};
use picky_krb::data_types::{
    Authenticator, AuthenticatorInner, Checksum, EncApRepPart, EncTicketPart, EncTicketPartInner,
    EncryptedData, EncryptionKey, Ticket, TicketInner, TransitedEncoding,
};
use picky_krb::gss_api::{ApplicationTag0, KrbMessage, NegTokenTarg1};
use picky_krb::messages::{ApRep, ApReq, ApReqInner};
use time::OffsetDateTime;

use crate::acceptor::{Enctype, Mech, ServiceKey};
use crate::mic::{ACCEPTOR_SIGN, INITIATOR_SIGN};

/// The fictitious realm and service of the plan.
pub const REALM: &str = "CORP.EXAMPLE.TEST";
pub const SPN: [&str; 2] = ["DNS", "tenko.corp.example.test"];
pub const CLIENT: &str = "pc01$";

/// What the initiator put in the AP-REQ.
pub struct Initiator {
    pub service_key: ServiceKey,
    pub session_enctype: Enctype,
    pub session_key: Vec<u8>,
    pub subkey: Option<Vec<u8>>,
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
    pub client: String,
}

/// A deterministic key of `len` octets from a seed.
pub fn key_bytes(seed: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(97).wrapping_add(seed))
        .collect()
}

/// A service key.
pub fn service_key(enctype: Enctype, kvno: u32) -> ServiceKey {
    ServiceKey {
        enctype,
        kvno: Some(kvno),
        key: key_bytes(0x51 + enctype.number(), enctype.key_len()),
    }
}

impl Initiator {
    /// A Windows-shaped initiator: mutual, replay, sequence and integrity flags, a subkey,
    /// an AP-REQ dated `now`, a ticket valid for ten hours.
    pub fn new(service_key: ServiceKey, session_enctype: Enctype, now: i64) -> Self {
        Initiator {
            service_key,
            session_enctype,
            session_key: key_bytes(0x11, session_enctype.key_len()),
            subkey: Some(key_bytes(0x22, session_enctype.key_len())),
            seq: 0x0123_4567,
            now,
            ticket_start: now - 60,
            ticket_end: now + 10 * 3600,
            // forwardable, renewable, initial, pre-authent
            ticket_flags: 0x40a1_0000,
            gss_flags: 0x3e,
            ap_options: 0x2000_0000,
            cusec: 123_456,
            realm: REALM.into(),
            spn: SPN.iter().map(|s| (*s).to_owned()).collect(),
            client: CLIENT.into(),
        }
    }

    fn cipher(e: Enctype) -> Box<dyn picky_krb::crypto::Cipher> {
        match e {
            Enctype::Aes128 => CipherSuite::Aes128CtsHmacSha196.cipher(),
            Enctype::Aes256 => CipherSuite::Aes256CtsHmacSha196.cipher(),
        }
    }

    fn time(unix: i64) -> GeneralizedTimeAsn1 {
        let odt = OffsetDateTime::from_unix_timestamp(unix).expect("in range");
        GeneralizedTimeAsn1::from(picky_asn1::date::GeneralizedTime::from(odt))
    }

    fn key(enctype: Enctype, bytes: &[u8]) -> EncryptionKey {
        EncryptionKey {
            key_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![enctype.number()])),
            key_value: ExplicitContextTag1::from(OctetStringAsn1::from(bytes.to_vec())),
        }
    }

    fn realm_asn1(&self) -> picky_krb::data_types::Realm {
        picky_krb::data_types::KerberosStringAsn1::from(
            picky_asn1::restricted_string::IA5String::from_string(self.realm.clone())
                .expect("ASCII"),
        )
    }

    /// The ticket, encrypted under the service key.
    pub fn ticket(&self) -> Ticket {
        let spn: Vec<&str> = self.spn.iter().map(String::as_str).collect();
        let enc = EncTicketPart::from(EncTicketPartInner {
            flags: ExplicitContextTag0::from(BitStringAsn1::from(BitString::with_bytes_and_len(
                self.ticket_flags.to_be_bytes().to_vec(),
                32,
            ))),
            key: ExplicitContextTag1::from(Self::key(self.session_enctype, &self.session_key)),
            crealm: ExplicitContextTag2::from(self.realm_asn1()),
            cname: ExplicitContextTag3::from(crate::own::ap::principal(
                NT_PRINCIPAL,
                &[&self.client],
            )),
            transited: ExplicitContextTag4::from(TransitedEncoding {
                tr_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![1])),
                contents: ExplicitContextTag1::from(OctetStringAsn1::from(Vec::new())),
            }),
            auth_time: ExplicitContextTag5::from(Self::time(self.ticket_start)),
            starttime: Optional::from(Some(ExplicitContextTag6::from(Self::time(
                self.ticket_start,
            )))),
            endtime: ExplicitContextTag7::from(Self::time(self.ticket_end)),
            renew_till: Optional::from(None),
            caddr: Optional::from(None),
            authorization_data: Optional::from(None),
        });
        let der = picky_asn1_der::to_vec(&enc).expect("EncTicketPart");
        let cipher = Self::cipher(self.service_key.enctype)
            .encrypt(&self.service_key.key, TICKET_REP, &der)
            .expect("encrypt");
        Ticket::from(TicketInner {
            tkt_vno: ExplicitContextTag0::from(IntegerAsn1::from(vec![5])),
            realm: ExplicitContextTag1::from(self.realm_asn1()),
            sname: ExplicitContextTag2::from(crate::own::ap::principal(NT_SRV_INST, &spn)),
            enc_part: ExplicitContextTag3::from(EncryptedData {
                etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![
                    self.service_key.enctype.number(),
                ])),
                kvno: Optional::from(
                    self.service_key
                        .kvno
                        .map(|k| ExplicitContextTag1::from(IntegerAsn1::from(vec![k as u8]))),
                ),
                cipher: ExplicitContextTag2::from(OctetStringAsn1::from(cipher)),
            }),
        })
    }

    /// The RFC 4121 section 4.1.1 checksum: Lgth 16, zero bindings, the flags.
    pub fn gss_checksum(&self) -> Vec<u8> {
        let mut c = vec![16, 0, 0, 0];
        c.extend_from_slice(&[0u8; 16]);
        c.extend_from_slice(&self.gss_flags.to_le_bytes());
        c
    }

    /// The authenticator, encrypted under the session key.
    pub fn authenticator(&self) -> EncryptedData {
        let auth = Authenticator::from(AuthenticatorInner {
            authenticator_vno: ExplicitContextTag0::from(IntegerAsn1::from(vec![5])),
            crealm: ExplicitContextTag1::from(self.realm_asn1()),
            cname: ExplicitContextTag2::from(crate::own::ap::principal(
                NT_PRINCIPAL,
                &[&self.client],
            )),
            cksum: Optional::from(Some(ExplicitContextTag3::from(Checksum {
                cksumtype: ExplicitContextTag0::from(IntegerAsn1::from_bytes_be_unsigned(vec![
                    0x80, 0x03,
                ])),
                checksum: ExplicitContextTag1::from(OctetStringAsn1::from(self.gss_checksum())),
            }))),
            cusec: ExplicitContextTag4::from(IntegerAsn1::from_bytes_be_unsigned(
                self.cusec.to_be_bytes().to_vec(),
            )),
            ctime: ExplicitContextTag5::from(Self::time(self.now)),
            subkey: Optional::from(self.subkey.as_ref().map(|k| {
                ExplicitContextTag6::from(Self::key(
                    Enctype::from_key_len(k.len()).expect("AES length"),
                    k,
                ))
            })),
            seq_number: Optional::from(Some(ExplicitContextTag7::from(
                IntegerAsn1::from_bytes_be_unsigned(self.seq.to_be_bytes().to_vec()),
            ))),
            authorization_data: Optional::from(None),
        });
        let der = picky_asn1_der::to_vec(&auth).expect("Authenticator");
        let cipher = Self::cipher(self.session_enctype)
            .encrypt(&self.session_key, AP_REQ_AUTHENTICATOR, &der)
            .expect("encrypt");
        EncryptedData {
            etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![
                self.session_enctype.number(),
            ])),
            kvno: Optional::from(None),
            cipher: ExplicitContextTag2::from(OctetStringAsn1::from(cipher)),
        }
    }

    /// The AP-REQ as an InitialContextToken under the mechanism's OID.
    pub fn ap_req_token(&self, mech: Mech) -> Vec<u8> {
        let ap_req = ApReq::from(ApReqInner {
            pvno: ExplicitContextTag0::from(IntegerAsn1::from(vec![5])),
            msg_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![AP_REQ_MSG_TYPE])),
            ap_options: ExplicitContextTag2::from(BitStringAsn1::from(
                BitString::with_bytes_and_len(self.ap_options.to_be_bytes().to_vec(), 32),
            )),
            ticket: ExplicitContextTag3::from(self.ticket()),
            authenticator: ExplicitContextTag4::from(self.authenticator()),
        });
        picky_asn1_der::to_vec(&ApplicationTag0(KrbMessage {
            krb5_oid: ObjectIdentifierAsn1::from(crate::own::ap::oid_of(mech)),
            krb5_token_id: AP_REQ_TOKEN_ID,
            krb_msg: ap_req,
        }))
        .expect("AP-REQ token")
    }

    /// The Windows mechanism list: MS KRB5, KRB5, NegoEx, NTLM.
    pub fn windows_mechs() -> Vec<oid::ObjectIdentifier> {
        vec![
            oids::ms_krb5(),
            oids::krb5(),
            oids::negoex(),
            oids::ntlm_ssp(),
        ]
    }

    /// The MIT mechanism list: KRB5 alone.
    pub fn mit_mechs() -> Vec<oid::ObjectIdentifier> {
        vec![oids::krb5()]
    }

    /// A `negTokenInit` with the given list and the optimistic AP-REQ under its first OID.
    pub fn spnego_token(&self, mechs: &[oid::ObjectIdentifier]) -> Vec<u8> {
        let inner = if mechs[0] == oids::ms_krb5() {
            Mech::MsKrb5
        } else {
            Mech::Krb5
        };
        crate::own::spnego::encode_init(mechs, &self.ap_req_token(inner))
    }

    /// Checks the AP-REP token: OID, token id, decryption, ctime and cusec; returns the
    /// acceptor subkey and sequence number.
    pub fn check_ap_rep(
        &self,
        token: &[u8],
        expected: Mech,
    ) -> Result<(Option<Vec<u8>>, u32), String> {
        let msg = KrbMessage::<ApRep>::decode_application_krb_message(token)
            .map_err(|e| format!("AP-REP token: {e:?}"))?
            .0;
        if msg.krb5_token_id != AP_REP_TOKEN_ID {
            return Err(format!("token id {:?}", msg.krb5_token_id));
        }
        let want = crate::own::ap::oid_of(expected);
        if msg.krb5_oid.0 != want {
            return Err(format!(
                "AP-REP under OID {} but the request used {}",
                crate::own::oid_string(&msg.krb5_oid.0),
                crate::own::oid_string(&want)
            ));
        }
        let enc = msg.krb_msg.0.enc_part.0;
        let etype = enc
            .etype
            .0
            .as_unsigned_bytes_be()
            .last()
            .copied()
            .unwrap_or(0);
        if i64::from(etype) != i64::from(self.session_enctype.number()) {
            return Err(format!(
                "AP-REP etype {etype}, session key is {}",
                self.session_enctype.number()
            ));
        }
        let plain = Self::cipher(self.session_enctype)
            .decrypt(&self.session_key, AP_REP_ENC, &enc.cipher.0.0)
            .map_err(|e| format!("AP-REP does not decrypt: {e:?}"))?;
        let part: EncApRepPart =
            picky_asn1_der::from_bytes(&plain).map_err(|e| format!("EncApRepPart: {e}"))?;
        let part = part.0;
        let ctime = OffsetDateTime::try_from(part.ctime.0.0)
            .map_err(|e| format!("{e:?}"))?
            .unix_timestamp();
        if ctime != self.now {
            return Err(format!("AP-REP ctime {ctime} is not {}", self.now));
        }
        let cusec = part
            .cusec
            .0
            .as_unsigned_bytes_be()
            .iter()
            .fold(0u32, |a, b| (a << 8) | u32::from(*b));
        if cusec != self.cusec {
            return Err(format!("AP-REP cusec {cusec} is not {}", self.cusec));
        }
        let subkey = part.subkey.0.map(|k| k.0.key_value.0.0);
        let seq = part
            .seq_number
            .0
            .map(|s| {
                s.0.as_unsigned_bytes_be()
                    .iter()
                    .fold(0u32, |a, b| (a << 8) | u32::from(*b))
            })
            .ok_or("AP-REP without a sequence number")?;
        Ok((subkey, seq))
    }

    /// Decodes the acceptor's `negTokenResp`.
    pub fn check_spnego_resp(&self, token: &[u8]) -> Result<SpnegoResp, String> {
        let t: NegTokenTarg1 =
            picky_asn1_der::from_bytes(token).map_err(|e| format!("negTokenResp: {e}"))?;
        let t = t.0;
        let result = t.neg_result.0.map(|r| r.0.0).unwrap_or_default();
        Ok(SpnegoResp {
            complete: result == picky_krb::constants::gss_api::ACCEPT_COMPLETE,
            supported_mech: t.supported_mech.0.map(|m| m.0.0),
            response_token: t.response_token.0.map(|r| r.0.0),
            mech_list_mic: t.mech_list_mic.0.map(|m| m.0.0),
        })
    }

    /// The context key the initiator ends with (RFC 4121, section 2).
    pub fn context_key(&self, acceptor_subkey: Option<&[u8]>) -> Vec<u8> {
        acceptor_subkey
            .map(<[u8]>::to_vec)
            .or_else(|| self.subkey.clone())
            .unwrap_or_else(|| self.session_key.clone())
    }

    /// A MIC as MIT would compute it, through `picky-krb`'s checksum rather than `mic.rs`.
    pub fn mic(
        &self,
        key: &[u8],
        acceptor_subkey: bool,
        from_acceptor: bool,
        seq: u64,
        data: &[u8],
    ) -> Vec<u8> {
        let mut flags = if from_acceptor { 0x01 } else { 0x00 };
        if acceptor_subkey {
            flags |= 0x04;
        }
        let mut header = vec![0x04, 0x04, flags, 0xff, 0xff, 0xff, 0xff, 0xff];
        header.extend_from_slice(&seq.to_be_bytes());
        let mut payload = data.to_vec();
        payload.extend_from_slice(&header);
        let aes = if key.len() == 16 {
            AesSize::Aes128
        } else {
            AesSize::Aes256
        };
        let usage = if from_acceptor {
            ACCEPTOR_SIGN
        } else {
            INITIATOR_SIGN
        };
        let sum = checksum_sha_aes(key, usage as i32, &payload, &aes).expect("checksum");
        header.extend_from_slice(&sum);
        header
    }
}

/// The acceptor's `negTokenResp`, decoded.
pub struct SpnegoResp {
    pub complete: bool,
    pub supported_mech: Option<oid::ObjectIdentifier>,
    pub response_token: Option<Vec<u8>>,
    pub mech_list_mic: Option<Vec<u8>>,
}
