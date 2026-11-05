//! The Kerberos mechanism, acceptor side: RFC 4120, section 3.2, and RFC 4121,
//! sections 4.1 and 4.1.1, over `picky-krb`.

use picky_asn1::restricted_string::IA5String;
use picky_asn1::wrapper::{
    ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2, ExplicitContextTag3,
    IntegerAsn1, ObjectIdentifierAsn1, OctetStringAsn1, Optional,
};
use picky_asn1_x509::oids;
use picky_krb::constants::gss_api::{AP_REP_TOKEN_ID, AP_REQ_TOKEN_ID};
use picky_krb::constants::key_usages::{AP_REP_ENC, AP_REQ_AUTHENTICATOR, TICKET_REP};
use picky_krb::constants::types::AP_REP_MSG_TYPE;
use picky_krb::crypto::CipherSuite;
use picky_krb::data_types::{
    Authenticator, EncApRepPart, EncApRepPartInner, EncTicketPart, EncryptedData, EncryptionKey,
    KerberosStringAsn1, PrincipalName,
};
use picky_krb::gss_api::{ApplicationTag0, KrbMessage};
use picky_krb::messages::{ApRep, ApRepInner, ApReq};
use time::OffsetDateTime;
use zeroize::Zeroizing;

use super::{Config, ReplayCache, ReplayKey};
use crate::acceptor::{Context, Enctype, Error, Mech, ServiceKey};

/// Checksum type of the RFC 4121 authenticator checksum.
pub const GSS_CKSUM_TYPE: i64 = 0x8003;
/// RFC 4121 flags.
pub const GSS_C_MUTUAL_FLAG: u32 = 0x02;
pub const GSS_C_REPLAY_FLAG: u32 = 0x04;
pub const GSS_C_SEQUENCE_FLAG: u32 = 0x08;
pub const GSS_C_INTEG_FLAG: u32 = 0x20;
pub const GSS_C_DCE_STYLE: u32 = 0x1000;
/// AP options (RFC 4120, section 5.5.1), as bits of the 32-bit field.
pub const AP_MUTUAL_REQUIRED: u32 = 0x2000_0000;
pub const AP_USE_SESSION_KEY: u32 = 0x4000_0000;
/// Ticket flags (RFC 4120, section 5.3), as bit indexes of the BIT STRING.
pub const TKT_INVALID: usize = 7;

/// The result of accepting an AP-REQ.
pub struct Accepted {
    /// The AP-REP as an InitialContextToken (`60 .. OID 02 00 ..`) under the request's OID.
    pub token: Vec<u8>,
    pub context: Context,
}

fn int(i: &IntegerAsn1) -> i64 {
    let b = i.as_unsigned_bytes_be();
    let mut v: i64 = 0;
    for x in b.iter().take(8) {
        v = (v << 8) | i64::from(*x);
    }
    v
}

fn name_parts(p: &PrincipalName) -> Vec<String> {
    p.name_string.0.0.iter().map(|s| s.0.to_string()).collect()
}

fn gen_time(t: &picky_asn1::wrapper::GeneralizedTimeAsn1) -> Result<i64, Error> {
    let odt = OffsetDateTime::try_from(t.0.clone()).map_err(|e| Error(format!("time: {e:?}")))?;
    Ok(odt.unix_timestamp())
}

fn now_odt(now: i64) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(now).unwrap_or(OffsetDateTime::UNIX_EPOCH)
}

fn pick_key(keys: &[ServiceKey], enctype: Enctype, kvno: Option<i64>) -> Option<&ServiceKey> {
    keys.iter().find(|k| {
        k.enctype == enctype
            && match (k.kvno, kvno) {
                (Some(mine), Some(theirs)) => i64::from(mine) == theirs,
                _ => true,
            }
    })
}

/// The flags and channel bindings of the 0x8003 checksum.
pub struct GssChecksum {
    pub bindings: [u8; 16],
    pub flags: u32,
}

/// Parses the RFC 4121 section 4.1.1 checksum. Decision: the length field must be 16 and
/// the delegation option, if present, is skipped; extensions are ignored.
pub fn parse_gss_checksum(data: &[u8]) -> Result<GssChecksum, Error> {
    if data.len() < 24 {
        return Err("GSS checksum shorter than 24 octets".into());
    }
    let lgth = u32::from_le_bytes(data[0..4].try_into().expect("4"));
    if lgth != 16 {
        return Err(format!("GSS checksum Lgth {lgth}, expected 16").into());
    }
    let bindings: [u8; 16] = data[4..20].try_into().expect("16");
    let flags = u32::from_le_bytes(data[20..24].try_into().expect("4"));
    Ok(GssChecksum { bindings, flags })
}

/// Accepts a raw Kerberos InitialContextToken carrying an AP-REQ, returns the AP-REP token
/// and the context. `mech` is the mechanism the OID named, when the caller knows it.
pub fn accept(
    cfg: &Config,
    replay: &mut ReplayCache,
    token: &[u8],
    mech: Option<Mech>,
) -> Result<Accepted, Error> {
    let now = cfg.now();
    let msg = KrbMessage::<ApReq>::decode_application_krb_message(token)
        .map_err(|e| Error(format!("InitialContextToken: {e:?}")))?
        .0;
    // Decision: the OID of the response is the OID of the request (MIT refuses an AP-REP
    // under the other Kerberos OID); the token id must be 01 00.
    if msg.krb5_token_id != AP_REQ_TOKEN_ID {
        return Err(format!("token id {:?} is not AP-REQ", msg.krb5_token_id).into());
    }
    let oid = msg.krb5_oid.0.clone();
    let mech = match (mech, super::mech_of_oid(&oid, false)) {
        (Some(m), _) => m,
        (None, Some(m)) => m,
        (None, None) => {
            return Err(format!("unsupported mechanism {}", crate::own::oid_string(&oid)).into());
        }
    };
    let ap_req = msg.krb_msg.0;

    // AP options.
    let ap_opts = ap_req.ap_options.0.0;
    let opt_bytes = ap_opts.payload_view();
    let ap_options = if opt_bytes.len() == 4 {
        u32::from_be_bytes(opt_bytes.try_into().expect("4"))
    } else {
        return Err("ap-options is not 32 bits".into());
    };
    if ap_options & AP_USE_SESSION_KEY != 0 {
        return Err("user-to-user (USE-SESSION-KEY) is not accepted".into());
    }

    // The ticket: name, realm, key selection, decryption.
    let ticket = ap_req.ticket.0.0;
    let sname = name_parts(&ticket.sname.0);
    if sname != cfg.spn {
        return Err(format!("ticket is for {sname:?}, not for {:?}", cfg.spn).into());
    }
    let realm = ticket.realm.0.to_string();
    if !realm.eq_ignore_ascii_case(&cfg.realm) {
        return Err(format!("ticket realm {realm} is not {}", cfg.realm).into());
    }
    let enc = ticket.enc_part.0;
    let etype = int(&enc.etype.0);
    let enctype = Enctype::from_number(etype)
        .ok_or_else(|| Error(format!("ticket enctype {etype} is not AES")))?;
    let kvno = enc.kvno.0.as_ref().map(|k| int(&k.0));
    let key = pick_key(&cfg.keys, enctype, kvno)
        .ok_or_else(|| Error(format!("no key for enctype {etype} kvno {kvno:?}")))?;
    let cipher = CipherSuite::try_from(usize::try_from(etype).expect("positive"))
        .expect("AES")
        .cipher();
    let plain = Zeroizing::new(
        cipher
            .decrypt(&key.key, TICKET_REP, &enc.cipher.0.0)
            .map_err(|e| Error(format!("ticket does not decrypt: {e:?}")))?,
    );
    let tkt: EncTicketPart =
        picky_asn1_der::from_bytes(&plain).map_err(|e| Error(format!("EncTicketPart: {e}")))?;
    let tkt = tkt.0;
    if tkt.flags.0.0.is_set(TKT_INVALID) {
        return Err("ticket carries the INVALID flag".into());
    }
    let start = match &tkt.starttime.0 {
        Some(s) => gen_time(&s.0)?,
        None => gen_time(&tkt.auth_time.0)?,
    };
    let end = gen_time(&tkt.endtime.0)?;
    if start > now + cfg.max_skew_secs {
        return Err("ticket not yet valid".into());
    }
    if now > end + cfg.max_skew_secs {
        return Err("ticket expired".into());
    }
    let session_key = Zeroizing::new(tkt.key.0.key_value.0.0.clone());
    let session_etype = int(&tkt.key.0.key_type.0);
    let session_enctype = Enctype::from_number(session_etype)
        .ok_or_else(|| Error(format!("session key enctype {session_etype}")))?;
    if session_key.len() != session_enctype.key_len() {
        return Err("session key length does not match its enctype".into());
    }

    // The authenticator.
    let auth_enc = ap_req.authenticator.0;
    let auth_etype = int(&auth_enc.etype.0);
    if auth_etype != session_etype {
        return Err(format!(
            "authenticator enctype {auth_etype} differs from the session key's {session_etype}"
        )
        .into());
    }
    let auth_plain = Zeroizing::new(
        cipher_for(session_enctype)
            .decrypt(&session_key, AP_REQ_AUTHENTICATOR, &auth_enc.cipher.0.0)
            .map_err(|e| Error(format!("authenticator does not decrypt: {e:?}")))?,
    );
    let auth: Authenticator = picky_asn1_der::from_bytes(&auth_plain)
        .map_err(|e| Error(format!("Authenticator: {e}")))?;
    let auth = auth.0;
    if int(&auth.authenticator_vno.0) != 5 {
        return Err("authenticator vno is not 5".into());
    }
    let cname = name_parts(&auth.cname.0);
    let crealm = auth.crealm.0.to_string();
    if cname != name_parts(&tkt.cname.0) || crealm != tkt.crealm.0.to_string() {
        return Err("client name or realm differs between ticket and authenticator".into());
    }
    let ctime = gen_time(&auth.ctime.0)?;
    if (now - ctime).abs() > cfg.max_skew_secs {
        return Err(format!("clock skew {} s", (now - ctime).abs()).into());
    }
    // Decision: the replay key is client, realm, ctime and cusec (RFC 4120, 3.2.3). The
    // service name is fixed per acceptor.
    let replay_key = ReplayKey {
        client: cname.join("/"),
        realm: crealm.clone(),
        ctime: format!("{:?}", auth.ctime.0.0),
        cusec: auth.cusec.0.as_unsigned_bytes_be().to_vec(),
    };
    if !replay.insert(replay_key) {
        return Err("authenticator replayed".into());
    }
    // The GSS checksum (RFC 4121, 4.1.1). Decision: a missing or foreign checksum type is
    // refused: GSS-API initiators always send 0x8003.
    let cksum = auth.cksum.0.ok_or("authenticator without a checksum")?.0;
    if int(&cksum.cksumtype.0) != GSS_CKSUM_TYPE {
        return Err(format!("checksum type {} is not 0x8003", int(&cksum.cksumtype.0)).into());
    }
    let gss = parse_gss_checksum(&cksum.checksum.0.0)?;
    // Decision: DNS has no channel bindings, so any Bnd is accepted (RFC 4121 says the
    // acceptor may ignore bindings it has none of).
    if gss.flags & GSS_C_DCE_STYLE != 0 {
        // Decision: DCE style needs a third leg (the initiator's AP-REP back); GSS-TSIG
        // clients do not use it, so the spike refuses it instead of implementing it.
        return Err("DCE style is not accepted".into());
    }
    let mutual = ap_options & AP_MUTUAL_REQUIRED != 0 || gss.flags & GSS_C_MUTUAL_FLAG != 0;
    if !mutual {
        // Decision: GSS-TSIG needs the AP-REP for its key and sequence; refuse without.
        return Err("mutual authentication was not requested".into());
    }
    let initiator_subkey = auth.subkey.0.as_ref().map(|k| k.0.key_value.0.0.clone());
    let initiator_seq = auth.seq_number.0.as_ref().map(|s| int(&s.0));
    let initiator_seq = match initiator_seq {
        Some(s) => Some(
            u32::try_from(s)
                .map_err(|_| Error("initiator sequence number exceeds 32 bits".into()))?,
        ),
        None => None,
    };

    // The AP-REP. Decision: an acceptor subkey of the session key's enctype, and a sequence
    // number below 2^30 so that its DER INTEGER stays positive and MIT's masks agree.
    let (subkey, acceptor_seq) = match &cfg.fixed_subkey {
        Some((k, s)) => (k.clone(), *s),
        None => {
            let mut k = vec![0u8; session_enctype.key_len()];
            getrandom::fill(&mut k).map_err(|e| Error(format!("random: {e}")))?;
            let mut s = [0u8; 4];
            getrandom::fill(&mut s).map_err(|e| Error(format!("random: {e}")))?;
            (k, u32::from_be_bytes(s) & 0x3fff_ffff)
        }
    };
    let subkey_field = if cfg.acceptor_subkey {
        Some(ExplicitContextTag2::from(EncryptionKey {
            key_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![session_enctype.number()])),
            key_value: ExplicitContextTag1::from(OctetStringAsn1::from(subkey.clone())),
        }))
    } else {
        None
    };
    let enc_part = EncApRepPart::from(EncApRepPartInner {
        ctime: ExplicitContextTag0::from(auth.ctime.0.clone()),
        cusec: ExplicitContextTag1::from(auth.cusec.0.clone()),
        subkey: Optional::from(subkey_field),
        seq_number: Optional::from(Some(ExplicitContextTag3::from(
            IntegerAsn1::from_bytes_be_unsigned(acceptor_seq.to_be_bytes().to_vec()),
        ))),
    });
    let enc_der =
        picky_asn1_der::to_vec(&enc_part).map_err(|e| Error(format!("EncApRepPart: {e}")))?;
    let cipher_text = cipher_for(session_enctype)
        .encrypt(&session_key, AP_REP_ENC, &enc_der)
        .map_err(|e| Error(format!("AP-REP encrypt: {e:?}")))?;
    let ap_rep = ApRep::from(ApRepInner {
        pvno: ExplicitContextTag0::from(IntegerAsn1::from(vec![5])),
        msg_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![AP_REP_MSG_TYPE])),
        enc_part: ExplicitContextTag2::from(EncryptedData {
            etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![session_enctype.number()])),
            kvno: Optional::from(None),
            cipher: ExplicitContextTag2::from(OctetStringAsn1::from(cipher_text)),
        }),
    });
    let token = picky_asn1_der::to_vec(&ApplicationTag0(KrbMessage {
        krb5_oid: ObjectIdentifierAsn1::from(oid),
        krb5_token_id: AP_REP_TOKEN_ID,
        krb_msg: ap_rep,
    }))
    .map_err(|e| Error(format!("AP-REP token: {e}")))?;

    // The context key (RFC 4121, section 2): the acceptor subkey when sent, else the
    // initiator's subkey, else the session key.
    let (key, acceptor_subkey, key_enctype) = if cfg.acceptor_subkey {
        (subkey, true, session_enctype)
    } else if let Some(k) = initiator_subkey {
        let e = Enctype::from_key_len(k.len()).ok_or("initiator subkey length")?;
        (k, false, e)
    } else {
        (session_key.to_vec(), false, session_enctype)
    };
    Ok(Accepted {
        token,
        context: Context {
            client: cname.join("/"),
            realm: crealm,
            mech,
            key,
            key_enctype,
            acceptor_subkey,
            initiator_seq,
            acceptor_seq,
            gss_flags: Some(gss.flags),
            expires_unix: Some(end),
        },
    })
}

fn cipher_for(e: Enctype) -> Box<dyn picky_krb::crypto::Cipher> {
    match e {
        Enctype::Aes128 => CipherSuite::Aes128CtsHmacSha196.cipher(),
        Enctype::Aes256 => CipherSuite::Aes256CtsHmacSha196.cipher(),
    }
}

/// Builds a principal name of type NT-SRV-INST from components (used by tests).
pub fn principal(name_type: u8, parts: &[&str]) -> PrincipalName {
    use picky_asn1::wrapper::Asn1SequenceOf;
    PrincipalName {
        name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![name_type])),
        name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(
            parts
                .iter()
                .map(|p| {
                    KerberosStringAsn1::from(
                        IA5String::from_string((*p).to_owned()).expect("ASCII"),
                    )
                })
                .collect::<Vec<_>>(),
        )),
    }
}

/// The OID of a mechanism.
pub fn oid_of(mech: Mech) -> oid::ObjectIdentifier {
    match mech {
        Mech::Krb5 | Mech::SpnegoKrb5 => oids::krb5(),
        Mech::MsKrb5 | Mech::SpnegoMsKrb5 => oids::ms_krb5(),
    }
}

#[allow(dead_code)]
fn _now(now: i64) -> OffsetDateTime {
    now_odt(now)
}
