//! RFC 4178 SPNEGO, acceptor side, over `picky-krb`'s `gss_api` types.

use picky_asn1::wrapper::{
    ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2, ExplicitContextTag3,
    ObjectIdentifierAsn1, OctetStringAsn1, Optional,
};
use picky_asn1_der::Asn1RawDer;
use picky_asn1_x509::oids;
use picky_krb::constants::gss_api::{ACCEPT_COMPLETE, ACCEPT_INCOMPLETE};
use picky_krb::gss_api::{
    ApplicationTag0, GssApiNegInit, MechTypeList, NegTokenTarg, NegTokenTarg1,
};

use crate::acceptor::{Context, Error, Mech};
use crate::mic::ContextMicKeys;

/// What the first octets of a token say it is.
pub enum Outer {
    Spnego,
    Krb5(Mech),
}

/// Reads the OID of an InitialContextToken (`60 len 06 ...`) without decoding the rest.
pub fn classify(token: &[u8]) -> Result<Outer, Error> {
    let (oid_der, _) = initial_context_oid(token)?;
    let oid: ObjectIdentifierAsn1 =
        picky_asn1_der::from_bytes(oid_der).map_err(|e| format!("token OID: {e}"))?;
    if oid.0 == oids::spnego() {
        return Ok(Outer::Spnego);
    }
    super::mech_of_oid(&oid.0, false)
        .map(Outer::Krb5)
        .ok_or_else(|| {
            Error(format!(
                "unsupported mechanism {}",
                super::oid_string(&oid.0)
            ))
        })
}

/// Splits `60 len` and returns the DER of the OID and the rest of the token.
fn initial_context_oid(token: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    if token.first() != Some(&0x60) {
        return Err("not an InitialContextToken (tag 0x60)".into());
    }
    let (len, hdr) = der_len(&token[1..])?;
    let body = token
        .get(1 + hdr..1 + hdr + len)
        .ok_or("InitialContextToken shorter than its length")?;
    if body.first() != Some(&0x06) {
        return Err("InitialContextToken without an OID".into());
    }
    let (olen, ohdr) = der_len(&body[1..])?;
    let oid_end = 1 + ohdr + olen;
    let oid = body.get(..oid_end).ok_or("truncated OID")?;
    Ok((oid, &body[oid_end..]))
}

fn der_len(b: &[u8]) -> Result<(usize, usize), Error> {
    let first = *b.first().ok_or("truncated length")?;
    if first < 0x80 {
        return Ok((usize::from(first), 1));
    }
    let n = usize::from(first & 0x7f);
    if n == 0 || n > 4 || b.len() < 1 + n {
        return Err("bad DER length".into());
    }
    let mut len = 0usize;
    for i in 0..n {
        len = (len << 8) | usize::from(b[1 + i]);
    }
    Ok((len, 1 + n))
}

/// The fields of a `negTokenInit` the acceptor reads.
pub struct Init {
    pub mech_types: Vec<oid::ObjectIdentifier>,
    /// The DER of the mechTypes list, the data a `mechListMIC` signs.
    pub mech_types_der: Vec<u8>,
    pub mech_token: Option<Vec<u8>>,
    pub mech_list_mic: Option<Vec<u8>>,
}

/// Decodes the initiator's first token.
pub fn decode_init(token: &[u8]) -> Result<Init, Error> {
    let neg: ApplicationTag0<GssApiNegInit> =
        picky_asn1_der::from_bytes(token).map_err(|e| format!("negTokenInit: {e}"))?;
    let init = neg.0.neg_token_init.0;
    let list: MechTypeList = init.mech_types.0.ok_or("negTokenInit without mechTypes")?.0;
    let mech_types_der = picky_asn1_der::to_vec(&list).map_err(|e| format!("mechTypes: {e}"))?;
    Ok(Init {
        mech_types: list.0.into_iter().map(|m| m.0).collect(),
        mech_types_der,
        mech_token: init.mech_token.0.map(|t| t.0.0),
        mech_list_mic: init.mech_list_mic.0.map(|t| t.0.0),
    })
}

/// Chooses the mechanism: the first of the initiator's list that is Kerberos (either OID),
/// in the initiator's order (RFC 4178, section 3.1). NTLM and NegoEx are never chosen.
pub fn choose(list: &[oid::ObjectIdentifier]) -> Result<(Mech, usize), Error> {
    list.iter()
        .enumerate()
        .find_map(|(i, o)| super::mech_of_oid(o, true).map(|m| (m, i)))
        .ok_or_else(|| "the mechanism list offers no Kerberos".into())
}

/// The fields of a `negTokenResp` from the initiator (the MIC leg).
pub struct Resp {
    pub mech_list_mic: Option<Vec<u8>>,
}

/// Decodes a `negTokenResp` sent by the initiator.
pub fn decode_resp(token: &[u8]) -> Result<Resp, Error> {
    let t: NegTokenTarg1 =
        picky_asn1_der::from_bytes(token).map_err(|e| format!("negTokenResp: {e}"))?;
    Ok(Resp {
        mech_list_mic: t.0.mech_list_mic.0.map(|m| m.0.0),
    })
}

/// Encodes the acceptor's `negTokenResp`.
pub fn encode_resp(
    complete: bool,
    mech: Option<Mech>,
    response_token: Option<&[u8]>,
    mech_list_mic: Option<&[u8]>,
) -> Result<Vec<u8>, Error> {
    let result = if complete {
        ACCEPT_COMPLETE
    } else {
        ACCEPT_INCOMPLETE
    };
    let supported = mech.map(|m| {
        let o = match m {
            Mech::SpnegoMsKrb5 | Mech::MsKrb5 => oids::ms_krb5(),
            Mech::SpnegoKrb5 | Mech::Krb5 => oids::krb5(),
        };
        ExplicitContextTag1::from(ObjectIdentifierAsn1::from(o))
    });
    let targ = NegTokenTarg {
        neg_result: Optional::from(Some(ExplicitContextTag0::from(Asn1RawDer(result.to_vec())))),
        supported_mech: Optional::from(supported),
        response_token: Optional::from(
            response_token.map(|t| ExplicitContextTag2::from(OctetStringAsn1::from(t.to_vec()))),
        ),
        mech_list_mic: Optional::from(
            mech_list_mic.map(|m| ExplicitContextTag3::from(OctetStringAsn1::from(m.to_vec()))),
        ),
    };
    picky_asn1_der::to_vec(&NegTokenTarg1::from(targ))
        .map_err(|e| Error(format!("negTokenResp: {e}")))
}

/// The acceptor's `mechListMIC`: GSS_GetMIC over the DER mechTypes on the new context.
/// Decision: it consumes the acceptor's first sequence number, so the first TSIG MIC
/// carries `acceptor_seq + 1`.
pub fn make_mech_list_mic(ctx: &Context, mech_types_der: &[u8]) -> Vec<u8> {
    let keys = ContextMicKeys::new(&ctx.key, ctx.key_enctype);
    let flags = keys.acceptor.sender_flags(ctx.acceptor_subkey);
    keys.acceptor
        .sign(flags, u64::from(ctx.acceptor_seq), mech_types_der)
        .to_vec()
}

/// Verifies the initiator's `mechListMIC`.
pub fn verify_mech_list_mic(ctx: &Context, mech_types_der: &[u8], mic: &[u8]) -> Result<(), Error> {
    let keys = ContextMicKeys::new(&ctx.key, ctx.key_enctype);
    let header = keys
        .initiator
        .verify(mic, mech_types_der)
        .map_err(|e| format!("mechListMIC: {e:?}"))?;
    if let Some(seq) = ctx.initiator_seq
        && header.seq != u64::from(seq)
    {
        return Err(format!(
            "mechListMIC sequence {} is not the authenticator's {seq}",
            header.seq
        )
        .into());
    }
    Ok(())
}

/// Builds a `negTokenInit` as an initiator would (used by the tests and the fixtures).
pub fn encode_init(mechs: &[oid::ObjectIdentifier], mech_token: &[u8]) -> Vec<u8> {
    use picky_krb::gss_api::NegTokenInit;
    let list = MechTypeList::from(
        mechs
            .iter()
            .cloned()
            .map(ObjectIdentifierAsn1::from)
            .collect::<Vec<_>>(),
    );
    let init = NegTokenInit {
        mech_types: Optional::from(Some(ExplicitContextTag0::from(list))),
        req_flags: Optional::from(None),
        mech_token: Optional::from(Some(ExplicitContextTag2::from(OctetStringAsn1::from(
            mech_token.to_vec(),
        )))),
        mech_list_mic: Optional::from(None),
    };
    let neg = ApplicationTag0(GssApiNegInit {
        oid: ObjectIdentifierAsn1::from(oids::spnego()),
        neg_token_init: ExplicitContextTag0::from(init),
    });
    picky_asn1_der::to_vec(&neg).expect("negTokenInit encodes")
}
