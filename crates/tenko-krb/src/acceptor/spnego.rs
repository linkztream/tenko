//! RFC 4178 SPNEGO, acceptor side, and the dispatch of the first token.

use super::{AcceptError, Context, Mech, Negotiation, State, Step, ap};
use crate::{
    der::{InitialContextToken, NegState, NegTokenInit, NegTokenResp, oid},
    mic::ContextMicKeys,
};

/// The first octets of an NTLMSSP message, which some clients send raw.
const NTLMSSP: &[u8] = b"NTLMSSP\0";

/// The mechanism an OID names, inside SPNEGO or raw.
fn kerberos(mech: &[u8], spnego: bool) -> Option<Mech> {
    match (mech, spnego) {
        (m, false) if m == oid::KRB5 => Some(Mech::Krb5),
        (m, false) if m == oid::MS_KRB5 => Some(Mech::MsKrb5),
        (m, true) if m == oid::KRB5 => Some(Mech::SpnegoKrb5),
        (m, true) if m == oid::MS_KRB5 => Some(Mech::SpnegoMsKrb5),
        _ => None,
    }
}

const fn mech_oid(mech: Mech) -> &'static [u8] {
    match mech {
        Mech::Krb5 | Mech::SpnegoKrb5 => oid::KRB5,
        Mech::MsKrb5 | Mech::SpnegoMsKrb5 => oid::MS_KRB5,
    }
}

/// The initiator's first token.
pub(super) fn first(negotiation: &mut Negotiation, token: &[u8]) -> Result<Step, AcceptError> {
    if token.starts_with(NTLMSSP) {
        return Err(AcceptError::Mechanism("NTLM is not accepted"));
    }
    // Decision 1: dispatch on the OID of the InitialContextToken: SPNEGO, krb5 or ms-krb5;
    // a raw Kerberos token is accepted (MIT clients may send one).
    let outer = InitialContextToken::decode(token)?;
    if outer.mech != oid::SPNEGO {
        let mech = kerberos(outer.mech, false)
            .ok_or(AcceptError::Mechanism("the token is not for Kerberos"))?;
        let accepted = ap::accept(&negotiation.service, token, mech)?;
        return Ok(Step::Established {
            token: accepted.token,
            context: Box::new(accepted.context),
        });
    }
    let init = NegTokenInit::decode_initial(token)?;
    // Decision 3 (RFC 4178 section 3.1): the mechanism is the first Kerberos OID in the
    // initiator's order; NTLM and NegoEx are never chosen.
    let (index, mech) = init
        .mech_types
        .iter()
        .enumerate()
        .find_map(|(index, m)| kerberos(m, true).map(|mech| (index, mech)))
        .ok_or(AcceptError::Mechanism(
            "the mechanism list offers no Kerberos",
        ))?;
    let mech_types_der = init.mech_types_der.to_vec();
    // The optimistic token is for the initiator's first mechanism (RFC 4178 section 3.2).
    // When Kerberos is not first, or no token came, the token is discarded and the
    // Kerberos token is asked for; the MIC exchange is then required (section 5).
    let Some(mech_token) = init.mech_token.filter(|_| index == 0) else {
        let resp = NegTokenResp {
            neg_state: Some(NegState::AcceptIncomplete),
            supported_mech: Some(mech_oid(mech)),
            response_token: None,
            mech_list_mic: None,
        };
        negotiation.state = State::AwaitToken {
            mech,
            mech_types_der,
        };
        return Ok(Step::Continue(resp.encode()));
    };
    let accepted = ap::accept(&negotiation.service, mech_token, mech)?;
    // Decision 2 (RFC 4178 section 5): when Kerberos is the initiator's first choice the
    // MIC exchange is optional and is skipped, so that the context is established in one
    // round trip as Windows DNS expects of TKEY; when the initiator sent a MIC anyway, it
    // is verified and answered.
    finish(
        negotiation,
        accepted,
        mech,
        mech_types_der,
        init.mech_list_mic,
        init.mech_list_mic.is_some(),
    )
}

/// The initiator's Kerberos token after the acceptor asked for it.
pub(super) fn token_leg(
    negotiation: &mut Negotiation,
    token: &[u8],
    mech: Mech,
    mech_types_der: Vec<u8>,
) -> Result<Step, AcceptError> {
    let resp = NegTokenResp::decode(token)?;
    let mech_token = resp.response_token.ok_or(AcceptError::State(
        "negTokenResp without the Kerberos token",
    ))?;
    let accepted = ap::accept(&negotiation.service, mech_token, mech)?;
    finish(
        negotiation,
        accepted,
        mech,
        mech_types_der,
        resp.mech_list_mic,
        true,
    )
}

/// Answers an accepted AP-REQ, with the `mechListMIC` exchange when it is needed.
fn finish(
    negotiation: &mut Negotiation,
    accepted: ap::Accepted,
    mech: Mech,
    mech_types_der: Vec<u8>,
    initiator_mic: Option<&[u8]>,
    mic_needed: bool,
) -> Result<Step, AcceptError> {
    let mut context = accepted.context;
    let keys = context.mic_keys().map_err(AcceptError::Cipher)?;
    if let Some(mic) = initiator_mic {
        verify_mech_list_mic(&keys, &mut context, &mech_types_der, mic)?;
    }
    let our_mic = if mic_needed {
        // Decision 4: the mechListMIC is GSS_GetMIC over the DER of the mechanism list and
        // consumes the acceptor's first sequence number, so the first TSIG MIC carries
        // one more.
        let mic = keys
            .acceptor
            .sign(u64::from(context.acceptor_seq), &mech_types_der);
        context.acceptor_seq = context.acceptor_seq.wrapping_add(1);
        Some(mic)
    } else {
        None
    };
    let complete = !mic_needed || initiator_mic.is_some();
    let resp = NegTokenResp {
        neg_state: Some(if complete {
            NegState::AcceptCompleted
        } else {
            NegState::AcceptIncomplete
        }),
        supported_mech: Some(mech_oid(mech)),
        response_token: Some(&accepted.token),
        mech_list_mic: our_mic.as_ref().map(|m| &m[..]),
    }
    .encode();
    if complete {
        Ok(Step::Established {
            token: resp,
            context: Box::new(context),
        })
    } else {
        negotiation.state = State::AwaitMic {
            context: Box::new(context),
            mech_types_der,
        };
        Ok(Step::Continue(resp))
    }
}

/// The initiator's `mechListMIC` after the acceptor sent its own.
pub(super) fn mic_leg(
    token: &[u8],
    mut context: Context,
    mech_types_der: &[u8],
) -> Result<Step, AcceptError> {
    let resp = NegTokenResp::decode(token)?;
    let mic = resp.mech_list_mic.ok_or(AcceptError::MechListMic(
        "the required mechListMIC is missing",
    ))?;
    let keys = context.mic_keys().map_err(AcceptError::Cipher)?;
    verify_mech_list_mic(&keys, &mut context, mech_types_der, mic)?;
    // Decision 5: the final token after the MIC leg is accept-completed without a
    // response token.
    let out = NegTokenResp {
        neg_state: Some(NegState::AcceptCompleted),
        supported_mech: None,
        response_token: None,
        mech_list_mic: None,
    }
    .encode();
    Ok(Step::Established {
        token: out,
        context: Box::new(context),
    })
}

/// Verifies the initiator's `mechListMIC`: it carries the authenticator's sequence
/// number, which it then consumes.
fn verify_mech_list_mic(
    keys: &ContextMicKeys,
    context: &mut Context,
    mech_types_der: &[u8],
    mic: &[u8],
) -> Result<(), AcceptError> {
    let header = keys.initiator.verify(mic, mech_types_der)?;
    if header.seq != u64::from(context.initiator_seq) {
        return Err(AcceptError::MechListMic(
            "its sequence number is not the authenticator's",
        ));
    }
    context.initiator_seq = context.initiator_seq.wrapping_add(1);
    Ok(())
}
