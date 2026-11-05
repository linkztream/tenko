//! The Kerberos mechanism, acceptor side: the AP-REQ checks of RFC 4120 section 3.2.3, the
//! authenticator checksum of RFC 4121 section 4.1.1, the PAC, and the AP-REP of RFC 4121
//! section 4.1 with an acceptor subkey.

use std::sync::PoisonError;

use tenko_core::dns::{PrincipalName, Realm};

use super::{AcceptError, Context, Mech, Service, gss_flags};
use crate::{
    cipher::{self, CipherError, Key, usage},
    der::{
        ApRep, ApReq, Authenticator, AuthorizationData, EncApRepPart, EncTicketPart, EncryptedData,
        InitialContextToken, KrbToken, ad_type, ap_options, gss::tok_id, oid, ticket_flags,
    },
    pac,
};

/// The checksum type of the RFC 4121 authenticator checksum.
pub const GSS_CHECKSUM_TYPE: i32 = 0x8003;

/// An accepted AP-REQ: the AP-REP token and the context.
pub(super) struct Accepted {
    /// The AP-REP as an `InitialContextToken` under the request's OID.
    pub token: Vec<u8>,
    pub context: Context,
}

/// The flags and bindings of the 0x8003 checksum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct GssChecksum {
    pub bindings: [u8; 16],
    pub flags: u32,
}

/// Parses the RFC 4121 section 4.1.1 checksum. Decision 7: the checksum is required
/// (GSS-API initiators always send it), `Lgth` must be 16, the delegation option is
/// skipped when the flags announce it, and extensions are ignored.
pub(super) fn parse_gss_checksum(data: &[u8]) -> Result<GssChecksum, AcceptError> {
    let malformed = AcceptError::Request("the GSS checksum is malformed");
    if data.len() < 24 {
        return Err(malformed);
    }
    let lgth = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if lgth != 16 {
        return Err(malformed);
    }
    let mut bindings = [0_u8; 16];
    bindings.copy_from_slice(&data[4..20]);
    let flags = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);
    if flags & gss_flags::DELEG != 0 {
        // DlgOpt (2 octets, 1), Dlgth (2 octets) and the KRB-CRED: present, and skipped.
        let header = data.get(24..28).ok_or(malformed.clone())?;
        let dlgth = usize::from(u16::from_le_bytes([header[2], header[3]]));
        if u16::from_le_bytes([header[0], header[1]]) != 1 || data.len() < 28 + dlgth {
            return Err(malformed);
        }
    }
    Ok(GssChecksum { bindings, flags })
}

/// Whether a ticket's service name is one of the acceptor's. Decision 12: the components
/// must match, compared without ASCII case (SPNs are case-insensitive in AD).
fn is_service(services: &[Vec<String>], sname: &[String]) -> bool {
    services.iter().any(|service| {
        service.len() == sname.len()
            && service
                .iter()
                .zip(sname)
                .all(|(a, b)| a.eq_ignore_ascii_case(b))
    })
}

/// The PAC in a ticket's authorization data: `AD-WIN2K-PAC` inside `AD-IF-RELEVANT`, at
/// most one.
fn find_pac(ad: Option<&AuthorizationData>) -> Result<Option<Vec<u8>>, AcceptError> {
    let mut found = None;
    for entry in ad.map(|a| a.0.as_slice()).unwrap_or_default() {
        if entry.ad_type != ad_type::IF_RELEVANT {
            continue;
        }
        let inner = AuthorizationData::decode(&entry.ad_data)?;
        for element in inner.0 {
            if element.ad_type == ad_type::WIN2K_PAC {
                if found.is_some() {
                    return Err(AcceptError::Pac(pac::PacError::Buffer(0)));
                }
                found = Some(element.ad_data);
            }
        }
    }
    Ok(found)
}

/// Decrypts the ticket with the keys its type and version select. Decision 12: the key
/// is selected by the ticket's `etype` and `kvno`.
fn decrypt_ticket(
    service: &Service,
    enc: &EncryptedData,
) -> Result<(Key, EncTicketPart), AcceptError> {
    let keys = service.keys();
    for key in keys.select(enc.etype, enc.kvno)? {
        match cipher::decrypt_data(key, usage::TICKET, enc) {
            Ok(plain) => return Ok((key.clone(), EncTicketPart::decode(&plain)?)),
            Err(CipherError::Integrity) => {}
            Err(other) => return Err(AcceptError::Cipher(other)),
        }
    }
    Err(AcceptError::TicketKey)
}

/// The random acceptor subkey and sequence number of the AP-REP. Decision 10: the subkey
/// has the session key's type, and the sequence number stays below 2^30 so that its DER
/// INTEGER stays positive and MIT's masks agree.
fn acceptor_subkey(service: &Service, session: &Key) -> Result<(Key, u32), AcceptError> {
    #[cfg(test)]
    if let Some((key, seq)) = &service.fixed_subkey {
        return Ok((key.clone(), *seq));
    }
    let _ = service;
    let key = Key::random(session.etype()).map_err(AcceptError::Cipher)?;
    let mut seq = [0_u8; 4];
    aws_lc_rs::rand::fill(&mut seq).map_err(|_| AcceptError::Cipher(CipherError::Library))?;
    Ok((key, u32::from_be_bytes(seq) & 0x3fff_ffff))
}

/// Accepts a Kerberos `InitialContextToken` carrying an AP-REQ.
#[allow(clippy::too_many_lines)]
pub(super) fn accept(service: &Service, token: &[u8], mech: Mech) -> Result<Accepted, AcceptError> {
    let config = &service.config;
    let now = service.clock.now();
    let skew = config.max_skew_secs;

    // Decision 2: the AP-REP's InitialContextToken carries the OID of the request (MIT
    // refuses an AP-REP under the other Kerberos OID).
    let outer = InitialContextToken::decode(token)?;
    if outer.mech != oid::KRB5 && outer.mech != oid::MS_KRB5 {
        return Err(AcceptError::Mechanism(
            "the inner token is not for Kerberos",
        ));
    }
    let inner = KrbToken::decode(outer.inner)?;
    if inner.tok_id != tok_id::AP_REQ {
        return Err(AcceptError::Request("the token is not an AP-REQ"));
    }
    let request = ApReq::decode(inner.message)?;
    if request.ap_options & ap_options::USE_SESSION_KEY != 0 {
        return Err(AcceptError::Request(
            "user-to-user (USE-SESSION-KEY) is not accepted",
        ));
    }

    // The ticket: realm, service, key, flags and times.
    let ticket = &request.ticket;
    let ticket_realm =
        Realm::new(&ticket.realm).map_err(|_| AcceptError::WrongService(ticket.realm.clone()))?;
    if ticket_realm != config.realm || !is_service(&config.services, &ticket.sname.components) {
        return Err(AcceptError::WrongService(format!(
            "{}@{}",
            ticket.sname.components.join("/"),
            ticket.realm
        )));
    }
    let (service_key, part) = decrypt_ticket(service, &ticket.enc_part)?;
    if part.flags & ticket_flags::INVALID != 0 {
        return Err(AcceptError::TicketInvalid);
    }
    let start = part.starttime.unwrap_or(part.authtime);
    if start > now.secs.saturating_add(skew) {
        return Err(AcceptError::NotYetValid(start));
    }
    if now.secs > part.endtime.saturating_add(skew) {
        return Err(AcceptError::Expired(part.endtime));
    }
    let session = Key::from_wire(&part.key).map_err(AcceptError::SessionKey)?;

    // The authenticator, under the session key's own type (decision 12).
    let auth_enc = &request.authenticator;
    if auth_enc.etype != session.etype().number() {
        return Err(AcceptError::SessionKey(CipherError::UnsupportedEnctype(
            auth_enc.etype,
        )));
    }
    let plain = cipher::decrypt_data(&session, usage::AP_REQ_AUTHENTICATOR, auth_enc).map_err(
        |e| match e {
            CipherError::Integrity | CipherError::Truncated => AcceptError::Authenticator,
            other => AcceptError::Cipher(other),
        },
    )?;
    let auth = Authenticator::decode(&plain)?;
    // RFC 4120 section 3.2.3 compares the names, not their types (as MIT's
    // krb5_principal_compare does).
    if auth.cname.components != part.cname.components || auth.crealm != part.crealm {
        return Err(AcceptError::ClientMismatch);
    }
    let offset = (now.secs - auth.ctime).abs();
    if offset > skew {
        return Err(AcceptError::Skew(offset));
    }
    let crealm = Realm::new(&auth.crealm).map_err(|_| AcceptError::ClientMismatch)?;
    let client = PrincipalName::new(auth.cname.components.clone(), crealm)
        .map_err(|_| AcceptError::ClientMismatch)?;

    // The GSS checksum (RFC 4121 section 4.1.1).
    let cksum = auth.cksum.as_ref().ok_or(AcceptError::Request(
        "the authenticator has no GSS checksum",
    ))?;
    if cksum.cksumtype != GSS_CHECKSUM_TYPE {
        return Err(AcceptError::Request(
            "the authenticator checksum is not 0x8003",
        ));
    }
    let gss = parse_gss_checksum(&cksum.checksum)?;
    // Decision 7 (continued): DNS has no channel bindings, so any Bnd is accepted (RFC
    // 4121 lets an acceptor without bindings ignore them).
    let _ = gss.bindings;
    if gss.flags & gss_flags::DCE_STYLE != 0 {
        // Decision 8: DCE style needs a third leg (the initiator's AP-REP back); GSS-TSIG
        // clients do not use it, so it is refused rather than implemented.
        return Err(AcceptError::Mechanism("DCE style is not accepted"));
    }
    if request.ap_options & ap_options::MUTUAL_REQUIRED == 0 && gss.flags & gss_flags::MUTUAL == 0 {
        // Decision 9: GSS-TSIG needs the AP-REP for its key and sequence number.
        return Err(AcceptError::Request(
            "mutual authentication was not requested",
        ));
    }
    // The initiator's subkey is not the context key (decision 11) but must be AES.
    if let Some(subkey) = &auth.subkey {
        Key::from_wire(subkey).map_err(AcceptError::SessionKey)?;
    }

    // The PAC: its server signature with the key that decrypted the ticket, its client
    // information against the ticket.
    let pac = find_pac(part.authorization_data.as_ref())?
        .map(|bytes| {
            pac::verify(
                &bytes,
                &service_key,
                &part.cname.components.join("/"),
                part.authtime,
            )
        })
        .transpose()?;

    // Decision 6: the replay key is the client, its realm, ctime and cusec; the service is
    // fixed per acceptor. The cache expires entries after the skew and refuses anything
    // from before the acceptor started. Recorded last, so only an authenticator that
    // passed every other check takes a place.
    service
        .replay
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .check(&client.to_string(), auth.ctime, auth.cusec, now.secs)?;

    // The AP-REP.
    let (subkey, acceptor_seq) = acceptor_subkey(service, &session)?;
    let reply_part = EncApRepPart {
        ctime: auth.ctime,
        cusec: auth.cusec,
        subkey: Some(subkey.to_wire()),
        seq_number: Some(acceptor_seq),
    };
    let enc_part = cipher::encrypt_data(&session, usage::AP_REP_ENC_PART, &reply_part.encode())
        .map_err(AcceptError::Cipher)?;
    let reply = ApRep { enc_part }.encode();
    let token = KrbToken::encode(outer.mech, tok_id::AP_REP, &reply);

    // Decision 11: the context key is the acceptor subkey, which the AP-REP always
    // carries (RFC 4121 section 2: it takes precedence over the initiator's subkey and the
    // session key), with the subkey flag in every MIC.
    Ok(Accepted {
        token,
        context: Context {
            client,
            mech,
            key: subkey,
            acceptor_subkey: true,
            initiator_seq: auth.seq_number.unwrap_or(0),
            acceptor_seq,
            gss_flags: gss.flags,
            auth_time: part.authtime,
            expires: part.endtime,
            ticket_kvno: ticket.enc_part.kvno,
            pac,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_gss_checksum_is_parsed_strictly() {
        let mut data = vec![16, 0, 0, 0];
        data.extend_from_slice(&[0; 16]);
        data.extend_from_slice(&0x3e_u32.to_le_bytes());
        assert_eq!(parse_gss_checksum(&data).map(|c| c.flags), Ok(0x3e));
        assert!(parse_gss_checksum(&data[..23]).is_err());
        let mut lgth = data.clone();
        lgth[0] = 15;
        assert!(parse_gss_checksum(&lgth).is_err());
        // The delegation flag announces DlgOpt, Dlgth and the credentials.
        let mut deleg = data.clone();
        deleg[20] |= 0x01;
        assert!(parse_gss_checksum(&deleg).is_err());
        deleg.extend_from_slice(&[1, 0, 3, 0, 9, 9, 9]);
        assert!(parse_gss_checksum(&deleg).is_ok());
        let mut short = deleg.clone();
        short.pop();
        assert!(parse_gss_checksum(&short).is_err());
    }

    #[test]
    fn services_compare_without_case() {
        let services = vec![vec!["DNS".to_owned(), "tenko.corp.example.test".to_owned()]];
        let name = |s: &str| s.split('/').map(str::to_owned).collect::<Vec<_>>();
        assert!(is_service(&services, &name("dns/TENKO.corp.example.test")));
        assert!(!is_service(&services, &name("DNS/other.corp.example.test")));
        assert!(!is_service(
            &services,
            &name("DNS/tenko.corp.example.test/extra")
        ));
        assert!(!is_service(
            &services,
            &name("HTTP/tenko.corp.example.test")
        ));
    }
}
