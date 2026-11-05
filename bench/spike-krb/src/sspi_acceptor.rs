//! Design (b): `sspi`'s Kerberos and SPNEGO server side behind the spike's interface.

use std::time::Duration;

use sspi::kerberos::ServerProperties;
use sspi::kerberos::config::{KerberosConfig, KerberosServerConfig};
use sspi::negotiate::NegotiateConfig;
use sspi::{
    AcceptSecurityContextResult, BufferType, DataRepresentation, Kerberos, Negotiate,
    SecurityBuffer, SecurityStatus, ServerRequestFlags, Sspi, SspiImpl,
};

use crate::acceptor::{Acceptor, Context, Enctype, Error, Mech, ServiceKey, Step};

enum Inner {
    Unstarted,
    Krb(Box<Kerberos>, Mech),
    Spnego(Box<Negotiate>),
    Done,
}

/// The (b) acceptor for one negotiation.
pub struct SspiAcceptor {
    props: ServerProperties,
    inner: Inner,
}

impl SspiAcceptor {
    /// `spn` are the name components (`["DNS", "tenko.corp.example.test"]`); `keys` the
    /// service keys. Decision forced by the library: `ServerProperties` takes one
    /// `ticket_decryption_key` per service name, with no enctype and no kvno, so one key
    /// per enctype cannot be registered under the same name; the spike hands over the key
    /// of the enctype the test expects. Tenko would have to pick the key by the ticket's
    /// enctype and kvno before calling `sspi`, which means decoding the AP-REQ itself.
    pub fn new(spn: &[&str], key: &ServiceKey, max_skew: Duration) -> Result<Self, Error> {
        let props = ServerProperties::new(spn, None, max_skew, Some(key.key.clone().into()))
            .map_err(|e| Error(format!("ServerProperties: {e}")))?;
        Ok(SspiAcceptor {
            props,
            inner: Inner::Unstarted,
        })
    }

    fn start(&mut self, token: &[u8]) -> Result<(), Error> {
        // Dispatch on the OID of the InitialContextToken: SPNEGO goes to `Negotiate`, a
        // raw Kerberos token to `Kerberos` (sspi's `Negotiate` does not accept a raw one).
        let oid = token_oid(token)?;
        let server_cfg = KerberosServerConfig {
            kerberos_config: KerberosConfig {
                kdc_resolution: sspi::kerberos::config::KdcResolution::KdcUrl(None),
                client_computer_name: "tenko".into(),
            },
            server_properties: self.props.clone(),
        };
        self.inner = match oid.as_str() {
            "1.3.6.1.5.5.2" => {
                let cfg = NegotiateConfig::new(
                    Box::new(server_cfg),
                    Some("kerberos,!ntlm".into()),
                    "tenko".into(),
                );
                Inner::Spnego(Box::new(
                    Negotiate::new_server(cfg, Vec::new())
                        .map_err(|e| Error(format!("Negotiate: {e}")))?,
                ))
            }
            "1.2.840.113554.1.2.2" | "1.2.840.48018.1.2.2" => {
                let mech = if oid == "1.2.840.113554.1.2.2" {
                    Mech::Krb5
                } else {
                    Mech::MsKrb5
                };
                Inner::Krb(
                    Box::new(
                        Kerberos::new_server_from_config(
                            server_cfg.kerberos_config,
                            server_cfg.server_properties,
                        )
                        .map_err(|e| Error(format!("Kerberos: {e}")))?,
                    ),
                    mech,
                )
            }
            other => return Err(format!("unsupported mechanism {other}").into()),
        };
        Ok(())
    }
}

fn oid_string(oid: &oid::ObjectIdentifier) -> String {
    oid.into()
}

/// The dotted OID of an InitialContextToken.
fn token_oid(token: &[u8]) -> Result<String, Error> {
    if token.first() != Some(&0x60) {
        return Err("not an InitialContextToken".into());
    }
    let mut i = 1;
    let first = *token.get(i).ok_or("truncated")?;
    i += 1;
    if first >= 0x80 {
        i += usize::from(first & 0x7f);
    }
    if token.get(i) != Some(&0x06) {
        return Err("no OID".into());
    }
    let len = usize::from(*token.get(i + 1).ok_or("truncated")?);
    let body = token.get(i + 2..i + 2 + len).ok_or("truncated OID")?;
    let oid: oid::ObjectIdentifier =
        oid::ObjectIdentifier::try_from(&[&[0x06, len as u8][..], body].concat()[2..])
            .map_err(|e| Error(format!("OID: {e:?}")))?;
    Ok(oid_string(&oid))
}

fn run_step<P>(pkg: &mut P, token: &[u8]) -> Result<(AcceptSecurityContextResult, Vec<u8>), Error>
where
    P: Sspi + SspiImpl<CredentialsHandle = Option<sspi::CredentialsBuffers>>,
{
    let mut input = vec![SecurityBuffer::new(token.to_vec(), BufferType::Token)];
    let mut output = vec![SecurityBuffer::new(Vec::new(), BufferType::Token)];
    let mut creds: Option<sspi::CredentialsBuffers> = None;
    let builder = pkg
        .accept_security_context()
        .with_credentials_handle(&mut creds)
        .with_context_requirements(ServerRequestFlags::MUTUAL_AUTH | ServerRequestFlags::INTEGRITY)
        .with_target_data_representation(DataRepresentation::Native)
        .with_input(&mut input)
        .with_output(&mut output);
    let result = pkg
        .accept_security_context_impl(builder)
        .map_err(|e| Error(format!("accept_security_context: {e}")))?
        .resolve_to_result()
        .map_err(|e| Error(format!("accept_security_context: {e}")))?;
    Ok((result, std::mem::take(&mut output[0].buffer)))
}

fn finish<P: Sspi>(pkg: &mut P, mech: Mech, krb_seq: Option<u32>) -> Result<Context, Error> {
    let keys = pkg
        .query_context_session_key()
        .map_err(|e| Error(format!("query_context_session_key: {e}")))?;
    let key = keys.session_key.as_ref().clone();
    let key_enctype = Enctype::from_key_len(key.len()).ok_or("session key length")?;
    let names = pkg
        .query_context_names()
        .map_err(|e| Error(format!("query_context_names: {e}")))?;
    let full = names.username.inner().to_string();
    let (client, realm) = match full.split_once('@') {
        Some((c, r)) => (c.to_owned(), r.to_owned()),
        None => (full, String::new()),
    };
    Ok(Context {
        client,
        realm,
        mech,
        key,
        key_enctype,
        // sspi always sends an acceptor subkey when mutual authentication is required.
        acceptor_subkey: true,
        // Not exposed by sspi: the initiator's sequence number, the GSS flags, the expiry.
        initiator_seq: None,
        acceptor_seq: krb_seq.unwrap_or(0),
        gss_flags: None,
        expires_unix: None,
    })
}

impl Acceptor for SspiAcceptor {
    fn step(&mut self, token: &[u8]) -> Result<Step, Error> {
        if matches!(self.inner, Inner::Unstarted) {
            self.start(token)?;
        }
        match &mut self.inner {
            Inner::Krb(krb, mech) => {
                let (result, out) = run_step(krb.as_mut(), token)?;
                match result.status {
                    SecurityStatus::Ok => {
                        // The AP-REP carried `seq_number + 1`, and `next_seq_number()`
                        // pre-increments, so the first call returns the AP-REP's number.
                        let seq = krb.next_seq_number();
                        let ctx = finish(krb.as_mut(), *mech, Some(seq))?;
                        self.inner = Inner::Done;
                        Ok(Step::Established {
                            token: out,
                            context: ctx,
                        })
                    }
                    SecurityStatus::ContinueNeeded => Ok(Step::Continue(out)),
                    other => Err(format!("unexpected status {other:?}").into()),
                }
            }
            Inner::Spnego(neg) => {
                let (result, out) = run_step(neg.as_mut(), token)?;
                match result.status {
                    SecurityStatus::Ok => {
                        // Decision forced by the library: `Negotiate` hides the inner
                        // `Kerberos`, so the acceptor's sequence number is unreachable; the
                        // spike reads the mechanism from `query_context_negotiation_package`
                        // and leaves the sequence to be learned from the first MIC.
                        let mech = Mech::SpnegoKrb5;
                        let ctx = finish(neg.as_mut(), mech, None)?;
                        self.inner = Inner::Done;
                        Ok(Step::Established {
                            token: out,
                            context: ctx,
                        })
                    }
                    SecurityStatus::ContinueNeeded => Ok(Step::Continue(out)),
                    other => Err(format!("unexpected status {other:?}").into()),
                }
            }
            Inner::Done => Err("the negotiation is over".into()),
            Inner::Unstarted => unreachable!("started above"),
        }
    }
}
