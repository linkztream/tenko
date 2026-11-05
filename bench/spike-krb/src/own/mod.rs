//! Design (b'): Tenko's own acceptor over `picky-krb`'s types and ciphers.
//!
//! `spnego` unwraps and answers the RFC 4178 negotiation, `ap` checks the AP-REQ and
//! builds the AP-REP (RFC 4120, section 3.2; RFC 4121, section 4.1). The decisions each
//! module had to take are listed in RESULT.md as the price of (b').

pub mod ap;
pub mod spnego;

use std::collections::HashSet;

use crate::acceptor::{Acceptor, Context, Error, Mech, ServiceKey, Step};

/// The clock the acceptor reads, injectable so that recorded tokens stay testable.
pub type Clock = Box<dyn Fn() -> i64 + Send>;

/// The acceptor's configuration: what `tenko-krb` would take from the vault and the
/// `[dns.gss]` section.
pub struct Config {
    /// The service principal's name components, for example `["DNS", "tenko.corp.example.test"]`.
    pub spn: Vec<String>,
    /// The realm the ticket must name.
    pub realm: String,
    /// The long-term keys, one per enctype and key version.
    pub keys: Vec<ServiceKey>,
    /// The clock skew allowed on the authenticator and the ticket, in seconds (300).
    pub max_skew_secs: i64,
    /// Whether to generate an acceptor subkey in the AP-REP (RFC 4121, section 4.1.1).
    pub acceptor_subkey: bool,
    /// Unix time; `None` reads the system clock.
    pub clock: Option<Clock>,
    /// A fixed acceptor subkey and sequence number, for deterministic tests only.
    pub fixed_subkey: Option<(Vec<u8>, u32)>,
}

impl Config {
    /// A configuration with the production choices.
    pub fn new(spn: &[&str], realm: &str, keys: Vec<ServiceKey>) -> Self {
        Config {
            spn: spn.iter().map(|s| (*s).to_owned()).collect(),
            realm: realm.to_owned(),
            keys,
            max_skew_secs: 300,
            acceptor_subkey: true,
            clock: None,
            fixed_subkey: None,
        }
    }

    fn now(&self) -> i64 {
        match &self.clock {
            Some(clock) => clock(),
            None => std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
                .unwrap_or(0),
        }
    }
}

/// A replay cache entry: client name, client time and microseconds (RFC 4120, 3.2.3).
#[derive(Hash, PartialEq, Eq)]
pub struct ReplayKey {
    pub client: String,
    pub realm: String,
    pub ctime: String,
    pub cusec: Vec<u8>,
}

/// The replay cache. Tenko's would expire entries after the skew; the spike's only grows.
pub type ReplayCache = HashSet<ReplayKey>;

enum State {
    Start,
    /// The context is established but RFC 4178 requires the initiator's `mechListMIC`.
    AwaitMic {
        context: Context,
        mech_types_der: Vec<u8>,
    },
    Done,
}

/// The (b') acceptor for one negotiation.
pub struct OwnAcceptor<'a> {
    config: &'a Config,
    replay: &'a mut ReplayCache,
    state: State,
}

impl<'a> OwnAcceptor<'a> {
    /// A new negotiation over a shared configuration and replay cache.
    pub fn new(config: &'a Config, replay: &'a mut ReplayCache) -> Self {
        OwnAcceptor {
            config,
            replay,
            state: State::Start,
        }
    }
}

impl Acceptor for OwnAcceptor<'_> {
    fn step(&mut self, token: &[u8]) -> Result<Step, Error> {
        match std::mem::replace(&mut self.state, State::Done) {
            State::Start => {
                // Decision 1: dispatch on the outer OID. `60 ..` is an InitialContextToken
                // for SPNEGO or for raw Kerberos (MIT may send the latter).
                match spnego::classify(token)? {
                    spnego::Outer::Spnego => {
                        let neg = spnego::decode_init(token)?;
                        let (mech, index) = spnego::choose(&neg.mech_types)?;
                        let mech_token = neg
                            .mech_token
                            .ok_or("negTokenInit without an optimistic token")?;
                        let mut accepted =
                            ap::accept(self.config, self.replay, &mech_token, Some(mech))?;
                        // Decision 2: RFC 4178, section 5. When the mechanism is the
                        // initiator's first choice the MIC exchange is optional, and the
                        // spike answers in one round trip, as Windows DNS expects. Otherwise,
                        // or when the initiator sent a MIC, the MIC exchange is required: the
                        // acceptor's MIC goes out now and the initiator's must come back.
                        let mic_needed = index != 0 || neg.mech_list_mic.is_some();
                        if let Some(mic) = &neg.mech_list_mic {
                            spnego::verify_mech_list_mic(
                                &accepted.context,
                                &neg.mech_types_der,
                                mic,
                            )?;
                        }
                        let our_mic = if mic_needed {
                            let mic =
                                spnego::make_mech_list_mic(&accepted.context, &neg.mech_types_der);
                            // The mechListMIC consumed the acceptor's first sequence number.
                            accepted.context.acceptor_seq =
                                accepted.context.acceptor_seq.wrapping_add(1);
                            Some(mic)
                        } else {
                            None
                        };
                        let complete = !mic_needed || neg.mech_list_mic.is_some();
                        let resp = spnego::encode_resp(
                            complete,
                            Some(mech),
                            Some(&accepted.token),
                            our_mic.as_deref(),
                        )?;
                        if complete {
                            Ok(Step::Established {
                                token: resp,
                                context: accepted.context,
                            })
                        } else {
                            self.state = State::AwaitMic {
                                context: accepted.context,
                                mech_types_der: neg.mech_types_der,
                            };
                            Ok(Step::Continue(resp))
                        }
                    }
                    spnego::Outer::Krb5(mech) => {
                        let accepted = ap::accept(self.config, self.replay, token, Some(mech))?;
                        Ok(Step::Established {
                            token: accepted.token,
                            context: accepted.context,
                        })
                    }
                }
            }
            State::AwaitMic {
                context,
                mech_types_der,
            } => {
                let resp = spnego::decode_resp(token)?;
                let mic = resp
                    .mech_list_mic
                    .ok_or("negTokenResp without the required mechListMIC")?;
                spnego::verify_mech_list_mic(&context, &mech_types_der, &mic)?;
                // Decision 3: the final token carries accept-completed and no response token.
                let out = spnego::encode_resp(true, None, None, None)?;
                Ok(Step::Established {
                    token: out,
                    context,
                })
            }
            State::Done => Err("the negotiation is over".into()),
        }
    }
}

/// Which raw mechanism an OID names.
pub fn mech_of_oid(oid: &oid::ObjectIdentifier, inside_spnego: bool) -> Option<Mech> {
    use picky_asn1_x509::oids;
    if *oid == oids::krb5() {
        Some(if inside_spnego {
            Mech::SpnegoKrb5
        } else {
            Mech::Krb5
        })
    } else if *oid == oids::ms_krb5() {
        Some(if inside_spnego {
            Mech::SpnegoMsKrb5
        } else {
            Mech::MsKrb5
        })
    } else {
        None
    }
}

/// Dotted text of an OID.
pub fn oid_string(oid: &oid::ObjectIdentifier) -> String {
    oid.into()
}
