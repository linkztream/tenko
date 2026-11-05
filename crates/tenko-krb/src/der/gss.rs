//! The GSS-API framing of RFC 2743 section 3.1 (the `InitialContextToken`), the Kerberos
//! token identifiers of RFC 4121 section 4.1, and the SPNEGO tokens of RFC 4178 section
//! 4.2 (`NegTokenInit`, `NegTokenResp`, `MechTypeList`).

use super::{DerError, DerErrorKind, Reader, tag, writer::Der};

/// The mechanism OIDs, as the content octets of their OBJECT IDENTIFIER.
pub mod oid {
    /// Kerberos V5, 1.2.840.113554.1.2.2 (RFC 1964).
    pub const KRB5: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02];
    /// Kerberos V5 under Microsoft's OID, 1.2.840.48018.1.2.2, which Windows lists first.
    pub const MS_KRB5: &[u8] = &[0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02];
    /// SPNEGO, 1.3.6.1.5.5.2 (RFC 4178).
    pub const SPNEGO: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];
    /// NTLM, 1.3.6.1.4.1.311.2.2.10: never chosen (ADR 0026 point 3).
    pub const NTLMSSP: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a];
    /// `NegoEx`, 1.3.6.1.4.1.311.2.2.30: never chosen.
    pub const NEGOEX: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x1e];
}

/// The Kerberos token identifiers (RFC 4121 section 4.1).
pub mod tok_id {
    /// `KRB_AP_REQ`.
    pub const AP_REQ: [u8; 2] = [0x01, 0x00];
    /// `KRB_AP_REP`.
    pub const AP_REP: [u8; 2] = [0x02, 0x00];
    /// `KRB_ERROR`.
    pub const ERROR: [u8; 2] = [0x03, 0x00];
}

/// The most mechanisms a `MechTypeList` may hold.
pub const MAX_MECH_TYPES: usize = 32;

/// An `InitialContextToken` (`[APPLICATION 0] IMPLICIT SEQUENCE { thisMech, innerContextToken }`):
/// the mechanism OID and the mechanism's octets after it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InitialContextToken<'a> {
    /// The OID's content octets.
    pub mech: &'a [u8],
    /// The inner context token.
    pub inner: &'a [u8],
}

impl<'a> InitialContextToken<'a> {
    /// Decodes a whole token.
    ///
    /// # Errors
    ///
    /// A [`DerError`] naming `InitialContextToken`.
    pub fn decode(token: &'a [u8]) -> Result<Self, DerError> {
        let mut r = Reader::new(token, "InitialContextToken");
        let mut content =
            Reader::new(r.expect(tag::application(0))?, "InitialContextToken").labeled("thisMech");
        r.finish()?;
        let tlv = content.expect_tlv(tag::OID)?;
        let mech = Reader::new(tlv.raw, "InitialContextToken")
            .labeled("thisMech")
            .oid()?;
        Ok(Self {
            mech,
            inner: content.remaining(),
        })
    }

    /// Encodes a token for `mech` around `inner`.
    pub fn encode(mech: &[u8], inner: &[u8]) -> Vec<u8> {
        super::writer::encode(|d| {
            d.application(0, |a| {
                a.oid(mech);
                a.raw(inner);
            });
        })
    }
}

/// A Kerberos mechanism token inside an `InitialContextToken`: the two-octet token
/// identifier and the Kerberos message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KrbToken<'a> {
    /// The token identifier ([`tok_id`]).
    pub tok_id: [u8; 2],
    /// The DER of the message (`AP-REQ`, `AP-REP` or `KRB-ERROR`).
    pub message: &'a [u8],
}

impl<'a> KrbToken<'a> {
    /// Splits an inner context token.
    ///
    /// # Errors
    ///
    /// [`DerErrorKind::Truncated`] naming `KrbToken`.
    pub fn decode(inner: &'a [u8]) -> Result<Self, DerError> {
        match inner {
            [a, b, message @ ..] => Ok(Self {
                tok_id: [*a, *b],
                message,
            }),
            _ => Err(DerError::new("KrbToken", "tok-id", DerErrorKind::Truncated)),
        }
    }

    /// The whole GSS token for `mech` with `tok_id` and `message`.
    pub fn encode(mech: &[u8], tok_id: [u8; 2], message: &[u8]) -> Vec<u8> {
        let mut inner = Vec::with_capacity(2 + message.len());
        inner.extend_from_slice(&tok_id);
        inner.extend_from_slice(message);
        InitialContextToken::encode(mech, &inner)
    }
}

/// The `negState` of a `NegTokenResp`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NegState {
    /// The context is established.
    AcceptCompleted,
    /// Another token is needed.
    AcceptIncomplete,
    /// Refused.
    Reject,
    /// The acceptor asks for the `mechListMIC`.
    RequestMic,
}

impl NegState {
    fn from_value(value: i64) -> Option<Self> {
        match value {
            0 => Some(Self::AcceptCompleted),
            1 => Some(Self::AcceptIncomplete),
            2 => Some(Self::Reject),
            3 => Some(Self::RequestMic),
            _ => None,
        }
    }

    fn value(self) -> i64 {
        match self {
            Self::AcceptCompleted => 0,
            Self::AcceptIncomplete => 1,
            Self::Reject => 2,
            Self::RequestMic => 3,
        }
    }
}

/// A `NegTokenInit`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegTokenInit<'a> {
    /// The mechanism OIDs in the initiator's order of preference.
    pub mech_types: Vec<&'a [u8]>,
    /// The DER of the `MechTypeList`: what a `mechListMIC` covers.
    pub mech_types_der: &'a [u8],
    /// The `reqFlags`, when sent.
    pub req_flags: Option<u32>,
    /// The optimistic token for the first mechanism.
    pub mech_token: Option<&'a [u8]>,
    /// The initiator's `mechListMIC`.
    pub mech_list_mic: Option<&'a [u8]>,
}

/// A `NegTokenResp`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegTokenResp<'a> {
    /// The state.
    pub neg_state: Option<NegState>,
    /// The mechanism the acceptor chose.
    pub supported_mech: Option<&'a [u8]>,
    /// The mechanism's token.
    pub response_token: Option<&'a [u8]>,
    /// The `mechListMIC`.
    pub mech_list_mic: Option<&'a [u8]>,
}

/// A `NegotiationToken`: the choice of the two.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NegotiationToken<'a> {
    /// `negTokenInit` (`[0]`).
    Init(NegTokenInit<'a>),
    /// `negTokenResp` (`[1]`).
    Resp(NegTokenResp<'a>),
}

/// Skips the extension fields after the last known one: context tags above `last`, in
/// increasing order (RFC 4178 marks both sequences extensible).
fn skip_extensions(s: &mut Reader<'_>, last: u8) -> Result<(), DerError> {
    let mut previous = last;
    while let Some(next) = s.peek_tag() {
        let n = next & 0x1f;
        if next & 0xe0 != 0xa0 || n <= previous {
            return Err(s.error(DerErrorKind::TrailingData));
        }
        s.read()?;
        previous = n;
    }
    Ok(())
}

impl<'a> NegTokenInit<'a> {
    /// Reads the content of `[0]`.
    fn read(r: &mut Reader<'a>) -> Result<Self, DerError> {
        let mut s = Reader::new(r.expect(tag::SEQUENCE)?, "NegTokenInit");
        let mut types = s.field(0, "mechTypes")?;
        let list = types.expect_tlv(tag::SEQUENCE)?;
        types.finish()?;
        let mech_types = Reader::new(list.raw, "NegTokenInit")
            .labeled("mechTypes")
            .sequence_of(MAX_MECH_TYPES, |e| {
                let oid = e.expect_tlv(tag::OID)?;
                Reader::new(oid.raw, "NegTokenInit")
                    .labeled("mechTypes")
                    .oid()
            })?;
        if mech_types.is_empty() {
            return Err(DerError::new(
                "NegTokenInit",
                "mechTypes",
                DerErrorKind::Missing,
            ));
        }
        let req_flags = s.opt_field(1, "reqFlags")?.map(Reader::flags).transpose()?;
        let mech_token = s
            .opt_field(2, "mechToken")?
            .map(Reader::octets)
            .transpose()?;
        let mech_list_mic = s
            .opt_field(3, "mechListMIC")?
            .map(Reader::octets)
            .transpose()?;
        skip_extensions(&mut s, 3)?;
        Ok(Self {
            mech_types,
            mech_types_der: list.raw,
            req_flags,
            mech_token,
            mech_list_mic,
        })
    }

    /// Decodes the initiator's first SPNEGO token: an `InitialContextToken` for SPNEGO
    /// around `negTokenInit`.
    ///
    /// # Errors
    ///
    /// A [`DerError`] naming `InitialContextToken` or `NegTokenInit`;
    /// [`DerErrorKind::Unsupported`] when the token is for another mechanism or holds a
    /// `negTokenResp`.
    pub fn decode_initial(token: &'a [u8]) -> Result<Self, DerError> {
        let outer = InitialContextToken::decode(token)?;
        if outer.mech != oid::SPNEGO {
            return Err(DerError::new(
                "InitialContextToken",
                "thisMech",
                DerErrorKind::Unsupported,
            ));
        }
        match NegotiationToken::decode(outer.inner)? {
            NegotiationToken::Init(init) => Ok(init),
            NegotiationToken::Resp(_) => Err(DerError::new(
                "NegotiationToken",
                "-",
                DerErrorKind::Unsupported,
            )),
        }
    }

    /// Encodes the initiator's first token (with the `InitialContextToken` around it).
    pub fn encode_initial(&self) -> Vec<u8> {
        let inner = super::writer::encode(|d| {
            d.field(0, |f| {
                f.sequence(|s| {
                    s.field(0, |g| {
                        g.sequence(|q| {
                            for mech in &self.mech_types {
                                q.oid(mech);
                            }
                        });
                    });
                    if let Some(flags) = self.req_flags {
                        s.field(1, |g| {
                            g.flags(flags);
                        });
                    }
                    if let Some(token) = self.mech_token {
                        s.field(2, |g| {
                            g.octets(token);
                        });
                    }
                    if let Some(mic) = self.mech_list_mic {
                        s.field(3, |g| {
                            g.octets(mic);
                        });
                    }
                });
            });
        });
        InitialContextToken::encode(oid::SPNEGO, &inner)
    }
}

/// The DER of a `MechTypeList` of `mechs`: the octets a `mechListMIC` covers.
pub fn encode_mech_type_list(mechs: &[&[u8]]) -> Vec<u8> {
    super::writer::encode(|d| {
        d.sequence(|q| {
            for mech in mechs {
                q.oid(mech);
            }
        });
    })
}

impl<'a> NegTokenResp<'a> {
    fn read(r: &mut Reader<'a>) -> Result<Self, DerError> {
        let mut s = Reader::new(r.expect(tag::SEQUENCE)?, "NegTokenResp");
        let neg_state = s
            .opt_field(0, "negState")?
            .map(|f| {
                let value = f.enumerated()?;
                NegState::from_value(value).ok_or_else(|| f.error(DerErrorKind::OutOfRange))
            })
            .transpose()?;
        let supported_mech = s
            .opt_field(1, "supportedMech")?
            .map(Reader::oid)
            .transpose()?;
        let response_token = s
            .opt_field(2, "responseToken")?
            .map(Reader::octets)
            .transpose()?;
        let mech_list_mic = s
            .opt_field(3, "mechListMIC")?
            .map(Reader::octets)
            .transpose()?;
        skip_extensions(&mut s, 3)?;
        Ok(Self {
            neg_state,
            supported_mech,
            response_token,
            mech_list_mic,
        })
    }

    /// Decodes a `negTokenResp` as it travels after the first token: `[1]` without the
    /// `InitialContextToken` framing.
    ///
    /// # Errors
    ///
    /// A [`DerError`] naming `NegTokenResp`.
    pub fn decode(token: &'a [u8]) -> Result<Self, DerError> {
        match NegotiationToken::decode(token)? {
            NegotiationToken::Resp(resp) => Ok(resp),
            NegotiationToken::Init(_) => Err(DerError::new(
                "NegotiationToken",
                "-",
                DerErrorKind::Unsupported,
            )),
        }
    }

    /// Encodes the `negTokenResp` as `[1]`.
    pub fn encode(&self) -> Vec<u8> {
        super::writer::encode(|d| {
            d.field(1, |f| {
                f.sequence(|s| self.write_fields(s));
            });
        })
    }

    fn write_fields(&self, s: &mut Der) {
        if let Some(state) = self.neg_state {
            s.field(0, |g| {
                g.enumerated(state.value());
            });
        }
        if let Some(mech) = self.supported_mech {
            s.field(1, |g| {
                g.oid(mech);
            });
        }
        if let Some(token) = self.response_token {
            s.field(2, |g| {
                g.octets(token);
            });
        }
        if let Some(mic) = self.mech_list_mic {
            s.field(3, |g| {
                g.octets(mic);
            });
        }
    }
}

impl<'a> NegotiationToken<'a> {
    /// Decodes a `NegotiationToken` (`[0]` or `[1]`).
    ///
    /// # Errors
    ///
    /// A [`DerError`] naming `NegotiationToken` or the structure inside.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, DerError> {
        let mut r = Reader::new(bytes, "NegotiationToken");
        let token = match r.peek_tag() {
            Some(t) if t == tag::context(0) => {
                NegotiationToken::Init(r.field(0, "negTokenInit")?.with(NegTokenInit::read)?)
            }
            Some(t) if t == tag::context(1) => {
                NegotiationToken::Resp(r.field(1, "negTokenResp")?.with(NegTokenResp::read)?)
            }
            Some(found) => {
                return Err(r.error(DerErrorKind::UnexpectedTag {
                    expected: tag::context(0),
                    found,
                }));
            }
            None => return Err(r.error(DerErrorKind::Missing)),
        };
        r.finish()?;
        Ok(token)
    }
}
