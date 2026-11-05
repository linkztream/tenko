//! The Kerberos structures of RFC 4120 section 5 that an acceptor and a client need, with
//! the change-password data of RFC 3244 and the pre-authentication data of RFC 4120
//! section 5.2.7. Each structure decodes from DER with the rules of [`super`] and encodes
//! back to the same octets.
//!
//! Times are Unix seconds (`KerberosTime` has whole seconds), flags the first 32 bits of
//! their BIT STRING with bit 0 as the most significant bit. Keys are held in
//! [`Zeroizing`] buffers and never printed.

use zeroize::Zeroizing;

use super::{DerError, DerErrorKind, Reader, tag, writer::Der};

/// The protocol version number of every message (`pvno`, `tkt-vno`, `authenticator-vno`).
pub const PVNO: i32 = 5;

/// The most name components the codec reads; a principal of `tenko-core` takes at most 8.
pub const MAX_NAME_COMPONENTS: usize = 16;
/// The most encryption types a KDC request lists.
pub const MAX_ETYPES: usize = 32;
/// The most host addresses a structure carries.
pub const MAX_ADDRESSES: usize = 32;
/// The most pre-authentication data elements in a message.
pub const MAX_PADATA: usize = 32;
/// The most authorization data elements at one level.
pub const MAX_AD_ENTRIES: usize = 64;
/// The most additional tickets of a KDC request.
pub const MAX_ADDITIONAL_TICKETS: usize = 4;
/// The most `LastReq` entries of a KDC reply.
pub const MAX_LAST_REQ: usize = 16;
/// The most entries of a `PA-ETYPE-INFO2`.
pub const MAX_ETYPE_INFO: usize = 16;

/// Message types (RFC 4120 section 7.5.7).
pub mod msg_type {
    /// AS-REQ.
    pub const AS_REQ: i32 = 10;
    /// AS-REP.
    pub const AS_REP: i32 = 11;
    /// TGS-REQ.
    pub const TGS_REQ: i32 = 12;
    /// TGS-REP.
    pub const TGS_REP: i32 = 13;
    /// AP-REQ.
    pub const AP_REQ: i32 = 14;
    /// AP-REP.
    pub const AP_REP: i32 = 15;
    /// KRB-PRIV.
    pub const KRB_PRIV: i32 = 21;
    /// KRB-ERROR.
    pub const KRB_ERROR: i32 = 30;
}

/// Principal name types (RFC 4120 section 6.2).
pub mod name_type {
    /// A user or a computer account.
    pub const PRINCIPAL: i32 = 1;
    /// A service and its instance (`krbtgt/REALM`, `kadmin/changepw`).
    pub const SRV_INST: i32 = 2;
    /// A service and a host name (`DNS/host.example.test`).
    pub const SRV_HST: i32 = 3;
    /// An enterprise name (RFC 6806 section 5), `user@domain` as one component.
    pub const ENTERPRISE: i32 = 10;
}

/// Pre-authentication data types (RFC 4120 section 7.5.2, MS-KILE).
pub mod pa_type {
    /// PA-TGS-REQ: the AP-REQ of a TGS request.
    pub const TGS_REQ: i32 = 1;
    /// PA-ENC-TIMESTAMP.
    pub const ENC_TIMESTAMP: i32 = 2;
    /// PA-ETYPE-INFO2.
    pub const ETYPE_INFO2: i32 = 19;
    /// PA-PAC-REQUEST ([MS-KILE] section 2.2.3).
    pub const PAC_REQUEST: i32 = 128;
}

/// Authorization data types (RFC 4120 section 7.5.4, [MS-PAC]).
pub mod ad_type {
    /// AD-IF-RELEVANT: authorization data a receiver may ignore if it does not know it.
    pub const IF_RELEVANT: i32 = 1;
    /// AD-WIN2K-PAC: the privilege attribute certificate of [MS-PAC].
    pub const WIN2K_PAC: i32 = 128;
}

/// Host address types (RFC 4120 section 7.5.3).
pub mod addr_type {
    /// An IPv4 address.
    pub const INET: i32 = 2;
    /// An IPv6 address.
    pub const INET6: i32 = 24;
}

// ---------------------------------------------------------------------------------------
// Small types

/// `PrincipalName`: the name type and the components, without the realm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrincipalName {
    /// The name type ([`name_type`]).
    pub name_type: i32,
    /// The components (`["DNS", "tenko.corp.example.test"]`).
    pub components: Vec<String>,
}

impl PrincipalName {
    /// A name from its type and components.
    pub fn new(name_type: i32, components: &[&str]) -> Self {
        Self {
            name_type,
            components: components.iter().map(|c| (*c).to_owned()).collect(),
        }
    }

    /// Reads one `PrincipalName`.
    ///
    /// # Errors
    ///
    /// A [`DerError`] naming `PrincipalName` and the field.
    pub fn read(r: &mut Reader<'_>) -> Result<Self, DerError> {
        let mut s = Reader::new(r.expect(tag::SEQUENCE)?, "PrincipalName");
        let name_type = s.field(0, "name-type")?.int32()?;
        let components = s
            .field(1, "name-string")?
            .sequence_of(MAX_NAME_COMPONENTS, Reader::string_tlv)?;
        s.finish()?;
        if components.is_empty() {
            return Err(DerError::new(
                "PrincipalName",
                "name-string",
                DerErrorKind::Missing,
            ));
        }
        Ok(Self {
            name_type,
            components,
        })
    }

    /// Writes the `PrincipalName`.
    pub fn write(&self, d: &mut Der) {
        d.sequence(|s| {
            s.field(0, |f| {
                f.integer(i64::from(self.name_type));
            });
            s.field(1, |f| {
                f.sequence(|q| {
                    for component in &self.components {
                        q.string(component);
                    }
                });
            });
        });
    }
}

impl Reader<'_> {
    /// Reads one `GeneralString` element of a `SEQUENCE OF KerberosString`.
    fn string_tlv(&mut self) -> Result<String, DerError> {
        let value = self.expect(tag::GENERAL_STRING)?;
        std::str::from_utf8(value)
            .map(str::to_owned)
            .map_err(|_| self.error(DerErrorKind::BadString))
    }
}

/// `HostAddress`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostAddress {
    /// The address type ([`addr_type`]).
    pub addr_type: i32,
    /// The address octets.
    pub address: Vec<u8>,
}

impl HostAddress {
    /// Reads one `HostAddress`.
    ///
    /// # Errors
    ///
    /// A [`DerError`] naming `HostAddress`.
    pub fn read(r: &mut Reader<'_>) -> Result<Self, DerError> {
        let mut s = Reader::new(r.expect(tag::SEQUENCE)?, "HostAddress");
        let addr_type = s.field(0, "addr-type")?.int32()?;
        let address = s.field(1, "address")?.octets()?.to_vec();
        s.finish()?;
        Ok(Self { addr_type, address })
    }

    /// Writes the `HostAddress`.
    pub fn write(&self, d: &mut Der) {
        d.sequence(|s| {
            s.field(0, |f| {
                f.integer(i64::from(self.addr_type));
            });
            s.field(1, |f| {
                f.octets(&self.address);
            });
        });
    }

    /// The `HostAddress` of a socket address (RFC 4120 section 7.5.3).
    pub fn from_ip(ip: std::net::IpAddr) -> Self {
        match ip {
            std::net::IpAddr::V4(v4) => Self {
                addr_type: addr_type::INET,
                address: v4.octets().to_vec(),
            },
            std::net::IpAddr::V6(v6) => Self {
                addr_type: addr_type::INET6,
                address: v6.octets().to_vec(),
            },
        }
    }
}

fn read_addresses(f: Reader<'_>) -> Result<Vec<HostAddress>, DerError> {
    f.sequence_of(MAX_ADDRESSES, HostAddress::read)
}

fn write_addresses(d: &mut Der, addresses: &[HostAddress]) {
    d.sequence(|q| {
        for address in addresses {
            address.write(q);
        }
    });
}

/// One element of `AuthorizationData`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdEntry {
    /// The type ([`ad_type`]).
    pub ad_type: i32,
    /// The data, itself DER for `AD-IF-RELEVANT`.
    pub ad_data: Vec<u8>,
}

/// `AuthorizationData`: a `SEQUENCE OF` [`AdEntry`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthorizationData(pub Vec<AdEntry>);

impl AuthorizationData {
    /// Reads one `AuthorizationData`.
    ///
    /// # Errors
    ///
    /// A [`DerError`] naming `AuthorizationData`.
    pub fn read(r: &mut Reader<'_>) -> Result<Self, DerError> {
        let content = r.expect(tag::SEQUENCE)?;
        let mut q = Reader::new(content, "AuthorizationData");
        let mut entries = Vec::new();
        while !q.is_empty() {
            if entries.len() == MAX_AD_ENTRIES {
                return Err(q.error(DerErrorKind::TooMany));
            }
            let mut s = Reader::new(q.expect(tag::SEQUENCE)?, "AuthorizationData");
            let ad_type = s.field(0, "ad-type")?.int32()?;
            let ad_data = s.field(1, "ad-data")?.octets()?.to_vec();
            s.finish()?;
            entries.push(AdEntry { ad_type, ad_data });
        }
        Ok(Self(entries))
    }

    /// Decodes the whole input as `AuthorizationData` (the content of `AD-IF-RELEVANT`).
    ///
    /// # Errors
    ///
    /// A [`DerError`] naming `AuthorizationData`.
    pub fn decode(bytes: &[u8]) -> Result<Self, DerError> {
        Reader::new(bytes, "AuthorizationData").with(Self::read)
    }

    /// Writes the `AuthorizationData`.
    pub fn write(&self, d: &mut Der) {
        d.sequence(|q| {
            for entry in &self.0 {
                q.sequence(|s| {
                    s.field(0, |f| {
                        f.integer(i64::from(entry.ad_type));
                    });
                    s.field(1, |f| {
                        f.octets(&entry.ad_data);
                    });
                });
            }
        });
    }

    /// The encoding.
    pub fn encode(&self) -> Vec<u8> {
        super::writer::encode(|d| self.write(d))
    }
}

/// `PA-DATA`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaData {
    /// The type ([`pa_type`]).
    pub padata_type: i32,
    /// The value.
    pub value: Vec<u8>,
}

impl PaData {
    /// Reads one `PA-DATA`. Its tags start at 1 (RFC 4120 section 5.2.7).
    ///
    /// # Errors
    ///
    /// A [`DerError`] naming `PA-DATA`.
    pub fn read(r: &mut Reader<'_>) -> Result<Self, DerError> {
        let mut s = Reader::new(r.expect(tag::SEQUENCE)?, "PA-DATA");
        let padata_type = s.field(1, "padata-type")?.int32()?;
        let value = s.field(2, "padata-value")?.octets()?.to_vec();
        s.finish()?;
        Ok(Self { padata_type, value })
    }

    /// Writes the `PA-DATA`.
    pub fn write(&self, d: &mut Der) {
        d.sequence(|s| {
            s.field(1, |f| {
                f.integer(i64::from(self.padata_type));
            });
            s.field(2, |f| {
                f.octets(&self.value);
            });
        });
    }
}

fn read_padata(f: Reader<'_>) -> Result<Vec<PaData>, DerError> {
    f.sequence_of(MAX_PADATA, PaData::read)
}

fn write_padata(d: &mut Der, padata: &[PaData]) {
    d.sequence(|q| {
        for pa in padata {
            pa.write(q);
        }
    });
}

/// `METHOD-DATA`: the `e-data` of a `KDC_ERR_PREAUTH_REQUIRED` error.
///
/// # Errors
///
/// A [`DerError`] naming `PA-DATA`.
pub fn decode_method_data(bytes: &[u8]) -> Result<Vec<PaData>, DerError> {
    read_padata(Reader::new(bytes, "METHOD-DATA"))
}

/// `EncryptedData`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedData {
    /// The encryption type.
    pub etype: i32,
    /// The key version number, when the key is a long-term key.
    pub kvno: Option<u32>,
    /// The ciphertext.
    pub cipher: Vec<u8>,
}

impl EncryptedData {
    /// Reads one `EncryptedData`.
    ///
    /// # Errors
    ///
    /// A [`DerError`] naming `EncryptedData`.
    pub fn read(r: &mut Reader<'_>) -> Result<Self, DerError> {
        let mut s = Reader::new(r.expect(tag::SEQUENCE)?, "EncryptedData");
        let etype = s.field(0, "etype")?.int32()?;
        let kvno = s.opt_field(1, "kvno")?.map(Reader::uint32).transpose()?;
        let cipher = s.field(2, "cipher")?.octets()?.to_vec();
        s.finish()?;
        Ok(Self {
            etype,
            kvno,
            cipher,
        })
    }

    /// Decodes the whole input as `EncryptedData` (the value of `PA-ENC-TIMESTAMP`).
    ///
    /// # Errors
    ///
    /// A [`DerError`] naming `EncryptedData`.
    pub fn decode(bytes: &[u8]) -> Result<Self, DerError> {
        Reader::new(bytes, "EncryptedData").with(Self::read)
    }

    /// Writes the `EncryptedData`.
    pub fn write(&self, d: &mut Der) {
        d.sequence(|s| {
            s.field(0, |f| {
                f.integer(i64::from(self.etype));
            });
            if let Some(kvno) = self.kvno {
                s.field(1, |f| {
                    f.uint32(kvno);
                });
            }
            s.field(2, |f| {
                f.octets(&self.cipher);
            });
        });
    }

    /// The encoding.
    pub fn encode(&self) -> Vec<u8> {
        super::writer::encode(|d| self.write(d))
    }
}

/// `EncryptionKey`. The key value is zeroed on drop and never printed.
#[derive(Clone, PartialEq, Eq)]
pub struct EncryptionKey {
    /// The key type (the encryption type).
    pub keytype: i32,
    /// The key octets.
    pub value: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for EncryptionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "EncryptionKey(type {}, {} octets)",
            self.keytype,
            self.value.len()
        )
    }
}

impl EncryptionKey {
    /// Reads one `EncryptionKey`.
    ///
    /// # Errors
    ///
    /// A [`DerError`] naming `EncryptionKey`.
    pub fn read(r: &mut Reader<'_>) -> Result<Self, DerError> {
        let mut s = Reader::new(r.expect(tag::SEQUENCE)?, "EncryptionKey");
        let keytype = s.field(0, "keytype")?.int32()?;
        let value = Zeroizing::new(s.field(1, "keyvalue")?.octets()?.to_vec());
        s.finish()?;
        Ok(Self { keytype, value })
    }

    /// Writes the `EncryptionKey`.
    pub fn write(&self, d: &mut Der) {
        d.sequence(|s| {
            s.field(0, |f| {
                f.integer(i64::from(self.keytype));
            });
            s.field(1, |f| {
                f.octets(&self.value);
            });
        });
    }
}

/// `Checksum`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checksum {
    /// The checksum type.
    pub cksumtype: i32,
    /// The checksum octets.
    pub checksum: Vec<u8>,
}

impl Checksum {
    /// Reads one `Checksum`.
    ///
    /// # Errors
    ///
    /// A [`DerError`] naming `Checksum`.
    pub fn read(r: &mut Reader<'_>) -> Result<Self, DerError> {
        let mut s = Reader::new(r.expect(tag::SEQUENCE)?, "Checksum");
        let cksumtype = s.field(0, "cksumtype")?.int32()?;
        let checksum = s.field(1, "checksum")?.octets()?.to_vec();
        s.finish()?;
        Ok(Self {
            cksumtype,
            checksum,
        })
    }

    /// Writes the `Checksum`.
    pub fn write(&self, d: &mut Der) {
        d.sequence(|s| {
            s.field(0, |f| {
                f.integer(i64::from(self.cksumtype));
            });
            s.field(1, |f| {
                f.octets(&self.checksum);
            });
        });
    }
}

/// `TransitedEncoding`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TransitedEncoding {
    /// The encoding type (1: domain-x500-compress).
    pub tr_type: i32,
    /// The realms transited.
    pub contents: Vec<u8>,
}

fn check_vno(value: i32, structure: &'static str, field: &'static str) -> Result<(), DerError> {
    if value == PVNO {
        Ok(())
    } else {
        Err(DerError::new(structure, field, DerErrorKind::Unsupported))
    }
}

fn check_msg_type(value: i32, allowed: &[i32], structure: &'static str) -> Result<(), DerError> {
    if allowed.contains(&value) {
        Ok(())
    } else {
        Err(DerError::new(
            structure,
            "msg-type",
            DerErrorKind::Unsupported,
        ))
    }
}

/// Opens `[APPLICATION n] SEQUENCE` and requires nothing after it in `r`'s TLV.
fn open_application<'a>(
    r: &mut Reader<'a>,
    n: u8,
    structure: &'static str,
) -> Result<Reader<'a>, DerError> {
    let mut outer = Reader::new(r.expect(tag::application(n))?, structure);
    let s = outer.sequence()?;
    outer.finish()?;
    Ok(s)
}

// ---------------------------------------------------------------------------------------
// Tickets and the AP exchange

/// `Ticket` (`[APPLICATION 1]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ticket {
    /// The realm of the service.
    pub realm: String,
    /// The service's name.
    pub sname: PrincipalName,
    /// The encrypted `EncTicketPart`, under the service's long-term key.
    pub enc_part: EncryptedData,
}

impl Ticket {
    /// Reads one `Ticket`.
    ///
    /// # Errors
    ///
    /// A [`DerError`] naming `Ticket`.
    pub fn read(r: &mut Reader<'_>) -> Result<Self, DerError> {
        let mut s = open_application(r, 1, "Ticket")?;
        check_vno(s.field(0, "tkt-vno")?.int32()?, "Ticket", "tkt-vno")?;
        let realm = s.field(1, "realm")?.string()?;
        let sname = s.field(2, "sname")?.with(PrincipalName::read)?;
        let enc_part = s.field(3, "enc-part")?.with(EncryptedData::read)?;
        s.finish()?;
        Ok(Self {
            realm,
            sname,
            enc_part,
        })
    }

    /// Writes the `Ticket`.
    pub fn write(&self, d: &mut Der) {
        d.application(1, |a| {
            a.sequence(|s| {
                s.field(0, |f| {
                    f.integer(i64::from(PVNO));
                });
                s.field(1, |f| {
                    f.string(&self.realm);
                });
                s.field(2, |f| self.sname.write(f));
                s.field(3, |f| self.enc_part.write(f));
            });
        });
    }

    /// Decodes a whole `Ticket`.
    ///
    /// # Errors
    ///
    /// A [`DerError`] naming `Ticket`.
    pub fn decode(bytes: &[u8]) -> Result<Self, DerError> {
        Reader::new(bytes, "Ticket").with(Self::read)
    }

    /// The encoding.
    pub fn encode(&self) -> Vec<u8> {
        super::writer::encode(|d| self.write(d))
    }
}

/// Ticket flags (RFC 4120 section 5.3) as bits of the 32-bit value.
pub mod ticket_flags {
    /// FORWARDABLE.
    pub const FORWARDABLE: u32 = 0x4000_0000;
    /// RENEWABLE.
    pub const RENEWABLE: u32 = 0x0080_0000;
    /// INITIAL: issued by the AS exchange.
    pub const INITIAL: u32 = 0x0040_0000;
    /// PRE-AUTHENT.
    pub const PRE_AUTHENT: u32 = 0x0020_0000;
    /// INVALID: must be validated by the KDC before use.
    pub const INVALID: u32 = 0x0100_0000;
}

/// `EncTicketPart` (`[APPLICATION 3]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncTicketPart {
    /// The ticket flags.
    pub flags: u32,
    /// The session key.
    pub key: EncryptionKey,
    /// The client's realm.
    pub crealm: String,
    /// The client's name.
    pub cname: PrincipalName,
    /// The realms transited.
    pub transited: TransitedEncoding,
    /// When the client authenticated (Unix seconds).
    pub authtime: i64,
    /// When the ticket becomes valid, if not `authtime`.
    pub starttime: Option<i64>,
    /// When the ticket expires.
    pub endtime: i64,
    /// The end of the renewable lifetime.
    pub renew_till: Option<i64>,
    /// The addresses the ticket may be used from.
    pub caddr: Option<Vec<HostAddress>>,
    /// The authorization data (the PAC, wrapped in `AD-IF-RELEVANT`).
    pub authorization_data: Option<AuthorizationData>,
}

impl EncTicketPart {
    /// Decodes a whole `EncTicketPart`.
    ///
    /// # Errors
    ///
    /// A [`DerError`] naming `EncTicketPart`.
    pub fn decode(bytes: &[u8]) -> Result<Self, DerError> {
        let mut r = Reader::new(bytes, "EncTicketPart");
        let mut s = open_application(&mut r, 3, "EncTicketPart")?;
        r.finish()?;
        let flags = s.field(0, "flags")?.flags()?;
        let key = s.field(1, "key")?.with(EncryptionKey::read)?;
        let crealm = s.field(2, "crealm")?.string()?;
        let cname = s.field(3, "cname")?.with(PrincipalName::read)?;
        let transited = s.field(4, "transited")?.with(|f| {
            let mut t = Reader::new(f.expect(tag::SEQUENCE)?, "TransitedEncoding");
            let tr_type = t.field(0, "tr-type")?.int32()?;
            let contents = t.field(1, "contents")?.octets()?.to_vec();
            t.finish()?;
            Ok(TransitedEncoding { tr_type, contents })
        })?;
        let authtime = s.field(5, "authtime")?.time()?;
        let starttime = s.opt_field(6, "starttime")?.map(Reader::time).transpose()?;
        let endtime = s.field(7, "endtime")?.time()?;
        let renew_till = s
            .opt_field(8, "renew-till")?
            .map(Reader::time)
            .transpose()?;
        let caddr = s.opt_field(9, "caddr")?.map(read_addresses).transpose()?;
        let authorization_data = s
            .opt_field(10, "authorization-data")?
            .map(|f| f.with(AuthorizationData::read))
            .transpose()?;
        s.finish()?;
        Ok(Self {
            flags,
            key,
            crealm,
            cname,
            transited,
            authtime,
            starttime,
            endtime,
            renew_till,
            caddr,
            authorization_data,
        })
    }

    /// The encoding (it holds the session key).
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        super::writer::encode_secret(|d| {
            d.application(3, |a| {
                a.sequence(|s| {
                    s.field(0, |f| {
                        f.flags(self.flags);
                    });
                    s.field(1, |f| self.key.write(f));
                    s.field(2, |f| {
                        f.string(&self.crealm);
                    });
                    s.field(3, |f| self.cname.write(f));
                    s.field(4, |f| {
                        f.sequence(|t| {
                            t.field(0, |g| {
                                g.integer(i64::from(self.transited.tr_type));
                            });
                            t.field(1, |g| {
                                g.octets(&self.transited.contents);
                            });
                        });
                    });
                    s.field(5, |f| {
                        f.time(self.authtime);
                    });
                    if let Some(time) = self.starttime {
                        s.field(6, |f| {
                            f.time(time);
                        });
                    }
                    s.field(7, |f| {
                        f.time(self.endtime);
                    });
                    if let Some(time) = self.renew_till {
                        s.field(8, |f| {
                            f.time(time);
                        });
                    }
                    if let Some(addresses) = &self.caddr {
                        s.field(9, |f| write_addresses(f, addresses));
                    }
                    if let Some(ad) = &self.authorization_data {
                        s.field(10, |f| ad.write(f));
                    }
                });
            });
        })
    }
}

/// `Authenticator` (`[APPLICATION 2]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authenticator {
    /// The client's realm.
    pub crealm: String,
    /// The client's name.
    pub cname: PrincipalName,
    /// The checksum (for GSS-API, type 0x8003 of RFC 4121 section 4.1.1).
    pub cksum: Option<Checksum>,
    /// The microseconds of the client's time.
    pub cusec: u32,
    /// The client's time (Unix seconds).
    pub ctime: i64,
    /// The initiator's subkey.
    pub subkey: Option<EncryptionKey>,
    /// The initiator's first sequence number.
    pub seq_number: Option<u32>,
    /// Authorization data the client adds.
    pub authorization_data: Option<AuthorizationData>,
}

impl Authenticator {
    /// Decodes a whole `Authenticator`.
    ///
    /// # Errors
    ///
    /// A [`DerError`] naming `Authenticator`.
    pub fn decode(bytes: &[u8]) -> Result<Self, DerError> {
        let mut r = Reader::new(bytes, "Authenticator");
        let mut s = open_application(&mut r, 2, "Authenticator")?;
        r.finish()?;
        check_vno(
            s.field(0, "authenticator-vno")?.int32()?,
            "Authenticator",
            "authenticator-vno",
        )?;
        let crealm = s.field(1, "crealm")?.string()?;
        let cname = s.field(2, "cname")?.with(PrincipalName::read)?;
        let cksum = s
            .opt_field(3, "cksum")?
            .map(|f| f.with(Checksum::read))
            .transpose()?;
        let cusec = s.field(4, "cusec")?.microseconds()?;
        let ctime = s.field(5, "ctime")?.time()?;
        let subkey = s
            .opt_field(6, "subkey")?
            .map(|f| f.with(EncryptionKey::read))
            .transpose()?;
        let seq_number = s
            .opt_field(7, "seq-number")?
            .map(Reader::uint32_lenient)
            .transpose()?;
        let authorization_data = s
            .opt_field(8, "authorization-data")?
            .map(|f| f.with(AuthorizationData::read))
            .transpose()?;
        s.finish()?;
        Ok(Self {
            crealm,
            cname,
            cksum,
            cusec,
            ctime,
            subkey,
            seq_number,
            authorization_data,
        })
    }

    /// The encoding (it may hold the subkey).
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        super::writer::encode_secret(|d| {
            d.application(2, |a| {
                a.sequence(|s| {
                    s.field(0, |f| {
                        f.integer(i64::from(PVNO));
                    });
                    s.field(1, |f| {
                        f.string(&self.crealm);
                    });
                    s.field(2, |f| self.cname.write(f));
                    if let Some(cksum) = &self.cksum {
                        s.field(3, |f| cksum.write(f));
                    }
                    s.field(4, |f| {
                        f.uint32(self.cusec);
                    });
                    s.field(5, |f| {
                        f.time(self.ctime);
                    });
                    if let Some(subkey) = &self.subkey {
                        s.field(6, |f| subkey.write(f));
                    }
                    if let Some(seq) = self.seq_number {
                        s.field(7, |f| {
                            f.uint32(seq);
                        });
                    }
                    if let Some(ad) = &self.authorization_data {
                        s.field(8, |f| ad.write(f));
                    }
                });
            });
        })
    }
}

/// AP options (RFC 4120 section 5.5.1) as bits of the 32-bit value.
pub mod ap_options {
    /// USE-SESSION-KEY: user-to-user, never accepted.
    pub const USE_SESSION_KEY: u32 = 0x4000_0000;
    /// MUTUAL-REQUIRED.
    pub const MUTUAL_REQUIRED: u32 = 0x2000_0000;
}

/// `AP-REQ` (`[APPLICATION 14]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApReq {
    /// The AP options ([`ap_options`]).
    pub ap_options: u32,
    /// The ticket.
    pub ticket: Ticket,
    /// The encrypted `Authenticator`, under the ticket's session key.
    pub authenticator: EncryptedData,
}

impl ApReq {
    /// Decodes a whole `AP-REQ`.
    ///
    /// # Errors
    ///
    /// A [`DerError`] naming `AP-REQ`.
    pub fn decode(bytes: &[u8]) -> Result<Self, DerError> {
        Reader::new(bytes, "AP-REQ").with(Self::read)
    }

    /// Reads one `AP-REQ`.
    ///
    /// # Errors
    ///
    /// A [`DerError`] naming `AP-REQ`.
    pub fn read(r: &mut Reader<'_>) -> Result<Self, DerError> {
        let mut s = open_application(r, 14, "AP-REQ")?;
        check_vno(s.field(0, "pvno")?.int32()?, "AP-REQ", "pvno")?;
        check_msg_type(
            s.field(1, "msg-type")?.int32()?,
            &[msg_type::AP_REQ],
            "AP-REQ",
        )?;
        let ap_options = s.field(2, "ap-options")?.flags()?;
        let ticket = s.field(3, "ticket")?.with(Ticket::read)?;
        let authenticator = s.field(4, "authenticator")?.with(EncryptedData::read)?;
        s.finish()?;
        Ok(Self {
            ap_options,
            ticket,
            authenticator,
        })
    }

    /// The encoding.
    pub fn encode(&self) -> Vec<u8> {
        super::writer::encode(|d| {
            d.application(14, |a| {
                a.sequence(|s| {
                    s.field(0, |f| {
                        f.integer(i64::from(PVNO));
                    });
                    s.field(1, |f| {
                        f.integer(i64::from(msg_type::AP_REQ));
                    });
                    s.field(2, |f| {
                        f.flags(self.ap_options);
                    });
                    s.field(3, |f| self.ticket.write(f));
                    s.field(4, |f| self.authenticator.write(f));
                });
            });
        })
    }
}

/// `AP-REP` (`[APPLICATION 15]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApRep {
    /// The encrypted `EncAPRepPart`, under the ticket's session key.
    pub enc_part: EncryptedData,
}

impl ApRep {
    /// Decodes a whole `AP-REP`.
    ///
    /// # Errors
    ///
    /// A [`DerError`] naming `AP-REP`.
    pub fn decode(bytes: &[u8]) -> Result<Self, DerError> {
        let mut r = Reader::new(bytes, "AP-REP");
        let mut s = open_application(&mut r, 15, "AP-REP")?;
        r.finish()?;
        check_vno(s.field(0, "pvno")?.int32()?, "AP-REP", "pvno")?;
        check_msg_type(
            s.field(1, "msg-type")?.int32()?,
            &[msg_type::AP_REP],
            "AP-REP",
        )?;
        let enc_part = s.field(2, "enc-part")?.with(EncryptedData::read)?;
        s.finish()?;
        Ok(Self { enc_part })
    }

    /// The encoding.
    pub fn encode(&self) -> Vec<u8> {
        super::writer::encode(|d| {
            d.application(15, |a| {
                a.sequence(|s| {
                    s.field(0, |f| {
                        f.integer(i64::from(PVNO));
                    });
                    s.field(1, |f| {
                        f.integer(i64::from(msg_type::AP_REP));
                    });
                    s.field(2, |f| self.enc_part.write(f));
                });
            });
        })
    }
}

/// `EncAPRepPart` (`[APPLICATION 27]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncApRepPart {
    /// The client's time from the authenticator.
    pub ctime: i64,
    /// Its microseconds.
    pub cusec: u32,
    /// The acceptor's subkey.
    pub subkey: Option<EncryptionKey>,
    /// The acceptor's first sequence number.
    pub seq_number: Option<u32>,
}

impl EncApRepPart {
    /// Decodes a whole `EncAPRepPart`.
    ///
    /// # Errors
    ///
    /// A [`DerError`] naming `EncAPRepPart`.
    pub fn decode(bytes: &[u8]) -> Result<Self, DerError> {
        let mut r = Reader::new(bytes, "EncAPRepPart");
        let mut s = open_application(&mut r, 27, "EncAPRepPart")?;
        r.finish()?;
        let ctime = s.field(0, "ctime")?.time()?;
        let cusec = s.field(1, "cusec")?.microseconds()?;
        let subkey = s
            .opt_field(2, "subkey")?
            .map(|f| f.with(EncryptionKey::read))
            .transpose()?;
        let seq_number = s
            .opt_field(3, "seq-number")?
            .map(Reader::uint32_lenient)
            .transpose()?;
        s.finish()?;
        Ok(Self {
            ctime,
            cusec,
            subkey,
            seq_number,
        })
    }

    /// The encoding (it may hold the subkey).
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        super::writer::encode_secret(|d| {
            d.application(27, |a| {
                a.sequence(|s| {
                    s.field(0, |f| {
                        f.time(self.ctime);
                    });
                    s.field(1, |f| {
                        f.uint32(self.cusec);
                    });
                    if let Some(subkey) = &self.subkey {
                        s.field(2, |f| subkey.write(f));
                    }
                    if let Some(seq) = self.seq_number {
                        s.field(3, |f| {
                            f.uint32(seq);
                        });
                    }
                });
            });
        })
    }
}

// ---------------------------------------------------------------------------------------
// The KDC exchanges

/// KDC options (RFC 4120 section 5.4.1) as bits of the 32-bit value.
pub mod kdc_options {
    /// FORWARDABLE.
    pub const FORWARDABLE: u32 = 0x4000_0000;
    /// RENEWABLE.
    pub const RENEWABLE: u32 = 0x0080_0000;
    /// CANONICALIZE (RFC 6806).
    pub const CANONICALIZE: u32 = 0x0001_0000;
    /// RENEWABLE-OK.
    pub const RENEWABLE_OK: u32 = 0x0000_0010;
}

/// `KDC-REQ-BODY`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KdcReqBody {
    /// The KDC options ([`kdc_options`]).
    pub kdc_options: u32,
    /// The client's name (AS only).
    pub cname: Option<PrincipalName>,
    /// The realm: the client's in an AS request, the service's in a TGS request.
    pub realm: String,
    /// The service's name.
    pub sname: Option<PrincipalName>,
    /// The start time asked for a postdated ticket.
    pub from: Option<i64>,
    /// The end time asked.
    pub till: i64,
    /// The renewable end time asked.
    pub rtime: Option<i64>,
    /// The nonce the reply must carry.
    pub nonce: u32,
    /// The encryption types acceptable for the session key, in preference order.
    pub etype: Vec<i32>,
    /// The addresses the ticket is for.
    pub addresses: Option<Vec<HostAddress>>,
    /// Encrypted authorization data (TGS only).
    pub enc_authorization_data: Option<EncryptedData>,
    /// Additional tickets (user-to-user, constrained delegation).
    pub additional_tickets: Option<Vec<Ticket>>,
}

impl KdcReqBody {
    /// Reads one `KDC-REQ-BODY`.
    ///
    /// # Errors
    ///
    /// A [`DerError`] naming `KDC-REQ-BODY`.
    pub fn read(r: &mut Reader<'_>) -> Result<Self, DerError> {
        let mut s = Reader::new(r.expect(tag::SEQUENCE)?, "KDC-REQ-BODY");
        let kdc_options = s.field(0, "kdc-options")?.flags()?;
        let cname = s
            .opt_field(1, "cname")?
            .map(|f| f.with(PrincipalName::read))
            .transpose()?;
        let realm = s.field(2, "realm")?.string()?;
        let sname = s
            .opt_field(3, "sname")?
            .map(|f| f.with(PrincipalName::read))
            .transpose()?;
        let from = s.opt_field(4, "from")?.map(Reader::time).transpose()?;
        let till = s.field(5, "till")?.time()?;
        let rtime = s.opt_field(6, "rtime")?.map(Reader::time).transpose()?;
        let nonce = s.field(7, "nonce")?.uint32_lenient()?;
        let etype = s.field(8, "etype")?.sequence_of(MAX_ETYPES, |e| {
            let value = e.expect_tlv(tag::INTEGER)?;
            let number = super::reader::decode_integer(value.value)
                .and_then(|v| i32::try_from(v).ok())
                .ok_or_else(|| e.error(DerErrorKind::BadInteger))?;
            Ok(number)
        })?;
        let addresses = s
            .opt_field(9, "addresses")?
            .map(read_addresses)
            .transpose()?;
        let enc_authorization_data = s
            .opt_field(10, "enc-authorization-data")?
            .map(|f| f.with(EncryptedData::read))
            .transpose()?;
        let additional_tickets = s
            .opt_field(11, "additional-tickets")?
            .map(|f| f.sequence_of(MAX_ADDITIONAL_TICKETS, Ticket::read))
            .transpose()?;
        s.finish()?;
        Ok(Self {
            kdc_options,
            cname,
            realm,
            sname,
            from,
            till,
            rtime,
            nonce,
            etype,
            addresses,
            enc_authorization_data,
            additional_tickets,
        })
    }

    /// The encoding: the octets a TGS request's authenticator checksum covers.
    pub fn encode(&self) -> Vec<u8> {
        super::writer::encode(|d| {
            d.sequence(|s| {
                s.field(0, |f| {
                    f.flags(self.kdc_options);
                });
                if let Some(cname) = &self.cname {
                    s.field(1, |f| cname.write(f));
                }
                s.field(2, |f| {
                    f.string(&self.realm);
                });
                if let Some(sname) = &self.sname {
                    s.field(3, |f| sname.write(f));
                }
                if let Some(from) = self.from {
                    s.field(4, |f| {
                        f.time(from);
                    });
                }
                s.field(5, |f| {
                    f.time(self.till);
                });
                if let Some(rtime) = self.rtime {
                    s.field(6, |f| {
                        f.time(rtime);
                    });
                }
                s.field(7, |f| {
                    f.uint32(self.nonce);
                });
                s.field(8, |f| {
                    f.sequence(|q| {
                        for etype in &self.etype {
                            q.integer(i64::from(*etype));
                        }
                    });
                });
                if let Some(addresses) = &self.addresses {
                    s.field(9, |f| write_addresses(f, addresses));
                }
                if let Some(data) = &self.enc_authorization_data {
                    s.field(10, |f| data.write(f));
                }
                if let Some(tickets) = &self.additional_tickets {
                    s.field(11, |f| {
                        f.sequence(|q| {
                            for ticket in tickets {
                                ticket.write(q);
                            }
                        });
                    });
                }
            });
        })
    }
}

/// `AS-REQ` (`[APPLICATION 10]`) or `TGS-REQ` (`[APPLICATION 12]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KdcReq {
    /// [`msg_type::AS_REQ`] or [`msg_type::TGS_REQ`].
    pub msg_type: i32,
    /// The pre-authentication data.
    pub padata: Option<Vec<PaData>>,
    /// The request body.
    pub req_body: KdcReqBody,
}

impl KdcReq {
    /// Decodes a whole `AS-REQ` or `TGS-REQ`.
    ///
    /// # Errors
    ///
    /// A [`DerError`] naming `KDC-REQ`.
    pub fn decode(bytes: &[u8]) -> Result<Self, DerError> {
        let mut r = Reader::new(bytes, "KDC-REQ");
        let (n, expected) = match r.peek_tag() {
            Some(t) if t == tag::application(12) => (12, msg_type::TGS_REQ),
            _ => (10, msg_type::AS_REQ),
        };
        let mut s = open_application(&mut r, n, "KDC-REQ")?;
        r.finish()?;
        check_vno(s.field(1, "pvno")?.int32()?, "KDC-REQ", "pvno")?;
        let msg_type = s.field(2, "msg-type")?.int32()?;
        check_msg_type(msg_type, &[expected], "KDC-REQ")?;
        let padata = s.opt_field(3, "padata")?.map(read_padata).transpose()?;
        let req_body = s.field(4, "req-body")?.with(KdcReqBody::read)?;
        s.finish()?;
        Ok(Self {
            msg_type,
            padata,
            req_body,
        })
    }

    /// The encoding, with the body's octets as given (they are what a TGS request's
    /// checksum covers).
    pub fn encode_with_body(&self, body: &[u8]) -> Vec<u8> {
        let n = if self.msg_type == msg_type::TGS_REQ {
            12
        } else {
            10
        };
        super::writer::encode(|d| {
            d.application(n, |a| {
                a.sequence(|s| {
                    s.field(1, |f| {
                        f.integer(i64::from(PVNO));
                    });
                    s.field(2, |f| {
                        f.integer(i64::from(self.msg_type));
                    });
                    if let Some(padata) = &self.padata {
                        s.field(3, |f| write_padata(f, padata));
                    }
                    s.field(4, |f| {
                        f.raw(body);
                    });
                });
            });
        })
    }

    /// The encoding.
    pub fn encode(&self) -> Vec<u8> {
        self.encode_with_body(&self.req_body.encode())
    }
}

/// `AS-REP` (`[APPLICATION 11]`) or `TGS-REP` (`[APPLICATION 13]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KdcRep {
    /// [`msg_type::AS_REP`] or [`msg_type::TGS_REP`].
    pub msg_type: i32,
    /// The pre-authentication data (`PA-ETYPE-INFO2` in an AS reply).
    pub padata: Option<Vec<PaData>>,
    /// The client's realm.
    pub crealm: String,
    /// The client's name.
    pub cname: PrincipalName,
    /// The ticket issued.
    pub ticket: Ticket,
    /// The encrypted `EncKDCRepPart`.
    pub enc_part: EncryptedData,
}

impl KdcRep {
    /// Decodes a whole `AS-REP` or `TGS-REP`.
    ///
    /// # Errors
    ///
    /// A [`DerError`] naming `KDC-REP`.
    pub fn decode(bytes: &[u8]) -> Result<Self, DerError> {
        let mut r = Reader::new(bytes, "KDC-REP");
        let (n, expected) = match r.peek_tag() {
            Some(t) if t == tag::application(13) => (13, msg_type::TGS_REP),
            _ => (11, msg_type::AS_REP),
        };
        let mut s = open_application(&mut r, n, "KDC-REP")?;
        r.finish()?;
        check_vno(s.field(0, "pvno")?.int32()?, "KDC-REP", "pvno")?;
        let msg_type = s.field(1, "msg-type")?.int32()?;
        check_msg_type(msg_type, &[expected], "KDC-REP")?;
        let padata = s.opt_field(2, "padata")?.map(read_padata).transpose()?;
        let crealm = s.field(3, "crealm")?.string()?;
        let cname = s.field(4, "cname")?.with(PrincipalName::read)?;
        let ticket = s.field(5, "ticket")?.with(Ticket::read)?;
        let enc_part = s.field(6, "enc-part")?.with(EncryptedData::read)?;
        s.finish()?;
        Ok(Self {
            msg_type,
            padata,
            crealm,
            cname,
            ticket,
            enc_part,
        })
    }

    /// The encoding.
    pub fn encode(&self) -> Vec<u8> {
        let n = if self.msg_type == msg_type::TGS_REP {
            13
        } else {
            11
        };
        super::writer::encode(|d| {
            d.application(n, |a| {
                a.sequence(|s| {
                    s.field(0, |f| {
                        f.integer(i64::from(PVNO));
                    });
                    s.field(1, |f| {
                        f.integer(i64::from(self.msg_type));
                    });
                    if let Some(padata) = &self.padata {
                        s.field(2, |f| write_padata(f, padata));
                    }
                    s.field(3, |f| {
                        f.string(&self.crealm);
                    });
                    s.field(4, |f| self.cname.write(f));
                    s.field(5, |f| self.ticket.write(f));
                    s.field(6, |f| self.enc_part.write(f));
                });
            });
        })
    }
}

/// One `LastReq` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LastReq {
    /// The type.
    pub lr_type: i32,
    /// The time.
    pub lr_value: i64,
}

/// `EncKDCRepPart`, as `EncASRepPart` (`[APPLICATION 25]`) or `EncTGSRepPart`
/// (`[APPLICATION 26]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncKdcRepPart {
    /// 25 or 26: the application tag found. RFC 4120 section 5.4.2 lets a client take
    /// either in either reply, since some KDCs always send 26.
    pub application: u8,
    /// The session key.
    pub key: EncryptionKey,
    /// The last-request information.
    pub last_req: Vec<LastReq>,
    /// The nonce of the request.
    pub nonce: u32,
    /// When the client's key expires.
    pub key_expiration: Option<i64>,
    /// The ticket flags.
    pub flags: u32,
    /// When the client authenticated.
    pub authtime: i64,
    /// When the ticket becomes valid.
    pub starttime: Option<i64>,
    /// When it expires.
    pub endtime: i64,
    /// The end of the renewable lifetime.
    pub renew_till: Option<i64>,
    /// The service's realm.
    pub srealm: String,
    /// The service's name.
    pub sname: PrincipalName,
    /// The addresses of the ticket.
    pub caddr: Option<Vec<HostAddress>>,
    /// Encrypted pre-authentication data (RFC 6806 section 11).
    pub encrypted_pa_data: Option<Vec<PaData>>,
}

impl EncKdcRepPart {
    /// Decodes a whole `EncASRepPart` or `EncTGSRepPart`.
    ///
    /// # Errors
    ///
    /// A [`DerError`] naming `EncKDCRepPart`.
    pub fn decode(bytes: &[u8]) -> Result<Self, DerError> {
        let mut r = Reader::new(bytes, "EncKDCRepPart");
        let application = match r.peek_tag() {
            Some(t) if t == tag::application(26) => 26,
            _ => 25,
        };
        let mut s = open_application(&mut r, application, "EncKDCRepPart")?;
        r.finish()?;
        let key = s.field(0, "key")?.with(EncryptionKey::read)?;
        let last_req = s.field(1, "last-req")?.sequence_of(MAX_LAST_REQ, |e| {
            let mut l = Reader::new(e.expect(tag::SEQUENCE)?, "LastReq");
            let lr_type = l.field(0, "lr-type")?.int32()?;
            let lr_value = l.field(1, "lr-value")?.time()?;
            l.finish()?;
            Ok(LastReq { lr_type, lr_value })
        })?;
        let nonce = s.field(2, "nonce")?.uint32_lenient()?;
        let key_expiration = s
            .opt_field(3, "key-expiration")?
            .map(Reader::time)
            .transpose()?;
        let flags = s.field(4, "flags")?.flags()?;
        let authtime = s.field(5, "authtime")?.time()?;
        let starttime = s.opt_field(6, "starttime")?.map(Reader::time).transpose()?;
        let endtime = s.field(7, "endtime")?.time()?;
        let renew_till = s
            .opt_field(8, "renew-till")?
            .map(Reader::time)
            .transpose()?;
        let srealm = s.field(9, "srealm")?.string()?;
        let sname = s.field(10, "sname")?.with(PrincipalName::read)?;
        let caddr = s.opt_field(11, "caddr")?.map(read_addresses).transpose()?;
        let encrypted_pa_data = s
            .opt_field(12, "encrypted-pa-data")?
            .map(read_padata)
            .transpose()?;
        s.finish()?;
        Ok(Self {
            application,
            key,
            last_req,
            nonce,
            key_expiration,
            flags,
            authtime,
            starttime,
            endtime,
            renew_till,
            srealm,
            sname,
            caddr,
            encrypted_pa_data,
        })
    }

    /// The encoding (it holds the session key).
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        super::writer::encode_secret(|d| {
            d.application(self.application, |a| {
                a.sequence(|s| {
                    s.field(0, |f| self.key.write(f));
                    s.field(1, |f| {
                        f.sequence(|q| {
                            for entry in &self.last_req {
                                q.sequence(|l| {
                                    l.field(0, |g| {
                                        g.integer(i64::from(entry.lr_type));
                                    });
                                    l.field(1, |g| {
                                        g.time(entry.lr_value);
                                    });
                                });
                            }
                        });
                    });
                    s.field(2, |f| {
                        f.uint32(self.nonce);
                    });
                    if let Some(time) = self.key_expiration {
                        s.field(3, |f| {
                            f.time(time);
                        });
                    }
                    s.field(4, |f| {
                        f.flags(self.flags);
                    });
                    s.field(5, |f| {
                        f.time(self.authtime);
                    });
                    if let Some(time) = self.starttime {
                        s.field(6, |f| {
                            f.time(time);
                        });
                    }
                    s.field(7, |f| {
                        f.time(self.endtime);
                    });
                    if let Some(time) = self.renew_till {
                        s.field(8, |f| {
                            f.time(time);
                        });
                    }
                    s.field(9, |f| {
                        f.string(&self.srealm);
                    });
                    s.field(10, |f| self.sname.write(f));
                    if let Some(addresses) = &self.caddr {
                        s.field(11, |f| write_addresses(f, addresses));
                    }
                    if let Some(padata) = &self.encrypted_pa_data {
                        s.field(12, |f| write_padata(f, padata));
                    }
                });
            });
        })
    }
}

/// `KRB-ERROR` (`[APPLICATION 30]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KrbError {
    /// The client's time, echoed.
    pub ctime: Option<i64>,
    /// Its microseconds.
    pub cusec: Option<u32>,
    /// The server's time.
    pub stime: i64,
    /// Its microseconds.
    pub susec: u32,
    /// The error code (RFC 4120 section 7.5.9).
    pub error_code: i32,
    /// The client's realm.
    pub crealm: Option<String>,
    /// The client's name.
    pub cname: Option<PrincipalName>,
    /// The service's realm.
    pub realm: String,
    /// The service's name.
    pub sname: PrincipalName,
    /// Text for a person.
    pub e_text: Option<String>,
    /// Data for the client (`METHOD-DATA` for pre-authentication).
    pub e_data: Option<Vec<u8>>,
}

impl KrbError {
    /// Decodes a whole `KRB-ERROR`.
    ///
    /// # Errors
    ///
    /// A [`DerError`] naming `KRB-ERROR`.
    pub fn decode(bytes: &[u8]) -> Result<Self, DerError> {
        let mut r = Reader::new(bytes, "KRB-ERROR");
        let mut s = open_application(&mut r, 30, "KRB-ERROR")?;
        r.finish()?;
        check_vno(s.field(0, "pvno")?.int32()?, "KRB-ERROR", "pvno")?;
        check_msg_type(
            s.field(1, "msg-type")?.int32()?,
            &[msg_type::KRB_ERROR],
            "KRB-ERROR",
        )?;
        let ctime = s.opt_field(2, "ctime")?.map(Reader::time).transpose()?;
        let cusec = s
            .opt_field(3, "cusec")?
            .map(Reader::microseconds)
            .transpose()?;
        let stime = s.field(4, "stime")?.time()?;
        let susec = s.field(5, "susec")?.microseconds()?;
        let error_code = s.field(6, "error-code")?.int32()?;
        let crealm = s.opt_field(7, "crealm")?.map(Reader::string).transpose()?;
        let cname = s
            .opt_field(8, "cname")?
            .map(|f| f.with(PrincipalName::read))
            .transpose()?;
        let realm = s.field(9, "realm")?.string()?;
        let sname = s.field(10, "sname")?.with(PrincipalName::read)?;
        let e_text = s.opt_field(11, "e-text")?.map(Reader::string).transpose()?;
        let e_data = s
            .opt_field(12, "e-data")?
            .map(|f| f.octets().map(<[u8]>::to_vec))
            .transpose()?;
        s.finish()?;
        Ok(Self {
            ctime,
            cusec,
            stime,
            susec,
            error_code,
            crealm,
            cname,
            realm,
            sname,
            e_text,
            e_data,
        })
    }

    /// The encoding.
    pub fn encode(&self) -> Vec<u8> {
        super::writer::encode(|d| {
            d.application(30, |a| {
                a.sequence(|s| {
                    s.field(0, |f| {
                        f.integer(i64::from(PVNO));
                    });
                    s.field(1, |f| {
                        f.integer(i64::from(msg_type::KRB_ERROR));
                    });
                    if let Some(time) = self.ctime {
                        s.field(2, |f| {
                            f.time(time);
                        });
                    }
                    if let Some(usec) = self.cusec {
                        s.field(3, |f| {
                            f.uint32(usec);
                        });
                    }
                    s.field(4, |f| {
                        f.time(self.stime);
                    });
                    s.field(5, |f| {
                        f.uint32(self.susec);
                    });
                    s.field(6, |f| {
                        f.integer(i64::from(self.error_code));
                    });
                    if let Some(realm) = &self.crealm {
                        s.field(7, |f| {
                            f.string(realm);
                        });
                    }
                    if let Some(cname) = &self.cname {
                        s.field(8, |f| cname.write(f));
                    }
                    s.field(9, |f| {
                        f.string(&self.realm);
                    });
                    s.field(10, |f| self.sname.write(f));
                    if let Some(text) = &self.e_text {
                        s.field(11, |f| {
                            f.string(text);
                        });
                    }
                    if let Some(data) = &self.e_data {
                        s.field(12, |f| {
                            f.octets(data);
                        });
                    }
                });
            });
        })
    }
}

/// `KRB-PRIV` (`[APPLICATION 21]`): the change-password request's and reply's payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KrbPriv {
    /// The encrypted `EncKrbPrivPart`.
    pub enc_part: EncryptedData,
}

impl KrbPriv {
    /// Decodes a whole `KRB-PRIV`. Its `enc-part` is field 3; there is no field 2.
    ///
    /// # Errors
    ///
    /// A [`DerError`] naming `KRB-PRIV`.
    pub fn decode(bytes: &[u8]) -> Result<Self, DerError> {
        let mut r = Reader::new(bytes, "KRB-PRIV");
        let mut s = open_application(&mut r, 21, "KRB-PRIV")?;
        r.finish()?;
        check_vno(s.field(0, "pvno")?.int32()?, "KRB-PRIV", "pvno")?;
        check_msg_type(
            s.field(1, "msg-type")?.int32()?,
            &[msg_type::KRB_PRIV],
            "KRB-PRIV",
        )?;
        let enc_part = s.field(3, "enc-part")?.with(EncryptedData::read)?;
        s.finish()?;
        Ok(Self { enc_part })
    }

    /// The encoding.
    pub fn encode(&self) -> Vec<u8> {
        super::writer::encode(|d| {
            d.application(21, |a| {
                a.sequence(|s| {
                    s.field(0, |f| {
                        f.integer(i64::from(PVNO));
                    });
                    s.field(1, |f| {
                        f.integer(i64::from(msg_type::KRB_PRIV));
                    });
                    s.field(3, |f| self.enc_part.write(f));
                });
            });
        })
    }
}

/// `EncKrbPrivPart` (`[APPLICATION 28]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncKrbPrivPart {
    /// The application data: the `ChangePasswdData` of a request, the result of a reply.
    pub user_data: Zeroizing<Vec<u8>>,
    /// The sender's time.
    pub timestamp: Option<i64>,
    /// Its microseconds.
    pub usec: Option<u32>,
    /// The sender's sequence number.
    pub seq_number: Option<u32>,
    /// The sender's address. RFC 4120 makes it required; it is read as optional because
    /// some change-password servers leave it out of their reply.
    pub s_address: Option<HostAddress>,
    /// The recipient's address.
    pub r_address: Option<HostAddress>,
}

impl EncKrbPrivPart {
    /// Decodes a whole `EncKrbPrivPart`.
    ///
    /// # Errors
    ///
    /// A [`DerError`] naming `EncKrbPrivPart`.
    pub fn decode(bytes: &[u8]) -> Result<Self, DerError> {
        let mut r = Reader::new(bytes, "EncKrbPrivPart");
        let mut s = open_application(&mut r, 28, "EncKrbPrivPart")?;
        r.finish()?;
        let user_data = Zeroizing::new(s.field(0, "user-data")?.octets()?.to_vec());
        let timestamp = s.opt_field(1, "timestamp")?.map(Reader::time).transpose()?;
        let usec = s
            .opt_field(2, "usec")?
            .map(Reader::microseconds)
            .transpose()?;
        let seq_number = s
            .opt_field(3, "seq-number")?
            .map(Reader::uint32_lenient)
            .transpose()?;
        let s_address = s
            .opt_field(4, "s-address")?
            .map(|f| f.with(HostAddress::read))
            .transpose()?;
        let r_address = s
            .opt_field(5, "r-address")?
            .map(|f| f.with(HostAddress::read))
            .transpose()?;
        s.finish()?;
        Ok(Self {
            user_data,
            timestamp,
            usec,
            seq_number,
            s_address,
            r_address,
        })
    }

    /// The encoding (it may hold a password).
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        super::writer::encode_secret(|d| {
            d.application(28, |a| {
                a.sequence(|s| {
                    s.field(0, |f| {
                        f.octets(&self.user_data);
                    });
                    if let Some(time) = self.timestamp {
                        s.field(1, |f| {
                            f.time(time);
                        });
                    }
                    if let Some(usec) = self.usec {
                        s.field(2, |f| {
                            f.uint32(usec);
                        });
                    }
                    if let Some(seq) = self.seq_number {
                        s.field(3, |f| {
                            f.uint32(seq);
                        });
                    }
                    if let Some(address) = &self.s_address {
                        s.field(4, |f| address.write(f));
                    }
                    if let Some(address) = &self.r_address {
                        s.field(5, |f| address.write(f));
                    }
                });
            });
        })
    }
}

/// `ChangePasswdData` (RFC 3244 section 2). The password is zeroed on drop.
#[derive(Clone, PartialEq, Eq)]
pub struct ChangePasswdData {
    /// The new password.
    pub newpasswd: Zeroizing<Vec<u8>>,
    /// The principal whose password is set; absent: the ticket's client.
    pub targname: Option<PrincipalName>,
    /// Its realm.
    pub targrealm: Option<String>,
}

impl std::fmt::Debug for ChangePasswdData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChangePasswdData")
            .field("targname", &self.targname)
            .field("targrealm", &self.targrealm)
            .finish_non_exhaustive()
    }
}

impl ChangePasswdData {
    /// Decodes a whole `ChangePasswdData`.
    ///
    /// # Errors
    ///
    /// A [`DerError`] naming `ChangePasswdData`.
    pub fn decode(bytes: &[u8]) -> Result<Self, DerError> {
        let mut r = Reader::new(bytes, "ChangePasswdData");
        let mut s = r.sequence()?;
        r.finish()?;
        let newpasswd = Zeroizing::new(s.field(0, "newpasswd")?.octets()?.to_vec());
        let targname = s
            .opt_field(1, "targname")?
            .map(|f| f.with(PrincipalName::read))
            .transpose()?;
        let targrealm = s
            .opt_field(2, "targrealm")?
            .map(Reader::string)
            .transpose()?;
        s.finish()?;
        Ok(Self {
            newpasswd,
            targname,
            targrealm,
        })
    }

    /// The encoding (it holds the password).
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        super::writer::encode_secret(|d| {
            d.sequence(|s| {
                s.field(0, |f| {
                    f.octets(&self.newpasswd);
                });
                if let Some(name) = &self.targname {
                    s.field(1, |f| name.write(f));
                }
                if let Some(realm) = &self.targrealm {
                    s.field(2, |f| {
                        f.string(realm);
                    });
                }
            });
        })
    }
}

/// `PA-ENC-TS-ENC`: the plaintext of `PA-ENC-TIMESTAMP`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaEncTsEnc {
    /// The client's time.
    pub patimestamp: i64,
    /// Its microseconds.
    pub pausec: Option<u32>,
}

impl PaEncTsEnc {
    /// Decodes a whole `PA-ENC-TS-ENC`.
    ///
    /// # Errors
    ///
    /// A [`DerError`] naming `PA-ENC-TS-ENC`.
    pub fn decode(bytes: &[u8]) -> Result<Self, DerError> {
        let mut r = Reader::new(bytes, "PA-ENC-TS-ENC");
        let mut s = r.sequence()?;
        r.finish()?;
        let patimestamp = s.field(0, "patimestamp")?.time()?;
        let pausec = s
            .opt_field(1, "pausec")?
            .map(Reader::microseconds)
            .transpose()?;
        s.finish()?;
        Ok(Self {
            patimestamp,
            pausec,
        })
    }

    /// The encoding.
    pub fn encode(&self) -> Vec<u8> {
        super::writer::encode(|d| {
            d.sequence(|s| {
                s.field(0, |f| {
                    f.time(self.patimestamp);
                });
                if let Some(usec) = self.pausec {
                    s.field(1, |f| {
                        f.uint32(usec);
                    });
                }
            });
        })
    }
}

/// One `ETYPE-INFO2-ENTRY`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EtypeInfo2Entry {
    /// The encryption type.
    pub etype: i32,
    /// The salt; absent: the default salt (the realm and the name's components).
    pub salt: Option<String>,
    /// The string-to-key parameters (for AES, the iteration count, four octets).
    pub s2kparams: Option<Vec<u8>>,
}

/// Decodes a `PA-ETYPE-INFO2` value.
///
/// # Errors
///
/// A [`DerError`] naming `ETYPE-INFO2`.
pub fn decode_etype_info2(bytes: &[u8]) -> Result<Vec<EtypeInfo2Entry>, DerError> {
    let entries = Reader::new(bytes, "ETYPE-INFO2").sequence_of(MAX_ETYPE_INFO, |e| {
        let mut s = Reader::new(e.expect(tag::SEQUENCE)?, "ETYPE-INFO2-ENTRY");
        let etype = s.field(0, "etype")?.int32()?;
        let salt = s.opt_field(1, "salt")?.map(Reader::string).transpose()?;
        let s2kparams = s
            .opt_field(2, "s2kparams")?
            .map(|f| f.octets().map(<[u8]>::to_vec))
            .transpose()?;
        s.finish()?;
        Ok(EtypeInfo2Entry {
            etype,
            salt,
            s2kparams,
        })
    })?;
    if entries.is_empty() {
        return Err(DerError::new("ETYPE-INFO2", "-", DerErrorKind::Missing));
    }
    Ok(entries)
}

/// Encodes a `PA-ETYPE-INFO2` value.
pub fn encode_etype_info2(entries: &[EtypeInfo2Entry]) -> Vec<u8> {
    super::writer::encode(|d| {
        d.sequence(|q| {
            for entry in entries {
                q.sequence(|s| {
                    s.field(0, |f| {
                        f.integer(i64::from(entry.etype));
                    });
                    if let Some(salt) = &entry.salt {
                        s.field(1, |f| {
                            f.string(salt);
                        });
                    }
                    if let Some(params) = &entry.s2kparams {
                        s.field(2, |f| {
                            f.octets(params);
                        });
                    }
                });
            }
        });
    })
}

/// Encodes the PAC request of [MS-KILE] section 2.2.3 (the value of `PA-PAC-REQUEST`).
pub fn encode_pac_request(include_pac: bool) -> Vec<u8> {
    super::writer::encode(|d| {
        d.sequence(|s| {
            s.field(0, |f| {
                f.boolean(include_pac);
            });
        });
    })
}
