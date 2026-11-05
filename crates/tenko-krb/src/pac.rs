//! The PAC reader ([MS-PAC]): the privilege attribute certificate an Active Directory KDC
//! puts in every ticket, inside `AD-IF-RELEVANT` as `AD-WIN2K-PAC` (identity plan section
//! 2.1 step 5, section 3.6; DNS-28).
//!
//! What is read:
//!
//! - **The buffers** (`PACTYPE`, section 2.3): at most [`MAX_BUFFERS`], each 8-aligned
//!   and inside the PAC, the logon information, the client information and the two
//!   signatures at most once.
//! - **The server signature** (`PAC_SERVER_CHECKSUM`, section 2.8.1): `hmac-sha1-96-aes`
//!   of the service key's type under usage 17, over the PAC with the data of the server
//!   and KDC signatures zeroed (as MIT's `verify_pac_checksums` does). It is required:
//!   only the KDC and a holder of the service key can make it.
//! - **The KDC signature is left unchecked** (and so are the ticket and full signatures of
//!   sections 2.8.3 and 2.8.5): they are made with the `krbtgt` key, which Tenko does not
//!   hold, and need not be checked, since only the KDC and a holder of the service key can
//!   make a ticket the acceptor decrypts.
//! - **The client information** (`PAC_CLIENT_INFO`, section 2.7): its time must be the
//!   ticket's `authtime` and its name the ticket's client name (ASCII case aside), as MIT
//!   checks it.
//! - **The logon information** (section 2.5, NDR of [MS-RPCE]): the
//!   user's SID, the primary group, the domain groups, the extra SIDs and the resource
//!   groups. Every count is bounded and checked against the octets left before anything
//!   is allocated. MIT's KDC writes a PAC without it; such a PAC has no SIDs.

use tenko_core::dns::Sid;

use crate::cipher::{self, CipherError, Key, usage};

/// The most buffers a PAC may have.
pub const MAX_BUFFERS: usize = 64;
/// The most group or SID entries in one list of the logon information.
pub const MAX_SIDS: usize = 4096;

/// `PAC_INFO_BUFFER` types (section 2.4).
pub mod buffer_type {
    /// The logon information.
    pub const LOGON_INFO: u32 = 1;
    /// The server signature.
    pub const SERVER_CHECKSUM: u32 = 6;
    /// The KDC signature.
    pub const PRIVSVR_CHECKSUM: u32 = 7;
    /// `PAC_CLIENT_INFO`.
    pub const CLIENT_INFO: u32 = 10;
    /// The ticket signature.
    pub const TICKET_CHECKSUM: u32 = 16;
    /// The extended KDC (full) signature.
    pub const FULL_CHECKSUM: u32 = 19;
}

/// `UserFlags` bit: the resource groups are valid (section 2.5, `D`).
pub const LOGON_RESOURCE_GROUPS: u32 = 0x200;

/// Why a PAC was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PacError {
    /// The header, a buffer or an NDR structure is malformed; the field is named.
    #[error("malformed PAC: {0}")]
    Malformed(&'static str),
    /// A required buffer is missing or a single one appears twice.
    #[error("PAC buffer {0} is missing or repeated")]
    Buffer(u32),
    /// The server signature does not verify with the service key, or has another type.
    #[error("the PAC's server signature does not verify: {0}")]
    Signature(CipherError),
    /// The client information does not match the ticket.
    #[error("the PAC's client information does not match the ticket")]
    ClientMismatch,
}

/// One buffer of the PAC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BufferInfo {
    kind: u32,
    offset: usize,
    size: usize,
}

/// The SIDs of the logon information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogonInfo {
    /// The account's name (`EffectiveName`).
    pub effective_name: String,
    /// The `NetBIOS` name of the account's domain.
    pub logon_domain_name: String,
    /// The domain's SID.
    pub logon_domain_sid: Sid,
    /// The user's SID: the domain's SID and `UserId`.
    pub user_sid: Sid,
    /// The primary group's SID.
    pub primary_group_sid: Sid,
    /// The domain groups' SIDs.
    pub group_sids: Vec<Sid>,
    /// The extra SIDs (universal groups of other domains, claims, the asserted identity).
    pub extra_sids: Vec<Sid>,
    /// The resource groups of the server's domain, when `UserFlags` says they are valid.
    pub resource_group_sids: Vec<Sid>,
    /// `UserFlags`.
    pub user_flags: u32,
}

impl LogonInfo {
    /// Every group SID once: the primary group, the domain groups, the extra SIDs and the
    /// resource groups, in that order (the user's own SID is [`LogonInfo::user_sid`]).
    pub fn groups(&self) -> Vec<Sid> {
        let mut out: Vec<Sid> = Vec::new();
        let all = std::iter::once(&self.primary_group_sid)
            .chain(&self.group_sids)
            .chain(&self.extra_sids)
            .chain(&self.resource_group_sids);
        for sid in all {
            if !out.contains(sid) {
                out.push(sid.clone());
            }
        }
        out
    }
}

/// A PAC whose server signature verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pac {
    /// The client's name in the client information.
    pub client_name: String,
    /// The client information's time (the ticket's `authtime`), Unix seconds.
    pub client_authtime: i64,
    /// The logon information; absent in a PAC from an MIT KDC.
    pub logon: Option<LogonInfo>,
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    let slice: [u8; 4] = bytes.get(at..at.checked_add(4)?)?.try_into().ok()?;
    Some(u32::from_le_bytes(slice))
}

fn u64_at(bytes: &[u8], at: usize) -> Option<u64> {
    let slice: [u8; 8] = bytes.get(at..at.checked_add(8)?)?.try_into().ok()?;
    Some(u64::from_le_bytes(slice))
}

fn buffers(pac: &[u8]) -> Result<Vec<BufferInfo>, PacError> {
    let count = u32_at(pac, 0).ok_or(PacError::Malformed("cBuffers"))?;
    let version = u32_at(pac, 4).ok_or(PacError::Malformed("Version"))?;
    if version != 0 {
        return Err(PacError::Malformed("Version"));
    }
    let count = usize::try_from(count).map_err(|_| PacError::Malformed("cBuffers"))?;
    if count == 0 || count > MAX_BUFFERS {
        return Err(PacError::Malformed("cBuffers"));
    }
    let header_len = 8 + count * 16;
    if pac.len() < header_len {
        return Err(PacError::Malformed("Buffers"));
    }
    let mut out = Vec::with_capacity(count);
    for index in 0..count {
        let at = 8 + index * 16;
        let kind = u32_at(pac, at).ok_or(PacError::Malformed("ulType"))?;
        let size = u32_at(pac, at + 4).ok_or(PacError::Malformed("cbBufferSize"))?;
        let offset = u64_at(pac, at + 8).ok_or(PacError::Malformed("Offset"))?;
        let size = usize::try_from(size).map_err(|_| PacError::Malformed("cbBufferSize"))?;
        let offset = usize::try_from(offset).map_err(|_| PacError::Malformed("Offset"))?;
        if offset % 8 != 0 || offset < header_len || offset > pac.len() || size > pac.len() - offset
        {
            return Err(PacError::Malformed("Offset"));
        }
        let single = matches!(
            kind,
            buffer_type::LOGON_INFO
                | buffer_type::SERVER_CHECKSUM
                | buffer_type::PRIVSVR_CHECKSUM
                | buffer_type::CLIENT_INFO
        );
        if single && out.iter().any(|b: &BufferInfo| b.kind == kind) {
            return Err(PacError::Buffer(kind));
        }
        out.push(BufferInfo { kind, offset, size });
    }
    Ok(out)
}

fn find(buffers: &[BufferInfo], kind: u32) -> Option<BufferInfo> {
    buffers.iter().copied().find(|b| b.kind == kind)
}

fn slice(pac: &[u8], buffer: BufferInfo) -> &[u8] {
    &pac[buffer.offset..buffer.offset + buffer.size]
}

/// Verifies the server signature with the service key that decrypted the ticket.
fn verify_server_signature(pac: &[u8], buffers: &[BufferInfo], key: &Key) -> Result<(), PacError> {
    let server = find(buffers, buffer_type::SERVER_CHECKSUM)
        .ok_or(PacError::Buffer(buffer_type::SERVER_CHECKSUM))?;
    let kdc = find(buffers, buffer_type::PRIVSVR_CHECKSUM)
        .ok_or(PacError::Buffer(buffer_type::PRIVSVR_CHECKSUM))?;
    let data = slice(pac, server);
    let cksumtype = data
        .get(..4)
        .map(|b| i32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or(PacError::Malformed("SignatureType"))?;
    let signature = data
        .get(4..4 + cipher::HMAC_LEN)
        .ok_or(PacError::Malformed("Signature"))?;
    let mut copy = pac.to_vec();
    for buffer in [server, kdc] {
        if buffer.size < 4 {
            return Err(PacError::Malformed("Signature"));
        }
        copy[buffer.offset + 4..buffer.offset + buffer.size].fill(0);
    }
    cipher::verify_checksum(key, usage::PAC_CHECKSUM, cksumtype, &copy, signature)
        .map_err(PacError::Signature)
}

/// FILETIME (100 ns since 1601) as Unix seconds.
fn filetime_to_unix(filetime: u64) -> i64 {
    i64::try_from(filetime / 10_000_000).unwrap_or(i64::MAX) - 11_644_473_600
}

fn utf16(bytes: &[u8]) -> Result<String, PacError> {
    if !bytes.len().is_multiple_of(2) {
        return Err(PacError::Malformed("UTF-16 string"));
    }
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect();
    String::from_utf16(&units).map_err(|_| PacError::Malformed("UTF-16 string"))
}

fn client_info(data: &[u8]) -> Result<(i64, String), PacError> {
    let time = u64_at(data, 0).ok_or(PacError::Malformed("ClientId"))?;
    let len = data.get(8..10).ok_or(PacError::Malformed("NameLength"))?;
    let len = usize::from(u16::from_le_bytes([len[0], len[1]]));
    let name = data.get(10..10 + len).ok_or(PacError::Malformed("Name"))?;
    Ok((filetime_to_unix(time), utf16(name)?))
}

/// Reads the PAC of a ticket, verifies its server signature with the service key and
/// checks its client information against the ticket's client name and `authtime`.
///
/// # Errors
///
/// A [`PacError`].
pub fn verify(
    pac: &[u8],
    service_key: &Key,
    client_name: &str,
    authtime: i64,
) -> Result<Pac, PacError> {
    let buffers = buffers(pac)?;
    verify_server_signature(pac, &buffers, service_key)?;
    let client = find(&buffers, buffer_type::CLIENT_INFO)
        .ok_or(PacError::Buffer(buffer_type::CLIENT_INFO))?;
    let (client_authtime, name) = client_info(slice(pac, client))?;
    if client_authtime != authtime || !name.eq_ignore_ascii_case(client_name) {
        return Err(PacError::ClientMismatch);
    }
    let logon = find(&buffers, buffer_type::LOGON_INFO)
        .map(|b| logon_info(slice(pac, b)))
        .transpose()?;
    Ok(Pac {
        client_name: name,
        client_authtime,
        logon,
    })
}

/// Reads the buffers and the logon information without checking any signature: for the
/// fuzz target and for tests.
///
/// # Errors
///
/// A [`PacError`].
pub fn read_unverified(pac: &[u8]) -> Result<Option<LogonInfo>, PacError> {
    let buffers = buffers(pac)?;
    if let Some(client) = find(&buffers, buffer_type::CLIENT_INFO) {
        client_info(slice(pac, client))?;
    }
    find(&buffers, buffer_type::LOGON_INFO)
        .map(|b| logon_info(slice(pac, b)))
        .transpose()
}

// ---------------------------------------------------------------------------------------
// NDR of the logon information ([MS-RPCE] section 2.2.6, type serialization version 1)

/// A little-endian NDR reader; alignment is relative to the start of the buffer, which
/// the PAC aligns to 8.
struct Ndr<'a> {
    data: &'a [u8],
    pos: usize,
}

/// An `RPC_UNICODE_STRING` header: the length in octets and whether its buffer follows.
#[derive(Clone, Copy)]
struct UnicodeString {
    length: usize,
    present: bool,
}

impl<'a> Ndr<'a> {
    fn align(&mut self, to: usize, field: &'static str) -> Result<(), PacError> {
        let aligned = self.pos.div_ceil(to) * to;
        if aligned > self.data.len() {
            return Err(PacError::Malformed(field));
        }
        self.pos = aligned;
        Ok(())
    }

    fn take(&mut self, len: usize, field: &'static str) -> Result<&'a [u8], PacError> {
        let end = self
            .pos
            .checked_add(len)
            .filter(|end| *end <= self.data.len())
            .ok_or(PacError::Malformed(field))?;
        let out = &self.data[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn u8(&mut self, field: &'static str) -> Result<u8, PacError> {
        Ok(self.take(1, field)?[0])
    }

    fn u16(&mut self, field: &'static str) -> Result<u16, PacError> {
        self.align(2, field)?;
        let b = self.take(2, field)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn u32(&mut self, field: &'static str) -> Result<u32, PacError> {
        self.align(4, field)?;
        let b = self.take(4, field)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn count(&mut self, field: &'static str) -> Result<usize, PacError> {
        usize::try_from(self.u32(field)?).map_err(|_| PacError::Malformed(field))
    }

    fn pointer(&mut self, field: &'static str) -> Result<bool, PacError> {
        Ok(self.u32(field)? != 0)
    }

    fn skip(&mut self, len: usize, field: &'static str) -> Result<(), PacError> {
        self.take(len, field).map(|_| ())
    }

    fn unicode_string(&mut self, field: &'static str) -> Result<UnicodeString, PacError> {
        let length = usize::from(self.u16(field)?);
        let maximum = usize::from(self.u16(field)?);
        let present = self.pointer(field)?;
        if length > maximum || length % 2 != 0 {
            return Err(PacError::Malformed(field));
        }
        Ok(UnicodeString { length, present })
    }

    /// The deferred buffer of an `RPC_UNICODE_STRING`: a conformant varying array of
    /// UTF-16 code units.
    fn deferred_string(
        &mut self,
        header: UnicodeString,
        field: &'static str,
    ) -> Result<String, PacError> {
        if !header.present {
            return Ok(String::new());
        }
        let max = self.count(field)?;
        let offset = self.count(field)?;
        let actual = self.count(field)?;
        if offset != 0 || actual > max || actual * 2 != header.length {
            return Err(PacError::Malformed(field));
        }
        let bytes = self.take(actual * 2, field)?;
        utf16(bytes)
    }

    /// A conformant array of `GROUP_MEMBERSHIP` (`RelativeId`, `Attributes`) whose count
    /// must be `count`.
    fn rids(&mut self, count: usize, field: &'static str) -> Result<Vec<u32>, PacError> {
        let max = self.count(field)?;
        if max != count || count > MAX_SIDS || count * 8 > self.data.len() - self.pos {
            return Err(PacError::Malformed(field));
        }
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            out.push(self.u32(field)?);
            self.u32(field)?;
        }
        Ok(out)
    }

    /// An `RPC_SID`: the conformance (the sub-authority count), the revision, the count,
    /// the six-octet authority and the sub-authorities.
    fn sid(&mut self, field: &'static str) -> Result<Sid, PacError> {
        let max = self.count(field)?;
        let revision = self.u8(field)?;
        let count = usize::from(self.u8(field)?);
        if revision != 1 || count != max || count > 15 {
            return Err(PacError::Malformed(field));
        }
        let authority = self.take(6, field)?;
        let mut octets = [0_u8; 8];
        octets[2..].copy_from_slice(authority);
        let mut subs = Vec::with_capacity(count);
        for _ in 0..count {
            subs.push(self.u32(field)?);
        }
        Sid::new(u64::from_be_bytes(octets), subs).map_err(|_| PacError::Malformed(field))
    }
}

fn with_rid(domain: &Sid, rid: u32, field: &'static str) -> Result<Sid, PacError> {
    let mut subs = domain.sub_authorities().to_vec();
    subs.push(rid);
    Sid::new(domain.authority(), subs).map_err(|_| PacError::Malformed(field))
}

#[allow(clippy::too_many_lines)]
fn logon_info(data: &[u8]) -> Result<LogonInfo, PacError> {
    let mut r = Ndr { data, pos: 0 };
    // The common and private headers of type serialization version 1.
    let version = r.u8("CommonHeader")?;
    let endianness = r.u8("CommonHeader")?;
    let header_len = r.u16("CommonHeader")?;
    r.u32("CommonHeader")?;
    if version != 1 || endianness != 0x10 || header_len != 8 {
        return Err(PacError::Malformed("CommonHeader"));
    }
    let object_len = r.count("PrivateHeader")?;
    r.u32("PrivateHeader")?;
    if object_len > data.len() - r.pos {
        return Err(PacError::Malformed("PrivateHeader"));
    }
    if !r.pointer("LogonInfo")? {
        return Err(PacError::Malformed("LogonInfo"));
    }
    // The fixed part of the logon information.
    r.skip(6 * 8, "logon times")?;
    let effective_name = r.unicode_string("EffectiveName")?;
    let mut strings = Vec::new();
    for field in [
        "FullName",
        "LogonScript",
        "ProfilePath",
        "HomeDirectory",
        "HomeDirectoryDrive",
    ] {
        strings.push((field, r.unicode_string(field)?));
    }
    r.u16("LogonCount")?;
    r.u16("BadPasswordCount")?;
    let user_id = r.u32("UserId")?;
    let primary_group_id = r.u32("PrimaryGroupId")?;
    let group_count = r.count("GroupCount")?;
    let groups_present = r.pointer("GroupIds")?;
    let user_flags = r.u32("UserFlags")?;
    r.skip(16, "UserSessionKey")?;
    let logon_server = r.unicode_string("LogonServer")?;
    let logon_domain_name = r.unicode_string("LogonDomainName")?;
    let domain_sid_present = r.pointer("LogonDomainId")?;
    r.skip(8, "Reserved1")?;
    r.u32("UserAccountControl")?;
    r.u32("SubAuthStatus")?;
    r.skip(16, "logon attempt times")?;
    r.u32("FailedILogonCount")?;
    r.u32("Reserved3")?;
    let sid_count = r.count("SidCount")?;
    let extra_present = r.pointer("ExtraSids")?;
    let resource_domain_present = r.pointer("ResourceGroupDomainSid")?;
    let resource_count = r.count("ResourceGroupCount")?;
    let resource_present = r.pointer("ResourceGroupIds")?;
    if (group_count > 0 && !groups_present) || (sid_count > 0 && !extra_present) {
        return Err(PacError::Malformed("GroupCount"));
    }
    // The deferred pointers, in the order of their fields.
    let effective_name = r.deferred_string(effective_name, "EffectiveName")?;
    for (field, header) in strings {
        r.deferred_string(header, field)?;
    }
    let group_rids = if groups_present {
        r.rids(group_count, "GroupIds")?
    } else {
        Vec::new()
    };
    r.deferred_string(logon_server, "LogonServer")?;
    let logon_domain_name = r.deferred_string(logon_domain_name, "LogonDomainName")?;
    if !domain_sid_present {
        return Err(PacError::Malformed("LogonDomainId"));
    }
    let logon_domain_sid = r.sid("LogonDomainId")?;
    let mut extra_sids = Vec::new();
    if extra_present {
        let max = r.count("ExtraSids")?;
        if max != sid_count || sid_count > MAX_SIDS || sid_count * 8 > data.len() - r.pos {
            return Err(PacError::Malformed("ExtraSids"));
        }
        let mut present = Vec::with_capacity(sid_count);
        for _ in 0..sid_count {
            present.push(r.pointer("ExtraSids")?);
            r.u32("ExtraSids")?;
        }
        for has_sid in present {
            if has_sid {
                extra_sids.push(r.sid("ExtraSids")?);
            }
        }
    }
    let resource_domain = if resource_domain_present {
        Some(r.sid("ResourceGroupDomainSid")?)
    } else {
        None
    };
    let resource_rids = if resource_present {
        r.rids(resource_count, "ResourceGroupIds")?
    } else {
        Vec::new()
    };
    let resource_group_sids = match resource_domain {
        Some(domain) if user_flags & LOGON_RESOURCE_GROUPS != 0 => resource_rids
            .iter()
            .map(|rid| with_rid(&domain, *rid, "ResourceGroupIds"))
            .collect::<Result<_, _>>()?,
        _ => Vec::new(),
    };
    Ok(LogonInfo {
        effective_name,
        logon_domain_name,
        user_sid: with_rid(&logon_domain_sid, user_id, "UserId")?,
        primary_group_sid: with_rid(&logon_domain_sid, primary_group_id, "PrimaryGroupId")?,
        group_sids: group_rids
            .iter()
            .map(|rid| with_rid(&logon_domain_sid, *rid, "GroupIds"))
            .collect::<Result<_, _>>()?,
        extra_sids,
        resource_group_sids,
        user_flags,
        logon_domain_sid,
    })
}

#[cfg(test)]
pub(crate) mod tests;
