//! Errors of the IPAM domain with their stable codes (API-08).
//!
//! [`IpamError`] is a [`CodedError`] built from the constants in [`codes`]; handlers turn it
//! into problem details with `?`. The codes are stable once merged.

use std::{borrow::Cow, collections::BTreeMap, fmt};

use tenko_core::{Coded, CodedError, FieldError, ObjectRef, Revision};
use tenko_jobs::JobError;
use tenko_store::StoreError;

/// Stable error and warning codes of the `ipam` namespace.
pub mod codes {
    /// The object does not exist (404). Params: `kind`, `id`.
    pub const NOT_FOUND: &str = "ipam.not_found";
    /// `If-Match` or the expected revision does not match (412). Params: `kind`, `id`,
    /// `expected`, `actual`.
    pub const REVISION_MISMATCH: &str = "ipam.revision_mismatch";
    /// The object is soft-deleted; restore it first (409). Params: `kind`, `id`.
    pub const OBJECT_DELETED: &str = "ipam.object_deleted";
    /// Restore of an object that is not deleted (409). Params: `kind`, `id`.
    pub const NOT_DELETED: &str = "ipam.not_deleted";
    /// A client-chosen identifier is already used (409). Params: `kind`, `id`.
    pub const ID_TAKEN: &str = "ipam.id_taken";
    /// The name is already used in its scope (409). Params: `kind`, `name`.
    pub const NAME_TAKEN: &str = "ipam.name_taken";
    /// The request has invalid fields (400); see the field errors.
    pub const VALIDATION: &str = "ipam.validation";
    /// A field cannot change after creation (400). Params: `field`.
    pub const IMMUTABLE: &str = "ipam.immutable";
    /// A referenced object is missing or deleted (409). Params: `kind`, `id`, `field`.
    pub const REFERENCE_MISSING: &str = "ipam.reference_missing";
    /// The object is still referenced (409). Params: `kind`, `id`, `by`, `count`.
    pub const IN_USE: &str = "ipam.in_use";
    /// Two prefixes overlap inside one VRF (409, IPAM-23). Params: `cidr`, `existing`.
    pub const PREFIX_OVERLAP: &str = "ipam.prefix.overlap";
    /// The network has host bits set (400). Params: `cidr`, `network`.
    pub const PREFIX_HOST_BITS: &str = "ipam.prefix.host_bits";
    /// A supernet with child prefixes cannot become a network (409). Params: `cidr`.
    pub const PREFIX_HAS_CHILDREN: &str = "ipam.prefix.has_children";
    /// A network with ranges cannot become a supernet (409). Params: `cidr`.
    pub const PREFIX_HAS_RANGES: &str = "ipam.prefix.has_ranges";
    /// A resized prefix would leave children, addresses or ranges outside (409).
    pub const PREFIX_RESIZE_ORPHANS: &str = "ipam.prefix.resize_orphans";
    /// A new prefix would cut through a range of its parent (409). Params: `range`.
    pub const PREFIX_OVERLAPS_RANGE: &str = "ipam.prefix.overlaps_range";
    /// No free prefix of the requested length (409). Params: `cidr`, `length`.
    pub const PREFIX_FULL: &str = "ipam.prefix.full";
    /// Two ranges of one prefix overlap (409, IPAM-23). Params: `range`, `existing`.
    pub const RANGE_OVERLAP: &str = "ipam.range.overlap";
    /// A range lies outside its prefix (409). Params: `cidr`.
    pub const RANGE_OUTSIDE_PREFIX: &str = "ipam.range.outside_prefix";
    /// Ranges belong to network prefixes only (409). Params: `cidr`.
    pub const RANGE_NOT_IN_NETWORK: &str = "ipam.range.not_in_network";
    /// A DHCP pool would cover the address of a `reserved` host (409, IPAM-23).
    /// Params: `ip`, `host`.
    pub const RANGE_COVERS_RESERVATION: &str = "ipam.range.covers_reservation";
    /// The address exists in the VRF already (409, IPAM-23). Params: `ip`.
    pub const ADDRESS_DUPLICATE: &str = "ipam.address.duplicate";
    /// No prefix in the VRF contains the address (409). Params: `ip`.
    pub const ADDRESS_NO_PREFIX: &str = "ipam.address.no_prefix";
    /// The network or broadcast address of an IPv4 network (409). Params: `ip`, `cidr`.
    pub const ADDRESS_NETWORK_OR_BROADCAST: &str = "ipam.address.network_or_broadcast";
    /// The address of a `reserved` host lies in a DHCP pool (409, IPAM-23); a warning for
    /// other addresses. Params: `ip`, `range`.
    pub const ADDRESS_IN_DHCP_POOL: &str = "ipam.address.in_dhcp_pool";
    /// No free address in the prefix or range (409). Params: `cidr`.
    pub const ADDRESS_FULL: &str = "ipam.address.full";
    /// The VLAN id exists at the site already (409). Params: `vid`.
    pub const VLAN_DUPLICATE: &str = "ipam.vlan.duplicate";
    /// A site cannot be its own ancestor (409).
    pub const SITE_CYCLE: &str = "ipam.site.cycle";
    /// The status change is not allowed (409, IPAM-05). Params: `from`, `to`.
    pub const STATUS_TRANSITION: &str = "ipam.status.transition";
    /// The host is locked against automation (423, IPAM-16). Params: `host`.
    pub const HOST_LOCKED: &str = "ipam.host.locked";
    /// Only people lock and unlock hosts (403, IPAM-16).
    pub const HOST_LOCK_MANUAL_ONLY: &str = "ipam.host.lock_manual_only";
    /// The plan has warnings that need an acknowledgement (409). Params: `codes`.
    pub const PLAN_UNACKNOWLEDGED: &str = "ipam.plan.unacknowledged";
    /// The store changed since the plan was made (409); preview again.
    pub const PLAN_STALE: &str = "ipam.plan.stale";
    /// Concurrent writers kept invalidating the plan (503); try again.
    pub const CONTENDED: &str = "ipam.contended";
    /// The idempotency key was used for a different request (422).
    pub const IDEMPOTENCY_MISMATCH: &str = "ipam.idempotency_mismatch";
    /// The bulk request is too large (413). Params: `count`, `limit`.
    pub const BULK_TOO_LARGE: &str = "ipam.bulk.too_large";
    /// A bulk operation targets another collection (400). Params: `index`, `expected`.
    pub const BULK_WRONG_COLLECTION: &str = "ipam.bulk.wrong_collection";
    /// A list cursor is malformed (400).
    pub const INVALID_CURSOR: &str = "ipam.invalid_cursor";
    /// A list filter or sort key is malformed or unknown (400). Params: `name`.
    pub const INVALID_FILTER: &str = "ipam.invalid_filter";
    /// The inline job failed for a reason other than the store (500).
    pub const JOB_FAILED: &str = "ipam.job.failed";
    /// The IPAM service is not configured in this server (503).
    pub const UNAVAILABLE: &str = "ipam.unavailable";

    /// Warning (needs acknowledgement): an IPv6 prefix off a nibble boundary (IPAM-06).
    pub const WARN_NIBBLE: &str = "ipam.prefix.nibble_boundary";
    /// Warning: a `reserved` host without MAC (IPv4) or DUID (IPv6) (IPAM-18).
    pub const WARN_RESERVATION_IDENTIFIER: &str = "ipam.host.reservation_identifier";
    /// Warning: an address directly in a supernet.
    pub const WARN_ADDRESS_IN_SUPERNET: &str = "ipam.address.in_supernet";
    /// Warning: an active object inside a deprecated or planned parent.
    pub const WARN_PARENT_STATUS: &str = "ipam.parent_status";
    /// Warning: two live interfaces share a MAC address.
    pub const WARN_DUPLICATE_MAC: &str = "ipam.interface.duplicate_mac";
    /// Warning: the address lies inside a reserved or infrastructure range.
    pub const WARN_ADDRESS_IN_RANGE: &str = "ipam.address.in_range";
}

/// An error of the IPAM domain: a stable code, an HTTP status, parameters and field
/// errors.
#[derive(Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", .0.detail)]
pub struct IpamError(Box<CodedError>);

impl fmt::Debug for IpamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IpamError({}: {})", self.0.code, self.0.detail)
    }
}

impl IpamError {
    /// Creates an error.
    pub fn new(code: &'static str, status: u16, detail: impl Into<String>) -> Self {
        Self(Box::new(CodedError::new(code, status, detail)))
    }

    /// Wraps a captured coded error.
    pub fn from_coded_error(error: CodedError) -> Self {
        Self(Box::new(error))
    }

    /// Adds a parameter.
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn param(mut self, key: &str, value: impl ToString) -> Self {
        self.0.params.insert(key.to_owned(), value.to_string());
        self
    }

    /// Adds a field error.
    #[must_use]
    pub fn field(mut self, field: impl Into<String>, code: &'static str) -> Self {
        self.0.errors.push(FieldError::new(field, code));
        self
    }

    /// Replaces the title.
    #[must_use]
    pub fn titled(mut self, title: &'static str) -> Self {
        self.0.title = Cow::Borrowed(title);
        self
    }

    /// The code.
    pub fn code_str(&self) -> &str {
        &self.0.code
    }

    /// Whether the error has `code`.
    pub fn is(&self, code: &str) -> bool {
        self.0.code == code
    }

    /// The captured error.
    pub fn coded(&self) -> &CodedError {
        &self.0
    }

    /// Unwraps the captured error.
    pub fn into_coded(self) -> CodedError {
        *self.0
    }

    /// `ipam.not_found`.
    pub fn not_found(object: ObjectRef) -> Self {
        Self::new(codes::NOT_FOUND, 404, format!("{object} does not exist"))
            .titled("Object not found")
            .param("kind", object.kind)
            .param("id", object.id)
    }

    /// `ipam.revision_mismatch`.
    pub fn revision_mismatch(object: ObjectRef, expected: Revision, actual: Revision) -> Self {
        Self::new(
            codes::REVISION_MISMATCH,
            412,
            format!("{object} is at revision {actual}, not {expected}"),
        )
        .titled("The object changed since it was read")
        .param("kind", object.kind)
        .param("id", object.id)
        .param("expected", expected)
        .param("actual", actual)
    }

    /// `ipam.object_deleted`.
    pub fn deleted(object: ObjectRef) -> Self {
        Self::new(
            codes::OBJECT_DELETED,
            409,
            format!("{object} is deleted; restore it first"),
        )
        .titled("The object is deleted")
        .param("kind", object.kind)
        .param("id", object.id)
    }

    /// `ipam.reference_missing`.
    pub fn reference_missing(field: &str, object: ObjectRef) -> Self {
        Self::new(
            codes::REFERENCE_MISSING,
            409,
            format!("{field} refers to {object}, which does not exist or is deleted"),
        )
        .titled("A referenced object is missing")
        .param("kind", object.kind)
        .param("id", object.id)
        .param("field", field)
        .field(field, codes::REFERENCE_MISSING)
    }

    /// `ipam.validation` for one field.
    pub fn invalid(field: &str, detail: impl Into<String>) -> Self {
        Self::new(codes::VALIDATION, 400, detail)
            .titled("Invalid request")
            .param("field", field)
            .field(field, codes::VALIDATION)
    }

    /// `ipam.in_use`.
    pub fn in_use(object: ObjectRef, by: &str, count: usize) -> Self {
        Self::new(
            codes::IN_USE,
            409,
            format!("{object} is still used by {count} {by}"),
        )
        .titled("The object is still in use")
        .param("kind", object.kind)
        .param("id", object.id)
        .param("by", by)
        .param("count", count)
    }

    /// `ipam.contended`.
    pub fn contended(attempts: u32) -> Self {
        Self::new(
            codes::CONTENDED,
            503,
            format!("concurrent changes invalidated the plan {attempts} times; try again"),
        )
        .titled("Too many concurrent changes")
        .param("attempts", attempts)
    }

    /// `ipam.plan.stale`.
    pub fn stale() -> Self {
        Self::new(
            codes::PLAN_STALE,
            409,
            "the data changed since the plan was made; preview again",
        )
        .titled("The plan is out of date")
    }
}

impl Coded for IpamError {
    fn code(&self) -> &'static str {
        match &self.0.code {
            Cow::Borrowed(code) => code,
            Cow::Owned(_) => codes::JOB_FAILED,
        }
    }

    fn http_status(&self) -> u16 {
        self.0.status
    }

    fn params(&self) -> BTreeMap<&'static str, String> {
        // Parameter names are owned strings here; `to_coded_error` below carries them.
        BTreeMap::new()
    }

    fn title(&self) -> &'static str {
        match &self.0.title {
            Cow::Borrowed(title) => title,
            Cow::Owned(_) => tenko_core::error::status_title(self.0.status),
        }
    }

    fn field_errors(&self) -> Vec<FieldError> {
        self.0.errors.clone()
    }

    fn to_coded_error(&self) -> CodedError {
        (*self.0).clone()
    }
}

impl From<StoreError> for IpamError {
    fn from(error: StoreError) -> Self {
        Self(Box::new(error.to_coded_error()))
    }
}

impl From<tenko_core::codec::CodecError> for IpamError {
    fn from(error: tenko_core::codec::CodecError) -> Self {
        Self(Box::new(error.to_coded_error()))
    }
}

impl From<tenko_core::codec::KeyError> for IpamError {
    fn from(error: tenko_core::codec::KeyError) -> Self {
        Self(Box::new(error.to_coded_error()))
    }
}

impl From<tenko_core::InvalidValue> for IpamError {
    fn from(error: tenko_core::InvalidValue) -> Self {
        Self(Box::new(error.to_coded_error()))
    }
}

impl From<JobError> for IpamError {
    fn from(error: JobError) -> Self {
        Self(Box::new(error.to_coded_error()))
    }
}

/// Result alias of the IPAM domain.
pub type IpamResult<T> = Result<T, IpamError>;

#[cfg(test)]
mod tests {
    use tenko_core::{ObjectKind, PrefixId};

    use super::*;

    #[test]
    fn errors_keep_code_status_and_params() {
        let id = PrefixId::generate();
        let error = IpamError::not_found(id.into());
        assert_eq!(error.code(), codes::NOT_FOUND);
        assert_eq!(error.http_status(), 404);
        let coded = error.to_coded_error();
        assert_eq!(coded.params["kind"], ObjectKind::Prefix.as_str());
        assert_eq!(coded.params["id"], id.to_string());
        let store: IpamError = StoreError::Timeout.into();
        assert_eq!(store.code(), "sys.store.timeout");
        assert_eq!(store.http_status(), 503);
    }
}
