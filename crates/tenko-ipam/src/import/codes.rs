//! Stable codes of the import: loss report entries (`import.*` with a severity) and the
//! problem codes of the import endpoints.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// How serious a loss report entry is.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Something to know; nothing was lost.
    Info,
    /// Imported, but differently than written, or possibly wrong.
    Warning,
    /// Not imported.
    Error,
}

// ----- loss report entries ---------------------------------------------------------------

/// A value in an address column is not an address, a network or a range; the row is not
/// imported.
pub const ADDRESS_UNPARSABLE: &str = "import.address.unparsable";
/// A column without a target (an unlabeled column, or one mapped to `ignore`) holds
/// values; they are not imported.
pub const COLUMN_UNMAPPED: &str = "import.column.unmapped";
/// A login looks like a description (it contains spaces); it is stored as a login anyway.
pub const CREDENTIAL_SUSPICIOUS: &str = "import.credential.suspicious";
/// A host address is the network address of its network; the host is imported without it.
pub const ADDRESS_IS_NETWORK: &str = "import.address.is_network";
/// A host address is the broadcast address of its network; the host is imported without
/// it.
pub const ADDRESS_IS_BROADCAST: &str = "import.address.is_broadcast";
/// A password is a number: a spreadsheet may have dropped its leading zeros.
pub const CREDENTIAL_NUMERIC: &str = "import.credential.numeric";
/// A sheet is named after a network that the `Index` sheet does not list; the mask was
/// inferred.
pub const PREFIX_UNLISTED: &str = "import.prefix.unlisted";
/// A sheet holds no values.
pub const SHEET_EMPTY: &str = "import.sheet.empty";
/// A sheet has no column the import understands; nothing of it is imported.
pub const SHEET_SKIPPED: &str = "import.sheet.skipped";
/// A label is not a valid host name; the host gets a normalized name and keeps the label
/// as its description.
pub const NAME_NORMALIZED: &str = "import.name.normalized";
/// A label cannot be turned into a host name; the row is not imported.
pub const NAME_INVALID: &str = "import.name.invalid";
/// A device row has addresses but no name; the row is not imported.
pub const NAME_MISSING: &str = "import.name.missing";
/// Addresses lie outside every known network: the import proposes a prefix for them.
pub const PREFIX_PROPOSED: &str = "import.prefix.proposed";
/// A proposed prefix was rejected; its addresses are not imported.
pub const ADDRESS_NO_PREFIX: &str = "import.address.no_prefix";
/// A network in a prefix column had host bits; the network was used.
pub const PREFIX_HOST_BITS: &str = "import.prefix.host_bits";
/// A network is not valid.
pub const PREFIX_UNPARSABLE: &str = "import.prefix.unparsable";
/// An address appears twice with different hosts or values; the first one is kept.
pub const ADDRESS_DUPLICATE: &str = "import.address.duplicate";
/// A range cell covers more addresses than the import splits.
pub const RANGE_TOO_LARGE: &str = "import.address.range_too_large";
/// A value of a column does not fit its target (a status, a MAC, a number); the value is
/// left out.
pub const VALUE_INVALID: &str = "import.value.invalid";
/// Two rows give a host different values for one field; the first one is kept.
pub const HOST_CONFLICT: &str = "import.host.conflict";
/// A row has credentials but no host to attach them to; they are not imported.
pub const CREDENTIAL_NO_HOST: &str = "import.credential.no_host";
/// A host has credentials in two rows; the first ones are kept.
pub const CREDENTIAL_DUPLICATE: &str = "import.credential.duplicate";
/// Credential columns are present but the import was told to leave credentials out.
pub const CREDENTIAL_SKIPPED: &str = "import.credential.skipped";
/// A row has data but no address where one is needed; the row is not imported.
pub const ADDRESS_MISSING: &str = "import.address.missing";
/// A custom field column names a field that is not defined; its values are left out.
pub const CUSTOM_UNDEFINED: &str = "import.custom.undefined";
/// The store holds a different value and the conflict policy keeps it.
pub const CONFLICT_KEPT: &str = "import.conflict.kept";
/// A host is locked against automation (IPAM-16); the import leaves it unchanged.
pub const HOST_LOCKED: &str = "import.host.locked";

/// The severity of a loss code.
pub fn severity(code: &str) -> Severity {
    match code {
        ADDRESS_UNPARSABLE | NAME_INVALID | NAME_MISSING | ADDRESS_NO_PREFIX
        | PREFIX_UNPARSABLE | ADDRESS_DUPLICATE | RANGE_TOO_LARGE | CREDENTIAL_NO_HOST
        | ADDRESS_MISSING | CUSTOM_UNDEFINED => Severity::Error,
        PREFIX_UNLISTED | SHEET_EMPTY | NAME_NORMALIZED | PREFIX_PROPOSED | PREFIX_HOST_BITS => {
            Severity::Info
        }
        _ => Severity::Warning,
    }
}

// ----- problem codes of the endpoints ----------------------------------------------------

/// No import with this identifier (or not visible to the caller).
pub const NOT_FOUND: &str = "import.not_found";
/// The upload expired (24 hours) or did not survive a restart.
pub const EXPIRED: &str = "import.expired";
/// The upload has no file.
pub const UPLOAD_EMPTY: &str = "import.upload.empty";
/// The upload exceeds the size limit.
pub const UPLOAD_TOO_LARGE: &str = "import.upload.too_large";
/// The file is not CSV or a workbook.
pub const UPLOAD_UNSUPPORTED: &str = "import.upload.unsupported";
/// The file cannot be read.
pub const UPLOAD_UNREADABLE: &str = "import.upload.unreadable";
/// The multipart body is malformed.
pub const UPLOAD_MALFORMED: &str = "import.upload.malformed";
/// The mapping does not fit the upload.
pub const MAPPING_INVALID: &str = "import.mapping.invalid";
/// The import is being applied, or was applied with another mapping.
pub const STATE_CONFLICT: &str = "import.state.conflict";
/// Credential columns need the vault and an account strong enough for operator secrets
/// (IAM-07, IAM-15).
pub const CREDENTIALS_VAULT_REQUIRED: &str = "import.credentials.vault_required";
/// The plan has warnings that need an acknowledgement, or errors.
pub const PLAN_BLOCKED: &str = "import.plan.blocked";
/// No preview was computed for the current mapping, or the mapping changed since the
/// cursor was made (409): preview again.
pub const PREVIEW_STALE: &str = "import.preview.stale";
/// The import service is not configured on this server.
pub const UNAVAILABLE: &str = "import.unavailable";
/// A chunk of the apply job failed.
pub const APPLY_FAILED: &str = "import.apply.failed";
/// The staged upload is gone (a restart): the job cannot continue.
pub const UPLOAD_LOST: &str = "import.upload.lost";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn specification_codes_have_their_severity() {
        assert_eq!(severity(ADDRESS_UNPARSABLE), Severity::Error);
        assert_eq!(severity(COLUMN_UNMAPPED), Severity::Warning);
        assert_eq!(severity(CREDENTIAL_SUSPICIOUS), Severity::Warning);
        assert_eq!(severity(ADDRESS_IS_NETWORK), Severity::Warning);
        assert_eq!(severity(CREDENTIAL_NUMERIC), Severity::Warning);
        assert_eq!(severity(PREFIX_UNLISTED), Severity::Info);
        assert_eq!(severity(SHEET_EMPTY), Severity::Info);
    }
}
