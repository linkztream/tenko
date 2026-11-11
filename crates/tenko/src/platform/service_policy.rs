//! The rules of the Windows service that need no Windows to check (ADR 0023, item 11): the
//! privileges the service token keeps, the accounts `tenko service install` refuses, what
//! it may do with a data directory it finds, and the arguments of the tools that carry
//! the rules out. Every function here is pure, so the tests run on every platform;
//! `platform::windows` runs the tools and reports.

use std::{
    collections::BTreeSet,
    ffi::OsString,
    path::{Path, PathBuf},
};

use tenko_api::dto::release::ReleaseVersion;

use crate::upgrade::layout;

/// The privileges the service token keeps, set with `sc.exe privs` at installation. Tenko
/// needs none of the rights a service account holds by default: binding ports below 1024
/// needs no privilege on Windows, the raw sockets of the probe role come from Npcap, whose
/// driver access list decides (not a privilege), the Event Log, DPAPI and the directory
/// junctions of the layout (`mklink /J`) need none. `SeChangeNotifyPrivilege` stays because
/// every token holds it and Windows uses it to open a file by its path without checking
/// every directory on the way; without it every path operation of the service would be
/// checked against the access lists of `C:\` and `C:\ProgramData`, which the account cannot
/// read.
pub const REQUIRED_PRIVILEGES: &[&str] = &["SeChangeNotifyPrivilege"];

/// The code of the refusal of a shared account.
pub const ACCOUNT_SHARED: &str = "service.account_shared";

/// The code of the refusal of a data directory that holds data under another access list.
pub const DATA_DIR_IN_USE: &str = "service.data_dir_in_use";

/// The code of the refusal of a data directory path that is a link or a junction.
pub const DATA_DIR_LINK: &str = "service.data_dir_link";

/// The code of the refusal of a data directory that holds data but no version layout.
pub const DATA_DIR_NO_LAYOUT: &str = "service.data_dir_no_layout";

/// The well-known SID of the local Administrators group.
pub const ADMINISTRATORS_SID: &str = "S-1-5-32-544";

/// The well-known SID of the `SYSTEM` account.
pub const SYSTEM_SID: &str = "S-1-5-18";

/// The prefix of a virtual service account.
const VIRTUAL_ACCOUNT_PREFIX: &str = r"NT SERVICE\";

/// The file name of the binary in the layout on Windows (`layout::binary_name()` names the
/// platform this code runs on; the rules here are Windows's wherever they are checked).
const WINDOWS_BINARY: &str = "tenko.exe";

/// The `sc.exe` arguments that set the required privileges of the service `name`.
pub fn sc_privs_arguments(name: &str) -> Vec<OsString> {
    vec![
        "privs".into(),
        name.into(),
        REQUIRED_PRIVILEGES.join("/").into(),
    ]
}

/// The `sc.exe` arguments that print the SID of the service `name` (which is the SID of its
/// virtual account, whether or not the service exists yet).
pub fn sc_showsid_arguments(name: &str) -> Vec<OsString> {
    vec!["showsid".into(), name.into()]
}

/// The SID in the output of `sc.exe showsid`: the line `SERVICE SID: S-1-5-80-…`.
pub fn parse_showsid(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let (label, value) = line.split_once(':')?;
        label
            .trim()
            .eq_ignore_ascii_case("SERVICE SID")
            .then(|| value.trim().to_owned())
            .filter(|sid| sid.starts_with("S-1-5-80-"))
    })
}

/// The service name behind a virtual account `NT SERVICE\<name>`.
pub fn virtual_account_service(account: &str) -> Option<&str> {
    let (prefix, name) = account.split_at_checked(VIRTUAL_ACCOUNT_PREFIX.len())?;
    (prefix.eq_ignore_ascii_case(VIRTUAL_ACCOUNT_PREFIX) && !name.is_empty()).then_some(name)
}

/// Refuses `LocalSystem` and the shared accounts `LocalService` and `NetworkService`, in
/// every spelling Windows accepts (`NT AUTHORITY\LocalService`, `.\LocalSystem`, `SYSTEM`).
/// The message is the refusal, with its code.
///
/// # Errors
///
/// The account is one of the three.
pub fn check_account(account: &str) -> Result<(), String> {
    let bare = account
        .rsplit_once('\\')
        .map_or(account, |(_, name)| name)
        .trim();
    let shared = ["LocalSystem", "System", "LocalService", "NetworkService"]
        .into_iter()
        .any(|name| bare.eq_ignore_ascii_case(name));
    if !shared {
        return Ok(());
    }
    Err(format!(
        "{ACCOUNT_SHARED}: the service does not run as `{account}`. It runs the binary in \
         its own data directory and must be the only account that can write it: \
         LocalSystem would run that binary with the rights of the whole machine, and \
         LocalService and NetworkService are shared with other services. Use the virtual \
         account `NT SERVICE\\<name>`, which is the default, or another virtual account \
         (ADR 0023, item 11)."
    ))
}

/// The `icacls` arguments of the first step on a new or empty data directory: the
/// inherited list goes, Administrators and SYSTEM get full control of the directory and of
/// everything created in it. The service account is not on the list yet, so what the
/// installer writes next (the version layout) is written into a directory the account
/// cannot write.
pub fn icacls_restrict_arguments(dir: &Path) -> Vec<OsString> {
    vec![
        dir.into(),
        "/inheritance:r".into(),
        "/grant:r".into(),
        format!("*{ADMINISTRATORS_SID}:(OI)(CI)F").into(),
        format!("*{SYSTEM_SID}:(OI)(CI)F").into(),
    ]
}

/// The `icacls` arguments of the last step: the service account gets full control of the
/// directory and of everything in it, inherited by what is created later.
pub fn icacls_grant_arguments(dir: &Path, account: &str) -> Vec<OsString> {
    vec![
        dir.into(),
        "/grant:r".into(),
        format!("{account}:(OI)(CI)F").into(),
    ]
}

/// The environment variable that hands the path to the script of
/// [`powershell_acl_arguments`].
pub const ACL_PATH_VARIABLE: &str = "TENKO_ACL_PATH";

/// The `powershell.exe` arguments that print the security descriptor of the path in
/// [`ACL_PATH_VARIABLE`]: in SDDL on the first line (the owner `O:`, the group `G:`, the
/// discretionary list `D:`), the owner's name on the second. A path that cannot be read
/// stops the script with status 1.
///
/// - The path is never part of the script: PowerShell takes the quotation marks `‘ ’ ‚ ‛`
///   for `'` as well, so a path spliced into a quoted string could run a command.
/// - `Get-Acl` comes from the system's `Microsoft.PowerShell.Security`, imported by its
///   full path under `$PSHOME` (the directory of `powershell.exe` itself), so the module
///   path is not searched for it. Started from PowerShell 7, the module path named
///   PowerShell 7's own copy first, which Windows PowerShell cannot load; a module planted
///   in a directory it names would have loaded.
/// - Commands and properties, no calls on .NET types: the script also runs in Constrained
///   Language mode, which Windows Defender Application Control sets.
pub fn powershell_acl_arguments() -> Vec<OsString> {
    vec![
        "-NoProfile".into(),
        "-NonInteractive".into(),
        "-ExecutionPolicy".into(),
        "Bypass".into(),
        "-Command".into(),
        format!(
            "$ErrorActionPreference = 'Stop'; \
             Import-Module -Name \
             \"$PSHOME\\Modules\\Microsoft.PowerShell.Security\\Microsoft.PowerShell.Security.psd1\"; \
             $acl = Get-Acl -LiteralPath $env:{ACL_PATH_VARIABLE}; $acl.Sddl; $acl.Owner"
        )
        .into(),
    ]
}

/// A parsed security descriptor: the owner and the explicit access entries, SIDs spelled
/// out (`BA` is `S-1-5-32-544`, `SY` is `S-1-5-18`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Descriptor {
    /// The owner's SID.
    pub owner: String,
    /// The list is protected: it inherits nothing from the parent (`/inheritance:r`).
    pub protected: bool,
    /// The access entries, in order.
    pub entries: Vec<Entry>,
}

/// One access control entry of the discretionary list.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Entry {
    /// The type: `A` allows, `D` denies.
    pub kind: String,
    /// The inheritance flags, as two-letter codes (`OI`, `CI`, `IO`, `ID`, `NP`).
    pub flags: BTreeSet<String>,
    /// The rights, as written (`FA`, or a hexadecimal mask).
    pub rights: String,
    /// The SID.
    pub sid: String,
}

/// The SID behind an SDDL abbreviation Windows uses for the well-known accounts that the
/// data directory's list may name; other names stay as they are.
fn expand_sid(name: &str) -> String {
    match name {
        "BA" => ADMINISTRATORS_SID.to_owned(),
        "SY" => SYSTEM_SID.to_owned(),
        other => other.to_owned(),
    }
}

/// Where the next section of an SDDL string begins (`G:`, `D:` or `S:`), or the end. A SID
/// is `S-…`, never `S:`, so it does not end a section.
fn section_end(text: &str) -> usize {
    ["G:", "D:", "S:"]
        .iter()
        .filter_map(|tag| text.find(tag))
        .min()
        .unwrap_or(text.len())
}

/// Parses the owner and the discretionary list of an SDDL string
/// (`O:BAG:…D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`).
pub fn parse_sddl(sddl: &str) -> Option<Descriptor> {
    let sddl = sddl.trim();
    let owner_start = sddl.find("O:")? + 2;
    let owner_end = owner_start + section_end(&sddl[owner_start..]);
    let owner = expand_sid(sddl[owner_start..owner_end].trim());
    let dacl_start = sddl.find("D:")? + 2;
    let dacl = &sddl[dacl_start..];
    let dacl = &dacl[..section_end(dacl)];
    let (flags, aces) = dacl.find('(').map_or((dacl, ""), |at| dacl.split_at(at));
    let protected = flags.contains('P');
    let mut entries = Vec::new();
    for ace in aces.split(')').map(str::trim).filter(|ace| !ace.is_empty()) {
        let ace = ace.strip_prefix('(')?;
        let fields: Vec<&str> = ace.split(';').collect();
        if fields.len() < 6 {
            return None;
        }
        let flags = fields[1]
            .as_bytes()
            .chunks(2)
            .map(|pair| String::from_utf8_lossy(pair).into_owned())
            .collect();
        entries.push(Entry {
            kind: fields[0].to_owned(),
            flags,
            rights: fields[2].to_owned(),
            sid: expand_sid(fields[5]),
        });
    }
    Some(Descriptor {
        owner,
        protected,
        entries,
    })
}

/// Whether `found` is the descriptor `service install` sets: the owner is Administrators or
/// SYSTEM (what an elevated process creates a directory with), the list inherits nothing,
/// and it holds exactly one entry each for the account, Administrators and SYSTEM, all
/// allowing full control of the directory and everything in it. The order of the entries
/// does not matter; a denied entry, a missing one or one more fails the comparison.
pub fn matches_secured_list(found: &Descriptor, account_sid: &str) -> bool {
    if !found.protected || !matches!(found.owner.as_str(), ADMINISTRATORS_SID | SYSTEM_SID) {
        return false;
    }
    let full = |entry: &Entry| {
        entry.kind == "A"
            && entry.flags == BTreeSet::from(["OI".to_owned(), "CI".to_owned()])
            && (entry.rights == "FA" || entry.rights.eq_ignore_ascii_case("0x1f01ff"))
    };
    let mut sids: Vec<&str> = found
        .entries
        .iter()
        .map(|entry| entry.sid.as_str())
        .collect();
    sids.sort_unstable();
    let mut expected = vec![account_sid, ADMINISTRATORS_SID, SYSTEM_SID];
    expected.sort_unstable();
    found.entries.iter().all(full) && sids == expected
}

/// What `service install` found at the data directory path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataDirFound {
    /// Nothing: the directory is created.
    Missing,
    /// A link or a junction, not a directory.
    Link,
    /// A directory with no entries.
    Empty,
    /// A directory with entries, and whether its descriptor is the one `service install`
    /// sets for this account (`None`: it could not be read or compared).
    InUse {
        /// Whether the owner and the list match.
        matching: Option<bool>,
        /// Whether `<dir>\updates\current\<binary>` exists.
        layout_present: bool,
    },
}

/// What `service install` does with the data directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataDirPlan {
    /// Create it, restrict it, build the layout in it, then grant the account.
    Create,
    /// It is empty: restrict it, build the layout in it, then grant the account.
    Restrict,
    /// It holds data under the right list: change nothing in it.
    Keep,
    /// Refuse, with the code and the reason.
    Refuse(String),
}

/// Decides what to do with the data directory. `with_layout` is whether the service runs the
/// version layout (the default) and so needs `updates\current` to exist before its first
/// start.
pub fn data_dir_plan(dir: &Path, found: &DataDirFound, with_layout: bool) -> DataDirPlan {
    let shown = dir.display();
    match found {
        DataDirFound::Missing => DataDirPlan::Create,
        DataDirFound::Empty => DataDirPlan::Restrict,
        DataDirFound::Link => DataDirPlan::Refuse(format!(
            "{DATA_DIR_LINK}: {shown} is a link or a junction; the data directory must be a \
             directory"
        )),
        DataDirFound::InUse {
            matching: Some(true),
            layout_present,
        } => {
            if with_layout && !layout_present {
                DataDirPlan::Refuse(format!(
                    "{DATA_DIR_NO_LAYOUT}: {shown} holds data but no version layout \
                     (updates\\current\\{WINDOWS_BINARY}), and the installer writes nothing into \
                     a data directory the service account controls; register the service \
                     with --no-update-layout, or restore the data into a new directory"
                ))
            } else {
                DataDirPlan::Keep
            }
        }
        DataDirFound::InUse {
            matching: Some(false),
            ..
        } => DataDirPlan::Refuse(format!(
            "{DATA_DIR_IN_USE}: {shown} holds data and its owner or its access list is not \
             the one service install sets for this account; the installer never changes the \
             access list of a directory that holds data. Use the account the directory was \
             set up for, or a new or empty directory"
        )),
        DataDirFound::InUse { matching: None, .. } => DataDirPlan::Refuse(format!(
            "{DATA_DIR_IN_USE}: {shown} holds data and its access list could not be \
             compared with the one service install sets; the installer never changes the \
             access list of a directory that holds data. Use a new or empty directory"
        )),
    }
}

/// A note for a payload the service will adopt newer versions of when it does not lie under
/// a Program Files directory, where only administrators write.
pub fn payload_location_note(payload: &Path, program_files: &[PathBuf]) -> Option<String> {
    // Compared as text, case-insensitively and on a separator boundary, so that the test
    // of a Windows path means the same on every platform.
    let path = payload.to_string_lossy().to_ascii_lowercase();
    let inside = program_files.iter().any(|root| {
        let root = root
            .to_string_lossy()
            .to_ascii_lowercase()
            .trim_end_matches(['\\', '/'])
            .to_owned();
        path.strip_prefix(root.as_str())
            .is_some_and(|rest| rest.starts_with(['\\', '/']))
    });
    (!inside).then(|| {
        format!(
            "the service adopts newer versions of {} at its start; keep that file where only \
             administrators can write, such as C:\\Program Files\\Tenko",
            payload.display()
        )
    })
}

/// The executable in the image path the SCM holds for a service: the first quoted word, or
/// the first word, of `"C:\…\tenko.exe" service run --name tenko …`.
pub fn registered_executable(image_path: &str) -> PathBuf {
    let text = image_path.trim_start();
    let executable = match text.strip_prefix('"') {
        Some(quoted) => quoted.split('"').next().unwrap_or(""),
        None => text.split_whitespace().next().unwrap_or(""),
    };
    PathBuf::from(executable)
}

/// The data directory of a service whose executable is the layout's
/// `<data_dir>\updates\current\<binary>`; `None` for an executable registered as itself.
/// The path is read as text with either separator, so the rule reads the same on every
/// platform.
pub fn layout_data_dir(executable: &Path) -> Option<PathBuf> {
    let text = executable.to_string_lossy();
    let mut parts = text.rsplitn(4, ['\\', '/']);
    let binary = parts.next()?;
    let current = parts.next()?;
    let updates = parts.next()?;
    let data_dir = parts.next()?;
    (binary == WINDOWS_BINARY
        && current == layout::CURRENT
        && updates == layout::UPDATES_DIR
        && !data_dir.is_empty())
    .then(|| PathBuf::from(data_dir))
}

/// After `service start`: whether the layout runs the version of this binary. `current` is
/// the version `updates\current` names (`None`: the service runs the executable it was
/// registered with). The error is the message for an installer's file that the service did
/// not adopt.
///
/// # Errors
///
/// The layout runs an older version than this binary.
pub fn adoption_outcome(
    own: &ReleaseVersion,
    current: Option<&ReleaseVersion>,
) -> Result<String, String> {
    match current {
        None => Ok("the service runs the executable it was registered with".to_owned()),
        Some(current) if current >= own => Ok(format!("the service runs version {current}")),
        Some(current) => Err(format!(
            "the service runs version {current} and did not adopt this binary ({own}) at its \
             start; the Application log, source of the service, names the reason (a store \
             check that refused, or a file that could not be read)"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(arguments: &[OsString]) -> Vec<String> {
        arguments
            .iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect()
    }

    const SERVICE_SID: &str = "S-1-5-80-1234567890-1234567890-1234567890-1234567890-1234567890";

    #[test]
    fn the_privilege_list_is_the_floor_and_sc_sets_it() {
        assert_eq!(REQUIRED_PRIVILEGES, ["SeChangeNotifyPrivilege"]);
        assert_eq!(
            text(&sc_privs_arguments("tenko")),
            ["privs", "tenko", "SeChangeNotifyPrivilege"]
        );
        assert_eq!(
            text(&sc_showsid_arguments("tenko-lab")),
            ["showsid", "tenko-lab"]
        );
    }

    #[test]
    fn showsid_output_yields_the_service_sid() {
        let output = format!("\r\nNAME: tenko\r\nSERVICE SID: {SERVICE_SID}\r\nSTATUS: Active\r\n");
        assert_eq!(parse_showsid(&output).as_deref(), Some(SERVICE_SID));
        assert_eq!(parse_showsid("NAME: tenko\nSTATUS: Inactive\n"), None);
        assert_eq!(parse_showsid("SERVICE SID: S-1-5-18"), None);
    }

    #[test]
    fn virtual_accounts_name_their_service() {
        assert_eq!(virtual_account_service(r"NT SERVICE\tenko"), Some("tenko"));
        assert_eq!(
            virtual_account_service(r"nt service\tenko-lab"),
            Some("tenko-lab")
        );
        assert_eq!(virtual_account_service(r"NT SERVICE\"), None);
        assert_eq!(virtual_account_service(r"NT AUTHORITY\LocalService"), None);
        assert_eq!(virtual_account_service(r"CORP\svc-tenko"), None);
    }

    #[test]
    fn shared_accounts_are_refused_in_every_spelling() {
        for account in [
            "LocalSystem",
            "localsystem",
            r".\LocalSystem",
            "SYSTEM",
            r"NT AUTHORITY\SYSTEM",
            r"NT AUTHORITY\LocalService",
            "LocalService",
            r"NT AUTHORITY\NetworkService",
            "networkservice",
        ] {
            let refusal = check_account(account).expect_err(account);
            assert!(refusal.starts_with(ACCOUNT_SHARED), "{refusal}");
            assert!(refusal.contains(account), "{refusal}");
            assert!(refusal.contains(r"NT SERVICE\<name>"), "{refusal}");
        }
        for account in [
            r"NT SERVICE\tenko",
            r"NT SERVICE\tenko-lab",
            r"CORP\svc-tenko",
        ] {
            check_account(account).expect(account);
        }
    }

    #[test]
    fn the_access_list_is_set_in_two_steps() {
        let dir = Path::new(r"C:\ProgramData\Tenko\data");
        assert_eq!(
            text(&icacls_restrict_arguments(dir)),
            [
                r"C:\ProgramData\Tenko\data",
                "/inheritance:r",
                "/grant:r",
                "*S-1-5-32-544:(OI)(CI)F",
                "*S-1-5-18:(OI)(CI)F"
            ]
        );
        assert_eq!(
            text(&icacls_grant_arguments(dir, r"NT SERVICE\tenko")),
            [
                r"C:\ProgramData\Tenko\data",
                "/grant:r",
                r"NT SERVICE\tenko:(OI)(CI)F"
            ]
        );
    }

    #[test]
    fn powershell_reads_the_descriptor_of_the_path_in_the_environment() {
        let arguments = text(&powershell_acl_arguments());
        assert_eq!(
            arguments[..5],
            [
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command"
            ]
        );
        assert_eq!(
            arguments[5],
            "$ErrorActionPreference = 'Stop'; Import-Module -Name \
             \"$PSHOME\\Modules\\Microsoft.PowerShell.Security\\Microsoft.PowerShell.Security.psd1\"; \
             $acl = Get-Acl -LiteralPath $env:TENKO_ACL_PATH; $acl.Sddl; $acl.Owner"
        );
    }

    #[test]
    fn sddl_parses_into_owner_flags_and_entries() {
        let sddl = format!(
            "O:BAG:S-1-5-21-1-2-3-513D:PAI(A;OICI;FA;;;{SERVICE_SID})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
        );
        let descriptor = parse_sddl(&sddl).expect("parses");
        assert_eq!(descriptor.owner, ADMINISTRATORS_SID);
        assert!(descriptor.protected);
        assert_eq!(descriptor.entries.len(), 3);
        assert_eq!(descriptor.entries[0].sid, SERVICE_SID);
        assert_eq!(descriptor.entries[1].sid, SYSTEM_SID);
        assert_eq!(descriptor.entries[2].sid, ADMINISTRATORS_SID);
        assert_eq!(descriptor.entries[0].kind, "A");
        assert_eq!(descriptor.entries[0].rights, "FA");
        assert_eq!(
            descriptor.entries[0].flags,
            BTreeSet::from(["OI".to_owned(), "CI".to_owned()])
        );
        assert!(matches_secured_list(&descriptor, SERVICE_SID));

        let inherited =
            parse_sddl("O:SYG:SYD:AI(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIID;0x1200a9;;;BU)")
                .expect("parses");
        let owned_by_sid = parse_sddl(&format!(
            "O:{SERVICE_SID}G:SYD:P(A;OICI;FA;;;SY)S:AI(AU;SA;FA;;;WD)"
        ))
        .expect("parses");
        assert_eq!(owned_by_sid.owner, SERVICE_SID);
        assert_eq!(owned_by_sid.entries.len(), 1, "the system list is not read");
        assert!(!inherited.protected);
        assert_eq!(inherited.owner, SYSTEM_SID);
        assert!(inherited.entries[2].flags.contains("ID"));
        assert!(!matches_secured_list(&inherited, SERVICE_SID));

        assert_eq!(parse_sddl("not sddl"), None);
        assert_eq!(parse_sddl("O:BAD:P(A;OICI)"), None);
    }

    #[test]
    fn the_secured_list_is_exactly_three_full_control_entries() {
        let good = |owner: &str, aces: &str| {
            let descriptor = parse_sddl(&format!("O:{owner}G:SYD:P{aces}")).expect("parses");
            matches_secured_list(&descriptor, SERVICE_SID)
        };
        let three = format!("(A;OICI;FA;;;{SERVICE_SID})(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)");
        assert!(good("BA", &three));
        assert!(good("SY", &three));
        assert!(good(
            "SY",
            &format!("(A;OICI;0x1f01ff;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{SERVICE_SID})")
        ));
        // The service account owns it: not what an elevated installer creates.
        assert!(!good(SERVICE_SID, &three));
        // Another account on the list, an entry missing, a denied entry, no inheritance.
        assert!(!good("BA", &format!("{three}(A;OICI;FA;;;BU)")));
        assert!(!good(
            "BA",
            &format!("(A;OICI;FA;;;{SERVICE_SID})(A;OICI;FA;;;BA)")
        ));
        assert!(!good("BA", &format!("(D;OICI;FA;;;BU){three}")));
        assert!(!good(
            "BA",
            &format!("(A;;FA;;;{SERVICE_SID})(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)")
        ));
        assert!(!good(
            "BA",
            "(A;OICI;FA;;;S-1-5-80-9-9-9-9-9)(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)"
        ));
        // Read-only for the account is not full control.
        assert!(!good(
            "BA",
            &format!("(A;OICI;0x1200a9;;;{SERVICE_SID})(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)")
        ));
        // Not protected: it inherits from ProgramData.
        let unprotected = parse_sddl(&format!("O:BAG:SYD:AI{three}")).expect("parses");
        assert!(!matches_secured_list(&unprotected, SERVICE_SID));
    }

    #[test]
    fn the_plan_follows_what_was_found() {
        let dir = Path::new(r"C:\ProgramData\Tenko\data");
        assert_eq!(
            data_dir_plan(dir, &DataDirFound::Missing, true),
            DataDirPlan::Create
        );
        assert_eq!(
            data_dir_plan(dir, &DataDirFound::Empty, true),
            DataDirPlan::Restrict
        );
        assert_eq!(
            data_dir_plan(dir, &DataDirFound::Empty, false),
            DataDirPlan::Restrict
        );
        let in_use = |matching, layout_present| DataDirFound::InUse {
            matching,
            layout_present,
        };
        assert_eq!(
            data_dir_plan(dir, &in_use(Some(true), true), true),
            DataDirPlan::Keep
        );
        assert_eq!(
            data_dir_plan(dir, &in_use(Some(true), false), false),
            DataDirPlan::Keep
        );
        let refusal = |found, with_layout| match data_dir_plan(dir, &found, with_layout) {
            DataDirPlan::Refuse(message) => message,
            other => panic!("expected a refusal, got {other:?}"),
        };
        let link = refusal(DataDirFound::Link, true);
        assert!(link.starts_with(DATA_DIR_LINK), "{link}");
        let no_layout = refusal(in_use(Some(true), false), true);
        assert!(no_layout.starts_with(DATA_DIR_NO_LAYOUT), "{no_layout}");
        assert!(no_layout.contains("--no-update-layout"), "{no_layout}");
        let other_list = refusal(in_use(Some(false), true), true);
        assert!(other_list.starts_with(DATA_DIR_IN_USE), "{other_list}");
        assert!(
            other_list.contains("never changes the access list"),
            "{other_list}"
        );
        let unknown = refusal(in_use(None, true), true);
        assert!(unknown.starts_with(DATA_DIR_IN_USE), "{unknown}");
        assert!(unknown.contains("could not be compared"), "{unknown}");
        for message in [&link, &no_layout, &other_list, &unknown] {
            assert!(message.contains(r"C:\ProgramData\Tenko\data"), "{message}");
        }
    }

    #[test]
    fn a_payload_outside_program_files_gets_a_note() {
        let roots = vec![
            PathBuf::from(r"C:\Program Files"),
            PathBuf::from(r"C:\Program Files (x86)"),
        ];
        assert_eq!(
            payload_location_note(Path::new(r"C:\Program Files\Tenko\tenko.exe"), &roots),
            None
        );
        let note = payload_location_note(Path::new(r"C:\Users\admin\Downloads\tenko.exe"), &roots)
            .expect("a note");
        assert!(
            note.contains(r"C:\Users\admin\Downloads\tenko.exe"),
            "{note}"
        );
        assert!(note.contains("only administrators can write"), "{note}");
        assert!(payload_location_note(Path::new(r"D:\tenko.exe"), &[]).is_some());
        assert_eq!(
            payload_location_note(Path::new(r"c:\program files\Tenko\tenko.exe"), &roots),
            None
        );
        assert!(
            payload_location_note(Path::new(r"C:\Program Files Extra\tenko.exe"), &roots).is_some()
        );
    }

    #[test]
    fn the_image_path_names_the_layout_and_its_data_directory() {
        let image = r#""C:\ProgramData\Tenko\data\updates\current\tenko.exe" service run --name tenko --config "C:\ProgramData\Tenko\tenko.toml""#;
        let executable = registered_executable(image);
        assert_eq!(
            executable,
            PathBuf::from(r"C:\ProgramData\Tenko\data\updates\current\tenko.exe")
        );
        assert_eq!(
            registered_executable(r"C:\Tenko\tenko.exe service run"),
            PathBuf::from(r"C:\Tenko\tenko.exe")
        );
        let data_dir = layout_data_dir(&executable);
        assert_eq!(
            data_dir
                .as_deref()
                .map(|dir| dir.to_string_lossy().into_owned()),
            Some(r"C:\ProgramData\Tenko\data".to_owned())
        );
        assert_eq!(
            layout_data_dir(Path::new(r"C:\Program Files\Tenko\tenko.exe")),
            None
        );
        assert_eq!(
            layout_data_dir(Path::new(r"C:\x\updates\previous\tenko.exe")),
            None
        );
        assert_eq!(
            layout_data_dir(Path::new(r"C:\x\updates\current\other.exe")),
            None
        );
    }

    #[test]
    fn the_outcome_after_start_compares_the_layout_with_this_binary() {
        let own: ReleaseVersion = "0.2.0".parse().expect("version");
        let older: ReleaseVersion = "0.1.0".parse().expect("version");
        let newer: ReleaseVersion = "0.3.0".parse().expect("version");
        assert!(adoption_outcome(&own, None).is_ok());
        assert_eq!(
            adoption_outcome(&own, Some(&own)).expect("same"),
            "the service runs version 0.2.0"
        );
        assert!(adoption_outcome(&own, Some(&newer)).is_ok());
        let refused = adoption_outcome(&own, Some(&older)).expect_err("older");
        assert!(refused.contains("runs version 0.1.0"), "{refused}");
        assert!(
            refused.contains("did not adopt this binary (0.2.0)"),
            "{refused}"
        );
        assert!(refused.contains("Application log"), "{refused}");
    }
}
