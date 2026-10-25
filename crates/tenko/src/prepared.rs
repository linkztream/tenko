//! What the installer prepared this machine for (OPS-01).
//!
//! A role is a runtime decision in the store (the nodes page, `PUT /nodes/{id}/roles`), but
//! some of what a role needs is root's and only the installer gives it: the systemd drop-ins
//! that grant `CAP_NET_RAW` (the probe role's raw methods, the dhcp role's direct mode), the
//! ports on the host firewall, systemd-resolved's stub listener off for the dns role on every
//! address. Outside the Hardened profile the installer prepares the machine for every role;
//! in Hardened only for the roles chosen at installation (`docs/cluster.md`, section 13).
//!
//! `deploy/install.sh` and the Windows MSI record what they prepared in [`FILE_NAME`] beside
//! `tenko.toml` (`/etc/tenko/prepared-roles`, `%ProgramData%\Tenko\prepared-roles`). The file
//! belongs to root (Administrators on Windows) and the service only reads it, once at start:
//! nothing in it is run, and it changes nothing; it only says what the installer did. The
//! server joins it with what it can check itself, whether `CAP_NET_RAW` is in the bounding
//! and the effective set of the process on Linux, and reports the result per role as
//! [`PreparedRoles`] in `GET /system/status` (`node.prepared`) and `GET /nodes/{id}/roles`
//! (`prepared`), with the installer command that prepares a role that is not.
//!
//! The format is `key=value` lines: `#` and `;` start a comment, a `[section]` line is
//! ignored (the MSI writes the file as an INI file) and so are unknown keys. The keys:
//! `profile`, `roles`, `dropins`, `ports` (`53/udp`) and `firewall` (`firewalld`, `ufw`,
//! `windows` or `none`), the lists comma separated.

use std::{
    path::{Path, PathBuf},
    sync::OnceLock,
};

use tenko_api::{
    dto::system::{PreparedRoles, RolePreparation, StatusWarning},
    routes::node_roles::{NET_RAW, privileges_finding, unprepared_finding},
};
use tenko_core::{Role, RoleSet};

use crate::config::Resolved;

/// The name of the record, beside `tenko.toml`.
pub const FILE_NAME: &str = "prepared-roles";

/// The drop-in of the probe role.
pub const PROBE_DROPIN: &str = "probe.conf";

/// The drop-in of the dhcp role's direct mode.
pub const DHCP_DIRECT_DROPIN: &str = "dhcp-direct.conf";

/// The configuration file `tenko serve` was started with.
static CONFIG_FILE: OnceLock<Option<PathBuf>> = OnceLock::new();

/// Remembers the configuration file of `tenko serve`, beside which the record lies.
pub fn remember_config_file(file: Option<PathBuf>) {
    let _ = CONFIG_FILE.set(file);
}

/// Where the record of this machine lies: beside the configuration file of `tenko serve`,
/// else beside the platform's default one.
pub fn record_path() -> PathBuf {
    let config = CONFIG_FILE.get().cloned().flatten();
    beside(config.as_deref(), Platform::current())
}

/// The record beside `config`, or beside the default configuration of `platform`.
pub fn beside(config: Option<&Path>, platform: Platform) -> PathBuf {
    if let Some(dir) = config.and_then(Path::parent)
        && !dir.as_os_str().is_empty()
    {
        return dir.join(FILE_NAME);
    }
    match platform {
        Platform::Linux => PathBuf::from("/etc/tenko").join(FILE_NAME),
        Platform::Windows => std::env::var_os("ProgramData")
            .map_or_else(|| PathBuf::from(r"C:\ProgramData"), PathBuf::from)
            .join("Tenko")
            .join(FILE_NAME),
    }
}

/// The installer of the platform, which decides what a role needs and the command that
/// prepares it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    /// `deploy/install.sh` with systemd.
    Linux,
    /// The MSI.
    Windows,
}

impl Platform {
    /// The platform of this build.
    pub const fn current() -> Self {
        if cfg!(windows) {
            Self::Windows
        } else {
            Self::Linux
        }
    }
}

/// What the installer recorded.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Record {
    /// The security profile of the run.
    pub profile: Option<String>,
    /// The roles it prepared the machine for.
    pub roles: RoleSet,
    /// The drop-ins it put in place.
    pub dropins: Vec<String>,
    /// The ports it prepared.
    pub ports: Vec<String>,
    /// The host firewall it configured.
    pub firewall: Option<String>,
}

fn list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_owned)
        .collect()
}

impl Record {
    /// The record in `text`; what does not parse is skipped.
    pub fn parse(text: &str) -> Self {
        let mut record = Self::default();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with(['#', ';', '[']) {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let value = value.trim();
            match key.trim() {
                "profile" if !value.is_empty() => record.profile = Some(value.to_owned()),
                "roles" => {
                    record.roles = list(value)
                        .iter()
                        .filter_map(|role| role.parse::<Role>().ok())
                        .collect();
                }
                "dropins" => record.dropins = list(value),
                "ports" => record.ports = list(value),
                "firewall" if !value.is_empty() => record.firewall = Some(value.to_owned()),
                _ => {}
            }
        }
        record
    }
}

/// `CAP_NET_RAW` in the capability sets of a process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetRaw {
    /// In the bounding set: the unit (a drop-in) allows it.
    pub bounding: bool,
    /// In the effective set: the process holds it.
    pub effective: bool,
}

/// Bit 13 of a capability set is `CAP_NET_RAW`.
const CAP_NET_RAW_BIT: u32 = 13;

fn set_has_net_raw(status: &str, field: &str) -> Option<bool> {
    let value = status.lines().find_map(|line| line.strip_prefix(field))?;
    let mask = u64::from_str_radix(value.trim(), 16).ok()?;
    Some(mask & (1 << CAP_NET_RAW_BIT) != 0)
}

/// `CAP_NET_RAW` in the text of `/proc/self/status`; `None` when the sets are not there.
pub fn net_raw_of(status: &str) -> Option<NetRaw> {
    Some(NetRaw {
        bounding: set_has_net_raw(status, "CapBnd:")?,
        effective: set_has_net_raw(status, "CapEff:")?,
    })
}

/// `CAP_NET_RAW` of this process on Linux; elsewhere the drop-ins do not apply and the
/// answer is that it holds it.
pub fn net_raw() -> NetRaw {
    if !cfg!(target_os = "linux") {
        return NetRaw {
            bounding: true,
            effective: true,
        };
    }
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .as_deref()
        .and_then(net_raw_of)
        .unwrap_or(NetRaw {
            bounding: false,
            effective: false,
        })
}

/// Whether the dhcp role of `resolved` has a listener in direct mode.
pub fn dhcp_direct(resolved: &Resolved) -> bool {
    resolved
        .config
        .dhcp
        .listen
        .iter()
        .any(|listen| listen.mode == crate::config::DhcpListenMode::Direct)
}

/// What the server knows about the machine it runs on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Machine {
    /// The installer of the platform.
    pub platform: Platform,
    /// The record and where it was read, when the installer wrote one.
    pub record: Option<(PathBuf, Record)>,
    /// The profile of `tenko.toml`, for the command when the record names none.
    pub profile: String,
    /// Whether the dhcp role has a listener in direct mode.
    pub dhcp_direct: bool,
    /// `CAP_NET_RAW` of the process.
    pub raw: NetRaw,
    /// The running version, for the name of the MSI.
    pub version: String,
}

impl Machine {
    /// The machine of the server `resolved` describes: the record read from
    /// [`record_path`], the capabilities of this process.
    pub fn of(resolved: &Resolved) -> Self {
        let path = record_path();
        let record = match std::fs::read_to_string(&path) {
            Ok(text) => Some((path, Record::parse(&text))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => {
                tracing::warn!(file = %path.display(), %error, "the installer's record does not read; the roles are reported as not recorded");
                None
            }
        };
        Self {
            platform: Platform::current(),
            record,
            profile: resolved.config.profile.name.as_str().to_owned(),
            dhcp_direct: dhcp_direct(resolved),
            raw: net_raw(),
            version: crate::upgrade::running_version().to_string(),
        }
    }

    /// A machine without a record whose process holds `CAP_NET_RAW` when `raw` says so.
    pub fn bare(raw: bool) -> Self {
        Self {
            platform: Platform::Linux,
            record: None,
            profile: "home".to_owned(),
            dhcp_direct: false,
            raw: NetRaw {
                bounding: raw,
                effective: raw,
            },
            version: "0.0.0".to_owned(),
        }
    }

    fn hardened(&self) -> bool {
        self.record
            .as_ref()
            .and_then(|(_, record)| record.profile.as_deref())
            .unwrap_or(&self.profile)
            == "hardened"
    }

    /// Whether `role` needs `CAP_NET_RAW` here.
    fn needs_raw(&self, role: Role) -> bool {
        self.platform == Platform::Linux
            && (role == Role::Probe || (role == Role::Dhcp && self.dhcp_direct))
    }

    /// What the installer prepares for `role` here: its drop-in and its ports. The
    /// controller's ports (the API and the cluster port) are prepared at every installation.
    fn needs(&self, role: Role) -> Vec<&'static str> {
        let mut needs = match role {
            Role::Dns => vec!["53/tcp", "53/udp"],
            Role::Dhcp => vec!["67/udp", "547/udp"],
            Role::Probe if self.platform == Platform::Linux => vec![PROBE_DROPIN],
            // The probe's raw methods need Npcap on Windows, which is not the MSI's.
            Role::Controller | Role::Probe => Vec::new(),
        };
        if role == Role::Dhcp && self.dhcp_direct && self.platform == Platform::Linux {
            needs.push(DHCP_DIRECT_DROPIN);
        }
        needs
    }

    /// What `role` misses here: what the installer did not prepare, and `CAP_NET_RAW` when
    /// the role needs it and the process lacks it.
    fn missing(&self, role: Role) -> Vec<String> {
        let mut missing: Vec<String> = match &self.record {
            Some((_, record)) if !record.roles.contains(role) => {
                self.needs(role).into_iter().map(str::to_owned).collect()
            }
            _ => Vec::new(),
        };
        if self.needs_raw(role) && !self.raw.effective {
            missing.push(NET_RAW.to_owned());
        }
        missing
    }

    /// The installer command that prepares the machine for `wanted` too. Outside Hardened
    /// the installer prepares every role, so it needs no role list; in Hardened it prepares
    /// the roles named, which are the prepared ones and `wanted`.
    pub fn command(&self, wanted: RoleSet) -> String {
        let hardened = self.hardened();
        let roles = || {
            let prepared = self
                .record
                .as_ref()
                .map_or(RoleSet::EMPTY, |(_, record)| record.roles);
            prepared
                .roles()
                .chain(wanted.roles())
                .chain([Role::Controller])
                .collect::<RoleSet>()
        };
        match (self.platform, hardened) {
            (Platform::Linux, false) => "sudo bash install.sh --prepare".to_owned(),
            (Platform::Linux, true) => {
                format!("sudo bash install.sh --prepare --roles {}", roles())
            }
            (Platform::Windows, false) => format!(
                "msiexec /i tenko-{}-windows-x86_64.msi REINSTALL=ALL",
                self.version
            ),
            (Platform::Windows, true) => format!(
                "msiexec /i tenko-{}-windows-x86_64.msi REINSTALL=ALL TENKO_ROLES={}",
                self.version,
                roles()
            ),
        }
    }

    /// Every role with whether the machine is prepared for it; `None` without a record.
    pub fn prepared(&self) -> Option<PreparedRoles> {
        let (path, record) = self.record.as_ref()?;
        let roles = Role::ALL
            .into_iter()
            .map(|role| {
                let missing = self.missing(role);
                let prepared = missing.is_empty();
                RolePreparation {
                    role: role.as_str().to_owned(),
                    prepared,
                    missing,
                    command: (!prepared).then(|| self.command(RoleSet::from_iter([role]))),
                }
            })
            .collect();
        Some(PreparedRoles {
            file: path.display().to_string(),
            profile: record.profile.clone(),
            dropins: record.dropins.clone(),
            ports: record.ports.clone(),
            firewall: record.firewall.clone(),
            roles,
        })
    }

    /// The finding `node.roles.privileges` for `roles` when one of them needs
    /// `CAP_NET_RAW` and the process lacks it; `None` when nothing is missing.
    pub fn privilege_gaps(&self, roles: RoleSet) -> Option<StatusWarning> {
        if self.raw.effective {
            return None;
        }
        let needing: RoleSet = roles.roles().filter(|role| self.needs_raw(*role)).collect();
        if needing.is_empty() {
            return None;
        }
        let names: Vec<&str> = needing.roles().map(Role::as_str).collect();
        let mut dropins = Vec::new();
        if needing.contains(Role::Probe) {
            dropins.push(PROBE_DROPIN);
        }
        if needing.contains(Role::Dhcp) {
            dropins.push(DHCP_DIRECT_DROPIN);
        }
        Some(privileges_finding(&names, &dropins, &self.command(needing)))
    }

    /// The finding `node.roles.unprepared` for the roles of `roles` that the installer did
    /// not prepare the machine for (their drop-ins and ports; `CAP_NET_RAW` is
    /// [`Self::privilege_gaps`]); `None` without a record or when nothing is missing.
    pub fn unprepared(&self, roles: RoleSet) -> Option<StatusWarning> {
        self.record.as_ref()?;
        let mut names = Vec::new();
        let mut missing = Vec::new();
        let mut gaps = RoleSet::EMPTY;
        for role in roles.roles() {
            let what: Vec<String> = self
                .missing(role)
                .into_iter()
                .filter(|item| item != NET_RAW)
                .collect();
            if what.is_empty() {
                continue;
            }
            names.push(role.as_str());
            gaps.insert(role);
            for item in what {
                if !missing.contains(&item) {
                    missing.push(item);
                }
            }
        }
        if names.is_empty() {
            return None;
        }
        let missing: Vec<&str> = missing.iter().map(String::as_str).collect();
        Some(unprepared_finding(&names, &missing, &self.command(gaps)))
    }

    /// One line for the start log about `CAP_NET_RAW` when it is missing.
    pub fn raw_detail(&self) -> Option<&'static str> {
        if self.raw.effective {
            None
        } else if self.raw.bounding {
            Some(
                "CAP_NET_RAW is in the bounding set of this process but not effective: the \
                 unit's AmbientCapabilities= lacks it",
            )
        } else {
            Some(
                "CAP_NET_RAW is not in the bounding set of this process: the unit's drop-in \
                 that grants it is missing",
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roles(text: &str) -> RoleSet {
        text.parse().expect("roles")
    }

    const RECORD: &str = "\
# Written by the Tenko installer.
[prepared]
profile=hardened
roles=controller,dns
dropins=
ports = 8443/tcp, 8444/tcp, 53/tcp, 53/udp
firewall=firewalld
unknown=ignored
";

    fn machine(record: Option<&str>, raw: bool) -> Machine {
        Machine {
            record: record.map(|text| {
                (
                    PathBuf::from("/etc/tenko/prepared-roles"),
                    Record::parse(text),
                )
            }),
            ..Machine::bare(raw)
        }
    }

    #[test]
    fn the_record_parses_and_skips_what_it_does_not_know() {
        let record = Record::parse(RECORD);
        assert_eq!(record.profile.as_deref(), Some("hardened"));
        assert_eq!(record.roles, roles("controller,dns"));
        assert_eq!(record.dropins, Vec::<String>::new());
        assert_eq!(record.ports, ["8443/tcp", "8444/tcp", "53/tcp", "53/udp"]);
        assert_eq!(record.firewall.as_deref(), Some("firewalld"));
        let windows = Record::parse(
            "[prepared]\r\nroles=controller,dns,dhcp,probe,scanner\r\nprofile=home\r\n",
        );
        assert_eq!(windows.roles, RoleSet::ALL, "an unknown role is skipped");
        assert_eq!(Record::parse(""), Record::default());
    }

    #[test]
    fn the_record_lies_beside_the_configuration() {
        assert_eq!(
            beside(Some(Path::new("/srv/tenko/tenko.toml")), Platform::Linux),
            PathBuf::from("/srv/tenko/prepared-roles")
        );
        assert_eq!(
            beside(None, Platform::Linux),
            PathBuf::from("/etc/tenko/prepared-roles")
        );
        assert_eq!(
            beside(Some(Path::new("tenko.toml")), Platform::Linux),
            PathBuf::from("/etc/tenko/prepared-roles"),
            "a bare file name has no directory to look in"
        );
    }

    #[test]
    fn the_capability_sets_read_from_the_status() {
        let status = "Name:\ttenko\nCapEff:\t0000000000000400\nCapBnd:\t0000000000002400\n";
        assert_eq!(
            net_raw_of(status),
            Some(NetRaw {
                bounding: true,
                effective: false
            })
        );
        let both = "CapEff:\t0000000000002400\nCapBnd:\t0000000000002400\n";
        assert_eq!(
            net_raw_of(both),
            Some(NetRaw {
                bounding: true,
                effective: true
            })
        );
        assert_eq!(net_raw_of("CapEff:\t0\n"), None);
    }

    #[test]
    fn hardened_prepares_the_chosen_roles_only() {
        let machine = machine(Some(RECORD), false);
        let prepared = machine.prepared().expect("a record");
        assert_eq!(prepared.file, "/etc/tenko/prepared-roles");
        let by_role = |name: &str| {
            prepared
                .roles
                .iter()
                .find(|role| role.role == name)
                .expect("every role")
                .clone()
        };
        assert!(by_role("controller").prepared);
        assert!(by_role("dns").prepared);
        let dhcp = by_role("dhcp");
        assert!(!dhcp.prepared);
        assert_eq!(dhcp.missing, ["67/udp", "547/udp"]);
        assert_eq!(
            dhcp.command.as_deref(),
            Some("sudo bash install.sh --prepare --roles controller,dns,dhcp")
        );
        let probe = by_role("probe");
        assert_eq!(probe.missing, ["probe.conf", "CAP_NET_RAW"]);
        assert_eq!(
            probe.command.as_deref(),
            Some("sudo bash install.sh --prepare --roles controller,dns,probe")
        );
    }

    #[test]
    fn other_profiles_prepare_every_role() {
        let all =
            "profile=home\nroles=controller,dns,dhcp,probe\ndropins=probe.conf,dhcp-direct.conf\n";
        let machine = machine(Some(all), true);
        let prepared = machine.prepared().expect("a record");
        assert!(
            prepared
                .roles
                .iter()
                .all(|role| role.prepared && role.command.is_none())
        );
        assert!(machine.unprepared(RoleSet::ALL).is_none());
        assert!(machine.privilege_gaps(RoleSet::ALL).is_none());
        // The drop-in is there, but the service was not restarted since.
        let stale = Machine {
            raw: NetRaw {
                bounding: true,
                effective: false,
            },
            ..machine
        };
        let probe = stale.prepared().expect("a record").roles[3].clone();
        assert_eq!(probe.missing, ["CAP_NET_RAW"]);
        assert_eq!(
            probe.command.as_deref(),
            Some("sudo bash install.sh --prepare")
        );
        assert!(
            stale
                .raw_detail()
                .expect("missing")
                .contains("AmbientCapabilities")
        );
    }

    #[test]
    fn the_warnings_name_the_role_the_capability_and_the_command() {
        let machine = machine(Some(RECORD), false);
        let privileges = machine
            .privilege_gaps(roles("controller,dns,probe"))
            .expect("the probe lacks CAP_NET_RAW");
        assert_eq!(privileges.code, "node.roles.privileges");
        assert_eq!(privileges.params["roles"], "probe");
        assert_eq!(privileges.params["capability"], "CAP_NET_RAW");
        assert_eq!(privileges.params["dropins"], "probe.conf");
        assert_eq!(
            privileges.params["command"],
            "sudo bash install.sh --prepare --roles controller,dns,probe"
        );
        assert!(privileges.detail.contains("sudo bash install.sh --prepare"));
        let unprepared = machine
            .unprepared(roles("controller,dns,dhcp,probe"))
            .expect("dhcp and probe are not prepared");
        assert_eq!(unprepared.code, "node.roles.unprepared");
        assert_eq!(unprepared.params["roles"], "dhcp, probe");
        assert_eq!(unprepared.params["missing"], "67/udp, 547/udp, probe.conf");
        assert_eq!(
            unprepared.params["command"],
            "sudo bash install.sh --prepare --roles controller,dns,dhcp,probe"
        );
        assert!(machine.unprepared(roles("controller,dns")).is_none());
        // Relay mode needs no capability; direct mode does, and its drop-in.
        assert!(machine.privilege_gaps(roles("controller,dhcp")).is_none());
        let direct = Machine {
            dhcp_direct: true,
            ..machine
        };
        let both = direct
            .privilege_gaps(roles("controller,dhcp,probe"))
            .expect("finding");
        assert_eq!(both.params["roles"], "dhcp, probe");
        assert_eq!(both.params["dropins"], "probe.conf, dhcp-direct.conf");
    }

    #[test]
    fn without_a_record_only_the_capability_counts() {
        let machine = machine(None, false);
        assert!(machine.prepared().is_none());
        assert!(machine.unprepared(RoleSet::ALL).is_none());
        let finding = machine
            .privilege_gaps(roles("controller,probe"))
            .expect("finding");
        assert_eq!(finding.params["command"], "sudo bash install.sh --prepare");
        assert!(
            machine
                .raw_detail()
                .expect("missing")
                .contains("bounding set")
        );
        assert!(Machine::bare(true).privilege_gaps(RoleSet::ALL).is_none());
    }

    #[test]
    fn windows_needs_ports_and_names_the_package() {
        let hardened = Machine {
            platform: Platform::Windows,
            version: "0.2.0".to_owned(),
            ..machine(
                Some("[prepared]\nprofile=hardened\nroles=controller\n"),
                true,
            )
        };
        let prepared = hardened.prepared().expect("a record");
        let dns = &prepared.roles[1];
        assert_eq!(dns.missing, ["53/tcp", "53/udp"]);
        assert_eq!(
            dns.command.as_deref(),
            Some(
                "msiexec /i tenko-0.2.0-windows-x86_64.msi REINSTALL=ALL TENKO_ROLES=controller,dns"
            )
        );
        assert!(
            prepared.roles[3].prepared,
            "the probe needs nothing from the MSI"
        );
        let home = Machine {
            record: Some((
                PathBuf::from("prepared-roles"),
                Record::parse("profile=home\nroles=controller\n"),
            )),
            ..hardened
        };
        assert_eq!(
            home.command(roles("dns")),
            "msiexec /i tenko-0.2.0-windows-x86_64.msi REINSTALL=ALL"
        );
    }
}
