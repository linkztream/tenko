//! Product modules (OPS-25): the parts of Tenko DDI an installation has at all.
//!
//! Modules answer a different question than node roles (`tenko_core::Role`): a role says
//! where a component runs, a module says whether the installation has it. IPAM, DNS, DHCP
//! and Discovery can each be switched off; a disabled module registers no API routes, shows
//! no UI area, runs no background tasks and allocates nothing. The platform itself (setup,
//! sign-in, users, settings, jobs, audit, events and system) is not a module and is always
//! there.
//!
//! The server binary decides the set at start (`modules` in `tenko.toml`, else the choice
//! of the first-run wizard, else every module) and hands it to the router through
//! [`crate::ServerConfig`]; `GET /system/status` reports it so that the web UI shows only
//! the areas of enabled modules.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use utoipa::ToSchema;

/// A product module that an installation can enable or disable (OPS-25).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum Module {
    /// IP address management: prefixes, addresses, hosts, VLANs, import, export and moves.
    Ipam,
    /// DNS: zones and records (Phase 2).
    Dns,
    /// DHCP: scopes, reservations and leases (Phase 3).
    Dhcp,
    /// Discovery: probes, scans and observations (Slice 2).
    Discovery,
}

impl Module {
    /// Every module, in canonical order.
    pub const ALL: [Module; 4] = [Module::Ipam, Module::Dns, Module::Dhcp, Module::Discovery];

    /// The lowercase name used in `tenko.toml`, the API and the UI.
    pub const fn as_str(self) -> &'static str {
        match self {
            Module::Ipam => "ipam",
            Module::Dns => "dns",
            Module::Dhcp => "dhcp",
            Module::Discovery => "discovery",
        }
    }

    /// A one-line description.
    pub const fn description(self) -> &'static str {
        match self {
            Module::Ipam => "IP address management: prefixes, addresses, hosts, VLANs",
            Module::Dns => "DNS zones and records",
            Module::Dhcp => "DHCP scopes, reservations and leases",
            Module::Discovery => "discovery: probes, scans and observations",
        }
    }

    const fn bit(self) -> u8 {
        match self {
            Module::Ipam => 0b0001,
            Module::Dns => 0b0010,
            Module::Dhcp => 0b0100,
            Module::Discovery => 0b1000,
        }
    }
}

impl fmt::Display for Module {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A module name that is not one of `ipam`, `dns`, `dhcp` and `discovery`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownModule(pub String);

impl fmt::Display for UnknownModule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "unknown module `{}` (expected ipam, dns, dhcp or discovery)",
            self.0
        )
    }
}

impl std::error::Error for UnknownModule {}

impl FromStr for Module {
    type Err = UnknownModule;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let name = s.trim();
        Module::ALL
            .into_iter()
            .find(|module| module.as_str().eq_ignore_ascii_case(name))
            .ok_or_else(|| UnknownModule(name.to_owned()))
    }
}

/// A set of [`Module`]s. Serializes as a list of names in canonical order; parses from a
/// list or from a comma-separated string (`"ipam,dns"`), and `all` means every module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ModuleSet(u8);

impl Default for ModuleSet {
    /// Every module: the default of an installation (OPS-25).
    fn default() -> Self {
        Self::ALL
    }
}

impl ModuleSet {
    /// No module: only the platform (setup, users, settings, jobs, audit).
    pub const EMPTY: ModuleSet = ModuleSet(0);

    /// Every module.
    pub const ALL: ModuleSet = ModuleSet(0b1111);

    /// A set of one module.
    pub const fn only(module: Module) -> Self {
        ModuleSet(module.bit())
    }

    /// Adds a module.
    pub fn insert(&mut self, module: Module) {
        self.0 |= module.bit();
    }

    /// Removes a module.
    pub fn remove(&mut self, module: Module) {
        self.0 &= !module.bit();
    }

    /// Whether the set contains `module`.
    pub const fn contains(self, module: Module) -> bool {
        (self.0 & module.bit()) != 0
    }

    /// Whether the set is empty.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The modules of the set, in canonical order.
    pub fn modules(self) -> impl Iterator<Item = Module> {
        Module::ALL
            .into_iter()
            .filter(move |module| self.contains(*module))
    }

    /// The names of the modules, in canonical order.
    pub fn names(self) -> Vec<String> {
        self.modules()
            .map(|module| module.as_str().to_owned())
            .collect()
    }
}

impl FromIterator<Module> for ModuleSet {
    fn from_iter<I: IntoIterator<Item = Module>>(iter: I) -> Self {
        let mut set = ModuleSet::EMPTY;
        for module in iter {
            set.insert(module);
        }
        set
    }
}

impl fmt::Display for ModuleSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return f.write_str("(none)");
        }
        for (index, module) in self.modules().enumerate() {
            if index > 0 {
                f.write_str(",")?;
            }
            f.write_str(module.as_str())?;
        }
        Ok(())
    }
}

impl FromStr for ModuleSet {
    type Err = UnknownModule;

    /// Parses `all`, an empty string (no module) or a comma-separated list.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let list = s.trim();
        if list.eq_ignore_ascii_case("all") {
            return Ok(ModuleSet::ALL);
        }
        list.split(',')
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(str::parse)
            .collect()
    }
}

impl Serialize for ModuleSet {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.modules())
    }
}

impl<'de> Deserialize<'de> for ModuleSet {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum ListOrText {
            List(Vec<String>),
            Text(String),
        }
        let names = match ListOrText::deserialize(deserializer)? {
            ListOrText::List(names) => names,
            ListOrText::Text(text) => {
                return text.parse().map_err(serde::de::Error::custom);
            }
        };
        names
            .iter()
            .map(|name| {
                if name.trim().eq_ignore_ascii_case("all") {
                    Ok(ModuleSet::ALL)
                } else {
                    name.parse::<Module>().map(ModuleSet::only)
                }
            })
            .try_fold(ModuleSet::EMPTY, |set, next| {
                next.map(|next| ModuleSet(set.0 | next.0))
            })
            .map_err(serde::de::Error::custom)
    }
}

impl utoipa::PartialSchema for ModuleSet {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        utoipa::openapi::schema::ArrayBuilder::new()
            .items(Module::schema())
            .description(Some(
                "Product modules in canonical order: ipam, dns, dhcp, discovery (OPS-25).",
            ))
            .into()
    }
}

impl ToSchema for ModuleSet {
    fn schemas(
        schemas: &mut Vec<(
            String,
            utoipa::openapi::RefOr<utoipa::openapi::schema::Schema>,
        )>,
    ) {
        schemas.push((
            Module::name().into_owned(),
            <Module as utoipa::PartialSchema>::schema(),
        ));
    }
}

/// What happens to a module change that the running server cannot apply by itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ModuleRestart {
    /// The running set is the configured one.
    None,
    /// The server restarts itself through its service manager to apply the change.
    Scheduled,
    /// Restart the server to apply the change (it runs without a service manager).
    Required,
}

/// `GET /system/modules` and the answer of `PUT /system/modules` (OPS-25).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ModuleSettings {
    /// The modules the server runs now.
    pub running: ModuleSet,
    /// The modules the next start runs: `modules` of `tenko.toml` when it sets them, else
    /// the installation's choice, else every module.
    pub configured: ModuleSet,
    /// `tenko.toml` sets the modules; the installation's choice cannot change them.
    pub pinned: bool,
    /// Whether a restart is pending to apply `configured`.
    pub restart: ModuleRestart,
}

/// `PUT /system/modules`: what the installation is for (the first-run wizard asks).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ModulesRequest {
    /// The modules to run.
    pub modules: ModuleSet,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip() {
        for module in Module::ALL {
            assert_eq!(module.as_str().parse::<Module>(), Ok(module));
            assert_eq!(module.to_string(), module.as_str());
        }
        assert_eq!(" IPAM ".parse::<Module>(), Ok(Module::Ipam));
        assert!("ntp".parse::<Module>().is_err());
    }

    #[test]
    fn sets_parse_lists_all_and_nothing() {
        let set: ModuleSet = "dns, ipam".parse().expect("list");
        assert!(set.contains(Module::Ipam) && set.contains(Module::Dns));
        assert!(!set.contains(Module::Dhcp));
        assert_eq!(set.to_string(), "ipam,dns");
        assert_eq!("all".parse::<ModuleSet>(), Ok(ModuleSet::ALL));
        assert_eq!("".parse::<ModuleSet>(), Ok(ModuleSet::EMPTY));
        assert_eq!(ModuleSet::default(), ModuleSet::ALL);
        assert!("ipam,ntp".parse::<ModuleSet>().is_err());
    }

    #[test]
    fn sets_serialize_as_name_lists() {
        let mut set = ModuleSet::ALL;
        set.remove(Module::Dhcp);
        let json = serde_json::to_string(&set).expect("serialize");
        assert_eq!(json, r#"["ipam","dns","discovery"]"#);
        let back: ModuleSet = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, set);
        let text: ModuleSet = serde_json::from_str(r#""ipam,dhcp""#).expect("text");
        assert_eq!(text.names(), ["ipam", "dhcp"]);
        let all: ModuleSet = serde_json::from_str(r#"["all"]"#).expect("all");
        assert_eq!(all, ModuleSet::ALL);
        assert!(serde_json::from_str::<ModuleSet>(r#"["ipam","ntp"]"#).is_err());
    }
}
