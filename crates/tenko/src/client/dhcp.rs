//! `tenko dhcp ...`: the DHCP endpoints of the public API (`/api/v1/dhcp/...`): server
//! settings, scopes, exclusions, shared networks, pools, options, classes, policies, MAC
//! filters, reservations, leases, the lease history and the Kea export (MIG-16).
//!
//! # Arguments
//!
//! - A `PREFIX` is the identifier (a UUID) of the IPAM prefix a scope serves; `RANGE`,
//!   `INTERFACE` and the other `ID`s are UUIDs too. `ADDR` is an IPv4 address.
//! - An `OWNER` names the level an option set belongs to, in the form of the API path:
//!   `server`, `scope:<uuid>`, `pool:<uuid>`, `shared_network:<uuid>`, `policy:<uuid>` or
//!   `host:<uuid>`.
//! - Option data is `CODE=HEXDATA` (`6=c0000201c0000202`); the hexadecimal digits may be
//!   separated by `:`, `-` or `.`.
//! - Lease times are given as a set, `--lease-default`, `--lease-min` and `--lease-max`
//!   together, in seconds with `0 < min <= default <= max`.
//! - Class matches (`--match`) and policy files (`--file`) are JSON in the shape of the API
//!   (`{"vendor_class": {"value": "MSFT", "prefix": true}}` is one `Match`).
//!
//! Everything that can be checked without the server is checked before the request, and a
//! mistake is a usage error (status 2), as for `tenko dns`.
//!
//! # Structure
//!
//! Each command is first turned into a [`Request`] (method, path, query, body, how to show
//! the answer) by [`DhcpCommand::request`], which does the validation and needs no network;
//! [`run`] then sends it.

use std::{fmt::Write as _, net::Ipv4Addr, path::PathBuf, str::FromStr as _};

use clap::{ArgGroup, Args, Subcommand, ValueEnum};
use serde_json::{Map, Value, json};
use tenko_api::client::Client;
use tenko_core::{
    Timestamp,
    dhcp::{BindingState, LeaseTimes, MacPattern, Match, OptionKind, OptionOwner, OptionSpace},
    net::MacAddr,
    serde_util::{from_hex, to_hex},
};
use uuid::Uuid;

use super::{ClientOpts, Failure, Output, Target, table};
use crate::exit;

/// Subcommands of `tenko dhcp`.
#[derive(Debug, Clone, Subcommand)]
pub enum DhcpCommand {
    /// The server-wide settings: lease times, authority, conflict detection, history.
    Settings {
        /// The `settings` subcommand to run.
        #[command(subcommand)]
        action: SettingsCommand,
    },
    /// Scopes, one per IPAM network that serves DHCP.
    Scope {
        /// The `scope` subcommand to run.
        #[command(subcommand)]
        action: ScopeCommand,
    },
    /// Exclusion ranges of a scope.
    Exclusion {
        /// The `exclusion` subcommand to run.
        #[command(subcommand)]
        action: ExclusionCommand,
    },
    /// Shared networks (superscopes).
    SharedNetwork {
        /// The `shared-network` subcommand to run.
        #[command(subcommand)]
        action: SharedNetworkCommand,
    },
    /// Pools: the IPAM ranges of the kind pool, with their DHCP settings.
    Pool {
        /// The `pool` subcommand to run.
        #[command(subcommand)]
        action: PoolCommand,
    },
    /// Options: the catalog, custom definitions and the option sets of each level.
    #[command(name = "option")]
    Options {
        /// The `option` subcommand to run.
        #[command(subcommand)]
        action: OptionCommand,
    },
    /// Client classes.
    Class {
        /// The `class` subcommand to run.
        #[command(subcommand)]
        action: ClassCommand,
    },
    /// Policies: conditions that pick options or refuse a client.
    Policy {
        /// The `policy` subcommand to run.
        #[command(subcommand)]
        action: PolicyCommand,
    },
    /// MAC filters: allow and deny entries.
    Filter {
        /// The `filter` subcommand to run.
        #[command(subcommand)]
        action: FilterCommand,
    },
    /// Reservations: IPAM hosts of mode reserved.
    Reservation {
        /// The `reservation` subcommand to run.
        #[command(subcommand)]
        action: ReservationCommand,
    },
    /// Leases: list, show, release.
    Lease {
        /// The `lease` subcommand to run.
        #[command(subcommand)]
        action: LeaseCommand,
    },
    /// Read the lease history.
    History(HistoryArgs),
    /// Export the DHCP configuration and leases for another server (MIG-16).
    Export(ExportArgs),
}

/// Subcommands of `tenko dhcp settings`.
#[derive(Debug, Clone, Subcommand)]
pub enum SettingsCommand {
    /// Show the server settings.
    Show(NoArgs),
    /// Change the server settings.
    Set(SettingsSetArgs),
}

/// Subcommands of `tenko dhcp scope`.
#[derive(Debug, Clone, Subcommand)]
pub enum ScopeCommand {
    /// List the scopes.
    List(NoArgs),
    /// Show one scope.
    Show(PrefixArg),
    /// Create a scope for an IPAM network (a prefix of the kind network).
    Create(ScopeCreateArgs),
    /// Change a scope.
    Set(ScopeSetArgs),
    /// Delete a scope (the prefix stays).
    Delete(PrefixArg),
    /// Show how full a scope is.
    Utilization(PrefixArg),
    /// Show the options a client gets in a scope.
    Options(ScopeOptionsArgs),
}

/// Subcommands of `tenko dhcp exclusion`.
#[derive(Debug, Clone, Subcommand)]
pub enum ExclusionCommand {
    /// List the exclusion ranges of a scope.
    List(PrefixArg),
    /// Exclude a range of a scope.
    Add(ExclusionAddArgs),
    /// Delete an exclusion range.
    Delete(ExclusionDeleteArgs),
}

/// Subcommands of `tenko dhcp shared-network`.
#[derive(Debug, Clone, Subcommand)]
pub enum SharedNetworkCommand {
    /// List the shared networks.
    List(NoArgs),
    /// Show one shared network.
    Show(IdArg),
    /// Create a shared network.
    Create(SharedNetworkCreateArgs),
    /// Change a shared network.
    Set(SharedNetworkSetArgs),
    /// Delete a shared network.
    Delete(IdArg),
}

/// Subcommands of `tenko dhcp pool`.
#[derive(Debug, Clone, Subcommand)]
pub enum PoolCommand {
    /// List the pools.
    List(ScopeFilterArgs),
    /// Show one pool (its range).
    Show(RangeArg),
    /// Set the DHCP settings of a pool: the classes it admits and its lease times.
    Set(PoolSetArgs),
    /// Remove the DHCP settings of a pool (the range stays).
    Clear(RangeArg),
}

/// Subcommands of `tenko dhcp option`.
#[derive(Debug, Clone, Subcommand)]
pub enum OptionCommand {
    /// List the built-in options.
    Catalog(NoArgs),
    /// List the custom option definitions.
    Defs(NoArgs),
    /// Define a custom option.
    Define(OptionDefineArgs),
    /// Delete a custom option definition.
    Undefine(IdArg),
    /// Show the options set at one level.
    Show(OwnerArg),
    /// Replace the options set at one level.
    Set(OptionSetArgs),
    /// Clear the options set at one level.
    Clear(OwnerArg),
}

/// Subcommands of `tenko dhcp class`.
#[derive(Debug, Clone, Subcommand)]
pub enum ClassCommand {
    /// List the classes.
    List(NoArgs),
    /// Show one class.
    Show(IdArg),
    /// Create a class.
    Create(ClassCreateArgs),
    // WP8.4: changing a class.
    /// Change a class: its name, its matches (all replaced) or its description.
    Set(ClassSetArgs),
    /// Delete a class.
    Delete(IdArg),
}

/// Subcommands of `tenko dhcp policy`.
#[derive(Debug, Clone, Subcommand)]
pub enum PolicyCommand {
    /// List the policies.
    List(ScopeFilterArgs),
    /// Show one policy.
    Show(IdArg),
    /// Create a policy from a JSON file.
    Create(PolicyCreateArgs),
    // WP8.4: changing a policy.
    /// Change a policy: from a JSON file with the parts to change, and the flags.
    Set(PolicySetArgs),
    /// Delete a policy.
    Delete(IdArg),
}

/// Subcommands of `tenko dhcp filter`.
#[derive(Debug, Clone, Subcommand)]
pub enum FilterCommand {
    /// List the MAC filters.
    List(NoArgs),
    /// Add a MAC filter.
    Add(FilterAddArgs),
    /// Delete a MAC filter.
    Delete(IdArg),
}

/// Subcommands of `tenko dhcp reservation`.
#[derive(Debug, Clone, Subcommand)]
pub enum ReservationCommand {
    /// List the reservations.
    List(ScopeFilterArgs),
    /// Show the reservation of an interface.
    Show(InterfaceArg),
}

/// Subcommands of `tenko dhcp lease`.
#[derive(Debug, Clone, Subcommand)]
pub enum LeaseCommand {
    /// List the leases.
    List(LeaseListArgs),
    /// Show the lease of an address.
    Show(LeaseShowArgs),
    /// Release a lease: the address returns to the pool.
    Release(LeaseReleaseArgs),
}

/// A command without arguments.
#[derive(Debug, Clone, Args)]
pub struct NoArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
}

/// A command that takes a scope.
#[derive(Debug, Clone, Args)]
pub struct PrefixArg {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The prefix the scope serves (identifier).
    #[arg(value_name = "PREFIX")]
    pub prefix: String,
}

/// A command that takes a pool.
#[derive(Debug, Clone, Args)]
pub struct RangeArg {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The IPAM range of the pool (identifier).
    #[arg(value_name = "RANGE")]
    pub range: String,
}

/// A command that takes the owner of an option set.
#[derive(Debug, Clone, Args)]
pub struct OwnerArg {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The level: `server`, `scope:<uuid>`, `pool:<uuid>`, `shared_network:<uuid>`,
    /// `policy:<uuid>` or `host:<uuid>`.
    #[arg(value_name = "OWNER")]
    pub owner: String,
}

/// A command that takes an object by identifier.
#[derive(Debug, Clone, Args)]
pub struct IdArg {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The identifier (a UUID).
    #[arg(value_name = "ID")]
    pub id: String,
}

/// A command that takes the IPAM interface of a reservation.
#[derive(Debug, Clone, Args)]
pub struct InterfaceArg {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The IPAM interface (identifier).
    #[arg(value_name = "INTERFACE")]
    pub interface: String,
}

/// A list that can be limited to one scope.
#[derive(Debug, Clone, Args)]
pub struct ScopeFilterArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// Only this scope (prefix identifier).
    #[arg(long, value_name = "PREFIX")]
    pub scope: Option<String>,
}

/// The lease time flags: one set of three.
#[derive(Debug, Clone, Default, Args)]
pub struct LeaseFlags {
    /// The lease time granted when the client asks for none, in seconds.
    #[arg(long, value_name = "SECS")]
    pub lease_default: Option<u32>,
    /// The shortest lease time granted, in seconds.
    #[arg(long, value_name = "SECS")]
    pub lease_min: Option<u32>,
    /// The longest lease time granted, in seconds.
    #[arg(long, value_name = "SECS")]
    pub lease_max: Option<u32>,
}

impl LeaseFlags {
    /// The lease times as the API's `LeaseTimes`, `None` when no flag was given.
    fn times(&self) -> Result<Option<Value>, Failure> {
        let (default, min, max) = match (self.lease_default, self.lease_min, self.lease_max) {
            (None, None, None) => return Ok(None),
            (Some(default), Some(min), Some(max)) => (default, min, max),
            _ => {
                return Err(usage(
                    "--lease-default, --lease-min and --lease-max go together: the API takes \
                     the three lease times as one set",
                ));
            }
        };
        let times = LeaseTimes {
            default_secs: default,
            min_secs: min,
            max_secs: max,
            t1_secs: None,
            t2_secs: None,
        };
        times
            .validate("lease")
            .map_err(|error| usage(format!("lease times: {error}")))?;
        Ok(Some(json!({
            "default_secs": default,
            "min_secs": min,
            "max_secs": max,
        })))
    }
}

/// Arguments of `tenko dhcp settings set`.
#[derive(Debug, Clone, Args)]
pub struct SettingsSetArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The server's default lease times.
    #[command(flatten)]
    pub lease: LeaseFlags,
    /// Whether the server is authoritative (answers NAK for addresses it does not know).
    #[arg(long, value_name = "BOOL")]
    pub authoritative: Option<bool>,
    /// How many days of lease history are kept.
    #[arg(long, value_name = "DAYS")]
    pub history_days: Option<u32>,
    /// Whether the server probes an address before it offers it.
    #[arg(long, value_name = "BOOL")]
    pub conflict_detection: Option<bool>,
}

/// Arguments of `tenko dhcp scope create`.
#[derive(Debug, Clone, Args)]
pub struct ScopeCreateArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The prefix to serve (identifier).
    #[arg(value_name = "PREFIX")]
    pub prefix: String,
    /// The scope's own lease times.
    #[command(flatten)]
    pub lease: LeaseFlags,
    /// Whether the scope is authoritative; the server's setting when absent.
    #[arg(long, value_name = "BOOL")]
    pub authoritative: Option<bool>,
    /// Create the scope switched off.
    #[arg(long)]
    pub disabled: bool,
    /// Serve only clients that match an allow filter.
    #[arg(long)]
    pub restricted: bool,
    /// Put the scope in this shared network (identifier).
    #[arg(long, value_name = "ID")]
    pub shared_network: Option<String>,
    /// The server identifier (option 54) for the scope's clients.
    #[arg(long, value_name = "ADDR")]
    pub server_id: Option<String>,
    /// A class the scope admits (identifier). Repeat for more; none admits every client.
    #[arg(long = "class", value_name = "ID")]
    pub classes: Vec<String>,
    /// Free text.
    #[arg(long, value_name = "TEXT")]
    pub description: Option<String>,
}

/// Arguments of `tenko dhcp scope set`.
#[derive(Debug, Clone, Args)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "command line switches, each of its own"
)]
pub struct ScopeSetArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The scope (prefix identifier).
    #[arg(value_name = "PREFIX")]
    pub prefix: String,
    /// The scope's own lease times.
    #[command(flatten)]
    pub lease: LeaseFlags,
    /// Drop the scope's own lease times: it uses the server's again.
    #[arg(long, conflicts_with_all = ["lease_default", "lease_min", "lease_max"])]
    pub clear_lease: bool,
    /// Whether the scope is authoritative.
    #[arg(long, value_name = "BOOL")]
    pub authoritative: Option<bool>,
    /// Switch the scope off.
    #[arg(long, conflicts_with = "enabled")]
    pub disabled: bool,
    /// Switch the scope on.
    #[arg(long)]
    pub enabled: bool,
    /// Serve only clients that match an allow filter.
    #[arg(long, conflicts_with = "unrestricted")]
    pub restricted: bool,
    /// Serve every client again.
    #[arg(long)]
    pub unrestricted: bool,
    /// Move the scope to this shared network (identifier).
    #[arg(long, value_name = "ID")]
    pub shared_network: Option<String>,
    /// The server identifier (option 54) for the scope's clients.
    #[arg(long, value_name = "ADDR")]
    pub server_id: Option<String>,
    /// The classes the scope admits, replacing all of them (identifier). Repeat for more.
    #[arg(long = "class", value_name = "ID", conflicts_with = "no_classes")]
    pub classes: Vec<String>,
    /// Admit every client again.
    #[arg(long)]
    pub no_classes: bool,
    /// Free text.
    #[arg(long, value_name = "TEXT")]
    pub description: Option<String>,
}

/// Arguments of `tenko dhcp scope options`.
#[derive(Debug, Clone, Args)]
pub struct ScopeOptionsArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The scope (prefix identifier).
    #[arg(value_name = "PREFIX")]
    pub prefix: String,
    /// The client's hardware address, to include its reservation, classes and policies.
    #[arg(long, value_name = "MAC")]
    pub mac: Option<String>,
    /// The client identifier (option 61) in hexadecimal.
    #[arg(long, value_name = "HEX")]
    pub client_id: Option<String>,
    /// The vendor class identifier (option 60).
    #[arg(long, value_name = "TEXT")]
    pub vendor_class: Option<String>,
    /// The user class (option 77).
    #[arg(long, value_name = "TEXT")]
    pub user_class: Option<String>,
}

/// Arguments of `tenko dhcp exclusion add`.
#[derive(Debug, Clone, Args)]
pub struct ExclusionAddArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The scope (prefix identifier).
    #[arg(value_name = "PREFIX")]
    pub prefix: String,
    /// The first address of the range.
    #[arg(value_name = "FIRST")]
    pub first: String,
    /// The last address of the range.
    #[arg(value_name = "LAST")]
    pub last: String,
    /// Free text.
    #[arg(long, value_name = "TEXT")]
    pub description: Option<String>,
}

/// Arguments of `tenko dhcp exclusion delete`.
#[derive(Debug, Clone, Args)]
pub struct ExclusionDeleteArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The scope (prefix identifier).
    #[arg(value_name = "PREFIX")]
    pub prefix: String,
    /// The exclusion (identifier).
    #[arg(value_name = "ID")]
    pub id: String,
}

/// Arguments of `tenko dhcp shared-network create`.
#[derive(Debug, Clone, Args)]
pub struct SharedNetworkCreateArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// A unique name.
    #[arg(value_name = "NAME")]
    pub name: String,
    /// The network interface the shared network is served on.
    #[arg(long, value_name = "IF")]
    pub interface: Option<String>,
    /// Free text.
    #[arg(long, value_name = "TEXT")]
    pub description: Option<String>,
}

/// Arguments of `tenko dhcp shared-network set`.
#[derive(Debug, Clone, Args)]
pub struct SharedNetworkSetArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The shared network (identifier).
    #[arg(value_name = "ID")]
    pub id: String,
    /// A new name.
    #[arg(long, value_name = "NAME")]
    pub name: Option<String>,
    /// The network interface the shared network is served on.
    #[arg(long, value_name = "IF")]
    pub interface: Option<String>,
    /// Free text.
    #[arg(long, value_name = "TEXT")]
    pub description: Option<String>,
}

/// Arguments of `tenko dhcp pool set`.
#[derive(Debug, Clone, Args)]
pub struct PoolSetArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The IPAM range of the pool (identifier).
    #[arg(value_name = "RANGE")]
    pub range: String,
    /// A class the pool admits (identifier). Repeat for more; none admits every client.
    #[arg(long = "class", value_name = "ID")]
    pub classes: Vec<String>,
    /// The pool's own lease times.
    #[command(flatten)]
    pub lease: LeaseFlags,
}

/// Arguments of `tenko dhcp option define`.
#[derive(Debug, Clone, Args)]
pub struct OptionDefineArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The option code, 1 to 65535 (1 to 254 in the DHCPv4 spaces).
    #[arg(long, value_name = "N")]
    pub code: u16,
    /// The option name.
    #[arg(long, value_name = "NAME")]
    pub name: String,
    /// The data kind: `ipv4_address`, `ipv6_address`, `ipv6_prefix`, `u8`, `u16`, `u32`,
    /// `i32`, `bool`, `string`, `fqdn`, `classless_routes`, `binary` or `empty`.
    #[arg(long, value_name = "KIND")]
    pub kind: String,
    /// The value is a list of the kind.
    #[arg(long)]
    pub array: bool,
    /// The option space: `dhcp4` when absent, or a vendor space name.
    #[arg(long, value_name = "SPACE")]
    pub space: Option<String>,
    /// The vendor class a vendor space belongs to.
    #[arg(long, value_name = "TEXT")]
    pub vendor_class: Option<String>,
    /// Free text.
    #[arg(long, value_name = "TEXT")]
    pub description: Option<String>,
}

/// Arguments of `tenko dhcp option set`.
#[derive(Debug, Clone, Args)]
pub struct OptionSetArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The level: `server`, `scope:<uuid>`, `pool:<uuid>`, `shared_network:<uuid>`,
    /// `policy:<uuid>` or `host:<uuid>`.
    #[arg(value_name = "OWNER")]
    pub owner: String,
    /// One option as `CODE=HEXDATA`; they replace the options of the level.
    #[arg(value_name = "CODE=HEXDATA", required = true)]
    pub values: Vec<String>,
}

/// Arguments of `tenko dhcp class create`.
#[derive(Debug, Clone, Args)]
pub struct ClassCreateArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// A unique name.
    #[arg(value_name = "NAME")]
    pub name: String,
    /// One test as JSON, for example `{"vendor_class":{"value":"MSFT","prefix":true}}`. Repeat
    /// for more; a client is in the class when any of them holds.
    #[arg(long = "match", value_name = "JSON", required = true)]
    pub matches: Vec<String>,
    /// Free text.
    #[arg(long, value_name = "TEXT")]
    pub description: Option<String>,
}

/// Arguments of `tenko dhcp policy create`.
#[derive(Debug, Clone, Args)]
pub struct PolicyCreateArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// A JSON file with the policy as the API takes it (`DhcpPolicyCreate`).
    #[arg(long, value_name = "FILE")]
    pub file: PathBuf,
}

// WP8.4: the arguments of `class set` and `policy set`.
/// Arguments of `tenko dhcp class set`.
#[derive(Debug, Clone, Args)]
pub struct ClassSetArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The class (identifier).
    #[arg(value_name = "ID")]
    pub id: String,
    /// A new unique name.
    #[arg(long, value_name = "NAME")]
    pub name: Option<String>,
    /// One test as JSON, as for `class create`; the tests given replace all of the class's.
    #[arg(long = "match", value_name = "JSON")]
    pub matches: Vec<String>,
    /// Free text; an empty text clears it.
    #[arg(long, value_name = "TEXT")]
    pub description: Option<String>,
}

/// Arguments of `tenko dhcp policy set`.
#[derive(Debug, Clone, Args)]
pub struct PolicySetArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The policy (identifier).
    #[arg(value_name = "ID")]
    pub id: String,
    /// A JSON file with the parts to change as the API takes them (`DhcpPolicyPatch`:
    /// `name`, `order`, `enabled`, `condition`, `action`, `description`).
    #[arg(long, value_name = "FILE")]
    pub file: Option<PathBuf>,
    /// A new name, unique in the scope.
    #[arg(long, value_name = "NAME")]
    pub name: Option<String>,
    /// The processing order in the scope, lowest first.
    #[arg(long, value_name = "N")]
    pub order: Option<u32>,
    /// Whether the policy applies.
    #[arg(long, value_name = "BOOL")]
    pub enabled: Option<bool>,
    /// Free text; an empty text clears it.
    #[arg(long, value_name = "TEXT")]
    pub description: Option<String>,
}

/// Arguments of `tenko dhcp filter add`.
#[derive(Debug, Clone, Args)]
#[command(group(ArgGroup::new("kind").required(true).args(["allow", "deny"])))]
pub struct FilterAddArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The hardware addresses: six octets, any of them `*`, or a prefix ending in `*`
    /// (`00:00:5e:00:53:*`).
    #[arg(value_name = "MAC-PATTERN")]
    pub mac_pattern: String,
    /// Clients that match may be served by restricted scopes.
    #[arg(long)]
    pub allow: bool,
    /// Clients that match are never served.
    #[arg(long)]
    pub deny: bool,
    /// Free text.
    #[arg(long, value_name = "TEXT")]
    pub note: Option<String>,
}

/// Arguments of `tenko dhcp lease list`.
#[derive(Debug, Clone, Args)]
pub struct LeaseListArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// Only this scope (prefix identifier).
    #[arg(long, value_name = "PREFIX")]
    pub scope: Option<String>,
    /// Only addresses that match this text.
    #[arg(long, value_name = "TEXT")]
    pub addr: Option<String>,
    /// Only this hardware address.
    #[arg(long, value_name = "MAC")]
    pub mac: Option<String>,
    /// Only host names that match this text.
    #[arg(long, value_name = "TEXT")]
    pub name: Option<String>,
    /// Only leases in this state: `free`, `active`, `expired`, `released`, `abandoned`,
    /// `reset` or `backup`.
    #[arg(long, value_name = "STATE")]
    pub state: Option<String>,
    /// Show one page of at most this many leases (and the cursor of the next one) instead
    /// of all of them.
    #[arg(long, value_name = "N")]
    pub limit: Option<u32>,
    /// Continue after the cursor an earlier page printed.
    #[arg(long, value_name = "CURSOR")]
    pub cursor: Option<String>,
}

/// Arguments of `tenko dhcp lease show`.
#[derive(Debug, Clone, Args)]
pub struct LeaseShowArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The leased address.
    #[arg(value_name = "ADDR")]
    pub addr: String,
    /// The VRF of the address (identifier); the default VRF when absent.
    #[arg(long, value_name = "ID")]
    pub vrf: Option<String>,
}

/// Arguments of `tenko dhcp lease release`.
#[derive(Debug, Clone, Args)]
pub struct LeaseReleaseArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The leased address.
    #[arg(value_name = "ADDR")]
    pub addr: String,
    /// The VRF of the address (identifier); the default VRF when absent.
    #[arg(long, value_name = "ID")]
    pub vrf: Option<String>,
    /// Why the lease is released, for the audit log.
    #[arg(long, value_name = "TEXT")]
    pub reason: Option<String>,
}

/// Arguments of `tenko dhcp history`.
#[derive(Debug, Clone, Args)]
pub struct HistoryArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// Only addresses that match this text.
    #[arg(long, value_name = "TEXT")]
    pub addr: Option<String>,
    /// Only this hardware address.
    #[arg(long, value_name = "MAC")]
    pub mac: Option<String>,
    /// Only this scope (prefix identifier).
    #[arg(long, value_name = "PREFIX")]
    pub scope: Option<String>,
    /// Only events from this time on (RFC 3339, for example `2026-01-31T08:00:00Z`).
    #[arg(long, value_name = "TIME")]
    pub from: Option<String>,
    /// Only events before this time (RFC 3339).
    #[arg(long, value_name = "TIME")]
    pub to: Option<String>,
    /// Show one page of at most this many events (and the cursor of the next one) instead
    /// of all of them.
    #[arg(long, value_name = "N")]
    pub limit: Option<u32>,
    /// Continue after the cursor an earlier page printed.
    #[arg(long, value_name = "CURSOR")]
    pub cursor: Option<String>,
}

/// The formats `tenko dhcp export` writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ExportFormat {
    /// Kea JSON (`Dhcp4`), with the leases as a memfile CSV.
    Kea,
}

impl ExportFormat {
    const fn api(self) -> &'static str {
        match self {
            Self::Kea => "kea",
        }
    }
}

/// Arguments of `tenko dhcp export`.
#[derive(Debug, Clone, Args)]
pub struct ExportArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The format of the export.
    #[arg(long, value_enum, default_value = "kea")]
    pub format: ExportFormat,
    /// Write the export to this file instead of standard output.
    #[arg(long, short = 'o', value_name = "FILE")]
    pub file: Option<PathBuf>,
    /// Leave the leases out.
    #[arg(long)]
    pub no_leases: bool,
}

// ---------------------------------------------------------------------------------------
// Names and connection options

impl DhcpCommand {
    /// The connection options of the subcommand.
    pub fn client(&self) -> &ClientOpts {
        match self {
            Self::Settings { action } => match action {
                SettingsCommand::Show(a) => &a.client,
                SettingsCommand::Set(a) => &a.client,
            },
            Self::Scope { action } => match action {
                ScopeCommand::List(a) => &a.client,
                ScopeCommand::Show(a) | ScopeCommand::Delete(a) | ScopeCommand::Utilization(a) => {
                    &a.client
                }
                ScopeCommand::Create(a) => &a.client,
                ScopeCommand::Set(a) => &a.client,
                ScopeCommand::Options(a) => &a.client,
            },
            Self::Exclusion { action } => match action {
                ExclusionCommand::List(a) => &a.client,
                ExclusionCommand::Add(a) => &a.client,
                ExclusionCommand::Delete(a) => &a.client,
            },
            Self::SharedNetwork { action } => match action {
                SharedNetworkCommand::List(a) => &a.client,
                SharedNetworkCommand::Show(a) | SharedNetworkCommand::Delete(a) => &a.client,
                SharedNetworkCommand::Create(a) => &a.client,
                SharedNetworkCommand::Set(a) => &a.client,
            },
            Self::Pool { action } => match action {
                PoolCommand::List(a) => &a.client,
                PoolCommand::Show(a) | PoolCommand::Clear(a) => &a.client,
                PoolCommand::Set(a) => &a.client,
            },
            Self::Options { action } => match action {
                OptionCommand::Catalog(a) | OptionCommand::Defs(a) => &a.client,
                OptionCommand::Define(a) => &a.client,
                OptionCommand::Undefine(a) => &a.client,
                OptionCommand::Show(a) | OptionCommand::Clear(a) => &a.client,
                OptionCommand::Set(a) => &a.client,
            },
            Self::Class { action } => match action {
                ClassCommand::List(a) => &a.client,
                ClassCommand::Show(a) | ClassCommand::Delete(a) => &a.client,
                ClassCommand::Create(a) => &a.client,
                // WP8.4: class set.
                ClassCommand::Set(a) => &a.client,
            },
            Self::Policy { action } => match action {
                PolicyCommand::List(a) => &a.client,
                PolicyCommand::Show(a) | PolicyCommand::Delete(a) => &a.client,
                PolicyCommand::Create(a) => &a.client,
                // WP8.4: policy set.
                PolicyCommand::Set(a) => &a.client,
            },
            Self::Filter { action } => match action {
                FilterCommand::List(a) => &a.client,
                FilterCommand::Add(a) => &a.client,
                FilterCommand::Delete(a) => &a.client,
            },
            Self::Reservation { action } => match action {
                ReservationCommand::List(a) => &a.client,
                ReservationCommand::Show(a) => &a.client,
            },
            Self::Lease { action } => match action {
                LeaseCommand::List(a) => &a.client,
                LeaseCommand::Show(a) => &a.client,
                LeaseCommand::Release(a) => &a.client,
            },
            Self::History(a) => &a.client,
            Self::Export(a) => &a.client,
        }
    }

    /// The name as typed.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Settings { action } => match action {
                SettingsCommand::Show(_) => "dhcp settings show",
                SettingsCommand::Set(_) => "dhcp settings set",
            },
            Self::Scope { action } => match action {
                ScopeCommand::List(_) => "dhcp scope list",
                ScopeCommand::Show(_) => "dhcp scope show",
                ScopeCommand::Create(_) => "dhcp scope create",
                ScopeCommand::Set(_) => "dhcp scope set",
                ScopeCommand::Delete(_) => "dhcp scope delete",
                ScopeCommand::Utilization(_) => "dhcp scope utilization",
                ScopeCommand::Options(_) => "dhcp scope options",
            },
            Self::Exclusion { action } => match action {
                ExclusionCommand::List(_) => "dhcp exclusion list",
                ExclusionCommand::Add(_) => "dhcp exclusion add",
                ExclusionCommand::Delete(_) => "dhcp exclusion delete",
            },
            Self::SharedNetwork { action } => match action {
                SharedNetworkCommand::List(_) => "dhcp shared-network list",
                SharedNetworkCommand::Show(_) => "dhcp shared-network show",
                SharedNetworkCommand::Create(_) => "dhcp shared-network create",
                SharedNetworkCommand::Set(_) => "dhcp shared-network set",
                SharedNetworkCommand::Delete(_) => "dhcp shared-network delete",
            },
            Self::Pool { action } => match action {
                PoolCommand::List(_) => "dhcp pool list",
                PoolCommand::Show(_) => "dhcp pool show",
                PoolCommand::Set(_) => "dhcp pool set",
                PoolCommand::Clear(_) => "dhcp pool clear",
            },
            Self::Options { action } => match action {
                OptionCommand::Catalog(_) => "dhcp option catalog",
                OptionCommand::Defs(_) => "dhcp option defs",
                OptionCommand::Define(_) => "dhcp option define",
                OptionCommand::Undefine(_) => "dhcp option undefine",
                OptionCommand::Show(_) => "dhcp option show",
                OptionCommand::Set(_) => "dhcp option set",
                OptionCommand::Clear(_) => "dhcp option clear",
            },
            Self::Class { action } => match action {
                ClassCommand::List(_) => "dhcp class list",
                ClassCommand::Show(_) => "dhcp class show",
                ClassCommand::Create(_) => "dhcp class create",
                // WP8.4: class set.
                ClassCommand::Set(_) => "dhcp class set",
                ClassCommand::Delete(_) => "dhcp class delete",
            },
            Self::Policy { action } => match action {
                PolicyCommand::List(_) => "dhcp policy list",
                PolicyCommand::Show(_) => "dhcp policy show",
                PolicyCommand::Create(_) => "dhcp policy create",
                // WP8.4: policy set.
                PolicyCommand::Set(_) => "dhcp policy set",
                PolicyCommand::Delete(_) => "dhcp policy delete",
            },
            Self::Filter { action } => match action {
                FilterCommand::List(_) => "dhcp filter list",
                FilterCommand::Add(_) => "dhcp filter add",
                FilterCommand::Delete(_) => "dhcp filter delete",
            },
            Self::Reservation { action } => match action {
                ReservationCommand::List(_) => "dhcp reservation list",
                ReservationCommand::Show(_) => "dhcp reservation show",
            },
            Self::Lease { action } => match action {
                LeaseCommand::List(_) => "dhcp lease list",
                LeaseCommand::Show(_) => "dhcp lease show",
                LeaseCommand::Release(_) => "dhcp lease release",
            },
            Self::History(_) => "dhcp history",
            Self::Export(_) => "dhcp export",
        }
    }
}

// ---------------------------------------------------------------------------------------
// Requests

/// An HTTP method of the DHCP endpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// `GET`.
    Get,
    /// `POST`.
    Post,
    /// `PUT`.
    Put,
    /// `PATCH`.
    Patch,
    /// `DELETE`.
    Delete,
}

/// The columns of a table: the title and the path of the field in an item.
type Columns = &'static [(&'static str, &'static str)];

/// How the answer to a request is shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Present {
    /// A paged list, read to its end, as a table.
    All(Columns),
    /// One page of a list, as a table, with the cursor of the next page.
    Page(Columns),
    /// A list without pages (a JSON array), as a table.
    Array(Columns),
    /// One object, as `name value` lines.
    Item,
    /// Nothing comes back; the text says what was done.
    Done(String),
    /// A document that goes to standard output or a file.
    Export(Option<PathBuf>),
}

/// What a command sends to the API.
#[derive(Debug, Clone, PartialEq)]
pub struct Request {
    /// The method.
    pub method: Method,
    /// The path below `/api/v1`.
    pub path: String,
    /// The query parameters, in order.
    pub query: Vec<(&'static str, String)>,
    /// The JSON body of a `POST`, `PUT` or `PATCH`.
    pub body: Option<Value>,
    /// How the answer is shown.
    pub present: Present,
}

impl Request {
    fn new(method: Method, path: impl Into<String>, present: Present) -> Self {
        Self {
            method,
            path: path.into(),
            query: Vec::new(),
            body: None,
            present,
        }
    }

    fn get(path: impl Into<String>, present: Present) -> Self {
        Self::new(Method::Get, path, present)
    }

    fn delete(path: impl Into<String>, done: impl Into<String>) -> Self {
        Self::new(Method::Delete, path, Present::Done(done.into()))
    }

    fn with_body(mut self, body: Value) -> Self {
        self.body = Some(body);
        self
    }

    fn with_query(mut self, key: &'static str, value: Option<String>) -> Self {
        if let Some(value) = value {
            self.query.push((key, value));
        }
        self
    }
}

const SCOPE_COLUMNS: Columns = &[
    ("PREFIX", "prefix"),
    ("NETWORK", "cidr"),
    ("ENABLED", "enabled"),
    ("POOLS", "pools"),
    ("LEASES", "leases"),
];
const EXCLUSION_COLUMNS: Columns = &[
    ("ID", "id"),
    ("FIRST", "first"),
    ("LAST", "last"),
    ("DESCRIPTION", "description"),
];
const SHARED_NETWORK_COLUMNS: Columns = &[
    ("ID", "id"),
    ("NAME", "name"),
    ("INTERFACE", "interface"),
    ("DESCRIPTION", "description"),
];
const POOL_COLUMNS: Columns = &[
    ("RANGE", "range"),
    ("SCOPE", "prefix"),
    ("FIRST", "first"),
    ("LAST", "last"),
    ("SIZE", "size"),
    ("LEASED", "leased"),
];
const CATALOG_COLUMNS: Columns = &[
    ("SPACE", "space"),
    ("CODE", "code"),
    ("NAME", "name"),
    ("KIND", "kind"),
    ("ARRAY", "array"),
    ("MANAGED", "server_managed"),
];
const OPTION_DEF_COLUMNS: Columns = &[
    ("ID", "id"),
    ("SPACE", "space"),
    ("CODE", "code"),
    ("NAME", "name"),
    ("KIND", "kind"),
    ("USED BY", "used_by"),
];
const CLASS_COLUMNS: Columns = &[
    ("ID", "id"),
    ("NAME", "name"),
    ("USED BY", "used_by"),
    ("DESCRIPTION", "description"),
];
const POLICY_COLUMNS: Columns = &[
    ("ID", "id"),
    ("NAME", "name"),
    ("SCOPE", "scope"),
    ("ORDER", "order"),
    ("ENABLED", "enabled"),
];
const FILTER_COLUMNS: Columns = &[
    ("ID", "id"),
    ("MAC", "mac"),
    ("KIND", "kind"),
    ("NOTE", "note"),
];
const RESERVATION_COLUMNS: Columns = &[
    ("INTERFACE", "interface"),
    ("HOST", "host_name"),
    ("MAC", "mac"),
    ("ADDRESS", "address"),
    ("SCOPE", "scope"),
];
const LEASE_COLUMNS: Columns = &[
    ("ADDRESS", "addr"),
    ("STATE", "state"),
    ("ENDS", "ends"),
    ("HOSTNAME", "hostname"),
    ("SCOPE", "scope"),
];
const HISTORY_COLUMNS: Columns = &[
    ("AT", "at"),
    ("EVENT", "kind"),
    ("ADDRESS", "addr"),
    ("STATE", "state"),
    ("HOSTNAME", "hostname"),
];

impl DhcpCommand {
    /// What the command sends to the API, after the checks that need no server.
    ///
    /// # Errors
    ///
    /// A usage error (status 2): an argument that is not what it should be, a file that
    /// cannot be read, or nothing to change.
    pub fn request(&self) -> Result<Request, Failure> {
        match self {
            Self::Settings { action } => settings(action),
            Self::Scope { action } => scope(action),
            Self::Exclusion { action } => exclusion(action),
            Self::SharedNetwork { action } => shared_network(action),
            Self::Pool { action } => pool(action),
            Self::Options { action } => options(action),
            Self::Class { action } => class(action),
            Self::Policy { action } => policy(action),
            Self::Filter { action } => filter(action),
            Self::Reservation { action } => reservation(action),
            Self::Lease { action } => lease(action),
            Self::History(args) => history(args),
            Self::Export(args) => Ok(export(args)),
        }
    }
}

fn settings(action: &SettingsCommand) -> Result<Request, Failure> {
    match action {
        SettingsCommand::Show(_) => Ok(Request::get("/dhcp/settings", Present::Item)),
        SettingsCommand::Set(args) => {
            let mut body = Map::new();
            insert(&mut body, "lease", args.lease.times()?);
            insert(&mut body, "authoritative", args.authoritative);
            insert(&mut body, "conflict_detection", args.conflict_detection);
            insert(&mut body, "history_days", args.history_days);
            Ok(
                Request::new(Method::Put, "/dhcp/settings", Present::Item)
                    .with_body(changes(body)?),
            )
        }
    }
}

fn scope(action: &ScopeCommand) -> Result<Request, Failure> {
    match action {
        ScopeCommand::List(_) => Ok(Request::get("/dhcp/scopes", Present::All(SCOPE_COLUMNS))),
        ScopeCommand::Show(args) => Ok(Request::get(scope_path(&args.prefix)?, Present::Item)),
        ScopeCommand::Create(args) => {
            let mut body = Map::new();
            body.insert("prefix".to_owned(), json!(id("prefix", &args.prefix)?));
            insert(&mut body, "enabled", args.disabled.then_some(false));
            insert(&mut body, "lease", args.lease.times()?);
            insert(&mut body, "authoritative", args.authoritative);
            insert(
                &mut body,
                "server_id",
                server_id(args.server_id.as_deref())?,
            );
            insert(
                &mut body,
                "shared_network",
                optional_id("shared network", args.shared_network.as_deref())?,
            );
            insert(&mut body, "restricted", args.restricted.then_some(true));
            if !args.classes.is_empty() {
                body.insert("classes".to_owned(), json!(ids("class", &args.classes)?));
            }
            insert(&mut body, "description", args.description.as_deref());
            Ok(Request::new(Method::Post, "/dhcp/scopes", Present::Item)
                .with_body(Value::Object(body)))
        }
        ScopeCommand::Set(args) => {
            let mut body = Map::new();
            insert(&mut body, "enabled", flag_pair(args.enabled, args.disabled));
            insert(&mut body, "lease", args.lease.times()?);
            insert(&mut body, "clear_lease", args.clear_lease.then_some(true));
            insert(&mut body, "authoritative", args.authoritative);
            insert(
                &mut body,
                "server_id",
                server_id(args.server_id.as_deref())?,
            );
            insert(
                &mut body,
                "shared_network",
                optional_id("shared network", args.shared_network.as_deref())?,
            );
            insert(
                &mut body,
                "restricted",
                flag_pair(args.restricted, args.unrestricted),
            );
            if args.no_classes {
                body.insert("classes".to_owned(), json!([]));
            } else if !args.classes.is_empty() {
                body.insert("classes".to_owned(), json!(ids("class", &args.classes)?));
            }
            insert(&mut body, "description", args.description.as_deref());
            Ok(
                Request::new(Method::Patch, scope_path(&args.prefix)?, Present::Item)
                    .with_body(changes(body)?),
            )
        }
        ScopeCommand::Delete(args) => {
            let path = scope_path(&args.prefix)?;
            Ok(Request::delete(
                path,
                format!("deleted the scope of prefix {}", args.prefix.trim()),
            ))
        }
        ScopeCommand::Utilization(args) => Ok(Request::get(
            format!("{}/utilization", scope_path(&args.prefix)?),
            Present::Item,
        )),
        ScopeCommand::Options(args) => {
            let mac = args.mac.as_deref().map(mac_address).transpose()?;
            let client_id = args
                .client_id
                .as_deref()
                .map(|text| hex("client identifier", text).map(|bytes| to_hex(&bytes)))
                .transpose()?;
            Ok(Request::get(
                format!("{}/effective-options", scope_path(&args.prefix)?),
                Present::Item,
            )
            .with_query("mac", mac)
            .with_query("client_id", client_id)
            .with_query("vendor_class", args.vendor_class.clone())
            .with_query("user_class", args.user_class.clone()))
        }
    }
}

fn exclusion(action: &ExclusionCommand) -> Result<Request, Failure> {
    match action {
        ExclusionCommand::List(args) => Ok(Request::get(
            format!("{}/exclusions", scope_path(&args.prefix)?),
            Present::All(EXCLUSION_COLUMNS),
        )),
        ExclusionCommand::Add(args) => {
            let first = ipv4("first address", &args.first)?;
            let last = ipv4("last address", &args.last)?;
            if first > last {
                return Err(usage(format!(
                    "the range runs backwards: {first} is above {last}"
                )));
            }
            let mut body = Map::new();
            body.insert("first".to_owned(), json!(first.to_string()));
            body.insert("last".to_owned(), json!(last.to_string()));
            insert(&mut body, "description", args.description.as_deref());
            Ok(Request::new(
                Method::Post,
                format!("{}/exclusions", scope_path(&args.prefix)?),
                Present::Item,
            )
            .with_body(Value::Object(body)))
        }
        ExclusionCommand::Delete(args) => {
            let exclusion = id("exclusion", &args.id)?;
            Ok(Request::delete(
                format!("{}/exclusions/{exclusion}", scope_path(&args.prefix)?),
                format!("deleted the exclusion {exclusion}"),
            ))
        }
    }
}

fn shared_network(action: &SharedNetworkCommand) -> Result<Request, Failure> {
    match action {
        SharedNetworkCommand::List(_) => Ok(Request::get(
            "/dhcp/shared-networks",
            Present::All(SHARED_NETWORK_COLUMNS),
        )),
        SharedNetworkCommand::Show(args) => {
            Ok(Request::get(shared_network_path(&args.id)?, Present::Item))
        }
        SharedNetworkCommand::Create(args) => {
            let mut body = Map::new();
            body.insert("name".to_owned(), json!(args.name));
            insert(&mut body, "interface", args.interface.as_deref());
            insert(&mut body, "description", args.description.as_deref());
            Ok(
                Request::new(Method::Post, "/dhcp/shared-networks", Present::Item)
                    .with_body(Value::Object(body)),
            )
        }
        SharedNetworkCommand::Set(args) => {
            let mut body = Map::new();
            insert(&mut body, "name", args.name.as_deref());
            insert(&mut body, "interface", args.interface.as_deref());
            insert(&mut body, "description", args.description.as_deref());
            Ok(
                Request::new(Method::Patch, shared_network_path(&args.id)?, Present::Item)
                    .with_body(changes(body)?),
            )
        }
        SharedNetworkCommand::Delete(args) => Ok(Request::delete(
            shared_network_path(&args.id)?,
            format!("deleted the shared network {}", args.id.trim()),
        )),
    }
}

fn pool(action: &PoolCommand) -> Result<Request, Failure> {
    match action {
        PoolCommand::List(args) => Ok(Request::get("/dhcp/pools", Present::All(POOL_COLUMNS))
            .with_query("scope", optional_id("scope", args.scope.as_deref())?)),
        PoolCommand::Show(args) => Ok(Request::get(pool_path(&args.range)?, Present::Item)),
        PoolCommand::Set(args) => {
            let mut body = Map::new();
            body.insert("classes".to_owned(), json!(ids("class", &args.classes)?));
            insert(&mut body, "lease", args.lease.times()?);
            Ok(
                Request::new(Method::Put, pool_path(&args.range)?, Present::Item)
                    .with_body(Value::Object(body)),
            )
        }
        PoolCommand::Clear(args) => Ok(Request::delete(
            pool_path(&args.range)?,
            format!(
                "cleared the DHCP settings of the pool {}",
                args.range.trim()
            ),
        )),
    }
}

fn options(action: &OptionCommand) -> Result<Request, Failure> {
    match action {
        OptionCommand::Catalog(_) => Ok(Request::get(
            "/dhcp/option-catalog",
            Present::Array(CATALOG_COLUMNS),
        )),
        OptionCommand::Defs(_) => Ok(Request::get(
            "/dhcp/option-defs",
            Present::All(OPTION_DEF_COLUMNS),
        )),
        OptionCommand::Define(args) => {
            let mut body = Map::new();
            if let Some(space) = &args.space {
                let space = OptionSpace::new(space.trim())
                    .map_err(|error| usage(format!("--space: {error}")))?;
                body.insert("space".to_owned(), json!(space.as_str()));
            }
            body.insert("code".to_owned(), json!(args.code));
            body.insert("name".to_owned(), json!(args.name));
            body.insert(
                "kind".to_owned(),
                json!(snake_enum::<OptionKind>("option kind", &args.kind)?),
            );
            body.insert("array".to_owned(), json!(args.array));
            insert(&mut body, "vendor_class", args.vendor_class.as_deref());
            insert(&mut body, "description", args.description.as_deref());
            Ok(
                Request::new(Method::Post, "/dhcp/option-defs", Present::Item)
                    .with_body(Value::Object(body)),
            )
        }
        OptionCommand::Undefine(args) => {
            let def = id("option definition", &args.id)?;
            Ok(Request::delete(
                format!("/dhcp/option-defs/{def}"),
                format!("deleted the option definition {def}"),
            ))
        }
        OptionCommand::Show(args) => Ok(Request::get(owner_path(&args.owner)?, Present::Item)),
        OptionCommand::Set(args) => {
            let values = args
                .values
                .iter()
                .map(|text| option_value(text))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(
                Request::new(Method::Put, owner_path(&args.owner)?, Present::Item)
                    .with_body(json!({ "values": values })),
            )
        }
        OptionCommand::Clear(args) => Ok(Request::delete(
            owner_path(&args.owner)?,
            format!("cleared the options of {}", args.owner.trim()),
        )),
    }
}

fn class(action: &ClassCommand) -> Result<Request, Failure> {
    match action {
        ClassCommand::List(_) => Ok(Request::get("/dhcp/classes", Present::All(CLASS_COLUMNS))),
        ClassCommand::Show(args) => Ok(Request::get(class_path(&args.id)?, Present::Item)),
        ClassCommand::Create(args) => {
            let matches = args
                .matches
                .iter()
                .map(|text| class_match(text))
                .collect::<Result<Vec<_>, _>>()?;
            let mut body = Map::new();
            body.insert("name".to_owned(), json!(args.name));
            body.insert("matches".to_owned(), Value::Array(matches));
            insert(&mut body, "description", args.description.as_deref());
            Ok(Request::new(Method::Post, "/dhcp/classes", Present::Item)
                .with_body(Value::Object(body)))
        }
        // WP8.4: class set.
        ClassCommand::Set(args) => {
            let mut body = Map::new();
            insert(&mut body, "name", args.name.as_deref());
            if !args.matches.is_empty() {
                let matches = args
                    .matches
                    .iter()
                    .map(|text| class_match(text))
                    .collect::<Result<Vec<_>, _>>()?;
                body.insert("matches".to_owned(), Value::Array(matches));
            }
            if let Some(description) = &args.description {
                body.insert("description".to_owned(), json!(description));
            }
            if body.is_empty() {
                return Err(usage(
                    "class set needs --name, --match or --description".to_owned(),
                ));
            }
            Ok(
                Request::new(Method::Patch, class_path(&args.id)?, Present::Item)
                    .with_body(Value::Object(body)),
            )
        }
        ClassCommand::Delete(args) => Ok(Request::delete(
            class_path(&args.id)?,
            format!("deleted the class {}", args.id.trim()),
        )),
    }
}

fn policy(action: &PolicyCommand) -> Result<Request, Failure> {
    match action {
        PolicyCommand::List(args) => {
            Ok(Request::get("/dhcp/policies", Present::All(POLICY_COLUMNS))
                .with_query("scope", optional_id("scope", args.scope.as_deref())?))
        }
        PolicyCommand::Show(args) => Ok(Request::get(policy_path(&args.id)?, Present::Item)),
        PolicyCommand::Create(args) => {
            let text = std::fs::read_to_string(&args.file)
                .map_err(|error| usage(format!("cannot read {}: {error}", args.file.display())))?;
            let body: Value = serde_json::from_str(&text)
                .map_err(|error| usage(format!("{} is not JSON: {error}", args.file.display())))?;
            if !body.is_object() {
                return Err(usage(format!(
                    "{} must hold one JSON object, the policy",
                    args.file.display()
                )));
            }
            Ok(Request::new(Method::Post, "/dhcp/policies", Present::Item).with_body(body))
        }
        // WP8.4: policy set.
        PolicyCommand::Set(args) => policy_set(args),
        PolicyCommand::Delete(args) => Ok(Request::delete(
            policy_path(&args.id)?,
            format!("deleted the policy {}", args.id.trim()),
        )),
    }
}

// WP8.4: policy set: the file's parts, then the flags over them.
fn policy_set(args: &PolicySetArgs) -> Result<Request, Failure> {
    let mut body = match &args.file {
        Some(file) => {
            let text = std::fs::read_to_string(file)
                .map_err(|error| usage(format!("cannot read {}: {error}", file.display())))?;
            match serde_json::from_str::<Value>(&text)
                .map_err(|error| usage(format!("{} is not JSON: {error}", file.display())))?
            {
                Value::Object(map) => map,
                _ => {
                    return Err(usage(format!(
                        "{} must hold one JSON object, the parts of the policy to change",
                        file.display()
                    )));
                }
            }
        }
        None => Map::new(),
    };
    if let Some(key) = body.keys().find(|key| {
        !matches!(
            key.as_str(),
            "name" | "order" | "enabled" | "condition" | "action" | "description"
        )
    }) {
        return Err(usage(format!(
            "`{key}` is not a part of a policy that changes (name, order, enabled, \
             condition, action, description; the scope stays)"
        )));
    }
    insert(&mut body, "name", args.name.as_deref());
    if let Some(order) = args.order {
        body.insert("order".to_owned(), json!(order));
    }
    if let Some(enabled) = args.enabled {
        body.insert("enabled".to_owned(), json!(enabled));
    }
    if let Some(description) = &args.description {
        body.insert("description".to_owned(), json!(description));
    }
    if body.is_empty() {
        return Err(usage(
            "policy set needs --file, --name, --order, --enabled or --description".to_owned(),
        ));
    }
    Ok(
        Request::new(Method::Patch, policy_path(&args.id)?, Present::Item)
            .with_body(Value::Object(body)),
    )
}

fn filter(action: &FilterCommand) -> Result<Request, Failure> {
    match action {
        FilterCommand::List(_) => Ok(Request::get("/dhcp/filters", Present::All(FILTER_COLUMNS))),
        FilterCommand::Add(args) => {
            let pattern = MacPattern::new(args.mac_pattern.trim())
                .map_err(|error| usage(error.to_string()))?;
            let mut body = Map::new();
            body.insert("mac".to_owned(), json!(pattern.to_string()));
            body.insert(
                "kind".to_owned(),
                json!(if args.deny { "deny" } else { "allow" }),
            );
            insert(&mut body, "note", args.note.as_deref());
            Ok(Request::new(Method::Post, "/dhcp/filters", Present::Item)
                .with_body(Value::Object(body)))
        }
        FilterCommand::Delete(args) => {
            let filter = id("filter", &args.id)?;
            Ok(Request::delete(
                format!("/dhcp/filters/{filter}"),
                format!("deleted the filter {filter}"),
            ))
        }
    }
}

fn reservation(action: &ReservationCommand) -> Result<Request, Failure> {
    match action {
        ReservationCommand::List(args) => Ok(Request::get(
            "/dhcp/reservations",
            Present::All(RESERVATION_COLUMNS),
        )
        .with_query("scope", optional_id("scope", args.scope.as_deref())?)),
        ReservationCommand::Show(args) => Ok(Request::get(
            format!("/dhcp/reservations/{}", id("interface", &args.interface)?),
            Present::Item,
        )),
    }
}

fn lease(action: &LeaseCommand) -> Result<Request, Failure> {
    match action {
        LeaseCommand::List(args) => {
            let page = args.limit.is_some() || args.cursor.is_some();
            let present = if page {
                Present::Page(LEASE_COLUMNS)
            } else {
                Present::All(LEASE_COLUMNS)
            };
            Ok(Request::get("/dhcp/leases", present)
                .with_query("scope", optional_id("scope", args.scope.as_deref())?)
                .with_query("addr", args.addr.clone())
                .with_query("mac", args.mac.as_deref().map(mac_address).transpose()?)
                .with_query("name", args.name.clone())
                .with_query(
                    "state",
                    args.state
                        .as_deref()
                        .map(|text| snake_enum::<BindingState>("lease state", text))
                        .transpose()?,
                )
                .with_query("limit", args.limit.map(|limit| limit.to_string()))
                .with_query("cursor", args.cursor.clone()))
        }
        LeaseCommand::Show(args) => Ok(Request::get(
            format!("/dhcp/leases/{}", ipv4("address", &args.addr)?),
            Present::Item,
        )
        .with_query("vrf", optional_id("VRF", args.vrf.as_deref())?)),
        LeaseCommand::Release(args) => {
            let addr = ipv4("address", &args.addr)?;
            let mut body = Map::new();
            insert(&mut body, "vrf", optional_id("VRF", args.vrf.as_deref())?);
            insert(&mut body, "reason", args.reason.as_deref());
            Ok(Request::new(
                Method::Post,
                format!("/dhcp/leases/{addr}/release"),
                Present::Item,
            )
            .with_body(Value::Object(body)))
        }
    }
}

fn history(args: &HistoryArgs) -> Result<Request, Failure> {
    let present = if args.limit.is_some() || args.cursor.is_some() {
        Present::Page(HISTORY_COLUMNS)
    } else {
        Present::All(HISTORY_COLUMNS)
    };
    Ok(Request::get("/dhcp/history", present)
        .with_query("addr", args.addr.clone())
        .with_query("mac", args.mac.as_deref().map(mac_address).transpose()?)
        .with_query("scope", optional_id("scope", args.scope.as_deref())?)
        .with_query("from", args.from.as_deref().map(time).transpose()?)
        .with_query("to", args.to.as_deref().map(time).transpose()?)
        .with_query("limit", args.limit.map(|limit| limit.to_string()))
        .with_query("cursor", args.cursor.clone()))
}

fn export(args: &ExportArgs) -> Request {
    let mut request = Request::get("/dhcp/export", Present::Export(args.file.clone()))
        .with_query("format", Some(args.format.api().to_owned()));
    if args.no_leases {
        request.query.push(("leases", "false".to_owned()));
    }
    request
}

// ---------------------------------------------------------------------------------------
// Checks and body helpers

/// A usage error (exit status 2).
fn usage(message: impl std::fmt::Display) -> Failure {
    Failure::new(exit::USAGE, message.to_string())
}

/// Puts `value` under `key` when there is one.
fn insert<V: Into<Value>>(body: &mut Map<String, Value>, key: &str, value: Option<V>) {
    if let Some(value) = value {
        body.insert(key.to_owned(), value.into());
    }
}

/// The body of a change, or the usage error of a change that changes nothing.
fn changes(body: Map<String, Value>) -> Result<Value, Failure> {
    if body.is_empty() {
        return Err(usage("nothing to change: give at least one option"));
    }
    Ok(Value::Object(body))
}

/// A switch pair: `Some(true)` for the first, `Some(false)` for the second, else `None`.
fn flag_pair(on: bool, off: bool) -> Option<bool> {
    match (on, off) {
        (true, _) => Some(true),
        (false, true) => Some(false),
        (false, false) => None,
    }
}

/// An identifier in its canonical form.
fn id(what: &str, text: &str) -> Result<String, Failure> {
    Uuid::parse_str(text.trim())
        .map(|uuid| uuid.to_string())
        .map_err(|_| usage(format!("`{text}` is not a {what} identifier (a UUID)")))
}

fn optional_id(what: &str, text: Option<&str>) -> Result<Option<String>, Failure> {
    text.map(|text| id(what, text)).transpose()
}

fn ids(what: &str, texts: &[String]) -> Result<Vec<String>, Failure> {
    texts.iter().map(|text| id(what, text)).collect()
}

fn ipv4(what: &str, text: &str) -> Result<Ipv4Addr, Failure> {
    Ipv4Addr::from_str(text.trim())
        .map_err(|_| usage(format!("`{text}` is not an IPv4 address ({what})")))
}

fn server_id(text: Option<&str>) -> Result<Option<String>, Failure> {
    text.map(|text| ipv4("server identifier", text).map(|addr| addr.to_string()))
        .transpose()
}

fn mac_address(text: &str) -> Result<String, Failure> {
    MacAddr::from_str(text.trim())
        .map(|mac| mac.to_string())
        .map_err(|error| usage(error.to_string()))
}

fn hex(what: &str, text: &str) -> Result<Vec<u8>, Failure> {
    from_hex(text.trim()).ok_or_else(|| {
        usage(format!(
            "`{text}` is not hexadecimal data ({what}): an even number of digits 0-9 and a-f"
        ))
    })
}

fn time(text: &str) -> Result<String, Failure> {
    Timestamp::from_str(text.trim())
        .map(Timestamp::to_rfc3339)
        .map_err(|_| {
            usage(format!(
                "`{text}` is not a time (RFC 3339, `2026-01-31T08:00:00Z`)"
            ))
        })
}

/// A name of an enum of the API in snake case, checked against the enum.
fn snake_enum<T: serde::de::DeserializeOwned>(what: &str, text: &str) -> Result<String, Failure> {
    let name = text.trim().to_ascii_lowercase().replace('-', "_");
    serde_json::from_value::<T>(Value::String(name.clone()))
        .map_err(|error| usage(format!("`{text}` is not an {what}: {error}")))?;
    Ok(name)
}

/// One `CODE=HEXDATA` as an option value of an option set.
fn option_value(text: &str) -> Result<Value, Failure> {
    let (code, data) = text
        .split_once('=')
        .ok_or_else(|| usage(format!("`{text}` is not CODE=HEXDATA")))?;
    let code: u16 = code.trim().parse().map_err(|_| {
        usage(format!(
            "`{}` in `{text}` is not an option code",
            code.trim()
        ))
    })?;
    let bytes = if data.trim().is_empty() {
        Vec::new()
    } else {
        hex("option data", data)?
    };
    Ok(json!({ "code": code, "data": to_hex(&bytes) }))
}

/// One `--match` as the JSON of a `Match`.
fn class_match(text: &str) -> Result<Value, Failure> {
    let parsed: Match = serde_json::from_str(text)
        .map_err(|error| usage(format!("--match `{text}` is not a class test: {error}")))?;
    serde_json::to_value(parsed).map_err(|error| usage(format!("--match `{text}`: {error}")))
}

fn scope_path(prefix: &str) -> Result<String, Failure> {
    Ok(format!("/dhcp/scopes/{}", id("prefix", prefix)?))
}

fn shared_network_path(text: &str) -> Result<String, Failure> {
    Ok(format!(
        "/dhcp/shared-networks/{}",
        id("shared network", text)?
    ))
}

fn pool_path(range: &str) -> Result<String, Failure> {
    Ok(format!("/dhcp/pools/{}", id("range", range)?))
}

fn class_path(text: &str) -> Result<String, Failure> {
    Ok(format!("/dhcp/classes/{}", id("class", text)?))
}

fn policy_path(text: &str) -> Result<String, Failure> {
    Ok(format!("/dhcp/policies/{}", id("policy", text)?))
}

fn owner_path(text: &str) -> Result<String, Failure> {
    let owner = OptionOwner::from_path(text.trim()).map_err(|error| {
        usage(format!(
            "{error} (expected server, scope:<uuid>, pool:<uuid>, shared_network:<uuid>, \
             policy:<uuid> or host:<uuid>)"
        ))
    })?;
    Ok(format!("/dhcp/option-sets/{}", owner.to_path()))
}

// ---------------------------------------------------------------------------------------
// Running

/// Runs a `tenko dhcp` subcommand.
///
/// # Errors
///
/// A usage error for an argument that fails the local checks, else the [`Failure`] of the
/// request.
pub async fn run(command: &DhcpCommand) -> Result<Output, Failure> {
    let request = command.request()?;
    let target = Target::resolve(command.client(), true)?;
    let client = target.connect().await?;
    execute(&target, &client, &request).await
}

/// Sends a request and shows the answer.
async fn execute(target: &Target, client: &Client, request: &Request) -> Result<Output, Failure> {
    let path = request.path.as_str();
    match &request.present {
        Present::All(columns) => {
            let items = list_all(client, path, &request.query).await?;
            if target.json {
                return Ok(Output::json(&json!({ "items": items })));
            }
            Ok(Output::text(render_table(columns, &items)))
        }
        Present::Page(columns) => {
            let answer: Value = client.get_query(path, &request.query).await?;
            if target.json {
                return Ok(Output::json(&answer));
            }
            let items = answer
                .get("items")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let mut output = Output::text(render_table(columns, &items));
            if let Some(cursor) = answer.get("next_cursor").and_then(Value::as_str) {
                output = output.note(format!("more: --cursor {cursor}"));
            }
            Ok(output)
        }
        Present::Array(columns) => {
            let answer: Value = client.get(path).await?;
            if target.json {
                return Ok(Output::json(&answer));
            }
            let items = answer.as_array().cloned().unwrap_or_default();
            Ok(Output::text(render_table(columns, &items)))
        }
        Present::Item => {
            let answer: Value = send(client, request).await?;
            if target.json {
                return Ok(Output::json(&answer));
            }
            Ok(Output::text(render_item(&answer)))
        }
        Present::Done(done) => {
            client.delete(path, None).await?;
            Ok(Output::text(format!("{done}\n")))
        }
        Present::Export(file) => {
            let answer: Value = client.get_query(path, &request.query).await?;
            let mut text = serde_json::to_string_pretty(&answer).unwrap_or_default();
            text.push('\n');
            match file {
                Some(out) => {
                    std::fs::write(out, text.as_bytes()).map_err(|error| {
                        Failure::other(format!("cannot write {}: {error}", out.display()))
                    })?;
                    Ok(Output::default().note(format!(
                        "{} byte(s) written to {}",
                        text.len(),
                        out.display()
                    )))
                }
                None => Ok(Output::text(text)),
            }
        }
    }
}

/// A request with an answer body, by its method.
async fn send(client: &Client, request: &Request) -> Result<Value, Failure> {
    let path = request.path.as_str();
    let empty = json!({});
    let body = request.body.as_ref().unwrap_or(&empty);
    Ok(match request.method {
        Method::Get if request.query.is_empty() => client.get(path).await?,
        Method::Get => client.get_query(path, &request.query).await?,
        Method::Post => {
            client
                .post(path, body, Some(&Uuid::now_v7().to_string()))
                .await?
        }
        Method::Put => client.put(path, body, None).await?,
        Method::Patch => client.patch(path, body, None).await?,
        Method::Delete => {
            client.delete(path, None).await?;
            Value::Null
        }
    })
}

/// Reads every page of a list endpoint.
async fn list_all(
    client: &Client,
    path: &str,
    filters: &[(&'static str, String)],
) -> Result<Vec<Value>, Failure> {
    let mut items = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let mut query: Vec<(&str, String)> = filters.to_vec();
        query.push(("limit", "1000".to_owned()));
        if let Some(cursor) = &cursor {
            query.push(("cursor", cursor.clone()));
        }
        let page: Value = client.get_query(path, &query).await?;
        if let Some(rows) = page.get("items").and_then(Value::as_array) {
            items.extend(rows.iter().cloned());
        }
        cursor = page
            .get("next_cursor")
            .and_then(Value::as_str)
            .map(str::to_owned);
        if cursor.is_none() {
            return Ok(items);
        }
    }
}

// ---------------------------------------------------------------------------------------
// Presentation

/// The field of an item at a dotted path.
fn at<'a>(item: &'a Value, path: &str) -> Option<&'a Value> {
    path.split('.').try_fold(item, |at, key| at.get(key))
}

/// A value as one table cell: text as is, scalars written out, lists of scalars joined by
/// commas, anything else as compact JSON; nothing as an empty cell.
fn cell(value: Option<&Value>) -> String {
    match value {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(text)) => text.clone(),
        Some(Value::Array(items)) if items.iter().all(|item| !item.is_object()) => items
            .iter()
            .map(|item| cell(Some(item)))
            .collect::<Vec<_>>()
            .join(","),
        Some(other @ (Value::Bool(_) | Value::Number(_))) => other.to_string(),
        Some(other) => serde_json::to_string(other).unwrap_or_default(),
    }
}

fn render_table(columns: Columns, items: &[Value]) -> String {
    let header: Vec<&str> = columns.iter().map(|(title, _)| *title).collect();
    let rows: Vec<Vec<String>> = items
        .iter()
        .map(|item| {
            columns
                .iter()
                .map(|(_, path)| cell(at(item, path)))
                .collect()
        })
        .collect();
    table(&header, &rows)
}

/// One object as `name  value` lines.
fn render_item(item: &Value) -> String {
    let Some(fields) = item.as_object() else {
        let mut text = serde_json::to_string_pretty(item).unwrap_or_default();
        text.push('\n');
        return text;
    };
    let width = fields
        .keys()
        .map(|key| key.chars().count())
        .max()
        .unwrap_or(0);
    let mut out = String::new();
    for (key, value) in fields {
        let _ = writeln!(out, "{key:<width$}  {}", cell(Some(value)));
    }
    out
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[derive(Parser)]
    struct Cli {
        #[command(subcommand)]
        command: DhcpCommand,
    }

    fn parse(args: &[&str]) -> Result<DhcpCommand, clap::Error> {
        Cli::try_parse_from(std::iter::once("dhcp").chain(args.iter().copied()))
            .map(|cli| cli.command)
    }

    fn request(args: &[&str]) -> Request {
        parse(args)
            .unwrap_or_else(|error| panic!("{args:?} does not parse: {error}"))
            .request()
            .unwrap_or_else(|failure| panic!("{args:?} is refused: {}", failure.message))
    }

    fn refused(args: &[&str]) -> Failure {
        match parse(args)
            .unwrap_or_else(|error| panic!("{args:?} does not parse: {error}"))
            .request()
        {
            Ok(request) => panic!("{args:?} was accepted: {request:?}"),
            Err(failure) => failure,
        }
    }

    const PREFIX: &str = "018f3c1e-0000-7000-8000-000000000001";
    const OTHER: &str = "018f3c1e-0000-7000-8000-000000000002";
    const THIRD: &str = "018f3c1e-0000-7000-8000-000000000003";

    #[track_caller]
    #[allow(
        clippy::needless_pass_by_value,
        reason = "the callers write the expected body inline"
    )]
    fn check(args: &[&str], method: Method, path: &str, body: Option<Value>) -> Request {
        let request = request(args);
        assert_eq!(request.method, method, "{args:?}");
        assert_eq!(request.path, path, "{args:?}");
        assert_eq!(request.body, body, "{args:?}");
        request
    }

    fn query(request: &Request) -> Vec<(&'static str, &str)> {
        request
            .query
            .iter()
            .map(|(key, value)| (*key, value.as_str()))
            .collect()
    }

    #[test]
    fn commands_have_their_names() {
        let cases: &[(&[&str], &str)] = &[
            (&["settings", "show"], "dhcp settings show"),
            (
                &["settings", "set", "--history-days", "7"],
                "dhcp settings set",
            ),
            (&["scope", "list"], "dhcp scope list"),
            (&["scope", "show", PREFIX], "dhcp scope show"),
            (&["scope", "create", PREFIX], "dhcp scope create"),
            (&["scope", "set", PREFIX, "--enabled"], "dhcp scope set"),
            (&["scope", "delete", PREFIX], "dhcp scope delete"),
            (&["scope", "utilization", PREFIX], "dhcp scope utilization"),
            (&["scope", "options", PREFIX], "dhcp scope options"),
            (&["exclusion", "list", PREFIX], "dhcp exclusion list"),
            (
                &["exclusion", "add", PREFIX, "192.0.2.1", "192.0.2.9"],
                "dhcp exclusion add",
            ),
            (
                &["exclusion", "delete", PREFIX, OTHER],
                "dhcp exclusion delete",
            ),
            (&["shared-network", "list"], "dhcp shared-network list"),
            (
                &["shared-network", "show", OTHER],
                "dhcp shared-network show",
            ),
            (
                &["shared-network", "create", "campus"],
                "dhcp shared-network create",
            ),
            (
                &["shared-network", "set", OTHER, "--name", "x"],
                "dhcp shared-network set",
            ),
            (
                &["shared-network", "delete", OTHER],
                "dhcp shared-network delete",
            ),
            (&["pool", "list"], "dhcp pool list"),
            (&["pool", "show", OTHER], "dhcp pool show"),
            (&["pool", "set", OTHER], "dhcp pool set"),
            (&["pool", "clear", OTHER], "dhcp pool clear"),
            (&["option", "catalog"], "dhcp option catalog"),
            (&["option", "defs"], "dhcp option defs"),
            (
                &[
                    "option", "define", "--code", "224", "--name", "x", "--kind", "u8",
                ],
                "dhcp option define",
            ),
            (&["option", "undefine", OTHER], "dhcp option undefine"),
            (&["option", "show", "server"], "dhcp option show"),
            (
                &["option", "set", "server", "6=c0000201"],
                "dhcp option set",
            ),
            (&["option", "clear", "server"], "dhcp option clear"),
            (&["class", "list"], "dhcp class list"),
            (&["class", "show", OTHER], "dhcp class show"),
            (
                &[
                    "class",
                    "create",
                    "x",
                    "--match",
                    r#"{"architecture":{"code":7}}"#,
                ],
                "dhcp class create",
            ),
            (&["class", "delete", OTHER], "dhcp class delete"),
            // WP8.4: class set and policy set.
            (&["class", "set", OTHER, "--name", "x"], "dhcp class set"),
            (&["policy", "set", OTHER, "--order", "1"], "dhcp policy set"),
            (&["policy", "list"], "dhcp policy list"),
            (&["policy", "show", OTHER], "dhcp policy show"),
            (
                &["policy", "create", "--file", "p.json"],
                "dhcp policy create",
            ),
            (&["policy", "delete", OTHER], "dhcp policy delete"),
            (&["filter", "list"], "dhcp filter list"),
            (
                &["filter", "add", "00:00:5e:*", "--deny"],
                "dhcp filter add",
            ),
            (&["filter", "delete", OTHER], "dhcp filter delete"),
            (&["reservation", "list"], "dhcp reservation list"),
            (&["reservation", "show", OTHER], "dhcp reservation show"),
            (&["lease", "list"], "dhcp lease list"),
            (&["lease", "show", "192.0.2.50"], "dhcp lease show"),
            (&["lease", "release", "192.0.2.50"], "dhcp lease release"),
            (&["history"], "dhcp history"),
            (&["export", "--format", "kea"], "dhcp export"),
        ];
        for (args, name) in cases {
            let command = parse(args).unwrap_or_else(|error| panic!("{args:?}: {error}"));
            assert_eq!(command.name(), *name, "{args:?}");
        }
    }

    #[test]
    fn connection_options_come_after_the_subcommand() {
        let command = parse(&[
            "lease",
            "list",
            "--url",
            "https://ddi.example.test",
            "--json",
        ])
        .expect("parses");
        assert_eq!(
            command.client().url.as_deref(),
            Some("https://ddi.example.test")
        );
        assert!(command.client().json);
    }

    #[test]
    fn settings() {
        check(&["settings", "show"], Method::Get, "/dhcp/settings", None);
        check(
            &[
                "settings",
                "set",
                "--lease-default",
                "7200",
                "--lease-min",
                "600",
                "--lease-max",
                "86400",
                "--authoritative",
                "true",
                "--history-days",
                "30",
                "--conflict-detection",
                "false",
            ],
            Method::Put,
            "/dhcp/settings",
            Some(json!({
                "lease": {"default_secs": 7200, "min_secs": 600, "max_secs": 86400},
                "authoritative": true,
                "conflict_detection": false,
                "history_days": 30,
            })),
        );
        // Nothing to change; a partial set of lease times; times out of order.
        assert_eq!(refused(&["settings", "set"]).status, exit::USAGE);
        let partial = refused(&["settings", "set", "--lease-default", "60"]);
        assert_eq!(partial.status, exit::USAGE);
        assert!(
            partial.message.contains("go together"),
            "{}",
            partial.message
        );
        let order = refused(&[
            "settings",
            "set",
            "--lease-default",
            "60",
            "--lease-min",
            "600",
            "--lease-max",
            "6000",
        ]);
        assert!(order.message.contains("out of order"), "{}", order.message);
        assert!(parse(&["settings", "set", "--authoritative", "maybe"]).is_err());
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one table of commands, read top to bottom"
    )]
    fn scopes() {
        let scope_path = format!("/dhcp/scopes/{PREFIX}");
        check(&["scope", "list"], Method::Get, "/dhcp/scopes", None);
        check(&["scope", "show", PREFIX], Method::Get, &scope_path, None);
        check(
            &["scope", "create", PREFIX],
            Method::Post,
            "/dhcp/scopes",
            Some(json!({"prefix": PREFIX})),
        );
        check(
            &[
                "scope",
                "create",
                PREFIX,
                "--lease-default",
                "3600",
                "--lease-min",
                "600",
                "--lease-max",
                "7200",
                "--disabled",
                "--restricted",
                "--shared-network",
                OTHER,
                "--server-id",
                "192.0.2.1",
                "--class",
                THIRD,
                "--authoritative",
                "false",
                "--description",
                "office",
            ],
            Method::Post,
            "/dhcp/scopes",
            Some(json!({
                "prefix": PREFIX,
                "enabled": false,
                "lease": {"default_secs": 3600, "min_secs": 600, "max_secs": 7200},
                "authoritative": false,
                "server_id": "192.0.2.1",
                "shared_network": OTHER,
                "restricted": true,
                "classes": [THIRD],
                "description": "office",
            })),
        );
        check(
            &[
                "scope",
                "set",
                PREFIX,
                "--enabled",
                "--unrestricted",
                "--clear-lease",
            ],
            Method::Patch,
            &scope_path,
            Some(json!({"enabled": true, "restricted": false, "clear_lease": true})),
        );
        check(
            &["scope", "set", PREFIX, "--disabled", "--no-classes"],
            Method::Patch,
            &scope_path,
            Some(json!({"enabled": false, "classes": []})),
        );
        check(
            &["scope", "delete", PREFIX],
            Method::Delete,
            &scope_path,
            None,
        );
        check(
            &["scope", "utilization", PREFIX],
            Method::Get,
            &format!("{scope_path}/utilization"),
            None,
        );
        let options = check(
            &[
                "scope",
                "options",
                PREFIX,
                "--mac",
                "00-00-5E-00-53-01",
                "--client-id",
                "01:00:00:5e:00:53:01",
                "--vendor-class",
                "MSFT 5.0",
                "--user-class",
                "staff",
            ],
            Method::Get,
            &format!("{scope_path}/effective-options"),
            None,
        );
        assert_eq!(
            query(&options),
            [
                ("mac", "00:00:5e:00:53:01"),
                ("client_id", "0100005e005301"),
                ("vendor_class", "MSFT 5.0"),
                ("user_class", "staff"),
            ]
        );
    }

    #[test]
    fn scopes_refuse_what_is_wrong() {
        assert_eq!(
            refused(&["scope", "show", "192.0.2.0/24"]).status,
            exit::USAGE
        );
        assert_eq!(refused(&["scope", "set", PREFIX]).status, exit::USAGE);
        for bad in [
            &["scope", "create", PREFIX, "--server-id", "2001:db8::1"][..],
            &["scope", "create", PREFIX, "--shared-network", "campus"],
            &["scope", "create", PREFIX, "--class", "x"],
            &["scope", "options", PREFIX, "--mac", "00:00:5e"],
            &["scope", "options", PREFIX, "--client-id", "abc"],
        ] {
            assert_eq!(refused(bad).status, exit::USAGE, "{bad:?}");
        }
        // The pairs exclude each other.
        assert!(parse(&["scope", "set", PREFIX, "--enabled", "--disabled"]).is_err());
        assert!(parse(&["scope", "set", PREFIX, "--restricted", "--unrestricted"]).is_err());
        assert!(parse(&["scope", "set", PREFIX, "--clear-lease", "--lease-min", "5"]).is_err());
    }

    #[test]
    fn exclusions() {
        let base = format!("/dhcp/scopes/{PREFIX}/exclusions");
        check(&["exclusion", "list", PREFIX], Method::Get, &base, None);
        check(
            &[
                "exclusion",
                "add",
                PREFIX,
                "192.0.2.10",
                "192.0.2.19",
                "--description",
                "printers",
            ],
            Method::Post,
            &base,
            Some(json!({"first": "192.0.2.10", "last": "192.0.2.19", "description": "printers"})),
        );
        check(
            &["exclusion", "delete", PREFIX, OTHER],
            Method::Delete,
            &format!("{base}/{OTHER}"),
            None,
        );
        for bad in [
            &["exclusion", "add", PREFIX, "192.0.2.19", "192.0.2.10"][..],
            &["exclusion", "add", PREFIX, "192.0.2.x", "192.0.2.10"],
            &["exclusion", "add", PREFIX, "2001:db8::1", "2001:db8::9"],
            &["exclusion", "delete", PREFIX, "7"],
        ] {
            assert_eq!(refused(bad).status, exit::USAGE, "{bad:?}");
        }
    }

    #[test]
    fn shared_networks() {
        let path = format!("/dhcp/shared-networks/{OTHER}");
        check(
            &["shared-network", "list"],
            Method::Get,
            "/dhcp/shared-networks",
            None,
        );
        check(&["shared-network", "show", OTHER], Method::Get, &path, None);
        check(
            &[
                "shared-network",
                "create",
                "campus",
                "--interface",
                "eth1",
                "--description",
                "two scopes",
            ],
            Method::Post,
            "/dhcp/shared-networks",
            Some(json!({"name": "campus", "interface": "eth1", "description": "two scopes"})),
        );
        check(
            &["shared-network", "set", OTHER, "--interface", "eth2"],
            Method::Patch,
            &path,
            Some(json!({"interface": "eth2"})),
        );
        check(
            &["shared-network", "delete", OTHER],
            Method::Delete,
            &path,
            None,
        );
        assert_eq!(
            refused(&["shared-network", "set", OTHER]).status,
            exit::USAGE
        );
        assert_eq!(
            refused(&["shared-network", "show", "campus"]).status,
            exit::USAGE
        );
    }

    #[test]
    fn pools() {
        let path = format!("/dhcp/pools/{OTHER}");
        let list = check(&["pool", "list"], Method::Get, "/dhcp/pools", None);
        assert_eq!(list.query, Vec::new());
        let list = check(
            &["pool", "list", "--scope", PREFIX],
            Method::Get,
            "/dhcp/pools",
            None,
        );
        assert_eq!(query(&list), [("scope", PREFIX)]);
        check(&["pool", "show", OTHER], Method::Get, &path, None);
        check(
            &["pool", "set", OTHER, "--class", PREFIX, "--class", THIRD],
            Method::Put,
            &path,
            Some(json!({"classes": [PREFIX, THIRD]})),
        );
        check(
            &[
                "pool",
                "set",
                OTHER,
                "--lease-default",
                "600",
                "--lease-min",
                "60",
                "--lease-max",
                "900",
            ],
            Method::Put,
            &path,
            Some(json!({
                "classes": [],
                "lease": {"default_secs": 600, "min_secs": 60, "max_secs": 900},
            })),
        );
        check(&["pool", "clear", OTHER], Method::Delete, &path, None);
        assert_eq!(
            refused(&["pool", "list", "--scope", "x"]).status,
            exit::USAGE
        );
    }

    #[test]
    fn options() {
        let catalog = check(
            &["option", "catalog"],
            Method::Get,
            "/dhcp/option-catalog",
            None,
        );
        assert_eq!(catalog.present, Present::Array(CATALOG_COLUMNS));
        check(&["option", "defs"], Method::Get, "/dhcp/option-defs", None);
        check(
            &[
                "option",
                "define",
                "--code",
                "224",
                "--name",
                "site-code",
                "--kind",
                "IPv4-Address",
                "--array",
                "--space",
                "acme-voip",
                "--vendor-class",
                "ACME",
            ],
            Method::Post,
            "/dhcp/option-defs",
            Some(json!({
                "space": "acme-voip",
                "code": 224,
                "name": "site-code",
                "kind": "ipv4_address",
                "array": true,
                "vendor_class": "ACME",
            })),
        );
        check(
            &["option", "undefine", OTHER],
            Method::Delete,
            &format!("/dhcp/option-defs/{OTHER}"),
            None,
        );
        check(
            &["option", "show", "server"],
            Method::Get,
            "/dhcp/option-sets/server",
            None,
        );
        let scope_owner = format!("scope:{PREFIX}");
        let path = format!("/dhcp/option-sets/{scope_owner}");
        check(&["option", "show", &scope_owner], Method::Get, &path, None);
        check(
            &[
                "option",
                "set",
                &scope_owner,
                "6=C0000201:c0000202",
                "15=",
                "3=c0000201",
            ],
            Method::Put,
            &path,
            Some(json!({"values": [
                {"code": 6, "data": "c0000201c0000202"},
                {"code": 15, "data": ""},
                {"code": 3, "data": "c0000201"},
            ]})),
        );
        check(
            &["option", "clear", &scope_owner],
            Method::Delete,
            &path,
            None,
        );
        for owner in ["shared_network", "pool:x", "vlan", "Server"] {
            assert_eq!(
                refused(&["option", "show", owner]).status,
                exit::USAGE,
                "{owner}"
            );
        }
        for bad in [
            &["option", "set", "server", "6"][..],
            &["option", "set", "server", "six=00"],
            &["option", "set", "server", "6=abc"],
            &["option", "set", "server", "6=zz"],
            &["option", "set", "server", "70000=00"],
            &[
                "option", "define", "--code", "224", "--name", "x", "--kind", "int",
            ],
            &[
                "option", "define", "--code", "224", "--name", "x", "--kind", "u8", "--space",
                "dhcp 4",
            ],
        ] {
            assert_eq!(refused(bad).status, exit::USAGE, "{bad:?}");
        }
        assert!(parse(&["option", "set", "server"]).is_err());
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one table of commands, read top to bottom"
    )]
    fn classes_policies_and_filters() {
        check(&["class", "list"], Method::Get, "/dhcp/classes", None);
        check(
            &["class", "show", OTHER],
            Method::Get,
            &format!("/dhcp/classes/{OTHER}"),
            None,
        );
        check(
            &[
                "class",
                "create",
                "windows",
                "--match",
                r#"{ "vendor_class": { "value": "MSFT", "prefix": true } }"#,
                "--match",
                r#"{"mac":{"pattern":"00-00-5E-*"}}"#,
                "--description",
                "PCs",
            ],
            Method::Post,
            "/dhcp/classes",
            Some(json!({
                "name": "windows",
                "matches": [
                    {"vendor_class": {"value": "MSFT", "prefix": true}},
                    {"mac": {"pattern": "00:00:5e:*:*:*"}},
                ],
                "description": "PCs",
            })),
        );
        check(
            &["class", "delete", OTHER],
            Method::Delete,
            &format!("/dhcp/classes/{OTHER}"),
            None,
        );
        for bad in [
            &["class", "create", "x", "--match", "{}"][..],
            &["class", "create", "x", "--match", "vendor_class"],
            &[
                "class",
                "create",
                "x",
                "--match",
                r#"{"mac":{"pattern":"zz"}}"#,
            ],
        ] {
            assert_eq!(refused(bad).status, exit::USAGE, "{bad:?}");
        }
        assert!(parse(&["class", "create", "x"]).is_err());

        let list = check(
            &["policy", "list", "--scope", PREFIX],
            Method::Get,
            "/dhcp/policies",
            None,
        );
        assert_eq!(query(&list), [("scope", PREFIX)]);
        check(
            &["policy", "show", OTHER],
            Method::Get,
            &format!("/dhcp/policies/{OTHER}"),
            None,
        );
        check(
            &["policy", "delete", OTHER],
            Method::Delete,
            &format!("/dhcp/policies/{OTHER}"),
            None,
        );

        check(&["filter", "list"], Method::Get, "/dhcp/filters", None);
        check(
            &[
                "filter",
                "add",
                "00-00-5E-00-53-*",
                "--allow",
                "--note",
                "lab",
            ],
            Method::Post,
            "/dhcp/filters",
            Some(json!({"mac": "00:00:5e:00:53:*", "kind": "allow", "note": "lab"})),
        );
        check(
            &["filter", "add", "00:00:5e:00:53:01", "--deny"],
            Method::Post,
            "/dhcp/filters",
            Some(json!({"mac": "00:00:5e:00:53:01", "kind": "deny"})),
        );
        check(
            &["filter", "delete", OTHER],
            Method::Delete,
            &format!("/dhcp/filters/{OTHER}"),
            None,
        );
        assert_eq!(
            refused(&["filter", "add", "00:00:5e", "--deny"]).status,
            exit::USAGE
        );
        assert!(parse(&["filter", "add", "00:00:5e:*"]).is_err());
        assert!(parse(&["filter", "add", "00:00:5e:*", "--allow", "--deny"]).is_err());
    }

    #[test]
    fn policy_files() {
        let dir = std::env::temp_dir().join(format!("tenko-dhcp-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&dir).expect("temporary directory");
        let good = dir.join("policy.json");
        let policy = json!({
            "name": "phones",
            "condition": {"all": []},
            "action": {},
        });
        std::fs::write(&good, policy.to_string()).expect("write");
        let wrong = dir.join("list.json");
        std::fs::write(&wrong, "[1]").expect("write");
        let broken = dir.join("broken.json");
        std::fs::write(&broken, "{").expect("write");

        check(
            &["policy", "create", "--file", good.to_str().expect("UTF-8")],
            Method::Post,
            "/dhcp/policies",
            Some(policy),
        );
        for bad in [&wrong, &broken, &dir.join("missing.json")] {
            let failure = refused(&["policy", "create", "--file", bad.to_str().expect("UTF-8")]);
            assert_eq!(failure.status, exit::USAGE, "{}", failure.message);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    // WP8.4: class set and policy set.
    #[test]
    fn class_set_and_policy_set() {
        check(
            &[
                "class",
                "set",
                OTHER,
                "--name",
                "uefi",
                "--match",
                r#"{"architecture":{"code":7}}"#,
                "--match",
                r#"{"architecture":{"code":9}}"#,
                "--description",
                "",
            ],
            Method::Patch,
            &format!("/dhcp/classes/{OTHER}"),
            Some(json!({
                "name": "uefi",
                "matches": [{"architecture": {"code": 7}}, {"architecture": {"code": 9}}],
                "description": "",
            })),
        );
        for args in [
            &["class", "set", OTHER][..],
            &["class", "set", OTHER, "--match", "{}"],
            &["policy", "set", OTHER],
            &["class", "set", "not-a-uuid", "--name", "x"],
        ] {
            assert_eq!(refused(args).status, exit::USAGE, "{args:?}");
        }
        let dir = std::env::temp_dir().join(format!("tenko-dhcp-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&dir).expect("temporary directory");
        let change = dir.join("change.json");
        let condition = json!({"join": "or", "terms": [{"class": THIRD}]});
        std::fs::write(
            &change,
            json!({"condition": condition, "order": 1}).to_string(),
        )
        .expect("write");
        let scoped = dir.join("scoped.json");
        std::fs::write(&scoped, json!({"scope": PREFIX}).to_string()).expect("write");
        check(
            &[
                "policy",
                "set",
                OTHER,
                "--file",
                change.to_str().expect("UTF-8"),
                "--order",
                "3",
                "--enabled",
                "false",
            ],
            Method::Patch,
            &format!("/dhcp/policies/{OTHER}"),
            Some(json!({"condition": condition, "order": 3, "enabled": false})),
        );
        let failure = refused(&[
            "policy",
            "set",
            OTHER,
            "--file",
            scoped.to_str().expect("UTF-8"),
        ]);
        assert!(failure.message.contains("scope"), "{}", failure.message);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reservations() {
        let list = check(
            &["reservation", "list", "--scope", PREFIX],
            Method::Get,
            "/dhcp/reservations",
            None,
        );
        assert_eq!(query(&list), [("scope", PREFIX)]);
        check(
            &["reservation", "show", OTHER],
            Method::Get,
            &format!("/dhcp/reservations/{OTHER}"),
            None,
        );
        assert_eq!(
            refused(&["reservation", "show", "192.0.2.5"]).status,
            exit::USAGE
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one table of commands, read top to bottom"
    )]
    fn leases_and_history() {
        let all = check(&["lease", "list"], Method::Get, "/dhcp/leases", None);
        assert_eq!(all.present, Present::All(LEASE_COLUMNS));
        let filtered = check(
            &[
                "lease",
                "list",
                "--scope",
                PREFIX,
                "--addr",
                "192.0.2.",
                "--mac",
                "00:00:5E:00:53:01",
                "--name",
                "laptop",
                "--state",
                "Active",
                "--limit",
                "50",
                "--cursor",
                "abc",
            ],
            Method::Get,
            "/dhcp/leases",
            None,
        );
        assert_eq!(filtered.present, Present::Page(LEASE_COLUMNS));
        assert_eq!(
            query(&filtered),
            [
                ("scope", PREFIX),
                ("addr", "192.0.2."),
                ("mac", "00:00:5e:00:53:01"),
                ("name", "laptop"),
                ("state", "active"),
                ("limit", "50"),
                ("cursor", "abc"),
            ]
        );
        let show = check(
            &["lease", "show", "192.0.2.50"],
            Method::Get,
            "/dhcp/leases/192.0.2.50",
            None,
        );
        assert_eq!(show.query, Vec::new());
        let show = check(
            &["lease", "show", "192.0.2.50", "--vrf", OTHER],
            Method::Get,
            "/dhcp/leases/192.0.2.50",
            None,
        );
        assert_eq!(query(&show), [("vrf", OTHER)]);
        check(
            &["lease", "release", "192.0.2.50"],
            Method::Post,
            "/dhcp/leases/192.0.2.50/release",
            Some(json!({})),
        );
        check(
            &[
                "lease",
                "release",
                "192.0.2.50",
                "--vrf",
                OTHER,
                "--reason",
                "device retired",
            ],
            Method::Post,
            "/dhcp/leases/192.0.2.50/release",
            Some(json!({"vrf": OTHER, "reason": "device retired"})),
        );
        for bad in [
            &["lease", "list", "--state", "leased"][..],
            &["lease", "list", "--mac", "nope"],
            &["lease", "show", "host"],
            &["lease", "release", "2001:db8::1"],
            &["lease", "show", "192.0.2.50", "--vrf", "default"],
        ] {
            assert_eq!(refused(bad).status, exit::USAGE, "{bad:?}");
        }

        let history = check(&["history"], Method::Get, "/dhcp/history", None);
        assert_eq!(history.query, Vec::new());
        let history = check(
            &[
                "history",
                "--addr",
                "192.0.2.50",
                "--mac",
                "00:00:5e:00:53:01",
                "--scope",
                PREFIX,
                "--from",
                "2026-01-31T08:00:00Z",
                "--to",
                "2026-02-01T00:00:00+01:00",
            ],
            Method::Get,
            "/dhcp/history",
            None,
        );
        assert_eq!(history.present, Present::All(HISTORY_COLUMNS));
        let query = query(&history);
        assert_eq!(
            &query[..3],
            [
                ("addr", "192.0.2.50"),
                ("mac", "00:00:5e:00:53:01"),
                ("scope", PREFIX)
            ]
        );
        assert_eq!(query[3].0, "from");
        assert!(query[3].1.starts_with("2026-01-31T08:00:00"), "{query:?}");
        assert_eq!(query[4].0, "to");
        assert_eq!(
            refused(&["history", "--from", "yesterday"]).status,
            exit::USAGE
        );
    }

    #[test]
    fn exports() {
        let request = check(
            &["export", "--format", "kea"],
            Method::Get,
            "/dhcp/export",
            None,
        );
        assert_eq!(query(&request), [("format", "kea")]);
        assert_eq!(request.present, Present::Export(None));
        let request = check(
            &["export", "--no-leases", "--file", "kea.json"],
            Method::Get,
            "/dhcp/export",
            None,
        );
        assert_eq!(query(&request), [("format", "kea"), ("leases", "false")]);
        assert_eq!(
            request.present,
            Present::Export(Some(PathBuf::from("kea.json")))
        );
        assert!(parse(&["export", "--format", "isc"]).is_err());
    }

    #[test]
    fn answers_are_shown_as_tables_and_lines() {
        let items = vec![
            json!({"addr": "192.0.2.50", "state": "active", "hostname": "laptop", "scope": PREFIX}),
            json!({"addr": "192.0.2.51", "state": "released"}),
        ];
        let text = render_table(LEASE_COLUMNS, &items);
        let mut lines = text.lines();
        assert_eq!(
            lines.next().expect("header"),
            "ADDRESS     STATE     ENDS  HOSTNAME  SCOPE"
        );
        assert_eq!(
            lines.next().expect("row"),
            format!("192.0.2.50  active          laptop    {PREFIX}")
        );
        assert_eq!(lines.next().expect("row"), "192.0.2.51  released");

        let item = json!({
            "prefix": PREFIX,
            "enabled": true,
            "pools": 2,
            "classes": [],
            "lease": {"default_secs": 60},
            "dns": ["192.0.2.1", "192.0.2.2"],
        });
        let text = render_item(&item);
        assert!(text.contains(&format!("prefix   {PREFIX}\n")), "{text}");
        assert!(text.contains("enabled  true\n"), "{text}");
        assert!(text.contains("lease    {\"default_secs\":60}\n"), "{text}");
        assert!(text.contains("dns      192.0.2.1,192.0.2.2\n"), "{text}");
    }
}
