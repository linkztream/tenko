//! `tenko dns ...`: the DNS endpoints of the public API (`/api/v1/dns/...`): zones, records,
//! zone file import and export, access lists, TSIG keys, forwarding rules and block lists.
//!
//! # Names
//!
//! A `<zone>` is the zone's identifier (a UUID) or its name; a name is looked up in the
//! list of zones. The owner `<name>` of a record is relative to the zone (`www`,
//! `_ldap._tcp`), absolute (`www.example.test`, with or without the final dot) or `@` for
//! the apex; a name that ends with the zone's name is taken as absolute. A name inside
//! record data (an MX exchange, a CNAME target) with a final dot or with a dot in it is
//! absolute, a single label is relative to the zone, and `@` is the apex.
//!
//! # Record data
//!
//! Every `<data>` argument is one record in presentation form: `192.0.2.10` (A),
//! `2001:db8::10` (AAAA), `www` (CNAME, NS, PTR, DNAME), `"10 mx.example.test"` (MX:
//! preference, exchange), `"0 5 5060 sip.example.test"` (SRV: priority, weight, port,
//! target), `"0 issue letsencrypt.org"` (CAA: flags, tag, value), and for TXT the text,
//! or several quoted strings. For the types with several fields the fields may also be
//! given as separate arguments when none of them has a blank in it
//! (`MX 10 mx.example.test`).
//!
//! # Answers the commands read
//!
//! - **Batch.** `POST /dns/zones/{id}/records/batch` answers `{dry_run, changes[], serial,
//!   revision}`; a change has `scope`, `name`, `type`, and `before` and `after` RRsets
//!   (`ttl`, `records[]`, `origin`).
//! - **Import.** With `dry_run=true` the answer is the report (`added`, `replaced`,
//!   `removed`, `types[].{rtype, records}`, `losses[].{line, code, detail}`); without it
//!   `202 {job_id}`, and the report is the output (hex of JSON, `types` as an object) of
//!   the job's step `dns.import.finish`.
//! - **Job.** `GET /jobs/{id}` is a `JobDetail`: `job.state`, `job.error.{code, detail}`
//!   and `job.steps[].{kind, state, output}`.

use std::{
    fmt::Write as _,
    io::Read as _,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::PathBuf,
    str::FromStr as _,
    time::Duration,
};

use clap::{ArgGroup, Args, Subcommand, ValueEnum};
use ipnet::IpNet;
use reqwest::header::CONTENT_TYPE;
use serde_json::{Map, Value, json};
use tenko_api::{client::Client, dto::Page, problem::ProblemDetails};
use tenko_core::Revision;
use uuid::Uuid;

use super::{ClientOpts, Failure, Output, Target, table};
use crate::exit;

/// Subcommands of `tenko dns`.
#[derive(Debug, Clone, Subcommand)]
pub enum DnsCommand {
    /// Zones: list, create, show, change, delete.
    Zone {
        /// The `zone` subcommand to run.
        #[command(subcommand)]
        action: ZoneCommand,
    },
    /// Records: list, add, replace, remove, delete.
    Record {
        /// The `record` subcommand to run.
        #[command(subcommand)]
        action: RecordCommand,
    },
    /// Import a zone file into a zone.
    Import(ImportArgs),
    /// Export a zone as a zone file.
    Export(ExportArgs),
    /// Access lists: list, create, show, change, delete.
    Acl {
        /// The `acl` subcommand to run.
        #[command(subcommand)]
        action: AclCommand,
    },
    /// TSIG keys: list, create, show, delete.
    Key {
        /// The `key` subcommand to run.
        #[command(subcommand)]
        action: KeyCommand,
    },
    /// Forwarding rules: list, create, show, change, delete.
    Forwarder {
        /// The `forwarder` subcommand to run.
        #[command(subcommand)]
        action: ForwarderCommand,
    },
    /// Block lists and allow lists: list, create, show, change, delete, fetch, upload.
    List {
        /// The `list` subcommand to run.
        #[command(subcommand)]
        action: BlockListCommand,
    },
}

/// Subcommands of `tenko dns list`.
#[derive(Debug, Clone, Subcommand)]
pub enum BlockListCommand {
    /// List the block lists and allow lists.
    List(ListArgs),
    /// Create a list.
    Create(BlockListCreateArgs),
    /// Show one list (its identifier or its name).
    Get(BlockListRefArgs),
    /// Change a list.
    Update(BlockListUpdateArgs),
    /// Delete a list and its versions.
    Delete(BlockListDeleteArgs),
    /// Fetch and compile a URL list now; prints the job.
    Fetch(BlockListRefArgs),
    /// Send the file of an uploaded list; prints the job.
    Upload(BlockListUploadArgs),
}

/// The file format of a list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ListFormatArg {
    /// A hosts file (`0.0.0.0 ads.example.test`).
    Hosts,
    /// One domain per line.
    Domains,
}

impl ListFormatArg {
    const fn api(self) -> &'static str {
        match self {
            Self::Hosts => "hosts",
            Self::Domains => "domains",
        }
    }
}

/// What a list does with the names it holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ListKindArg {
    /// Answer the names with the list's action.
    Block,
    /// Keep the names from being blocked, and exempt the list's clients.
    Allow,
}

impl ListKindArg {
    const fn api(self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::Allow => "allow",
        }
    }
}

/// What a blocked name answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum BlockActionArg {
    /// NXDOMAIN.
    Nxdomain,
    /// NOERROR without data.
    Nodata,
    /// An address record of the `--redirect` address.
    Redirect,
}

/// Arguments of `tenko dns list create`.
#[derive(Debug, Clone, Args)]
#[command(group(ArgGroup::new("source").required(true).args(["source_url", "upload"])))]
pub struct BlockListCreateArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// A unique name, 1 to 64 characters.
    #[arg(long, value_name = "NAME")]
    pub name: String,
    /// Fetch the list from this `https://` or `http://` URL (`--url` is the controller).
    #[arg(long, value_name = "URL")]
    pub source_url: Option<String>,
    /// The list is uploaded (`tenko dns list upload`), not fetched.
    #[arg(long)]
    pub upload: bool,
    /// The file format; `domains` when absent.
    #[arg(long, value_enum)]
    pub format: Option<ListFormatArg>,
    /// A block list or an allow list; `block` when absent.
    #[arg(long, value_enum)]
    pub kind: Option<ListKindArg>,
    /// How often a URL list is fetched, in hours (1 to 168); the server's default (24)
    /// when absent.
    #[arg(
        long,
        value_name = "N",
        value_parser = clap::value_parser!(u16).range(1..=168)
    )]
    pub interval_hours: Option<u16>,
    /// What a blocked name answers; `nxdomain` when absent.
    #[arg(long, value_enum)]
    pub action: Option<BlockActionArg>,
    /// The address `--action redirect` answers.
    #[arg(long, value_name = "ADDRESS", requires = "action")]
    pub redirect: Option<IpAddr>,
    /// A client prefix (or address) exempt from the list; an allow list exempts it from
    /// every list and RPZ zone. Repeat for more, up to 1,000.
    #[arg(long = "exempt", value_name = "PREFIX")]
    pub exempt: Vec<String>,
    /// Create the list switched off.
    #[arg(long)]
    pub disabled: bool,
    /// Free text.
    #[arg(long, value_name = "TEXT")]
    pub description: Option<String>,
}

/// Arguments of the list commands that take one list.
#[derive(Debug, Clone, Args)]
pub struct BlockListRefArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The list: its identifier or its name.
    #[arg(value_name = "LIST")]
    pub list: String,
}

/// Arguments of `tenko dns list delete`.
#[derive(Debug, Clone, Args)]
pub struct BlockListDeleteArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The list: its identifier or its name.
    #[arg(value_name = "LIST")]
    pub list: String,
    /// Refuse the change when the list is no longer at this revision.
    #[arg(long, value_name = "REV")]
    pub if_match: Option<u64>,
}

/// Arguments of `tenko dns list update`.
#[derive(Debug, Clone, Args)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "command line switches, each of its own"
)]
pub struct BlockListUpdateArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The list: its identifier or its name.
    #[arg(value_name = "LIST")]
    pub list: String,
    /// Refuse the change when the list is no longer at this revision.
    #[arg(long, value_name = "REV")]
    pub if_match: Option<u64>,
    /// A new name.
    #[arg(long, value_name = "NAME")]
    pub name: Option<String>,
    /// A new source URL; the versions of the list are dropped and it is fetched again.
    #[arg(long, value_name = "URL", conflicts_with = "upload")]
    pub source_url: Option<String>,
    /// Make the list an uploaded one; its versions are dropped.
    #[arg(long)]
    pub upload: bool,
    /// The file format; the versions of the list are dropped.
    #[arg(long, value_enum)]
    pub format: Option<ListFormatArg>,
    /// A block list or an allow list.
    #[arg(long, value_enum)]
    pub kind: Option<ListKindArg>,
    /// How often a URL list is fetched, in hours (1 to 168).
    #[arg(
        long,
        value_name = "N",
        value_parser = clap::value_parser!(u16).range(1..=168)
    )]
    pub interval_hours: Option<u16>,
    /// What a blocked name answers.
    #[arg(long, value_enum)]
    pub action: Option<BlockActionArg>,
    /// The address `--action redirect` answers.
    #[arg(long, value_name = "ADDRESS", requires = "action")]
    pub redirect: Option<IpAddr>,
    /// The exempt client prefixes, replacing all of them. Repeat for more.
    #[arg(
        long = "exempt",
        value_name = "PREFIX",
        conflicts_with = "clear_exempt"
    )]
    pub exempt: Vec<String>,
    /// Remove every exempt prefix.
    #[arg(long)]
    pub clear_exempt: bool,
    /// Switch the list on.
    #[arg(long, conflicts_with = "disable")]
    pub enable: bool,
    /// Switch the list off.
    #[arg(long)]
    pub disable: bool,
    /// Free text; an empty text clears it.
    #[arg(long, value_name = "TEXT")]
    pub description: Option<String>,
}

/// Arguments of `tenko dns list upload`.
#[derive(Debug, Clone, Args)]
pub struct BlockListUploadArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The list: its identifier or its name.
    #[arg(value_name = "LIST")]
    pub list: String,
    /// The file to send, or `-` for standard input.
    #[arg(value_name = "FILE")]
    pub file: PathBuf,
}

/// Subcommands of `tenko dns forwarder`.
#[derive(Debug, Clone, Subcommand)]
pub enum ForwarderCommand {
    /// List the forwarding rules.
    List(ListArgs),
    /// Create a forwarding rule.
    Create(ForwarderCreateArgs),
    /// Show one forwarding rule (its identifier or its suffix).
    Get(NamedArgs),
    /// Change a forwarding rule.
    Update(ForwarderUpdateArgs),
    /// Delete a forwarding rule (its identifier or its suffix).
    Delete(NamedArgs),
}

/// How the upstreams of a rule are reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum TransportArg {
    /// UDP, TCP when an answer is truncated (port 53).
    Plain,
    /// DNS over TLS (port 853).
    Dot,
    /// DNS over HTTPS (port 443).
    Doh,
}

impl TransportArg {
    const fn api(self) -> &'static str {
        match self {
            Self::Plain => "plain",
            Self::Dot => "dot",
            Self::Doh => "doh",
        }
    }
}

/// Arguments of `tenko dns forwarder create`.
#[derive(Debug, Clone, Args)]
pub struct ForwarderCreateArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The names the rule covers (`example.test`), or `.` for the default forwarder.
    #[arg(value_name = "SUFFIX")]
    pub suffix: String,
    /// An upstream: an address with an optional port (`192.0.2.1`, `192.0.2.1:5353`,
    /// `[2001:db8::1]:853`) and, for DoH, an optional path (`192.0.2.1:443/dns-query`).
    /// Repeat for more, up to 16.
    #[arg(long = "upstream", value_name = "UPSTREAM", required = true)]
    pub upstreams: Vec<String>,
    /// How the upstreams are reached; plain when absent.
    #[arg(long, value_enum)]
    pub transport: Option<TransportArg>,
    /// The name in the upstreams' certificates (DoT and DoH).
    #[arg(long, value_name = "NAME")]
    pub tls_name: Option<String>,
    /// The view the rule applies in (its identifier); every view when absent.
    #[arg(long, value_name = "VIEW")]
    pub view: Option<String>,
    /// Free text.
    #[arg(long, value_name = "TEXT")]
    pub description: Option<String>,
}

/// Arguments of `tenko dns forwarder update`.
#[derive(Debug, Clone, Args)]
pub struct ForwarderUpdateArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The rule: its identifier or its suffix.
    #[arg(value_name = "RULE")]
    pub rule: String,
    /// A new suffix.
    #[arg(long, value_name = "SUFFIX")]
    pub suffix: Option<String>,
    /// The new upstreams, replacing all of them; as for `create`.
    #[arg(long = "upstream", value_name = "UPSTREAM")]
    pub upstreams: Vec<String>,
    /// The transport.
    #[arg(long, value_enum)]
    pub transport: Option<TransportArg>,
    /// The certificate name; an empty text clears it.
    #[arg(long, value_name = "NAME")]
    pub tls_name: Option<String>,
    /// The view the rule applies in.
    #[arg(long, value_name = "VIEW", conflicts_with = "all_views")]
    pub view: Option<String>,
    /// Apply the rule in every view.
    #[arg(long)]
    pub all_views: bool,
    /// Free text; an empty text clears it.
    #[arg(long, value_name = "TEXT")]
    pub description: Option<String>,
}

/// Subcommands of `tenko dns zone`.
#[derive(Debug, Clone, Subcommand)]
pub enum ZoneCommand {
    /// List the zones.
    List(ListArgs),
    /// Create a zone.
    Create(ZoneCreateArgs),
    /// Show one zone.
    Get(ZoneRefArgs),
    /// Change a zone.
    Update(ZoneUpdateArgs),
    /// Delete a zone and its records.
    Delete(ZoneRefArgs),
}

/// Subcommands of `tenko dns record`.
#[derive(Debug, Clone, Subcommand)]
pub enum RecordCommand {
    /// List the records of a zone.
    List(RecordListArgs),
    /// Add records to an RRset (create it when absent).
    Add(ChangeArgs),
    /// Replace an RRset with these records (create it when absent).
    Replace(ChangeArgs),
    /// Delete an RRset.
    Delete(ChangeArgs),
    /// Remove these records from an RRset; an RRset left empty is deleted.
    Remove(ChangeArgs),
}

/// Subcommands of `tenko dns acl`.
#[derive(Debug, Clone, Subcommand)]
pub enum AclCommand {
    /// List the access lists.
    List(ListArgs),
    /// Create an access list.
    Create(AclCreateArgs),
    /// Show one access list.
    Get(NamedArgs),
    /// Change an access list.
    Update(AclUpdateArgs),
    /// Delete an access list.
    Delete(NamedArgs),
}

/// Subcommands of `tenko dns key`.
#[derive(Debug, Clone, Subcommand)]
pub enum KeyCommand {
    /// List the TSIG keys.
    List(ListArgs),
    /// Create a TSIG key; the secret is printed once. The server accepts this from an
    /// interactive session only: the API token of `tenko login` is refused (403).
    Create(KeyCreateArgs),
    /// Show one TSIG key.
    Get(NamedArgs),
    /// Delete a TSIG key (an interactive session only, as for `create`).
    Delete(NamedArgs),
}

impl DnsCommand {
    /// The connection options of the subcommand.
    pub fn client(&self) -> &ClientOpts {
        match self {
            Self::Zone { action } => match action {
                ZoneCommand::List(a) => &a.client,
                ZoneCommand::Create(a) => &a.client,
                ZoneCommand::Get(a) | ZoneCommand::Delete(a) => &a.client,
                ZoneCommand::Update(a) => &a.client,
            },
            Self::Record { action } => match action {
                RecordCommand::List(a) => &a.client,
                RecordCommand::Add(a)
                | RecordCommand::Replace(a)
                | RecordCommand::Delete(a)
                | RecordCommand::Remove(a) => &a.client,
            },
            Self::Import(a) => &a.client,
            Self::Export(a) => &a.client,
            Self::Acl { action } => match action {
                AclCommand::List(a) => &a.client,
                AclCommand::Create(a) => &a.client,
                AclCommand::Get(a) | AclCommand::Delete(a) => &a.client,
                AclCommand::Update(a) => &a.client,
            },
            Self::Key { action } => match action {
                KeyCommand::List(a) => &a.client,
                KeyCommand::Create(a) => &a.client,
                KeyCommand::Get(a) | KeyCommand::Delete(a) => &a.client,
            },
            Self::Forwarder { action } => match action {
                ForwarderCommand::List(a) => &a.client,
                ForwarderCommand::Create(a) => &a.client,
                ForwarderCommand::Get(a) | ForwarderCommand::Delete(a) => &a.client,
                ForwarderCommand::Update(a) => &a.client,
            },
            Self::List { action } => match action {
                BlockListCommand::List(a) => &a.client,
                BlockListCommand::Create(a) => &a.client,
                BlockListCommand::Get(a) | BlockListCommand::Fetch(a) => &a.client,
                BlockListCommand::Update(a) => &a.client,
                BlockListCommand::Delete(a) => &a.client,
                BlockListCommand::Upload(a) => &a.client,
            },
        }
    }

    /// The name as typed.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Zone { action } => match action {
                ZoneCommand::List(_) => "dns zone list",
                ZoneCommand::Create(_) => "dns zone create",
                ZoneCommand::Get(_) => "dns zone get",
                ZoneCommand::Update(_) => "dns zone update",
                ZoneCommand::Delete(_) => "dns zone delete",
            },
            Self::Record { action } => match action {
                RecordCommand::List(_) => "dns record list",
                RecordCommand::Add(_) => "dns record add",
                RecordCommand::Replace(_) => "dns record replace",
                RecordCommand::Delete(_) => "dns record delete",
                RecordCommand::Remove(_) => "dns record remove",
            },
            Self::Import(_) => "dns import",
            Self::Export(_) => "dns export",
            Self::Acl { action } => match action {
                AclCommand::List(_) => "dns acl list",
                AclCommand::Create(_) => "dns acl create",
                AclCommand::Get(_) => "dns acl get",
                AclCommand::Update(_) => "dns acl update",
                AclCommand::Delete(_) => "dns acl delete",
            },
            Self::Key { action } => match action {
                KeyCommand::List(_) => "dns key list",
                KeyCommand::Create(_) => "dns key create",
                KeyCommand::Get(_) => "dns key get",
                KeyCommand::Delete(_) => "dns key delete",
            },
            Self::Forwarder { action } => match action {
                ForwarderCommand::List(_) => "dns forwarder list",
                ForwarderCommand::Create(_) => "dns forwarder create",
                ForwarderCommand::Get(_) => "dns forwarder get",
                ForwarderCommand::Update(_) => "dns forwarder update",
                ForwarderCommand::Delete(_) => "dns forwarder delete",
            },
            Self::List { action } => match action {
                BlockListCommand::List(_) => "dns list list",
                BlockListCommand::Create(_) => "dns list create",
                BlockListCommand::Get(_) => "dns list get",
                BlockListCommand::Update(_) => "dns list update",
                BlockListCommand::Delete(_) => "dns list delete",
                BlockListCommand::Fetch(_) => "dns list fetch",
                BlockListCommand::Upload(_) => "dns list upload",
            },
        }
    }
}

/// Arguments of the `list` commands.
#[derive(Debug, Clone, Args)]
pub struct ListArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
}

/// Arguments of the commands that take one name or identifier.
#[derive(Debug, Clone, Args)]
pub struct NamedArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The name, or the identifier for access lists.
    #[arg(value_name = "NAME")]
    pub name: String,
}

/// How the serial of a zone moves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SerialArg {
    /// The previous serial plus one.
    Counter,
    /// Seconds since 1970.
    Unixtime,
    /// `YYYYMMDDnn`.
    #[value(name = "date_counter", alias = "date-counter")]
    DateCounter,
}

impl SerialArg {
    const fn api(self) -> &'static str {
        match self {
            Self::Counter => "counter",
            Self::Unixtime => "unixtime",
            Self::DateCounter => "date_counter",
        }
    }
}

/// The kinds of zone this command creates (the others need servers to copy from).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum KindArg {
    /// Tenko holds the data.
    Primary,
    /// A response policy zone held by Tenko.
    Rpz,
}

impl KindArg {
    const fn api(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Rpz => "rpz",
        }
    }
}

/// Arguments of `tenko dns zone create`.
#[derive(Debug, Clone, Args)]
pub struct ZoneCreateArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The apex, for example example.test.
    #[arg(value_name = "NAME")]
    pub name: String,
    /// What the zone is.
    #[arg(long, value_enum, default_value = "primary")]
    pub kind: KindArg,
    /// A name server of the apex NS set; repeat for more.
    #[arg(long = "ns", value_name = "HOST", required = true)]
    pub name_servers: Vec<String>,
    /// The primary name server of the SOA record.
    #[arg(long, value_name = "HOST")]
    pub mname: String,
    /// The mailbox of the responsible person, for example hostmaster@example.test.
    #[arg(long, value_name = "MAILBOX")]
    pub rname: String,
    /// How the serial moves; `date_counter` when absent.
    #[arg(long, value_enum)]
    pub serial: Option<SerialArg>,
    /// TTL of the SOA record and the default TTL of new RRsets, in seconds.
    #[arg(long, value_name = "N")]
    pub ttl: Option<u32>,
    /// SOA refresh interval in seconds.
    #[arg(long, value_name = "N")]
    pub refresh: Option<u32>,
    /// SOA retry interval in seconds.
    #[arg(long, value_name = "N")]
    pub retry: Option<u32>,
    /// SOA expiry in seconds.
    #[arg(long, value_name = "N")]
    pub expire: Option<u32>,
    /// TTL of negative answers in seconds.
    #[arg(long, value_name = "N")]
    pub minimum: Option<u32>,
    /// Free text.
    #[arg(long, value_name = "TEXT")]
    pub description: Option<String>,
}

/// Arguments of the commands that take a zone and maybe a revision.
#[derive(Debug, Clone, Args)]
pub struct ZoneRefArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The zone: its identifier or its name.
    #[arg(value_name = "ZONE")]
    pub zone: String,
    /// Refuse the change when the zone is no longer at this revision.
    #[arg(long, value_name = "REV")]
    pub if_match: Option<u64>,
}

/// Arguments of `tenko dns zone update`.
#[derive(Debug, Clone, Args)]
pub struct ZoneUpdateArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The zone: its identifier or its name.
    #[arg(value_name = "ZONE")]
    pub zone: String,
    /// Refuse the change when the zone is no longer at this revision.
    #[arg(long, value_name = "REV")]
    pub if_match: Option<u64>,
    /// How the serial moves.
    #[arg(long, value_enum)]
    pub serial: Option<SerialArg>,
    /// Free text; an empty text clears it.
    #[arg(long, value_name = "TEXT")]
    pub description: Option<String>,
    /// The primary name server of the SOA record.
    #[arg(long, value_name = "HOST")]
    pub mname: Option<String>,
    /// The mailbox of the responsible person.
    #[arg(long, value_name = "MAILBOX")]
    pub rname: Option<String>,
    /// SOA refresh interval in seconds.
    #[arg(long, value_name = "N")]
    pub refresh: Option<u32>,
    /// SOA retry interval in seconds.
    #[arg(long, value_name = "N")]
    pub retry: Option<u32>,
    /// SOA expiry in seconds.
    #[arg(long, value_name = "N")]
    pub expire: Option<u32>,
    /// TTL of negative answers in seconds.
    #[arg(long, value_name = "N")]
    pub minimum: Option<u32>,
    /// TTL of the SOA record and the default TTL of new RRsets, in seconds.
    #[arg(long, value_name = "N")]
    pub ttl: Option<u32>,
}

/// Arguments of `tenko dns record list`.
#[derive(Debug, Clone, Args)]
pub struct RecordListArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The zone: its identifier or its name.
    #[arg(value_name = "ZONE")]
    pub zone: String,
    /// The scope; default when absent.
    #[arg(long, value_name = "SCOPE")]
    pub scope: Option<String>,
    /// Only owner names starting with this text.
    #[arg(long, value_name = "PREFIX")]
    pub name: Option<String>,
    /// Only this record type.
    #[arg(long = "type", value_name = "TYPE")]
    pub rtype: Option<String>,
    /// Only RRsets of this origin (manual, ipam, dynamic, dhcp, ad).
    #[arg(long, value_name = "ORIGIN")]
    pub origin: Option<String>,
    /// Most RRsets in one request, 1 to 1,000. With it only that page is listed; without
    /// it the cursor is followed to the end.
    #[arg(long, value_name = "N")]
    pub limit: Option<u32>,
}

/// Arguments of `tenko dns record add|replace|delete|remove`.
#[derive(Debug, Clone, Args)]
pub struct ChangeArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The zone: its identifier or its name.
    #[arg(value_name = "ZONE")]
    pub zone: String,
    /// The owner name: relative to the zone, absolute, or @ for the apex.
    #[arg(value_name = "NAME")]
    pub name: String,
    /// The record type: A, AAAA, CNAME, DNAME, MX, NS, PTR, TXT, SRV or CAA.
    #[arg(value_name = "TYPE")]
    pub rtype: String,
    /// The records, one argument each, in presentation form.
    #[arg(value_name = "DATA")]
    pub data: Vec<String>,
    /// TTL in seconds; the zone's default when absent.
    #[arg(long, value_name = "N")]
    pub ttl: Option<u32>,
    /// The scope; default when absent.
    #[arg(long, value_name = "SCOPE")]
    pub scope: Option<String>,
    /// Allow the change to replace an RRset that another origin owns.
    #[arg(long)]
    pub take_over: bool,
    /// Show the diff without writing (API-09).
    #[arg(long)]
    pub dry_run: bool,
}

/// Arguments of `tenko dns import`.
#[derive(Debug, Clone, Args)]
pub struct ImportArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The zone: its identifier or its name.
    #[arg(value_name = "ZONE")]
    pub zone: String,
    /// The zone file (RFC 1035 master format).
    #[arg(value_name = "FILE")]
    pub file: PathBuf,
    /// The scope to import into; default when absent.
    #[arg(long, value_name = "SCOPE")]
    pub scope: Option<String>,
    /// Replace the records of the scope instead of merging into them.
    #[arg(long)]
    pub replace: bool,
    /// Show what the import would do without writing.
    #[arg(long)]
    pub dry_run: bool,
    /// Seconds to wait for the import job.
    #[arg(long, value_name = "SECONDS", default_value_t = 300)]
    pub wait_secs: u64,
}

/// Arguments of `tenko dns export`.
#[derive(Debug, Clone, Args)]
pub struct ExportArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The zone: its identifier or its name.
    #[arg(value_name = "ZONE")]
    pub zone: String,
    /// The scope; default when absent.
    #[arg(long, value_name = "SCOPE")]
    pub scope: Option<String>,
    /// Write the zone file to this file instead of standard output.
    #[arg(long, value_name = "PATH")]
    pub file: Option<PathBuf>,
}

/// Arguments of `tenko dns acl create`.
#[derive(Debug, Clone, Args)]
pub struct AclCreateArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// A unique name.
    #[arg(value_name = "NAME")]
    pub name: String,
    /// An entry, in order: a network (192.0.2.0/24), key:NAME or any; add ,deny to refuse
    /// instead of allow. Repeat for more.
    #[arg(long = "entry", value_name = "ENTRY", required = true)]
    pub entries: Vec<String>,
    /// Free text.
    #[arg(long, value_name = "TEXT")]
    pub description: Option<String>,
}

/// Arguments of `tenko dns acl update`.
#[derive(Debug, Clone, Args)]
pub struct AclUpdateArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The access list: its identifier or its name.
    #[arg(value_name = "ACL")]
    pub acl: String,
    /// A new name.
    #[arg(long, value_name = "NAME")]
    pub name: Option<String>,
    /// The new entries, replacing all of them; as for `create`.
    #[arg(long = "entry", value_name = "ENTRY")]
    pub entries: Vec<String>,
    /// Free text; an empty text clears it.
    #[arg(long, value_name = "TEXT")]
    pub description: Option<String>,
}

/// The algorithms of a TSIG key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum AlgorithmArg {
    /// `hmac-sha256`.
    #[value(name = "hmac-sha256")]
    HmacSha256,
    /// `hmac-sha384`.
    #[value(name = "hmac-sha384")]
    HmacSha384,
    /// `hmac-sha512`.
    #[value(name = "hmac-sha512")]
    HmacSha512,
    /// `hmac-sha1`, for peers that know nothing better.
    #[value(name = "hmac-sha1")]
    HmacSha1,
}

impl AlgorithmArg {
    const fn api(self) -> &'static str {
        match self {
            Self::HmacSha256 => "hmac-sha256",
            Self::HmacSha384 => "hmac-sha384",
            Self::HmacSha512 => "hmac-sha512",
            Self::HmacSha1 => "hmac-sha1",
        }
    }
}

/// Arguments of `tenko dns key create`.
#[derive(Debug, Clone, Args)]
pub struct KeyCreateArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The key name, as the peers know it.
    #[arg(value_name = "NAME")]
    pub name: String,
    /// The algorithm; hmac-sha256 when absent.
    #[arg(long, value_enum)]
    pub algorithm: Option<AlgorithmArg>,
    /// Import the base64 secret in this file instead of generating one.
    #[arg(long, value_name = "PATH")]
    pub secret_file: Option<PathBuf>,
    /// Free text.
    #[arg(long, value_name = "TEXT")]
    pub description: Option<String>,
}

/// Runs a `tenko dns` subcommand.
///
/// # Errors
///
/// The [`Failure`] of the request.
pub async fn run(command: &DnsCommand) -> Result<Output, Failure> {
    let target = Target::resolve(command.client(), true)?;
    match command {
        DnsCommand::Zone { action } => match action {
            ZoneCommand::List(_) => zone_list(&target).await,
            ZoneCommand::Create(args) => zone_create(&target, args).await,
            ZoneCommand::Get(args) => zone_get(&target, args).await,
            ZoneCommand::Update(args) => zone_update(&target, args).await,
            ZoneCommand::Delete(args) => zone_delete(&target, args).await,
        },
        DnsCommand::Record { action } => match action {
            RecordCommand::List(args) => record_list(&target, args).await,
            RecordCommand::Add(args) => record_change(&target, args, Op::Add).await,
            RecordCommand::Replace(args) => record_change(&target, args, Op::Set).await,
            RecordCommand::Delete(args) => record_change(&target, args, Op::Delete).await,
            RecordCommand::Remove(args) => record_change(&target, args, Op::Remove).await,
        },
        DnsCommand::Import(args) => import(&target, args).await,
        DnsCommand::Export(args) => export(&target, args).await,
        DnsCommand::Acl { action } => match action {
            AclCommand::List(_) => acl_list(&target).await,
            AclCommand::Create(args) => acl_create(&target, args).await,
            AclCommand::Get(args) => acl_get(&target, args).await,
            AclCommand::Update(args) => acl_update(&target, args).await,
            AclCommand::Delete(args) => acl_delete(&target, args).await,
        },
        DnsCommand::Key { action } => match action {
            KeyCommand::List(_) => key_list(&target).await,
            KeyCommand::Create(args) => key_create(&target, args).await,
            KeyCommand::Get(args) => key_get(&target, args).await,
            KeyCommand::Delete(args) => key_delete(&target, args).await,
        },
        DnsCommand::Forwarder { action } => match action {
            ForwarderCommand::List(_) => forwarder_list(&target).await,
            ForwarderCommand::Create(args) => forwarder_create(&target, args).await,
            ForwarderCommand::Get(args) => forwarder_get(&target, args).await,
            ForwarderCommand::Update(args) => forwarder_update(&target, args).await,
            ForwarderCommand::Delete(args) => forwarder_delete(&target, args).await,
        },
        DnsCommand::List { action } => match action {
            BlockListCommand::List(_) => block_list_list(&target).await,
            BlockListCommand::Create(args) => block_list_create(&target, args).await,
            BlockListCommand::Get(args) => block_list_get(&target, args).await,
            BlockListCommand::Update(args) => block_list_update(&target, args).await,
            BlockListCommand::Delete(args) => block_list_delete(&target, args).await,
            BlockListCommand::Fetch(args) => block_list_fetch(&target, args).await,
            BlockListCommand::Upload(args) => block_list_upload(&target, args).await,
        },
    }
}

// ---------------------------------------------------------------------------------------
// Shared helpers

/// A usage error (exit status 2).
fn usage(message: impl std::fmt::Display) -> Failure {
    Failure::new(exit::USAGE, message.to_string())
}

/// A `not found` failure shaped like the server's problem details, so that `--json`
/// prints problem details here too.
fn not_found(code: &str, what: &str, name: &str) -> Failure {
    Failure::problem(ProblemDetails {
        type_: "about:blank".to_owned(),
        status: 404,
        code: code.to_owned(),
        title: "Not Found".to_owned(),
        detail: format!("no {what} {name}"),
        params: std::collections::BTreeMap::from([("name".to_owned(), name.to_owned())]),
        errors: Vec::new(),
        instance: None,
    })
}

fn text<'a>(value: &'a Value, path: &[&str]) -> &'a str {
    let mut at = value;
    for key in path {
        match at.get(*key) {
            Some(next) => at = next,
            None => return "",
        }
    }
    at.as_str().unwrap_or_default()
}

fn number(value: &Value, path: &[&str]) -> String {
    let mut at = value;
    for key in path {
        match at.get(*key) {
            Some(next) => at = next,
            None => return String::new(),
        }
    }
    at.as_u64().map(|n| n.to_string()).unwrap_or_default()
}

/// A fresh idempotency key.
fn key() -> String {
    Uuid::now_v7().to_string()
}

/// Reads every page of a list endpoint.
async fn list_all(
    client: &Client,
    path: &str,
    filters: &[(&str, String)],
) -> Result<Vec<Value>, Failure> {
    let mut items = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let mut query: Vec<(&str, String)> = filters.to_vec();
        query.push(("limit", "1000".to_owned()));
        if let Some(cursor) = &cursor {
            query.push(("cursor", cursor.clone()));
        }
        let page: Page<Value> = client.get_query(path, &query).await?;
        items.extend(page.items);
        cursor = page.next_cursor;
        if cursor.is_none() {
            return Ok(items);
        }
    }
}

/// The name of a zone or similar in its canonical form: lowercase, without the final dot.
fn canonical(name: &str) -> String {
    let trimmed = name.trim();
    if trimmed == "." {
        return ".".to_owned();
    }
    trimmed
        .strip_suffix('.')
        .unwrap_or(trimmed)
        .to_ascii_lowercase()
}

/// The zone with this name among `zones`.
fn find_named<'a>(zones: &'a [Value], name: &str) -> Option<&'a Value> {
    let wanted = canonical(name);
    zones.iter().find(|zone| text(zone, &["name"]) == wanted)
}

/// The zone `reference` names (an identifier or a name), read from the server.
async fn resolve_zone(client: &Client, reference: &str) -> Result<Value, Failure> {
    if Uuid::parse_str(reference).is_ok() {
        return Ok(client.get(&format!("/dns/zones/{reference}")).await?);
    }
    let zones = list_all(client, "/dns/zones", &[]).await?;
    find_named(&zones, reference)
        .cloned()
        .ok_or_else(|| not_found("dns.zone.not_found", "zone", reference))
}

fn zone_path(zone: &Value) -> String {
    format!("/dns/zones/{}", text(zone, &["id"]))
}

fn revision(rev: Option<u64>) -> Option<Revision> {
    rev.map(Revision)
}

// ---------------------------------------------------------------------------------------
// Zones

async fn zone_list(target: &Target) -> Result<Output, Failure> {
    let client = target.connect().await?;
    let items = list_all(&client, "/dns/zones", &[]).await?;
    if target.json {
        return Ok(Output::json(&json!({ "items": items })));
    }
    let rows: Vec<Vec<String>> = items
        .iter()
        .map(|zone| {
            vec![
                text(zone, &["name"]).to_owned(),
                text(zone, &["kind"]).to_owned(),
                number(zone, &["soa_serial"]),
                number(zone, &["rrsets"]),
                text(zone, &["id"]).to_owned(),
            ]
        })
        .collect();
    Ok(Output::text(table(
        &["NAME", "KIND", "SERIAL", "RRSETS", "ID"],
        &rows,
    )))
}

/// A mailbox (`hostmaster@example.test`) as the name of an SOA `rname`.
fn mailbox_name(mailbox: &str) -> String {
    mailbox.trim().replacen('@', ".", 1)
}

fn describe_zone(zone: &Value) -> String {
    let mut lines: Vec<(&str, String)> = vec![
        ("name", text(zone, &["name"]).to_owned()),
        ("id", text(zone, &["id"]).to_owned()),
        ("kind", text(zone, &["kind"]).to_owned()),
        ("serial policy", text(zone, &["serial"]).to_owned()),
        ("serial", number(zone, &["soa_serial"])),
        ("mname", text(zone, &["soa", "mname"]).to_owned()),
        ("rname", text(zone, &["soa", "rname"]).to_owned()),
        (
            "soa timers",
            format!(
                "refresh {} retry {} expire {} minimum {}",
                number(zone, &["soa", "refresh"]),
                number(zone, &["soa", "retry"]),
                number(zone, &["soa", "expire"]),
                number(zone, &["soa", "minimum"]),
            ),
        ),
        ("ttl", number(zone, &["soa", "ttl"])),
        ("rrsets", number(zone, &["rrsets"])),
        ("revision", number(zone, &["revision"])),
    ];
    let description = text(zone, &["description"]);
    if !description.is_empty() {
        lines.push(("description", description.to_owned()));
    }
    let width = lines.iter().map(|(key, _)| key.len()).max().unwrap_or(0);
    let mut out = String::new();
    for (key, value) in lines {
        let _ = writeln!(out, "{key:<width$}  {value}");
    }
    out
}

/// Qualifies a name inside record data (or a host name option) against the zone.
fn qualify_data(name: &str, zone: &str) -> String {
    let name = name.trim();
    if name == "@" {
        return zone.to_owned();
    }
    if let Some(absolute) = name.strip_suffix('.') {
        return absolute.to_ascii_lowercase();
    }
    if name.contains('.') || zone == "." {
        return name.to_ascii_lowercase();
    }
    format!("{}.{zone}", name.to_ascii_lowercase())
}

/// Qualifies an owner name against the zone.
fn qualify_owner(name: &str, zone: &str) -> String {
    let name = name.trim();
    if name == "@" {
        return zone.to_owned();
    }
    let lowered = name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase();
    if name.ends_with('.')
        || zone == "."
        || lowered == zone
        || lowered.ends_with(&format!(".{zone}"))
    {
        return lowered;
    }
    format!("{lowered}.{zone}")
}

async fn zone_create(target: &Target, args: &ZoneCreateArgs) -> Result<Output, Failure> {
    let client = target.connect().await?;
    let zone = canonical(&args.name);
    let mut soa = Map::new();
    soa.insert("mname".to_owned(), json!(qualify_data(&args.mname, &zone)));
    soa.insert("rname".to_owned(), json!(mailbox_name(&args.rname)));
    for (key, value) in [
        ("refresh", args.refresh),
        ("retry", args.retry),
        ("expire", args.expire),
        ("minimum", args.minimum),
        ("ttl", args.ttl),
    ] {
        if let Some(value) = value {
            soa.insert(key.to_owned(), json!(value));
        }
    }
    let servers: Vec<String> = args
        .name_servers
        .iter()
        .map(|host| qualify_data(host, &zone))
        .collect();
    let mut body = json!({
        "name": zone,
        "kind": args.kind.api(),
        "soa": soa,
        "name_servers": servers,
    });
    if let Some(serial) = args.serial {
        body["serial"] = json!(serial.api());
    }
    if let Some(description) = &args.description {
        body["description"] = json!(description);
    }
    let answer: Value = client.post("/dns/zones", &body, Some(&key())).await?;
    if target.json {
        return Ok(Output::json(&answer));
    }
    Ok(Output::text(format!(
        "created zone {} ({}) at revision {}\n",
        text(&answer, &["name"]),
        text(&answer, &["id"]),
        number(&answer, &["revision"]),
    )))
}

async fn zone_get(target: &Target, args: &ZoneRefArgs) -> Result<Output, Failure> {
    let client = target.connect().await?;
    let zone = resolve_zone(&client, &args.zone).await?;
    if target.json {
        return Ok(Output::json(&zone));
    }
    Ok(Output::text(describe_zone(&zone)))
}

async fn zone_update(target: &Target, args: &ZoneUpdateArgs) -> Result<Output, Failure> {
    let client = target.connect().await?;
    let zone = resolve_zone(&client, &args.zone).await?;
    let mut body = Map::new();
    if let Some(serial) = args.serial {
        body.insert("serial".to_owned(), json!(serial.api()));
    }
    if let Some(description) = &args.description {
        body.insert("description".to_owned(), json!(description));
    }
    let soa_flags = [
        ("refresh", args.refresh),
        ("retry", args.retry),
        ("expire", args.expire),
        ("minimum", args.minimum),
        ("ttl", args.ttl),
    ];
    if args.mname.is_some() || args.rname.is_some() || soa_flags.iter().any(|(_, v)| v.is_some()) {
        // The SOA is replaced as a whole: start from the one the zone has.
        let mut soa = zone.get("soa").cloned().unwrap_or_else(|| json!({}));
        let apex = text(&zone, &["name"]).to_owned();
        if let Some(mname) = &args.mname {
            soa["mname"] = json!(qualify_data(mname, &apex));
        }
        if let Some(rname) = &args.rname {
            soa["rname"] = json!(mailbox_name(rname));
        }
        for (key, value) in soa_flags {
            if let Some(value) = value {
                soa[key] = json!(value);
            }
        }
        body.insert("soa".to_owned(), soa);
    }
    if body.is_empty() {
        return Err(usage(
            "nothing to change: give --serial, --description or an SOA option",
        ));
    }
    let answer: Value = client
        .patch(
            &zone_path(&zone),
            &Value::Object(body),
            revision(args.if_match),
        )
        .await?;
    if target.json {
        return Ok(Output::json(&answer));
    }
    Ok(Output::text(format!(
        "updated zone {} at revision {}\n",
        text(&answer, &["name"]),
        number(&answer, &["revision"]),
    )))
}

async fn zone_delete(target: &Target, args: &ZoneRefArgs) -> Result<Output, Failure> {
    let client = target.connect().await?;
    let zone = resolve_zone(&client, &args.zone).await?;
    client
        .delete(&zone_path(&zone), revision(args.if_match))
        .await?;
    if target.json {
        return Ok(Output::json(&json!({ "deleted": text(&zone, &["id"]) })));
    }
    Ok(Output::text(format!(
        "deleted zone {} ({})\n",
        text(&zone, &["name"]),
        text(&zone, &["id"]),
    )))
}

// ---------------------------------------------------------------------------------------
// Record data

/// What a change does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Add,
    Set,
    Remove,
    Delete,
}

impl Op {
    const fn api(self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Set => "set",
            Self::Remove => "remove",
            Self::Delete => "delete",
        }
    }
}

/// The fields a record of the type has, or `None` for a type the command cannot build.
const fn field_count(rtype: &str) -> Option<usize> {
    match rtype.as_bytes() {
        b"A" | b"AAAA" | b"CNAME" | b"DNAME" | b"NS" | b"PTR" | b"TXT" => Some(1),
        b"MX" => Some(2),
        b"CAA" => Some(3),
        b"SRV" => Some(4),
        _ => None,
    }
}

/// Splits presentation text at blanks, with double quotes grouping words and `\"` and
/// `\\` escaping inside them (other escapes are kept for the server to read).
fn tokenize(text: &str) -> Result<Vec<String>, String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_token = false;
    let mut quoted = false;
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                quoted = !quoted;
                in_token = true;
            }
            '\\' if quoted => match chars.next() {
                Some('"') => current.push('"'),
                Some(other) => {
                    current.push('\\');
                    current.push(other);
                }
                None => return Err("a quoted string ends with a lone backslash".to_owned()),
            },
            c if c.is_whitespace() && !quoted => {
                if in_token {
                    tokens.push(std::mem::take(&mut current));
                    in_token = false;
                }
            }
            c => {
                current.push(c);
                in_token = true;
            }
        }
    }
    if quoted {
        return Err(format!("unterminated quote in `{text}`"));
    }
    if in_token {
        tokens.push(current);
    }
    Ok(tokens)
}

/// The tokens of each record of the `<data>` arguments.
fn group_data(rtype: &str, data: &[String]) -> Result<Vec<Vec<String>>, String> {
    let fields = field_count(rtype).ok_or_else(|| {
        format!("record type {rtype} is not supported by the command line; use the API")
    })?;
    if rtype == "TXT" {
        return data
            .iter()
            .map(|arg| {
                if arg.contains('"') {
                    tokenize(arg)
                } else {
                    Ok(vec![arg.clone()])
                }
            })
            .collect();
    }
    if fields > 1
        && data.len() >= fields
        && data.iter().all(|arg| !arg.contains(char::is_whitespace))
    {
        // `MX 10 mx.example.test`: the arguments are the fields of one record.
        return Ok(vec![data.to_vec()]);
    }
    data.iter().map(|arg| tokenize(arg)).collect()
}

fn parse_num<T: std::str::FromStr>(token: &str, what: &str) -> Result<T, String> {
    token
        .parse()
        .map_err(|_| format!("{what} `{token}` is not a number in range"))
}

/// One record as the typed JSON of the API, from its presentation tokens.
fn parse_record(rtype: &str, tokens: &[String], zone: &str) -> Result<Value, String> {
    let fields = field_count(rtype).ok_or_else(|| format!("unsupported record type {rtype}"))?;
    let wrong =
        |expected: &str| format!("{rtype} data is `{expected}`, got `{}`", tokens.join(" "));
    if rtype != "TXT" && rtype != "CAA" && tokens.len() != fields {
        return Err(wrong(match rtype {
            "MX" => "<preference> <exchange>",
            "SRV" => "<priority> <weight> <port> <target>",
            _ => "<value>",
        }));
    }
    let name = |token: &String| qualify_data(token, zone);
    Ok(match rtype {
        "A" => {
            let address: Ipv4Addr = tokens[0]
                .parse()
                .map_err(|_| format!("`{}` is not an IPv4 address", tokens[0]))?;
            json!({"type": "A", "address": address.to_string()})
        }
        "AAAA" => {
            let address: Ipv6Addr = tokens[0]
                .parse()
                .map_err(|_| format!("`{}` is not an IPv6 address", tokens[0]))?;
            json!({"type": "AAAA", "address": address.to_string()})
        }
        "CNAME" | "DNAME" | "PTR" => json!({"type": rtype, "target": name(&tokens[0])}),
        "NS" => json!({"type": "NS", "host": name(&tokens[0])}),
        "MX" => json!({
            "type": "MX",
            "preference": parse_num::<u16>(&tokens[0], "preference")?,
            "exchange": name(&tokens[1]),
        }),
        "SRV" => json!({
            "type": "SRV",
            "priority": parse_num::<u16>(&tokens[0], "priority")?,
            "weight": parse_num::<u16>(&tokens[1], "weight")?,
            "port": parse_num::<u16>(&tokens[2], "port")?,
            "target": name(&tokens[3]),
        }),
        "TXT" => {
            if tokens.is_empty() {
                return Err(wrong("<text>..."));
            }
            json!({"type": "TXT", "strings": tokens})
        }
        "CAA" => {
            if tokens.len() < 3 {
                return Err(wrong("<flags> <tag> <value>"));
            }
            json!({
                "type": "CAA",
                "flags": parse_num::<u8>(&tokens[0], "flags")?,
                "tag": tokens[1].to_ascii_lowercase(),
                "value": tokens[2..].join(" "),
            })
        }
        _ => return Err(format!("unsupported record type {rtype}")),
    })
}

/// The `records` of a change.
fn parse_records(rtype: &str, data: &[String], zone: &str) -> Result<Vec<Value>, String> {
    group_data(rtype, data)?
        .iter()
        .map(|tokens| parse_record(rtype, tokens, zone))
        .collect()
}

/// A record of the API in presentation form.
fn present(record: &Value) -> String {
    let field = |key: &str| match record.get(key) {
        Some(Value::String(text)) => text.clone(),
        Some(other) => other.to_string(),
        None => String::new(),
    };
    match text(record, &["type"]) {
        "A" | "AAAA" => field("address"),
        "CNAME" | "DNAME" | "PTR" => field("target"),
        "NS" => field("host"),
        "MX" => format!("{} {}", field("preference"), field("exchange")),
        "SRV" => format!(
            "{} {} {} {}",
            field("priority"),
            field("weight"),
            field("port"),
            field("target")
        ),
        "TXT" => record
            .get("strings")
            .and_then(Value::as_array)
            .map(|strings| {
                strings
                    .iter()
                    .map(|s| {
                        format!(
                            "\"{}\"",
                            s.as_str().unwrap_or_default().replace('"', "\\\"")
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .unwrap_or_default(),
        "CAA" => format!("{} {} \"{}\"", field("flags"), field("tag"), field("value")),
        "SOA" => format!(
            "{} {} {} {} {} {} {}",
            field("mname"),
            field("rname"),
            field("serial"),
            field("refresh"),
            field("retry"),
            field("expire"),
            field("minimum")
        ),
        _ => {
            let mut rest = record.clone();
            if let Some(object) = rest.as_object_mut() {
                object.remove("type");
            }
            rest.to_string()
        }
    }
}

/// The records of an RRset in presentation form.
fn present_all(rrset: &Value) -> Vec<String> {
    rrset
        .get("records")
        .and_then(Value::as_array)
        .map(|records| records.iter().map(present).collect())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------------------
// Records

async fn record_list(target: &Target, args: &RecordListArgs) -> Result<Output, Failure> {
    let client = target.connect().await?;
    let zone = resolve_zone(&client, &args.zone).await?;
    let path = format!("{}/records", zone_path(&zone));
    let mut filters: Vec<(&str, String)> = Vec::new();
    for (key, value) in [
        ("scope", &args.scope),
        ("name", &args.name),
        ("type", &args.rtype),
        ("origin", &args.origin),
    ] {
        if let Some(value) = value {
            filters.push((key, value.clone()));
        }
    }
    let (items, more) = if let Some(limit) = args.limit {
        filters.push(("limit", limit.clamp(1, 1000).to_string()));
        let page: Page<Value> = client.get_query(&path, &filters).await?;
        (page.items, page.next_cursor.is_some())
    } else {
        (list_all(&client, &path, &filters).await?, false)
    };
    if target.json {
        return Ok(Output::json(&json!({ "items": items })));
    }
    let mut rows = Vec::new();
    for rrset in &items {
        for data in present_all(rrset) {
            rows.push(vec![
                text(rrset, &["name"]).to_owned(),
                text(rrset, &["type"]).to_owned(),
                number(rrset, &["ttl"]),
                data,
                text(rrset, &["origin"]).to_owned(),
            ]);
        }
    }
    let mut output = Output::text(table(&["NAME", "TYPE", "TTL", "DATA", "ORIGIN"], &rows));
    if more {
        output = output.note("more records follow: raise --limit or leave it out");
    }
    Ok(output)
}

/// The text of a diff.
fn render_diff(changes: &[Value]) -> String {
    let mut out = String::new();
    for change in changes {
        let name = text(change, &["name"]);
        let rtype = text(change, &["type"]);
        let before = change.get("before").filter(|v| !v.is_null());
        let after = change.get("after").filter(|v| !v.is_null());
        for (mark, rrset) in [("-", before), ("+", after)] {
            let Some(rrset) = rrset else { continue };
            for data in present_all(rrset) {
                let _ = writeln!(
                    out,
                    "{mark} {name} {} {rtype} {data}",
                    number(rrset, &["ttl"])
                );
            }
        }
    }
    out
}

async fn record_change(target: &Target, args: &ChangeArgs, op: Op) -> Result<Output, Failure> {
    let rtype = args.rtype.trim().to_ascii_uppercase();
    if op == Op::Delete && !args.data.is_empty() {
        return Err(usage(
            "`delete` removes the whole RRset and takes no data; use `remove` for single records",
        ));
    }
    if op != Op::Delete && args.data.is_empty() {
        return Err(usage(format!(
            "`{}` needs the record data",
            match op {
                Op::Add => "add",
                Op::Set => "replace",
                _ => "remove",
            }
        )));
    }
    let client = target.connect().await?;
    let zone = resolve_zone(&client, &args.zone).await?;
    let apex = text(&zone, &["name"]).to_owned();
    let records = parse_records(&rtype, &args.data, &apex).map_err(usage)?;
    let mut change = json!({
        "op": op.api(),
        "name": qualify_owner(&args.name, &apex),
        "type": rtype,
        "records": records,
    });
    if let Some(scope) = &args.scope {
        change["scope"] = json!(scope);
    }
    if let Some(ttl) = args.ttl {
        change["ttl"] = json!(ttl);
    }
    if args.take_over {
        change["take_over"] = json!(true);
    }
    let mut path = format!("{}/records/batch", zone_path(&zone));
    if args.dry_run {
        path.push_str("?dry_run=true");
    }
    let answer: Value = client
        .post(&path, &json!({ "changes": [change] }), Some(&key()))
        .await?;
    if target.json {
        return Ok(Output::json(&answer));
    }
    let changes = answer
        .get("changes")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut out = render_diff(&changes);
    if args.dry_run {
        if changes.is_empty() {
            out.push_str("no change\n");
        }
        out.push_str("dry run: nothing was written\n");
    } else if changes.is_empty() {
        out.push_str("no change\n");
    } else {
        let _ = writeln!(
            out,
            "applied {} change(s), serial {}, revision {}",
            changes.len(),
            number(&answer, &["serial"]),
            number(&answer, &["revision"]),
        );
    }
    Ok(Output::text(out))
}

// ---------------------------------------------------------------------------------------
// Import and export

/// The bytes of a lowercase or uppercase hexadecimal text.
fn from_hex(text: &str) -> Option<Vec<u8>> {
    let digits = text.as_bytes();
    if !digits.len().is_multiple_of(2) {
        return None;
    }
    digits
        .chunks(2)
        .map(|pair| {
            let high = char::from(pair[0]).to_digit(16)?;
            let low = char::from(pair[1]).to_digit(16)?;
            u8::try_from(high * 16 + low).ok()
        })
        .collect()
}

/// The records per type of a report: an array of `{rtype, records}` (the preview) or an
/// object of type to count (the job's report).
fn type_counts(report: &Value) -> Vec<(String, u64)> {
    match report.get("types") {
        Some(Value::Array(list)) => list
            .iter()
            .map(|item| {
                (
                    text(item, &["rtype"]).to_owned(),
                    item.get("records").and_then(Value::as_u64).unwrap_or(0),
                )
            })
            .collect(),
        Some(Value::Object(map)) => map
            .iter()
            .map(|(rtype, count)| (rtype.clone(), count.as_u64().unwrap_or(0)))
            .collect(),
        _ => Vec::new(),
    }
}

fn render_report(report: &Value) -> String {
    let count = |key: &str| report.get(key).and_then(Value::as_u64).unwrap_or(0);
    let dry = report
        .get("dry_run")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{}: {} RRset(s) added, {} replaced, {} removed",
        if dry { "preview" } else { "imported" },
        count("added"),
        count("replaced"),
        count("removed"),
    );
    let types = type_counts(report);
    if !types.is_empty() {
        let list: Vec<String> = types
            .iter()
            .map(|(rtype, records)| format!("{rtype} {records}"))
            .collect();
        let _ = writeln!(out, "records per type: {}", list.join(", "));
    }
    let losses = report
        .get("losses")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let lost = count("lost").max(losses.len() as u64);
    if lost > 0 {
        let _ = writeln!(out, "losses: {lost}");
        for loss in &losses {
            let _ = writeln!(
                out,
                "  line {}: [{}] {}",
                number(loss, &["line"]),
                text(loss, &["code"]),
                text(loss, &["detail"]),
            );
        }
        if lost > losses.len() as u64 {
            let _ = writeln!(out, "  ... and {} more", lost - losses.len() as u64);
        }
    } else {
        out.push_str("losses: none\n");
    }
    if let Some(serial) = report.get("serial").and_then(Value::as_u64) {
        let _ = writeln!(
            out,
            "serial {serial}, revision {}",
            number(report, &["revision"])
        );
    }
    out
}

/// What the job did not do: `[code] detail` of its error or of the first failed step.
fn job_error(detail: &Value) -> String {
    let error = detail
        .pointer("/job/error")
        .filter(|error| !error.is_null())
        .cloned()
        .or_else(|| {
            detail
                .pointer("/job/steps")
                .and_then(Value::as_array)
                .and_then(|steps| {
                    steps.iter().find_map(|step| {
                        step.pointer("/state/error")
                            .filter(|e| !e.is_null())
                            .cloned()
                    })
                })
        });
    match error {
        Some(error) => format!(
            "[{}] {}",
            text(&error, &["code"]),
            text(&error, &["detail"])
        ),
        None => "no reason given".to_owned(),
    }
}

/// Waits for the job to end; its detail.
async fn wait_job(client: &Client, job_id: &str, secs: u64) -> Result<Value, Failure> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    loop {
        let detail: Value = client.get(&format!("/jobs/{job_id}")).await?;
        let state = text(&detail, &["job", "state"]).to_owned();
        match state.as_str() {
            "queued" | "running" | "waiting" | "rolling_back" => {}
            "succeeded" => return Ok(detail),
            other => {
                return Err(Failure::new(
                    exit::JOB,
                    format!(
                        "import job {job_id} ended {}: {}",
                        other.replace('_', " "),
                        job_error(&detail)
                    ),
                ));
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(Failure::new(
                exit::JOB,
                format!(
                    "timed out after {secs} s waiting for import job {job_id} (last state: \
                     {state}); it keeps running on the controller, read it with \
                     GET /api/v1/jobs/{job_id}"
                ),
            ));
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// The JSON report in the output of the finishing step.
fn job_report(detail: &Value) -> Option<Value> {
    let steps = detail.pointer("/job/steps")?.as_array()?;
    let finish = steps
        .iter()
        .find(|step| text(step, &["kind"]) == "dns.import.finish")?;
    let bytes = from_hex(finish.get("output")?.as_str()?)?;
    serde_json::from_slice(&bytes).ok()
}

async fn import(target: &Target, args: &ImportArgs) -> Result<Output, Failure> {
    let bytes = std::fs::read(&args.file)
        .map_err(|error| usage(format!("cannot read {}: {error}", args.file.display())))?;
    let zone_file = String::from_utf8(bytes)
        .map_err(|_| usage(format!("{} is not UTF-8 text", args.file.display())))?;
    let client = target.connect().await?;
    let zone = resolve_zone(&client, &args.zone).await?;
    let mut body = json!({ "zone_file": zone_file, "replace": args.replace });
    if let Some(scope) = &args.scope {
        body["scope"] = json!(scope);
    }
    let mut path = format!("{}/records/import", zone_path(&zone));
    if args.dry_run {
        path.push_str("?dry_run=true");
    }
    // No `Idempotency-Key`: the idempotency middleware keeps keyed requests under a smaller
    // limit (32 MiB) than a zone file may have, and an import is checked again before it
    // starts.
    let answer: Value = client.post(&path, &body, None).await?;
    if args.dry_run {
        if target.json {
            return Ok(Output::json(&answer));
        }
        return Ok(Output::text(render_report(&answer)));
    }
    let job_id = text(&answer, &["job_id"]).to_owned();
    if job_id.is_empty() {
        return Err(Failure::other(
            "unexpected answer: the import has no job_id",
        ));
    }
    let detail = wait_job(&client, &job_id, args.wait_secs).await?;
    let report = job_report(&detail).ok_or_else(|| {
        Failure::new(
            exit::JOB,
            format!("import job {job_id} succeeded but its report is missing"),
        )
    })?;
    if target.json {
        return Ok(Output::json(&json!({ "job_id": job_id, "report": report })));
    }
    Ok(Output::text(render_report(&report)))
}

async fn export(target: &Target, args: &ExportArgs) -> Result<Output, Failure> {
    let client = target.connect().await?;
    let zone = resolve_zone(&client, &args.zone).await?;
    let mut path = format!("{}/records/export", zone_path(&zone));
    if let Some(scope) = &args.scope {
        path.push_str("?scope=");
        path.push_str(scope);
    }
    let file = client.get_text(&path).await?;
    match &args.file {
        Some(out) => {
            // The bytes are the server's, unchanged (MIG-15).
            std::fs::write(out, file.as_bytes()).map_err(|error| {
                Failure::other(format!("cannot write {}: {error}", out.display()))
            })?;
            Ok(Output::default().note(format!(
                "{} byte(s) written to {}",
                file.len(),
                out.display()
            )))
        }
        None => Ok(Output::text(file)),
    }
}

// ---------------------------------------------------------------------------------------
// Access lists

/// One `--entry` as the JSON of an access list entry.
fn parse_entry(entry: &str) -> Result<Value, String> {
    let mut parts = entry.split(',').map(str::trim);
    let spec = parts.next().unwrap_or_default();
    let mut deny = false;
    for flag in parts {
        match flag {
            "deny" => deny = true,
            "allow" => deny = false,
            other => return Err(format!("`{other}` in entry `{entry}` is not allow or deny")),
        }
    }
    if spec.eq_ignore_ascii_case("any") {
        return Ok(json!({"kind": "any", "deny": deny}));
    }
    if let Some(name) = spec.strip_prefix("key:") {
        if name.is_empty() {
            return Err(format!("entry `{entry}` names no key"));
        }
        return Ok(json!({"kind": "key", "name": name.to_ascii_lowercase(), "deny": deny}));
    }
    let net = IpNet::from_str(spec)
        .ok()
        .or_else(|| IpAddr::from_str(spec).ok().map(IpNet::from))
        .ok_or_else(|| format!("entry `{entry}` is not a network, an address, key:NAME or any"))?;
    Ok(json!({"kind": "prefix", "prefix": net.to_string(), "deny": deny}))
}

fn parse_entries(entries: &[String]) -> Result<Vec<Value>, Failure> {
    entries
        .iter()
        .map(|entry| parse_entry(entry).map_err(usage))
        .collect()
}

/// An entry in the syntax of `--entry`.
fn present_entry(entry: &Value) -> String {
    let base = match text(entry, &["kind"]) {
        "prefix" => text(entry, &["prefix"]).to_owned(),
        "key" => format!("key:{}", text(entry, &["name"])),
        _ => "any".to_owned(),
    };
    if entry.get("deny").and_then(Value::as_bool) == Some(true) {
        format!("{base},deny")
    } else {
        base
    }
}

fn entries_of(acl: &Value) -> Vec<String> {
    acl.get("entries")
        .and_then(Value::as_array)
        .map(|entries| entries.iter().map(present_entry).collect())
        .unwrap_or_default()
}

async fn resolve_acl(client: &Client, reference: &str) -> Result<Value, Failure> {
    if Uuid::parse_str(reference).is_ok() {
        return Ok(client.get(&format!("/dns/acls/{reference}")).await?);
    }
    let acls = list_all(client, "/dns/acls", &[]).await?;
    acls.into_iter()
        .find(|acl| text(acl, &["name"]) == reference)
        .ok_or_else(|| not_found("dns.acl.not_found", "access list", reference))
}

fn describe_acl(acl: &Value) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "name         {}", text(acl, &["name"]));
    let _ = writeln!(out, "id           {}", text(acl, &["id"]));
    let description = text(acl, &["description"]);
    if !description.is_empty() {
        let _ = writeln!(out, "description  {description}");
    }
    let used: Vec<&str> = acl
        .get("used_by")
        .and_then(Value::as_array)
        .map(|list| list.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    if !used.is_empty() {
        let _ = writeln!(out, "used by      {}", used.join(", "));
    }
    let _ = writeln!(out, "revision     {}", number(acl, &["revision"]));
    for (index, entry) in entries_of(acl).iter().enumerate() {
        let _ = writeln!(out, "entry {:<2}     {entry}", index + 1);
    }
    out
}

async fn acl_list(target: &Target) -> Result<Output, Failure> {
    let client = target.connect().await?;
    let items = list_all(&client, "/dns/acls", &[]).await?;
    if target.json {
        return Ok(Output::json(&json!({ "items": items })));
    }
    let rows: Vec<Vec<String>> = items
        .iter()
        .map(|acl| {
            vec![
                text(acl, &["name"]).to_owned(),
                entries_of(acl).join(" "),
                text(acl, &["id"]).to_owned(),
            ]
        })
        .collect();
    Ok(Output::text(table(&["NAME", "ENTRIES", "ID"], &rows)))
}

async fn acl_create(target: &Target, args: &AclCreateArgs) -> Result<Output, Failure> {
    let entries = parse_entries(&args.entries)?;
    let client = target.connect().await?;
    let mut body = json!({ "name": args.name, "entries": entries });
    if let Some(description) = &args.description {
        body["description"] = json!(description);
    }
    let answer: Value = client.post("/dns/acls", &body, Some(&key())).await?;
    if target.json {
        return Ok(Output::json(&answer));
    }
    Ok(Output::text(format!(
        "created access list {} ({})\n",
        text(&answer, &["name"]),
        text(&answer, &["id"]),
    )))
}

async fn acl_get(target: &Target, args: &NamedArgs) -> Result<Output, Failure> {
    let client = target.connect().await?;
    let acl = resolve_acl(&client, &args.name).await?;
    if target.json {
        return Ok(Output::json(&acl));
    }
    Ok(Output::text(describe_acl(&acl)))
}

async fn acl_update(target: &Target, args: &AclUpdateArgs) -> Result<Output, Failure> {
    let mut body = Map::new();
    if let Some(name) = &args.name {
        body.insert("name".to_owned(), json!(name));
    }
    if !args.entries.is_empty() {
        body.insert("entries".to_owned(), json!(parse_entries(&args.entries)?));
    }
    if let Some(description) = &args.description {
        body.insert("description".to_owned(), json!(description));
    }
    if body.is_empty() {
        return Err(usage(
            "nothing to change: give --name, --entry or --description",
        ));
    }
    let client = target.connect().await?;
    let acl = resolve_acl(&client, &args.acl).await?;
    let path = format!("/dns/acls/{}", text(&acl, &["id"]));
    let answer: Value = client.patch(&path, &Value::Object(body), None).await?;
    if target.json {
        return Ok(Output::json(&answer));
    }
    Ok(Output::text(format!(
        "updated access list {} at revision {}\n",
        text(&answer, &["name"]),
        number(&answer, &["revision"]),
    )))
}

async fn acl_delete(target: &Target, args: &NamedArgs) -> Result<Output, Failure> {
    let client = target.connect().await?;
    let acl = resolve_acl(&client, &args.name).await?;
    client
        .delete(&format!("/dns/acls/{}", text(&acl, &["id"])), None)
        .await?;
    if target.json {
        return Ok(Output::json(&json!({ "deleted": text(&acl, &["id"]) })));
    }
    Ok(Output::text(format!(
        "deleted access list {} ({})\n",
        text(&acl, &["name"]),
        text(&acl, &["id"]),
    )))
}

// ---------------------------------------------------------------------------------------
// Forwarding rules

/// An upstream as the API takes it, from `ADDRESS[:PORT][/PATH]`.
fn parse_upstream(text: &str) -> Result<Value, Failure> {
    let text = text.trim();
    let bad = || {
        usage(format!(
            "`{text}` is not an upstream: an address with an optional port and path, such as \
             192.0.2.1, 192.0.2.1:853, [2001:db8::1]:443/dns-query"
        ))
    };
    if let Ok(address) = text.parse::<IpAddr>() {
        return Ok(json!({ "address": address.to_string() }));
    }
    // The path starts at the first `/` after the address (and its port).
    let (head, path) = if let Some(rest) = text.strip_prefix('[') {
        let close = rest.find(']').ok_or_else(bad)?;
        let after = &rest[close + 1..];
        match after.find('/') {
            Some(slash) => (&text[..close + 2 + slash], Some(&after[slash..])),
            None => (text, None),
        }
    } else {
        match text.find('/') {
            Some(slash) => (&text[..slash], Some(&text[slash..])),
            None => (text, None),
        }
    };
    let mut upstream = Map::new();
    if let Ok(address) = head.parse::<IpAddr>() {
        upstream.insert("address".to_owned(), json!(address.to_string()));
    } else {
        let socket: std::net::SocketAddr = head.parse().map_err(|_| bad())?;
        upstream.insert("address".to_owned(), json!(socket.ip().to_string()));
        upstream.insert("port".to_owned(), json!(socket.port()));
    }
    if let Some(path) = path {
        upstream.insert("path".to_owned(), json!(path));
    }
    Ok(Value::Object(upstream))
}

fn parse_upstreams(upstreams: &[String]) -> Result<Vec<Value>, Failure> {
    upstreams.iter().map(|text| parse_upstream(text)).collect()
}

/// An upstream of a rule as the commands print it.
fn present_upstream(upstream: &Value) -> String {
    let address = text(upstream, &["address"]);
    let mut out = match upstream.get("port").and_then(Value::as_u64) {
        Some(port) if address.contains(':') => format!("[{address}]:{port}"),
        Some(port) => format!("{address}:{port}"),
        None => address.to_owned(),
    };
    out.push_str(text(upstream, &["path"]));
    out
}

fn upstreams_of(rule: &Value) -> Vec<String> {
    rule.get("upstreams")
        .and_then(Value::as_array)
        .map(|list| list.iter().map(present_upstream).collect())
        .unwrap_or_default()
}

/// The rule `reference` names: its identifier, or its suffix when one rule has it.
async fn resolve_rule(client: &Client, reference: &str) -> Result<Value, Failure> {
    if Uuid::parse_str(reference).is_ok() {
        return Ok(client.get(&format!("/dns/forwarders/{reference}")).await?);
    }
    let wanted = canonical(reference);
    let rules = list_all(client, "/dns/forwarders", &[]).await?;
    let mut found: Vec<Value> = rules
        .into_iter()
        .filter(|rule| text(rule, &["suffix"]) == wanted)
        .collect();
    match found.len() {
        0 => Err(not_found(
            "dns.forwarder.not_found",
            "forwarding rule",
            reference,
        )),
        1 => Ok(found.remove(0)),
        _ => Err(usage(format!(
            "{} rules cover {wanted} (in different views): give the identifier",
            found.len()
        ))),
    }
}

fn describe_rule(rule: &Value) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "suffix       {}", text(rule, &["suffix"]));
    let _ = writeln!(out, "id           {}", text(rule, &["id"]));
    let transport = text(rule, &["transport"]);
    let _ = writeln!(
        out,
        "transport    {}",
        if transport.is_empty() {
            "plain"
        } else {
            transport
        }
    );
    let tls_name = text(rule, &["tls_name"]);
    if !tls_name.is_empty() {
        let _ = writeln!(out, "tls name     {tls_name}");
    }
    let view = text(rule, &["view"]);
    let _ = writeln!(
        out,
        "view         {}",
        if view.is_empty() { "all" } else { view }
    );
    let description = text(rule, &["description"]);
    if !description.is_empty() {
        let _ = writeln!(out, "description  {description}");
    }
    let _ = writeln!(out, "revision     {}", number(rule, &["revision"]));
    for (index, upstream) in upstreams_of(rule).iter().enumerate() {
        let _ = writeln!(out, "upstream {:<2}  {upstream}", index + 1);
    }
    out
}

async fn forwarder_list(target: &Target) -> Result<Output, Failure> {
    let client = target.connect().await?;
    let items = list_all(&client, "/dns/forwarders", &[]).await?;
    if target.json {
        return Ok(Output::json(&json!({ "items": items })));
    }
    let rows: Vec<Vec<String>> = items
        .iter()
        .map(|rule| {
            let view = text(rule, &["view"]);
            vec![
                text(rule, &["suffix"]).to_owned(),
                text(rule, &["transport"]).to_owned(),
                upstreams_of(rule).join(" "),
                if view.is_empty() {
                    "all".to_owned()
                } else {
                    view.to_owned()
                },
                text(rule, &["id"]).to_owned(),
            ]
        })
        .collect();
    Ok(Output::text(table(
        &["SUFFIX", "TRANSPORT", "UPSTREAMS", "VIEW", "ID"],
        &rows,
    )))
}

async fn forwarder_create(target: &Target, args: &ForwarderCreateArgs) -> Result<Output, Failure> {
    let upstreams = parse_upstreams(&args.upstreams)?;
    let client = target.connect().await?;
    let mut body = json!({
        "suffix": canonical(&args.suffix),
        "upstreams": upstreams,
        "transport": args.transport.unwrap_or(TransportArg::Plain).api(),
    });
    if let Some(tls_name) = &args.tls_name {
        body["tls_name"] = json!(tls_name);
    }
    if let Some(view) = &args.view {
        body["view"] = json!(view);
    }
    if let Some(description) = &args.description {
        body["description"] = json!(description);
    }
    let answer: Value = client.post("/dns/forwarders", &body, Some(&key())).await?;
    if target.json {
        return Ok(Output::json(&answer));
    }
    Ok(Output::text(format!(
        "created forwarding rule {} ({})\n",
        text(&answer, &["suffix"]),
        text(&answer, &["id"]),
    )))
}

async fn forwarder_get(target: &Target, args: &NamedArgs) -> Result<Output, Failure> {
    let client = target.connect().await?;
    let rule = resolve_rule(&client, &args.name).await?;
    if target.json {
        return Ok(Output::json(&rule));
    }
    Ok(Output::text(describe_rule(&rule)))
}

async fn forwarder_update(target: &Target, args: &ForwarderUpdateArgs) -> Result<Output, Failure> {
    let mut body = Map::new();
    if let Some(suffix) = &args.suffix {
        body.insert("suffix".to_owned(), json!(canonical(suffix)));
    }
    if !args.upstreams.is_empty() {
        body.insert(
            "upstreams".to_owned(),
            json!(parse_upstreams(&args.upstreams)?),
        );
    }
    if let Some(transport) = args.transport {
        body.insert("transport".to_owned(), json!(transport.api()));
    }
    if let Some(tls_name) = &args.tls_name {
        body.insert("tls_name".to_owned(), json!(tls_name));
    }
    if let Some(view) = &args.view {
        body.insert("view".to_owned(), json!(view));
    }
    if args.all_views {
        body.insert("all_views".to_owned(), json!(true));
    }
    if let Some(description) = &args.description {
        body.insert("description".to_owned(), json!(description));
    }
    if body.is_empty() {
        return Err(usage(
            "nothing to change: give --suffix, --upstream, --transport, --tls-name, --view, \
             --all-views or --description",
        ));
    }
    let client = target.connect().await?;
    let rule = resolve_rule(&client, &args.rule).await?;
    let path = format!("/dns/forwarders/{}", text(&rule, &["id"]));
    let answer: Value = client.patch(&path, &Value::Object(body), None).await?;
    if target.json {
        return Ok(Output::json(&answer));
    }
    Ok(Output::text(format!(
        "updated forwarding rule {} at revision {}\n",
        text(&answer, &["suffix"]),
        number(&answer, &["revision"]),
    )))
}

async fn forwarder_delete(target: &Target, args: &NamedArgs) -> Result<Output, Failure> {
    let client = target.connect().await?;
    let rule = resolve_rule(&client, &args.name).await?;
    client
        .delete(&format!("/dns/forwarders/{}", text(&rule, &["id"])), None)
        .await?;
    if target.json {
        return Ok(Output::json(&json!({ "deleted": text(&rule, &["id"]) })));
    }
    Ok(Output::text(format!(
        "deleted forwarding rule {} ({})\n",
        text(&rule, &["suffix"]),
        text(&rule, &["id"]),
    )))
}

// ---------------------------------------------------------------------------------------
// Block lists and allow lists

/// The `action` of a list as the API takes it, from `--action` and `--redirect`; `None`
/// when neither is given.
fn action_body(
    action: Option<BlockActionArg>,
    redirect: Option<IpAddr>,
) -> Result<Option<Value>, Failure> {
    match (action, redirect) {
        (None, None) => Ok(None),
        (Some(BlockActionArg::Nxdomain), None) => Ok(Some(json!({ "kind": "nxdomain" }))),
        (Some(BlockActionArg::Nodata), None) => Ok(Some(json!({ "kind": "nodata" }))),
        (Some(BlockActionArg::Redirect), Some(address)) => Ok(Some(json!({
            "kind": "redirect",
            "address": address.to_string(),
        }))),
        (Some(BlockActionArg::Redirect), None) => {
            Err(usage("--action redirect needs the address in --redirect"))
        }
        (_, Some(_)) => Err(usage("--redirect goes with --action redirect only")),
    }
}

/// The exempt prefixes of a request; an address is its host prefix.
fn exempt_body(prefixes: &[String]) -> Result<Vec<String>, Failure> {
    prefixes
        .iter()
        .map(|text| {
            let text = text.trim();
            IpNet::from_str(text)
                .ok()
                .or_else(|| IpAddr::from_str(text).ok().map(IpNet::from))
                .map(|net| net.trunc().to_string())
                .ok_or_else(|| {
                    usage(format!(
                        "`{text}` is not a prefix such as 192.0.2.0/24 or an address"
                    ))
                })
        })
        .collect()
}

/// The `source` of a list as the API takes it.
fn source_body(url: Option<&str>, upload: bool) -> Option<Value> {
    match (url, upload) {
        (Some(url), _) => Some(json!({ "kind": "url", "url": url.trim() })),
        (None, true) => Some(json!({ "kind": "upload" })),
        (None, false) => None,
    }
}

/// The body of `POST /dns/lists`.
fn block_list_create_body(args: &BlockListCreateArgs) -> Result<Value, Failure> {
    let source = source_body(args.source_url.as_deref(), args.upload)
        .ok_or_else(|| usage("give --source-url URL or --upload"))?;
    let mut body = json!({
        "name": args.name.trim(),
        "kind": args.kind.unwrap_or(ListKindArg::Block).api(),
        "source": source,
        "format": args.format.unwrap_or(ListFormatArg::Domains).api(),
        "exempt": exempt_body(&args.exempt)?,
    });
    if let Some(hours) = args.interval_hours {
        body["interval_hours"] = json!(hours);
    }
    if let Some(action) = action_body(args.action, args.redirect)? {
        body["action"] = action;
    }
    if args.disabled {
        body["enabled"] = json!(false);
    }
    if let Some(description) = &args.description {
        body["description"] = json!(description);
    }
    Ok(body)
}

/// The body of `PATCH /dns/lists/{id}`; empty when nothing is to change.
fn block_list_update_body(args: &BlockListUpdateArgs) -> Result<Map<String, Value>, Failure> {
    let mut body = Map::new();
    if let Some(name) = &args.name {
        body.insert("name".to_owned(), json!(name.trim()));
    }
    if let Some(source) = source_body(args.source_url.as_deref(), args.upload) {
        body.insert("source".to_owned(), source);
    }
    if let Some(format) = args.format {
        body.insert("format".to_owned(), json!(format.api()));
    }
    if let Some(kind) = args.kind {
        body.insert("kind".to_owned(), json!(kind.api()));
    }
    if let Some(hours) = args.interval_hours {
        body.insert("interval_hours".to_owned(), json!(hours));
    }
    if let Some(action) = action_body(args.action, args.redirect)? {
        body.insert("action".to_owned(), action);
    }
    if args.clear_exempt {
        body.insert("exempt".to_owned(), json!([]));
    } else if !args.exempt.is_empty() {
        body.insert("exempt".to_owned(), json!(exempt_body(&args.exempt)?));
    }
    if args.enable {
        body.insert("enabled".to_owned(), json!(true));
    }
    if args.disable {
        body.insert("enabled".to_owned(), json!(false));
    }
    if let Some(description) = &args.description {
        body.insert("description".to_owned(), json!(description));
    }
    Ok(body)
}

/// The list `reference` names: its identifier or its name, read from the server.
async fn resolve_block_list(client: &Client, reference: &str) -> Result<Value, Failure> {
    if Uuid::parse_str(reference).is_ok() {
        return Ok(client.get(&format!("/dns/lists/{reference}")).await?);
    }
    let wanted = reference.trim().to_lowercase();
    let lists = list_all(client, "/dns/lists", &[]).await?;
    lists
        .into_iter()
        .find(|list| text(list, &["name"]).to_lowercase() == wanted)
        .ok_or_else(|| not_found("dns.list.not_found", "block list", reference))
}

fn block_list_path(list: &Value) -> String {
    format!("/dns/lists/{}", text(list, &["id"]))
}

/// Where a list comes from: its URL, or `upload`.
fn present_source(list: &Value) -> String {
    match text(list, &["source", "kind"]) {
        "url" => text(list, &["source", "url"]).to_owned(),
        other => other.to_owned(),
    }
}

/// What a list answers: `nxdomain`, `nodata` or `redirect ADDRESS`.
fn present_action(list: &Value) -> String {
    match text(list, &["action", "kind"]) {
        "redirect" => format!("redirect {}", text(list, &["action", "address"])),
        other => other.to_owned(),
    }
}

/// The kind of a list; `block` when the answer has none.
fn present_kind(list: &Value) -> String {
    match text(list, &["kind"]) {
        "" => "block".to_owned(),
        kind => kind.to_owned(),
    }
}

/// `yes` unless the list is switched off.
fn present_enabled(list: &Value) -> String {
    if list.get("enabled").and_then(Value::as_bool) == Some(false) {
        "no".to_owned()
    } else {
        "yes".to_owned()
    }
}

fn exempt_of(list: &Value) -> Vec<String> {
    list.get("exempt")
        .and_then(Value::as_array)
        .map(|prefixes| {
            prefixes
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn describe_block_list(list: &Value) -> String {
    let mut lines: Vec<(&str, String)> = vec![
        ("name", text(list, &["name"]).to_owned()),
        ("id", text(list, &["id"]).to_owned()),
        ("kind", present_kind(list)),
        ("source", present_source(list)),
        ("format", text(list, &["format"]).to_owned()),
        (
            "interval",
            format!("{} h", number(list, &["interval_hours"])),
        ),
        ("action", present_action(list)),
        ("enabled", present_enabled(list)),
    ];
    let exempt = exempt_of(list);
    if !exempt.is_empty() {
        lines.push(("exempt", exempt.join(" ")));
    }
    let description = text(list, &["description"]);
    if !description.is_empty() {
        lines.push(("description", description.to_owned()));
    }
    if list
        .get("version")
        .is_some_and(|version| !version.is_null())
    {
        lines.push(("version", number(list, &["version", "revision"])));
        lines.push(("entries", number(list, &["version", "entries"])));
        lines.push(("bytes", number(list, &["version", "bytes"])));
        lines.push(("fetched", text(list, &["version", "fetched"]).to_owned()));
        let etag = text(list, &["version", "etag"]);
        if !etag.is_empty() {
            lines.push(("etag", etag.to_owned()));
        }
    } else {
        lines.push(("version", "none yet".to_owned()));
    }
    let checked = text(list, &["last_checked"]);
    if !checked.is_empty() {
        lines.push(("last checked", checked.to_owned()));
    }
    let error = text(list, &["last_error"]);
    if !error.is_empty() {
        lines.push(("last error", error.to_owned()));
        let detail = text(list, &["last_error_detail"]);
        if !detail.is_empty() {
            lines.push(("", detail.to_owned()));
        }
    }
    lines.push(("revision", number(list, &["revision"])));
    let width = lines.iter().map(|(key, _)| key.len()).max().unwrap_or(0);
    let mut out = String::new();
    for (key, value) in lines {
        let _ = writeln!(out, "{key:<width$}  {value}");
    }
    out
}

/// The rows of `tenko dns list list`.
fn block_list_rows(lists: &[Value]) -> Vec<Vec<String>> {
    lists
        .iter()
        .map(|list| {
            vec![
                text(list, &["name"]).to_owned(),
                present_kind(list),
                present_source(list),
                text(list, &["format"]).to_owned(),
                present_action(list),
                present_enabled(list),
                number(list, &["version", "entries"]),
                number(list, &["version", "revision"]),
                text(list, &["version", "fetched"]).to_owned(),
                text(list, &["last_error"]).to_owned(),
                text(list, &["id"]).to_owned(),
            ]
        })
        .collect()
}

async fn block_list_list(target: &Target) -> Result<Output, Failure> {
    let client = target.connect().await?;
    let items = list_all(&client, "/dns/lists", &[]).await?;
    if target.json {
        return Ok(Output::json(&json!({ "items": items })));
    }
    Ok(Output::text(table(
        &[
            "NAME",
            "KIND",
            "SOURCE",
            "FORMAT",
            "ACTION",
            "ENABLED",
            "ENTRIES",
            "VERSION",
            "FETCHED",
            "LAST ERROR",
            "ID",
        ],
        &block_list_rows(&items),
    )))
}

async fn block_list_create(target: &Target, args: &BlockListCreateArgs) -> Result<Output, Failure> {
    let body = block_list_create_body(args)?;
    let client = target.connect().await?;
    let answer: Value = client.post("/dns/lists", &body, Some(&key())).await?;
    if target.json {
        return Ok(Output::json(&answer));
    }
    let mut out = format!(
        "created list {} ({}) at revision {}\n",
        text(&answer, &["name"]),
        text(&answer, &["id"]),
        number(&answer, &["revision"]),
    );
    if args.upload {
        let _ = writeln!(
            out,
            "send its file with `tenko dns list upload {} FILE`",
            text(&answer, &["name"])
        );
    }
    Ok(Output::text(out))
}

async fn block_list_get(target: &Target, args: &BlockListRefArgs) -> Result<Output, Failure> {
    let client = target.connect().await?;
    let list = resolve_block_list(&client, &args.list).await?;
    if target.json {
        return Ok(Output::json(&list));
    }
    Ok(Output::text(describe_block_list(&list)))
}

async fn block_list_update(target: &Target, args: &BlockListUpdateArgs) -> Result<Output, Failure> {
    let body = block_list_update_body(args)?;
    if body.is_empty() {
        return Err(usage(
            "nothing to change: give --name, --source-url, --upload, --format, --kind, \
             --interval-hours, --action, --exempt, --clear-exempt, --enable, --disable or \
             --description",
        ));
    }
    let client = target.connect().await?;
    let list = resolve_block_list(&client, &args.list).await?;
    let answer: Value = client
        .patch(
            &block_list_path(&list),
            &Value::Object(body),
            revision(args.if_match),
        )
        .await?;
    if target.json {
        return Ok(Output::json(&answer));
    }
    Ok(Output::text(format!(
        "updated list {} at revision {}\n",
        text(&answer, &["name"]),
        number(&answer, &["revision"]),
    )))
}

async fn block_list_delete(target: &Target, args: &BlockListDeleteArgs) -> Result<Output, Failure> {
    let client = target.connect().await?;
    let list = resolve_block_list(&client, &args.list).await?;
    client
        .delete(&block_list_path(&list), revision(args.if_match))
        .await?;
    if target.json {
        return Ok(Output::json(&json!({ "deleted": text(&list, &["id"]) })));
    }
    Ok(Output::text(format!(
        "deleted list {} ({})\n",
        text(&list, &["name"]),
        text(&list, &["id"]),
    )))
}

/// What `fetch` and `upload` print for the job they started. The CLI has no jobs command
/// yet, so the line names the API route.
fn job_started(answer: &Value, list: &Value) -> Result<Output, Failure> {
    let job_id = text(answer, &["job_id"]);
    if job_id.is_empty() {
        return Err(Failure::other(
            "unexpected answer: the request has no job_id",
        ));
    }
    let name = text(list, &["name"]);
    Ok(Output::text(format!(
        "started job {job_id} for list {name}\n\
         follow it with GET /api/v1/jobs/{job_id}; the outcome shows in `tenko dns list get \
         {name}` (version and last error)\n",
    )))
}

async fn block_list_fetch(target: &Target, args: &BlockListRefArgs) -> Result<Output, Failure> {
    let client = target.connect().await?;
    let list = resolve_block_list(&client, &args.list).await?;
    let path = format!("{}/fetch", block_list_path(&list));
    let answer: Value = client.post(&path, &json!({}), Some(&key())).await?;
    if target.json {
        return Ok(Output::json(&answer));
    }
    job_started(&answer, &list)
}

/// The bytes of the file, or of standard input for `-`.
fn read_upload(file: &std::path::Path) -> Result<Vec<u8>, Failure> {
    if file.as_os_str() == "-" {
        let mut bytes = Vec::new();
        std::io::stdin()
            .lock()
            .read_to_end(&mut bytes)
            .map_err(|error| usage(format!("cannot read standard input: {error}")))?;
        return Ok(bytes);
    }
    std::fs::read(file).map_err(|error| usage(format!("cannot read {}: {error}", file.display())))
}

async fn block_list_upload(target: &Target, args: &BlockListUploadArgs) -> Result<Output, Failure> {
    let bytes = read_upload(&args.file)?;
    let client = target.connect().await?;
    let list = resolve_block_list(&client, &args.list).await?;
    // The typed client sends JSON only: the file goes as `text/plain` through the raw helper,
    // without an `Idempotency-Key` (keyed requests are buffered under a smaller limit than an
    // upload may have).
    let raw = target.raw()?;
    let mut request = raw
        .http
        .put(raw.url(&format!("{}/file", block_list_path(&list))))
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(bytes);
    if let Some(token) = &raw.token {
        request = request.bearer_auth(token);
    }
    let answer: Value = raw.send(request).await?.json()?;
    if target.json {
        return Ok(Output::json(&answer));
    }
    job_started(&answer, &list)
}

// ---------------------------------------------------------------------------------------
// TSIG keys

fn describe_key(key: &Value) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "name       {}", text(key, &["name"]));
    let _ = writeln!(out, "id         {}", text(key, &["id"]));
    let _ = writeln!(out, "algorithm  {}", text(key, &["algorithm"]));
    let description = text(key, &["description"]);
    if !description.is_empty() {
        let _ = writeln!(out, "description  {description}");
    }
    out
}

async fn key_list(target: &Target) -> Result<Output, Failure> {
    let client = target.connect().await?;
    let items = list_all(&client, "/dns/keys", &[]).await?;
    if target.json {
        return Ok(Output::json(&json!({ "items": items })));
    }
    let rows: Vec<Vec<String>> = items
        .iter()
        .map(|key| {
            vec![
                text(key, &["name"]).to_owned(),
                text(key, &["algorithm"]).to_owned(),
                text(key, &["id"]).to_owned(),
            ]
        })
        .collect();
    Ok(Output::text(table(&["NAME", "ALGORITHM", "ID"], &rows)))
}

async fn key_create(target: &Target, args: &KeyCreateArgs) -> Result<Output, Failure> {
    let client = target.connect().await?;
    let mut body = json!({ "name": canonical(&args.name) });
    if let Some(algorithm) = args.algorithm {
        body["algorithm"] = json!(algorithm.api());
    }
    if let Some(description) = &args.description {
        body["description"] = json!(description);
    }
    if let Some(path) = &args.secret_file {
        let secret = std::fs::read_to_string(path)
            .map_err(|error| usage(format!("cannot read {}: {error}", path.display())))?;
        body["secret"] = json!(secret.trim());
    }
    let answer: Value = client.post("/dns/keys", &body, Some(&key())).await?;
    if target.json {
        return Ok(Output::json(&answer));
    }
    let created = answer.get("key").unwrap_or(&Value::Null);
    let mut out = describe_key(created);
    let _ = writeln!(out, "secret     {}", text(&answer, &["secret"]));
    Ok(Output::text(out).note("the secret is shown this once; store it now"))
}

async fn key_get(target: &Target, args: &NamedArgs) -> Result<Output, Failure> {
    let client = target.connect().await?;
    let answer: Value = client
        .get(&format!("/dns/keys/{}", canonical(&args.name)))
        .await?;
    if target.json {
        return Ok(Output::json(&answer));
    }
    Ok(Output::text(describe_key(&answer)))
}

async fn key_delete(target: &Target, args: &NamedArgs) -> Result<Output, Failure> {
    let client = target.connect().await?;
    let name = canonical(&args.name);
    client.delete(&format!("/dns/keys/{name}"), None).await?;
    if target.json {
        return Ok(Output::json(&json!({ "deleted": name })));
    }
    Ok(Output::text(format!("deleted key {name}\n")))
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[derive(Parser)]
    struct Cli {
        #[command(subcommand)]
        command: DnsCommand,
    }

    fn parse(args: &[&str]) -> Result<DnsCommand, clap::Error> {
        Cli::try_parse_from(std::iter::once("dns").chain(args.iter().copied()))
            .map(|cli| cli.command)
    }

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn commands_have_their_names() {
        let cases: &[(&[&str], &str)] = &[
            (&["zone", "list"], "dns zone list"),
            (
                &[
                    "zone",
                    "create",
                    "example.test",
                    "--ns",
                    "ns1",
                    "--mname",
                    "ns1",
                    "--rname",
                    "hostmaster@example.test",
                ],
                "dns zone create",
            ),
            (&["zone", "get", "example.test"], "dns zone get"),
            (
                &["zone", "update", "example.test", "--serial", "counter"],
                "dns zone update",
            ),
            (
                &["zone", "delete", "example.test", "--if-match", "7"],
                "dns zone delete",
            ),
            (&["record", "list", "example.test"], "dns record list"),
            (
                &["record", "add", "example.test", "www", "A", "192.0.2.1"],
                "dns record add",
            ),
            (
                &["record", "replace", "example.test", "www", "A", "192.0.2.1"],
                "dns record replace",
            ),
            (
                &["record", "delete", "example.test", "www", "A"],
                "dns record delete",
            ),
            (
                &["record", "remove", "example.test", "www", "A", "192.0.2.1"],
                "dns record remove",
            ),
            (
                &["import", "example.test", "z.db", "--dry-run"],
                "dns import",
            ),
            (&["export", "example.test", "--file", "z.db"], "dns export"),
            (&["acl", "list"], "dns acl list"),
            (
                &["acl", "create", "lan", "--entry", "192.0.2.0/24,deny"],
                "dns acl create",
            ),
            (&["acl", "get", "lan"], "dns acl get"),
            (
                &["key", "create", "k1", "--algorithm", "hmac-sha512"],
                "dns key create",
            ),
            (&["key", "delete", "k1"], "dns key delete"),
            (&["forwarder", "list"], "dns forwarder list"),
            (
                &[
                    "forwarder",
                    "create",
                    ".",
                    "--upstream",
                    "192.0.2.1:853",
                    "--transport",
                    "dot",
                    "--tls-name",
                    "resolver.example.test",
                ],
                "dns forwarder create",
            ),
            (&["forwarder", "get", "example.test"], "dns forwarder get"),
            (
                &["forwarder", "update", "example.test", "--all-views"],
                "dns forwarder update",
            ),
            (
                &["forwarder", "delete", "example.test"],
                "dns forwarder delete",
            ),
        ];
        for (args, name) in cases {
            let command = parse(args).unwrap_or_else(|error| panic!("{args:?}: {error}"));
            assert_eq!(command.name(), *name);
        }
    }

    #[test]
    fn arguments_are_checked() {
        assert!(parse(&["zone", "create", "example.test"]).is_err());
        assert!(parse(&["zone", "update", "z", "--serial", "weekly"]).is_err());
        assert!(parse(&["key", "create", "k", "--algorithm", "md5"]).is_err());
        assert!(parse(&["acl", "create", "x"]).is_err());
        assert!(parse(&["forwarder", "create", "example.test"]).is_err());
        assert!(
            parse(&[
                "forwarder",
                "create",
                "x",
                "--upstream",
                "192.0.2.1",
                "--transport",
                "tls"
            ])
            .is_err()
        );
        assert!(
            parse(&["forwarder", "update", "x", "--view", "v", "--all-views"]).is_err(),
            "a view and every view at once"
        );
        let DnsCommand::Zone {
            action: ZoneCommand::Update(args),
        } = parse(&["zone", "update", "z", "--serial", "date-counter"]).expect("valid")
        else {
            panic!("not a zone update");
        };
        assert_eq!(args.serial, Some(SerialArg::DateCounter));
        assert_eq!(args.if_match, None);
    }

    #[test]
    fn owner_names_are_qualified() {
        let zone = "example.test";
        assert_eq!(qualify_owner("@", zone), "example.test");
        assert_eq!(qualify_owner("www", zone), "www.example.test");
        assert_eq!(qualify_owner("_ldap._tcp", zone), "_ldap._tcp.example.test");
        assert_eq!(qualify_owner("WWW.example.test", zone), "www.example.test");
        assert_eq!(qualify_owner("www.example.test.", zone), "www.example.test");
        assert_eq!(qualify_owner("example.test", zone), "example.test");
        assert_eq!(qualify_owner("other.test.", zone), "other.test");
        assert_eq!(qualify_owner("host", "."), "host");
    }

    #[test]
    fn names_in_data_are_qualified() {
        let zone = "example.test";
        assert_eq!(qualify_data("@", zone), "example.test");
        assert_eq!(qualify_data("mx", zone), "mx.example.test");
        assert_eq!(qualify_data("mx.example.test", zone), "mx.example.test");
        assert_eq!(qualify_data("mail.other.test.", zone), "mail.other.test");
        assert_eq!(qualify_data("ns1", "."), "ns1");
    }

    #[test]
    fn zones_are_found_by_name() {
        let zones = vec![
            json!({"name": "example.test", "id": "a"}),
            json!({"name": "copy.test", "id": "b"}),
        ];
        assert_eq!(
            text(find_named(&zones, "Copy.Test.").expect("found"), &["id"]),
            "b"
        );
        assert!(find_named(&zones, "other.test").is_none());
    }

    #[test]
    fn tokens_honour_quotes() {
        assert_eq!(
            tokenize("10  mx.example.test").expect("ok"),
            strings(&["10", "mx.example.test"])
        );
        assert_eq!(
            tokenize(r#""v=spf1 -all" "second \"one\"""#).expect("ok"),
            strings(&["v=spf1 -all", "second \"one\""])
        );
        assert_eq!(tokenize(r#""""#).expect("ok"), strings(&[""]));
        assert!(tokenize("\"open").is_err());
    }

    #[test]
    fn record_data_is_built_per_type() {
        let zone = "example.test";
        let one = |rtype: &str, data: &[&str]| {
            let records = parse_records(rtype, &strings(data), zone).expect("valid");
            assert_eq!(records.len(), 1, "{rtype} {data:?}");
            records.into_iter().next().expect("one")
        };
        assert_eq!(
            one("A", &["192.0.2.10"]),
            json!({"type": "A", "address": "192.0.2.10"})
        );
        assert_eq!(
            one("AAAA", &["2001:db8::10"]),
            json!({"type": "AAAA", "address": "2001:db8::10"})
        );
        assert_eq!(
            one("CNAME", &["www"]),
            json!({"type": "CNAME", "target": "www.example.test"})
        );
        assert_eq!(
            one("NS", &["ns1.example.test."]),
            json!({"type": "NS", "host": "ns1.example.test"})
        );
        assert_eq!(
            one("PTR", &["host.example.test"]),
            json!({"type": "PTR", "target": "host.example.test"})
        );
        let mx = json!({"type": "MX", "preference": 10, "exchange": "mx.example.test"});
        assert_eq!(one("MX", &["10 mx.example.test"]), mx);
        assert_eq!(one("MX", &["10", "mx"]), mx);
        assert_eq!(
            one("SRV", &["0 5 5060 sip"]),
            json!({"type": "SRV", "priority": 0, "weight": 5, "port": 5060,
                   "target": "sip.example.test"})
        );
        assert_eq!(
            one("CAA", &["0", "issue", "letsencrypt.org"]),
            json!({"type": "CAA", "flags": 0, "tag": "issue", "value": "letsencrypt.org"})
        );
        assert_eq!(
            one("CAA", &["0 issue \"letsencrypt.org\""]),
            json!({"type": "CAA", "flags": 0, "tag": "issue", "value": "letsencrypt.org"})
        );
        assert_eq!(
            one("TXT", &["v=spf1 -all"]),
            json!({"type": "TXT", "strings": ["v=spf1 -all"]})
        );
        assert_eq!(
            one("TXT", &[r#""a b" "c""#]),
            json!({"type": "TXT", "strings": ["a b", "c"]})
        );
    }

    #[test]
    fn several_arguments_are_several_records() {
        let records =
            parse_records("A", &strings(&["192.0.2.1", "192.0.2.2"]), "z.test").expect("valid");
        assert_eq!(records.len(), 2);
        let records = parse_records("MX", &strings(&["10 a", "20 b"]), "z.test").expect("valid");
        assert_eq!(records.len(), 2);
        let records =
            parse_records("TXT", &strings(&["one", "two words"]), "z.test").expect("valid");
        assert_eq!(records.len(), 2);
    }

    #[test]
    fn bad_record_data_is_refused() {
        let zone = "example.test";
        for (rtype, data) in [
            ("A", vec!["2001:db8::1"]),
            ("A", vec!["not-an-address"]),
            ("AAAA", vec!["192.0.2.1"]),
            ("MX", vec!["mx.example.test"]),
            ("MX", vec!["high mx"]),
            ("MX", vec!["70000 mx"]),
            ("SRV", vec!["0 5 sip"]),
            ("CAA", vec!["0 issue"]),
            ("HINFO", vec!["x"]),
        ] {
            let result = parse_records(rtype, &strings(&data), zone);
            assert!(result.is_err(), "{rtype} {data:?} should be refused");
        }
    }

    #[test]
    fn records_are_shown_in_presentation_form() {
        for (data, shown) in [
            (json!({"type": "A", "address": "192.0.2.1"}), "192.0.2.1"),
            (
                json!({"type": "MX", "preference": 10, "exchange": "mx.example.test"}),
                "10 mx.example.test",
            ),
            (
                json!({"type": "TXT", "strings": ["a b", "c"]}),
                "\"a b\" \"c\"",
            ),
            (
                json!({"type": "CAA", "flags": 0, "tag": "issue", "value": "x.test"}),
                "0 issue \"x.test\"",
            ),
        ] {
            assert_eq!(present(&data), shown);
        }
    }

    #[test]
    fn diffs_show_before_and_after() {
        let change = json!({
            "name": "www.example.test", "type": "A",
            "before": {"ttl": 300, "records": [{"type": "A", "address": "192.0.2.1"}]},
            "after": {"ttl": 300, "records": [{"type": "A", "address": "192.0.2.2"}]},
        });
        assert_eq!(
            render_diff(&[change]),
            "- www.example.test 300 A 192.0.2.1\n+ www.example.test 300 A 192.0.2.2\n"
        );
    }

    #[test]
    fn acl_entries_are_parsed() {
        assert_eq!(
            parse_entry("192.0.2.0/24").expect("ok"),
            json!({"kind": "prefix", "prefix": "192.0.2.0/24", "deny": false})
        );
        assert_eq!(
            parse_entry("2001:db8::/32,deny").expect("ok"),
            json!({"kind": "prefix", "prefix": "2001:db8::/32", "deny": true})
        );
        assert_eq!(
            parse_entry("192.0.2.9").expect("ok"),
            json!({"kind": "prefix", "prefix": "192.0.2.9/32", "deny": false})
        );
        assert_eq!(
            parse_entry("key:Transfer-Key").expect("ok"),
            json!({"kind": "key", "name": "transfer-key", "deny": false})
        );
        assert_eq!(
            parse_entry("any,deny").expect("ok"),
            json!({"kind": "any", "deny": true})
        );
        assert!(parse_entry("nonsense").is_err());
        assert!(parse_entry("any,maybe").is_err());
        assert!(parse_entry("key:").is_err());
        assert_eq!(
            present_entry(&json!({"kind": "key", "name": "k", "deny": true})),
            "key:k,deny"
        );
    }

    #[test]
    fn hex_and_reports() {
        assert_eq!(from_hex("7b7d"), Some(b"{}".to_vec()));
        assert_eq!(from_hex("7b7"), None);
        assert_eq!(from_hex("zz"), None);
        let job = json!({"job": {"steps": [
            {"kind": "dns.import.chunk", "output": null},
            {"kind": "dns.import.finish",
             "output": "7b22616464656422 3a312c22747970657322 3a7b2241223a317d7d".replace(' ', "")},
        ]}});
        let report = job_report(&job).expect("a report");
        assert_eq!(report["added"], 1);
        assert_eq!(type_counts(&report), vec![("A".to_owned(), 1)]);
    }

    #[test]
    fn reports_list_losses_with_lines() {
        let report = json!({
            "dry_run": true, "added": 2, "replaced": 1, "removed": 0,
            "types": [{"rtype": "A", "records": 2}, {"rtype": "MX", "records": 1}],
            "losses": [{"line": 12, "code": "dns.import.class", "detail": "class CH"}],
        });
        let text = render_report(&report);
        assert!(text.contains("preview: 2 RRset(s) added, 1 replaced, 0 removed"));
        assert!(text.contains("records per type: A 2, MX 1"));
        assert!(text.contains("line 12: [dns.import.class] class CH"));
    }

    #[test]
    fn mailboxes_become_names() {
        assert_eq!(
            mailbox_name("hostmaster@example.test"),
            "hostmaster.example.test"
        );
        assert_eq!(
            mailbox_name("hostmaster.example.test"),
            "hostmaster.example.test"
        );
    }

    #[test]
    fn upstreams_are_parsed_and_printed() {
        let cases: &[(&str, Value)] = &[
            ("192.0.2.1", json!({ "address": "192.0.2.1" })),
            (
                "192.0.2.1:853",
                json!({ "address": "192.0.2.1", "port": 853 }),
            ),
            ("2001:db8::1", json!({ "address": "2001:db8::1" })),
            (
                "[2001:db8::1]:443/dns-query",
                json!({ "address": "2001:db8::1", "port": 443, "path": "/dns-query" }),
            ),
            (
                "192.0.2.1/custom/path",
                json!({ "address": "192.0.2.1", "path": "/custom/path" }),
            ),
        ];
        for (text, want) in cases {
            let got = parse_upstream(text).unwrap_or_else(|_| panic!("{text}"));
            assert_eq!(&got, want, "{text}");
        }
        for bad in ["resolver.example.test", "192.0.2.1:99999", "[2001:db8::1"] {
            assert!(parse_upstream(bad).is_err(), "{bad}");
        }
        assert_eq!(
            present_upstream(&json!({ "address": "2001:db8::1", "port": 443, "path": "/q" })),
            "[2001:db8::1]:443/q"
        );
        assert_eq!(
            present_upstream(&json!({ "address": "192.0.2.1" })),
            "192.0.2.1"
        );
    }

    const URL: &str = "https://lists.example.test/h";

    #[test]
    fn list_commands_are_parsed() {
        let cases: &[(&[&str], &str)] = &[
            (&["list", "list"], "dns list list"),
            (
                &["list", "create", "--name", "ads", "--source-url", URL],
                "dns list create",
            ),
            (
                &["list", "create", "--name", "mine", "--upload"],
                "dns list create",
            ),
            (&["list", "get", "ads"], "dns list get"),
            (&["list", "update", "ads", "--disable"], "dns list update"),
            (
                &["list", "delete", "ads", "--if-match", "4"],
                "dns list delete",
            ),
            (&["list", "fetch", "ads"], "dns list fetch"),
            (&["list", "upload", "ads", "-"], "dns list upload"),
        ];
        for (args, name) in cases {
            let command = parse(args).unwrap_or_else(|error| panic!("{args:?}: {error}"));
            assert_eq!(command.name(), *name);
        }
        let refused: &[&[&str]] = &[
            &["list", "create", "--name", "x"],
            &[
                "list",
                "create",
                "--name",
                "x",
                "--source-url",
                URL,
                "--upload",
            ],
            &["list", "create", "--source-url", URL],
            &[
                "list", "create", "--name", "x", "--upload", "--format", "csv",
            ],
            &[
                "list", "create", "--name", "x", "--upload", "--kind", "deny",
            ],
            &[
                "list",
                "create",
                "--name",
                "x",
                "--upload",
                "--interval-hours",
                "0",
            ],
            &[
                "list",
                "create",
                "--name",
                "x",
                "--upload",
                "--interval-hours",
                "169",
            ],
            &[
                "list",
                "create",
                "--name",
                "x",
                "--upload",
                "--redirect",
                "192.0.2.1",
            ],
            &["list", "update", "x", "--enable", "--disable"],
            &[
                "list",
                "update",
                "x",
                "--exempt",
                "192.0.2.0/24",
                "--clear-exempt",
            ],
            &["list", "update", "x", "--source-url", URL, "--upload"],
            &["list", "upload", "x"],
        ];
        for args in refused {
            assert!(parse(args).is_err(), "{args:?}");
        }
    }

    fn create_args(args: &[&str]) -> BlockListCreateArgs {
        let mut line = vec!["list", "create"];
        line.extend_from_slice(args);
        match parse(&line).expect("valid") {
            DnsCommand::List {
                action: BlockListCommand::Create(args),
            } => args,
            other => panic!("not a list create: {other:?}"),
        }
    }

    fn update_args(args: &[&str]) -> BlockListUpdateArgs {
        let mut line = vec!["list", "update", "ads"];
        line.extend_from_slice(args);
        match parse(&line).expect("valid") {
            DnsCommand::List {
                action: BlockListCommand::Update(args),
            } => args,
            other => panic!("not a list update: {other:?}"),
        }
    }

    #[test]
    fn list_create_bodies_have_the_defaults() {
        let body = block_list_create_body(&create_args(&["--name", "ads", "--source-url", URL]))
            .expect("body");
        assert_eq!(
            body,
            json!({
                "name": "ads",
                "kind": "block",
                "source": { "kind": "url", "url": URL },
                "format": "domains",
                "exempt": [],
            })
        );
        let body = block_list_create_body(&create_args(&[
            "--name",
            "hosts",
            "--upload",
            "--format",
            "hosts",
            "--kind",
            "allow",
            "--interval-hours",
            "12",
            "--action",
            "redirect",
            "--redirect",
            "192.0.2.80",
            "--exempt",
            "192.0.2.10",
            "--exempt",
            "198.51.100.77/24",
            "--exempt",
            "2001:db8::/32",
            "--disabled",
            "--description",
            "kids",
        ]))
        .expect("body");
        assert_eq!(
            body,
            json!({
                "name": "hosts",
                "kind": "allow",
                "source": { "kind": "upload" },
                "format": "hosts",
                "interval_hours": 12,
                "action": { "kind": "redirect", "address": "192.0.2.80" },
                "exempt": ["192.0.2.10/32", "198.51.100.0/24", "2001:db8::/32"],
                "enabled": false,
                "description": "kids",
            })
        );
    }

    #[test]
    fn list_actions_and_prefixes_are_checked() {
        assert_eq!(action_body(None, None).expect("none"), None);
        assert_eq!(
            action_body(Some(BlockActionArg::Nodata), None).expect("nodata"),
            Some(json!({ "kind": "nodata" }))
        );
        assert!(action_body(Some(BlockActionArg::Redirect), None).is_err());
        assert!(
            action_body(
                Some(BlockActionArg::Nxdomain),
                Some("192.0.2.1".parse().expect("address"))
            )
            .is_err()
        );
        assert!(exempt_body(&strings(&["192.0.2.0/33"])).is_err());
        assert!(exempt_body(&strings(&["kids.example.test"])).is_err());
        let bad = block_list_create_body(&create_args(&[
            "--name", "x", "--upload", "--exempt", "nonsense",
        ]));
        assert_eq!(bad.expect_err("prefix").status, exit::USAGE);
    }

    #[test]
    fn list_update_bodies_hold_only_what_is_given() {
        assert!(
            block_list_update_body(&update_args(&[]))
                .expect("body")
                .is_empty()
        );
        let body = block_list_update_body(&update_args(&[
            "--name",
            "ads2",
            "--source-url",
            URL,
            "--format",
            "hosts",
            "--kind",
            "block",
            "--interval-hours",
            "6",
            "--action",
            "nxdomain",
            "--exempt",
            "192.0.2.0/24",
            "--disable",
            "--description",
            "",
        ]))
        .expect("body");
        assert_eq!(
            Value::Object(body),
            json!({
                "name": "ads2",
                "source": { "kind": "url", "url": URL },
                "format": "hosts",
                "kind": "block",
                "interval_hours": 6,
                "action": { "kind": "nxdomain" },
                "exempt": ["192.0.2.0/24"],
                "enabled": false,
                "description": "",
            })
        );
        let body =
            block_list_update_body(&update_args(&["--clear-exempt", "--enable", "--upload"]))
                .expect("body");
        assert_eq!(
            Value::Object(body),
            json!({ "source": { "kind": "upload" }, "exempt": [], "enabled": true })
        );
        assert_eq!(update_args(&["--if-match", "9"]).if_match, Some(9));
    }

    #[test]
    fn lists_are_shown_in_tables_and_details() {
        let lists = vec![
            json!({
                "id": "0191f9a0-0000-7000-8000-000000000001",
                "name": "ads",
                "kind": "block",
                "source": { "kind": "url", "url": URL },
                "format": "hosts",
                "interval_hours": 24,
                "action": { "kind": "redirect", "address": "192.0.2.80" },
                "enabled": true,
                "exempt": ["192.0.2.10/32"],
                "version": {
                    "revision": 3,
                    "entries": 1200,
                    "fetched": "2026-10-09T12:00:00Z",
                    "etag": "\"abc\"",
                    "bytes": 20480
                },
                "last_error": "dns.list.fetch_failed",
                "last_error_detail": "the server answered 503",
                "last_checked": "2026-10-09T13:00:00Z",
                "revision": 17,
            }),
            json!({
                "id": "0191f9a0-0000-7000-8000-000000000002",
                "name": "mine",
                "kind": "allow",
                "source": { "kind": "upload" },
                "format": "domains",
                "interval_hours": 24,
                "action": { "kind": "nxdomain" },
                "enabled": false,
                "revision": 18,
            }),
        ];
        let rows = block_list_rows(&lists);
        assert_eq!(
            rows[0],
            strings(&[
                "ads",
                "block",
                URL,
                "hosts",
                "redirect 192.0.2.80",
                "yes",
                "1200",
                "3",
                "2026-10-09T12:00:00Z",
                "dns.list.fetch_failed",
                "0191f9a0-0000-7000-8000-000000000001",
            ])
        );
        assert_eq!(
            rows[1],
            strings(&[
                "mine",
                "allow",
                "upload",
                "domains",
                "nxdomain",
                "no",
                "",
                "",
                "",
                "",
                "0191f9a0-0000-7000-8000-000000000002",
            ])
        );
        let first = describe_block_list(&lists[0]);
        for want in [
            "source        https://lists.example.test/h",
            "action        redirect 192.0.2.80",
            "exempt        192.0.2.10/32",
            "entries       1200",
            "last error    dns.list.fetch_failed",
            "              the server answered 503",
            "revision      17",
        ] {
            assert!(first.contains(want), "{want}\n{first}");
        }
        let second = describe_block_list(&lists[1]);
        assert!(second.contains("version   none yet"), "{second}");
        assert!(second.contains("enabled   no"), "{second}");
        let job = job_started(&json!({ "job_id": "j1" }), &lists[0]).expect("job");
        assert!(job.stdout.contains("started job j1 for list ads"));
        assert!(job_started(&json!({}), &lists[0]).is_err());
    }
}
