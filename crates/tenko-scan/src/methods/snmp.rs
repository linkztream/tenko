//! `snmp`: SNMPv3 polling of the configured switches (SCAN-05). One run polls every device
//! and reports, per device:
//!
//! - the name (`sysName`) and an OS hint (`sysDescr`) of its management address,
//! - address sightings with MAC addresses from its ARP tables, inside the scope,
//! - attachments: the switch port and VLAN behind which each client MAC address was learned
//!   (Q-BRIDGE or BRIDGE forwarding tables), except on ports with an LLDP neighbour, which
//!   lead to other network devices that report their own clients,
//! - LLDP links between its ports and its neighbours,
//! - vendors of the MAC addresses from the OUI table.
//!
//! The device addresses are configured explicitly and may lie outside the scan prefixes
//! (a management network); polling them is not a scan.
//!
//! Passwords come from a file, the configuration file itself, or the vault: devices that
//! name vault secrets get their values from the [`SecretSource`] at the start of every
//! run, held in memory for the run only. A device whose secret is not available (no
//! controller reached since the probe started, or a configuration still waiting for an
//! administrator to pick the secret) is skipped with a note, and the run is partial.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, SocketAddr},
    path::Path,
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use tenko_cluster::probe::SightingSubject;
use tenko_core::{
    MacAddr,
    observe::{Endpoint, LinkKind},
};
use zeroize::Zeroizing;

use crate::{
    config::{SecretText, SnmpAuth, SnmpDevice, SnmpPrivacy},
    error::ScanError,
    method::{Availability, Found, Method, MethodKind, MethodOutput, RunContext},
    methods::neighbours::usable_mac,
    oui,
    scope::Scope,
    secrets::{SecretSource, VaultSecrets},
    snmp::{self, AuthProtocol, Credentials, DeviceTables, PollOptions, PrivProtocol},
};

/// Longest OS hint taken from `sysDescr`.
const MAX_OS_HINT: usize = 120;

/// One device with the credentials it is polled with.
#[derive(Debug, Clone)]
pub struct Device {
    /// The configuration of the device.
    pub config: SnmpDevice,
}

/// Where one password of a device comes from.
#[derive(Clone, Copy)]
struct PasswordSource<'a> {
    inline: Option<&'a SecretText>,
    file: Option<&'a Path>,
    secret: Option<tenko_core::SecretId>,
}

/// Reads a password from the vault values, its file (first line, trimmed) or the inline
/// value.
fn password(
    source: PasswordSource<'_>,
    vault: &VaultSecrets,
    what: &str,
    at: SocketAddr,
) -> Result<Zeroizing<String>, ScanError> {
    let PasswordSource {
        inline,
        file,
        secret,
    } = source;
    if let Some(secret) = secret {
        return vault
            .get(secret)
            .map(|value| Zeroizing::new(value.expose().to_owned()))
            .ok_or_else(|| {
                ScanError::unavailable(format!(
                    "scan.snmp.devices ({at}): the {what} password is the vault secret \
                     {secret}, which this probe has not received from a controller"
                ))
            });
    }
    if let Some(file) = file {
        let text = Zeroizing::new(std::fs::read_to_string(file).map_err(|error| {
            ScanError::config(format!(
                "scan.snmp.devices ({at}): cannot read the {what} password file {}: {error}",
                file.display()
            ))
        })?);
        let line = text.lines().next().unwrap_or_default().trim();
        return Ok(Zeroizing::new(line.to_owned()));
    }
    inline
        .map(|secret| Zeroizing::new(secret.expose().to_owned()))
        .ok_or_else(|| ScanError::config(format!("scan.snmp.devices ({at}): no {what} password")))
}

/// The SNMPv3 credentials of a device, with vault secrets from `vault`.
///
/// # Errors
///
/// `scan.config` when a password file cannot be read or a password is missing,
/// `scan.unavailable` when a vault secret has not been received.
pub fn credentials(device: &SnmpDevice, vault: &VaultSecrets) -> Result<Credentials, ScanError> {
    let at = device.socket();
    let auth = match device.auth {
        Some(protocol) => Some((
            match protocol {
                SnmpAuth::Sha1 => AuthProtocol::Sha1,
                SnmpAuth::Sha224 => AuthProtocol::Sha224,
                SnmpAuth::Sha256 => AuthProtocol::Sha256,
                SnmpAuth::Sha384 => AuthProtocol::Sha384,
                SnmpAuth::Sha512 => AuthProtocol::Sha512,
            },
            password(
                PasswordSource {
                    inline: device.auth_password.as_ref(),
                    file: device.auth_password_file.as_deref(),
                    secret: device.auth_secret,
                },
                vault,
                "authentication",
                at,
            )?,
        )),
        None => None,
    };
    let privacy = match device.privacy {
        Some(SnmpPrivacy::Aes128) => Some((
            PrivProtocol::Aes128,
            password(
                PasswordSource {
                    inline: device.privacy_password.as_ref(),
                    file: device.privacy_password_file.as_deref(),
                    secret: device.privacy_secret,
                },
                vault,
                "privacy",
                at,
            )?,
        )),
        None => None,
    };
    Ok(Credentials {
        user: device.user.clone(),
        auth,
        privacy,
        context: device.context.clone(),
    })
}

/// The name a device goes by in attachments and links.
pub fn device_name(device: &SnmpDevice, tables: &DeviceTables) -> String {
    device
        .name
        .clone()
        .or_else(|| tables.sys_name.clone())
        .unwrap_or_else(|| device.address.to_string())
}

/// The first line of `sysDescr`, shortened, as an OS hint.
pub fn os_hint(descr: &str) -> Option<String> {
    let line = descr.lines().map(str::trim).find(|line| !line.is_empty())?;
    Some(line.chars().take(MAX_OS_HINT).collect())
}

/// The sightings of one polled device.
pub fn device_findings(
    device: &SnmpDevice,
    tables: &DeviceTables,
    scope: &Scope,
    attach_on_lldp_ports: bool,
) -> Vec<Found> {
    let name = device_name(device, tables);
    let mut found = Vec::new();
    if let Some(sys_name) = &tables.sys_name {
        found.push(Found::now(SightingSubject::Name {
            ip: device.address,
            name: sys_name.clone(),
        }));
    }
    if let Some(guess) = tables.sys_descr.as_deref().and_then(os_hint) {
        found.push(Found::now(SightingSubject::Os {
            ip: device.address,
            guess,
            confidence: 90,
        }));
    }
    let port_name = |if_index: u32| {
        tables
            .interfaces
            .get(&if_index)
            .and_then(|interface| interface.name.clone().or_else(|| interface.descr.clone()))
            .unwrap_or_else(|| if_index.to_string())
    };
    let mut macs = BTreeSet::new();
    let mut arp: BTreeMap<IpAddr, MacAddr> = BTreeMap::new();
    for entry in &tables.arp {
        if scope.contains(entry.ip) && usable_mac(entry.mac) {
            arp.entry(entry.ip).or_insert(entry.mac);
        }
    }
    for (ip, mac) in arp {
        macs.insert(mac);
        found.push(Found::now(SightingSubject::Address { ip, mac: Some(mac) }));
    }
    let lldp_ports: BTreeSet<String> = tables
        .lldp
        .iter()
        .filter_map(|neighbour| neighbour.local_port.clone())
        .collect();
    let own: BTreeSet<MacAddr> = tables
        .interfaces
        .values()
        .filter_map(|interface| interface.mac)
        .collect();
    let mut attached: BTreeMap<MacAddr, (String, Option<u16>)> = BTreeMap::new();
    for entry in &tables.fdb {
        if !usable_mac(entry.mac) || own.contains(&entry.mac) {
            continue;
        }
        let port = entry
            .if_index
            .map_or_else(|| entry.bridge_port.to_string(), port_name);
        if !attach_on_lldp_ports && lldp_ports.contains(&port) {
            continue;
        }
        attached.entry(entry.mac).or_insert((port, entry.vlan));
    }
    for (mac, (port, vlan)) in attached {
        macs.insert(mac);
        found.push(Found::now(SightingSubject::Attachment {
            mac,
            device: name.clone(),
            port: Some(port),
            vlan,
        }));
    }
    for neighbour in &tables.lldp {
        let Some(remote) = neighbour
            .remote_sys_name
            .clone()
            .or_else(|| neighbour.remote_chassis.clone())
        else {
            continue;
        };
        found.push(Found::now(SightingSubject::Link {
            a: Endpoint {
                device: name.clone(),
                port: neighbour.local_port.clone(),
            },
            b: Endpoint {
                device: remote,
                port: neighbour
                    .remote_port
                    .clone()
                    .or_else(|| neighbour.remote_port_desc.clone()),
            },
            kind: LinkKind::Lldp,
        }));
    }
    for mac in macs {
        if let Some(vendor) = oui::vendor(mac) {
            found.push(Found::now(SightingSubject::Vendor {
                mac,
                vendor: vendor.to_owned(),
            }));
        }
    }
    found
}

/// The `snmp` method.
#[derive(Debug, Clone)]
pub struct SnmpPoll {
    devices: Vec<SnmpDevice>,
    options: PollOptions,
    attach_on_lldp_ports: bool,
    secrets: Option<Arc<dyn SecretSource>>,
}

impl SnmpPoll {
    /// Polls `devices`, waiting `timeout` per request with `retries`.
    pub fn new(
        devices: Vec<SnmpDevice>,
        timeout: Duration,
        retries: u32,
        attach_on_lldp_ports: bool,
    ) -> Self {
        Self {
            devices,
            options: PollOptions {
                timeout,
                retries,
                ..PollOptions::default()
            },
            attach_on_lldp_ports,
            secrets: None,
        }
    }

    /// With the source of the vault secrets the devices name.
    #[must_use]
    pub fn with_secrets(mut self, secrets: Option<Arc<dyn SecretSource>>) -> Self {
        self.secrets = secrets;
        self
    }

    /// The values of the vault secrets the devices name, fetched for this run.
    async fn vault_values(&self, notes: &mut Vec<String>) -> VaultSecrets {
        let mut wanted: Vec<tenko_core::SecretId> =
            self.devices.iter().flat_map(SnmpDevice::secrets).collect();
        wanted.sort_unstable_by_key(|secret| secret.uuid());
        wanted.dedup();
        if wanted.is_empty() {
            return VaultSecrets::new();
        }
        let Some(source) = &self.secrets else {
            notes.push(
                "the devices name vault secrets, but this probe has no controller to fetch them from"
                    .to_owned(),
            );
            return VaultSecrets::new();
        };
        match source.fetch(&wanted).await {
            Ok(values) => values,
            Err(error) => {
                notes.push(format!(
                    "the vault secrets could not be fetched: {}",
                    error.detail()
                ));
                VaultSecrets::new()
            }
        }
    }
}

#[async_trait]
impl Method for SnmpPoll {
    fn kind(&self) -> MethodKind {
        MethodKind::Snmp
    }

    fn availability(&self) -> Availability {
        if self.devices.is_empty() {
            Availability::Unavailable("no devices in [scan.snmp]".to_owned())
        } else {
            Availability::Ready
        }
    }

    async fn run(&self, ctx: &RunContext) -> Result<MethodOutput, ScanError> {
        let mut output = MethodOutput {
            covered_all: true,
            ..MethodOutput::default()
        };
        let vault = self.vault_values(&mut output.notes).await;
        for device in &self.devices {
            if ctx.cancel.is_cancelled() {
                output.covered_all = false;
                break;
            }
            let at = device.socket();
            if !device.has_credentials() {
                output.covered_all = false;
                output.notes.push(format!(
                    "{at}: waits for a vault secret for its passwords (the scan-config of this probe)"
                ));
                continue;
            }
            let credentials = match credentials(device, &vault) {
                Ok(credentials) => credentials,
                Err(error) => {
                    output.covered_all = false;
                    output.notes.push(error.detail().to_owned());
                    continue;
                }
            };
            let sent_before = ctx.pacer.sent();
            match snmp::poll(at, &credentials, &self.options, &ctx.pacer, &ctx.cancel).await {
                Ok(tables) => {
                    if tables.truncated || !tables.failures.is_empty() {
                        output.covered_all = false;
                        for failure in &tables.failures {
                            output.notes.push(format!("{at}: {failure}"));
                        }
                        if tables.truncated {
                            output.notes.push(format!("{at}: a table was cut short"));
                        }
                    }
                    output.found.extend(device_findings(
                        device,
                        &tables,
                        &ctx.scope,
                        self.attach_on_lldp_ports,
                    ));
                }
                Err(error) => {
                    output.covered_all = false;
                    output.notes.push(format!("{at}: {error}"));
                }
            }
            output.probes += ctx.pacer.sent().saturating_sub(sent_before);
        }
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snmp::{ArpEntry, FdbEntry, Interface, LldpNeighbour};

    fn mac(text: &str) -> MacAddr {
        text.parse().expect("mac")
    }

    fn device() -> SnmpDevice {
        SnmpDevice {
            address: "192.0.2.2".parse().expect("ip"),
            port: 161,
            name: None,
            user: "tenko".to_owned(),
            auth: Some(SnmpAuth::Sha256),
            auth_password: Some(SecretText::new("example-auth-secret")),
            auth_password_file: None,
            privacy: Some(SnmpPrivacy::Aes128),
            privacy_password: Some(SecretText::new("example-priv-secret")),
            privacy_password_file: None,
            auth_secret: None,
            privacy_secret: None,
            context: String::new(),
        }
    }

    fn tables() -> DeviceTables {
        let mut interfaces = BTreeMap::new();
        interfaces.insert(
            1,
            Interface {
                name: Some("ge-0/0/1".to_owned()),
                descr: None,
                alias: None,
                mac: Some(mac("00:00:5e:00:53:f1")),
            },
        );
        interfaces.insert(
            2,
            Interface {
                name: Some("ge-0/0/2".to_owned()),
                descr: None,
                alias: None,
                mac: None,
            },
        );
        DeviceTables {
            sys_descr: Some("Example switch OS 1.2\r\nbuild 7".to_owned()),
            sys_name: Some("switch-a.example.net".to_owned()),
            sys_object_id: None,
            interfaces,
            arp: vec![
                ArpEntry {
                    if_index: 1,
                    ip: "192.0.2.10".parse().expect("ip"),
                    mac: mac("00:00:5e:00:53:10"),
                },
                ArpEntry {
                    if_index: 1,
                    ip: "198.51.100.10".parse().expect("ip"),
                    mac: mac("00:00:5e:00:53:11"),
                },
            ],
            fdb: vec![
                FdbEntry {
                    mac: mac("00:00:5e:00:53:10"),
                    vlan: Some(10),
                    bridge_port: 1,
                    if_index: Some(1),
                },
                FdbEntry {
                    mac: mac("00:00:5e:00:53:20"),
                    vlan: Some(20),
                    bridge_port: 2,
                    if_index: Some(2),
                },
                FdbEntry {
                    mac: mac("00:00:5e:00:53:f1"),
                    vlan: Some(10),
                    bridge_port: 1,
                    if_index: Some(1),
                },
            ],
            lldp: vec![LldpNeighbour {
                local_port: Some("ge-0/0/2".to_owned()),
                remote_chassis: None,
                remote_port: Some("eth0".to_owned()),
                remote_port_desc: None,
                remote_sys_name: Some("ap-b.example.net".to_owned()),
            }],
            truncated: false,
            failures: Vec::new(),
        }
    }

    #[test]
    fn a_device_reports_addresses_attachments_links_and_its_own_identity() {
        let scope = Scope::parse(&["192.0.2.0/24".to_owned()], &[], 256).expect("scope");
        let found = device_findings(&device(), &tables(), &scope, false);
        let subjects: Vec<&SightingSubject> = found.iter().map(|f| &f.subject).collect();
        assert!(subjects.contains(&&SightingSubject::Name {
            ip: "192.0.2.2".parse().expect("ip"),
            name: "switch-a.example.net".to_owned()
        }));
        assert!(subjects.contains(&&SightingSubject::Os {
            ip: "192.0.2.2".parse().expect("ip"),
            guess: "Example switch OS 1.2".to_owned(),
            confidence: 90
        }));
        let addresses: Vec<_> = subjects
            .iter()
            .filter(|s| matches!(s, SightingSubject::Address { .. }))
            .collect();
        assert_eq!(addresses.len(), 1, "198.51.100.10 is outside the scope");
        let attachments: Vec<_> = subjects
            .iter()
            .filter_map(|s| match s {
                SightingSubject::Attachment {
                    mac,
                    port,
                    vlan,
                    device,
                } => Some((*mac, port.clone(), *vlan, device.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(
            attachments,
            [(
                mac("00:00:5e:00:53:10"),
                Some("ge-0/0/1".to_owned()),
                Some(10),
                "switch-a.example.net".to_owned()
            )],
            "the LLDP port and the switch's own MAC address are left out"
        );
        assert!(subjects.iter().any(|s| matches!(
            s,
            SightingSubject::Link { b, kind: LinkKind::Lldp, .. } if b.device == "ap-b.example.net"
        )));
        let with_lldp = device_findings(&device(), &tables(), &scope, true);
        assert!(with_lldp.len() > found.len());
    }

    #[test]
    fn credentials_come_from_files_first() {
        let dir = tempfile::tempdir().expect("dir");
        let file = dir.path().join("auth");
        std::fs::write(&file, "example-file-secret\n").expect("write");
        let mut device = device();
        device.auth_password_file = Some(file);
        let credentials = credentials(&device, &VaultSecrets::new()).expect("credentials");
        let (protocol, secret) = credentials.auth.expect("auth");
        assert_eq!(protocol, AuthProtocol::Sha256);
        assert_eq!(secret.as_str(), "example-file-secret");
        device.auth_password_file = Some(dir.path().join("missing"));
        let error = credentials_error(&device);
        assert!(error.contains("password file"), "{error}");
    }

    #[tokio::test]
    async fn a_poll_of_the_recorded_switch_reports_its_clients_and_neighbours() {
        use crate::{
            limit::{PaceLimits, Pacer},
            method::Cancel,
            snmp::testing::{AUTH_PASSWORD, AgentConfig, FakeAgent, PRIV_PASSWORD, switch_a},
        };
        let agent = FakeAgent::start(AgentConfig::new(switch_a())).await;
        let mut config = device();
        config.address = agent.addr().ip();
        config.port = agent.addr().port();
        config.user = "sha256-priv".to_owned();
        config.auth_password = Some(SecretText::new(AUTH_PASSWORD));
        config.privacy_password = Some(SecretText::new(PRIV_PASSWORD));
        let unreachable = SnmpDevice {
            port: {
                let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
                socket.local_addr().expect("addr").port()
            },
            ..config.clone()
        };
        let method = SnmpPoll::new(vec![config], Duration::from_millis(500), 1, false);
        let ctx = RunContext {
            scope: std::sync::Arc::new(
                Scope::parse(&["192.0.2.0/24".to_owned()], &[], 256).expect("scope"),
            ),
            narrowed: false,
            known: Vec::new(),
            pacer: std::sync::Arc::new(Pacer::new(PaceLimits {
                per_second: None,
                per_host_interval: Duration::ZERO,
                concurrency: 4,
            })),
            cancel: Cancel::never(),
        };
        let output = method.run(&ctx).await.expect("run");
        assert!(output.covered_all, "{:?}", output.notes);
        assert!(output.probes > 0);
        let subjects: Vec<&SightingSubject> = output.found.iter().map(|f| &f.subject).collect();
        assert!(subjects.iter().any(|s| matches!(
            s,
            SightingSubject::Name { name, .. } if name == "switch-a.example.net"
        )));
        assert!(
            subjects
                .iter()
                .any(|s| matches!(s, SightingSubject::Address { .. }))
        );
        assert!(subjects.iter().any(|s| matches!(
            s,
            SightingSubject::Attachment { device, vlan: Some(_), .. }
                if device == "switch-a.example.net"
        )));
        assert!(subjects.iter().any(|s| matches!(
            s,
            SightingSubject::Link { b, .. } if b.device == "ap-b.example.net"
        )));
        assert!(
            subjects
                .iter()
                .any(|s| matches!(s, SightingSubject::Vendor { .. }))
        );

        // A device that does not answer makes the run partial; the other's findings stay.
        let method = SnmpPoll::new(vec![unreachable], Duration::from_millis(100), 0, false);
        let output = method.run(&ctx).await.expect("run");
        assert!(!output.covered_all);
        assert!(output.notes[0].contains("scan.snmp"), "{:?}", output.notes);
    }

    fn credentials_error(device: &SnmpDevice) -> String {
        credentials(device, &VaultSecrets::new())
            .expect_err("missing")
            .detail()
            .to_owned()
    }

    #[test]
    fn credentials_come_from_the_vault_values_when_the_device_names_a_secret() {
        let secret = tenko_core::SecretId::generate();
        let mut device = device();
        device.auth_password = None;
        device.auth_secret = Some(secret);
        let error = credentials_error(&device);
        assert!(error.contains("vault secret"), "{error}");
        let mut vault = VaultSecrets::new();
        vault.insert(secret, SecretText::new("example-vault-secret"));
        let credentials = credentials(&device, &vault).expect("credentials");
        let (_, value) = credentials.auth.expect("auth");
        assert_eq!(value.as_str(), "example-vault-secret");
    }

    #[tokio::test]
    async fn a_run_fetches_the_vault_secrets_and_skips_devices_without_them() {
        let secret = tenko_core::SecretId::generate();
        let mut waiting = device();
        waiting.auth_password = None;
        waiting.privacy_password = None;
        let mut named = device();
        named.address = "192.0.2.250".parse().expect("ip");
        named.auth_password = None;
        named.auth_secret = Some(secret);
        let method = SnmpPoll::new(vec![waiting, named], Duration::from_millis(50), 0, false)
            .with_secrets(Some(Arc::new(crate::secrets::StaticSecrets::default())));
        let ctx = RunContext {
            scope: std::sync::Arc::new(
                Scope::parse(&["192.0.2.0/24".to_owned()], &[], 256).expect("scope"),
            ),
            narrowed: false,
            known: Vec::new(),
            pacer: std::sync::Arc::new(crate::limit::Pacer::new(crate::limit::PaceLimits {
                per_second: None,
                per_host_interval: Duration::ZERO,
                concurrency: 4,
            })),
            cancel: crate::method::Cancel::never(),
        };
        let output = method.run(&ctx).await.expect("run");
        assert!(!output.covered_all);
        assert!(
            output
                .notes
                .iter()
                .any(|note| note.contains("waits for a vault secret")),
            "{:?}",
            output.notes
        );
        assert!(
            output
                .notes
                .iter()
                .any(|note| note.contains("has not received")),
            "{:?}",
            output.notes
        );
        assert_eq!(output.probes, 0, "nothing was sent without credentials");
    }
}
