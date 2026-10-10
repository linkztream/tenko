//! Tests that drive the client and `poll` against the fake agent over loopback.

use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

use tenko_core::MacAddr;
use tokio::{net::UdpSocket, sync::watch};

use super::{
    ArpEntry, AuthProtocol, Client, Credentials, DeviceTables, FdbEntry, Interface, LldpNeighbour,
    Oid, PollOptions, PrivProtocol, Value, poll,
    testing::{
        AUTH_PASSWORD, AgentConfig, FakeAgent, PRIV_PASSWORD, TimeWindow, credentials_for,
        parse_walk, switch_a,
    },
};
use crate::{
    error::ScanError,
    limit::{PaceLimits, Pacer},
    method::Cancel,
};

fn options() -> PollOptions {
    PollOptions {
        timeout: Duration::from_secs(5),
        retries: 1,
        max_repetitions: 20,
        max_rows: 20_000,
    }
}

fn quick(retries: u32) -> PollOptions {
    PollOptions {
        timeout: Duration::from_millis(100),
        retries,
        ..options()
    }
}

/// A timeout long enough for a loaded machine to answer in, for the tests in which the
/// device does answer some of the datagrams.
fn patient(retries: u32) -> PollOptions {
    PollOptions {
        timeout: Duration::from_millis(300),
        retries,
        ..options()
    }
}

fn pacer() -> Pacer {
    Pacer::new(PaceLimits {
        per_second: None,
        per_host_interval: Duration::ZERO,
        concurrency: 8,
    })
}

fn oid(text: &str) -> Oid {
    text.parse().expect("oid")
}

fn mac(last: u8) -> MacAddr {
    MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, last])
}

fn ip(text: &str) -> IpAddr {
    text.parse().expect("ip address")
}

async fn agent() -> FakeAgent {
    FakeAgent::start(AgentConfig::new(switch_a())).await
}

async fn poll_as(
    agent: &FakeAgent,
    credentials: &Credentials,
    options: &PollOptions,
) -> Result<DeviceTables, ScanError> {
    poll(
        agent.addr(),
        credentials,
        options,
        &pacer(),
        &Cancel::never(),
    )
    .await
}

fn arp_entry(if_index: u32, address: &str, last: u8) -> ArpEntry {
    ArpEntry {
        if_index,
        ip: ip(address),
        mac: mac(last),
    }
}

fn fdb_entry(last: u8, vlan: Option<u16>, bridge_port: u32, if_index: Option<u32>) -> FdbEntry {
    FdbEntry {
        mac: mac(last),
        vlan,
        bridge_port,
        if_index,
    }
}

fn neighbour(
    local_port: &str,
    chassis: &str,
    port: &str,
    port_desc: &str,
    sys_name: &str,
) -> LldpNeighbour {
    LldpNeighbour {
        local_port: Some(local_port.to_owned()),
        remote_chassis: Some(chassis.to_owned()),
        remote_port: Some(port.to_owned()),
        remote_port_desc: Some(port_desc.to_owned()),
        remote_sys_name: Some(sys_name.to_owned()),
    }
}

/// What the recorded walk of the example switch decodes to, written out by hand.
fn expected_tables() -> DeviceTables {
    let mut interfaces = BTreeMap::new();
    for index in 1..=8u8 {
        interfaces.insert(
            u32::from(index),
            Interface {
                name: Some(format!("Gi0/{index}")),
                descr: Some(format!("GigabitEthernet0/{index}")),
                alias: match index {
                    1 => Some("uplink to core".to_owned()),
                    2 => Some("access point b".to_owned()),
                    5 => Some("printer".to_owned()),
                    _ => None,
                },
                mac: (index != 8).then(|| mac(0x10 + index)),
            },
        );
    }
    DeviceTables {
        sys_descr: Some("Example access switch, 8 ports, firmware 1.2.3".to_owned()),
        sys_name: Some("switch-a.example.net".to_owned()),
        sys_object_id: Some("1.3.6.1.4.1.8072.3.2.10".to_owned()),
        interfaces,
        arp: vec![
            arp_entry(1, "192.0.2.1", 0x01),
            arp_entry(1, "2001:db8::1", 0x01),
            arp_entry(2, "192.0.2.10", 0x20),
            arp_entry(2, "2001:db8::a", 0x20),
            arp_entry(3, "192.0.2.11", 0x21),
            arp_entry(3, "2001:db8::b", 0x21),
        ],
        fdb: vec![
            fdb_entry(0x20, Some(10), 2, Some(2)),
            fdb_entry(0x21, Some(20), 3, Some(3)),
            fdb_entry(0x30, Some(20), 7, Some(8)),
            fdb_entry(0x40, Some(10), 5, Some(5)),
            fdb_entry(0x41, Some(20), 9, None),
            fdb_entry(0x44, None, 6, Some(6)),
        ],
        lldp: vec![
            neighbour(
                "Gi0/2",
                "00:00:5e:00:53:a0",
                "00:00:5e:00:53:a1",
                "eth0",
                "ap-b.example.net",
            ),
            neighbour(
                "Gi0/1",
                "00:00:5e:00:53:b0",
                "Te1/0/48",
                "uplink Te1/0/48",
                "switch-c.example.net",
            ),
        ],
        truncated: false,
        failures: Vec::new(),
    }
}

#[tokio::test]
async fn every_authentication_protocol_with_privacy_reads_the_tables() {
    let agent = agent().await;
    for protocol in AuthProtocol::ALL {
        let credentials = credentials_for(&format!("{}-priv", protocol.name()));
        let tables = poll_as(&agent, &credentials, &options())
            .await
            .unwrap_or_else(|error| panic!("{protocol}: {error}"));
        assert_eq!(tables, expected_tables(), "{protocol}");
    }
    assert!(
        agent
            .reports()
            .iter()
            .all(|report| *report == "usmStatsUnknownEngineIDs")
    );
}

#[tokio::test]
async fn every_authentication_protocol_without_privacy_reads_the_tables() {
    let agent = agent().await;
    for protocol in AuthProtocol::ALL {
        let credentials = credentials_for(&format!("{}-auth", protocol.name()));
        let tables = poll_as(&agent, &credentials, &options())
            .await
            .unwrap_or_else(|error| panic!("{protocol}: {error}"));
        assert_eq!(tables, expected_tables(), "{protocol}");
    }
}

#[tokio::test]
async fn no_authentication_reads_the_tables() {
    let agent = agent().await;
    let tables = poll_as(&agent, &credentials_for("noauth"), &options())
        .await
        .expect("poll");
    assert_eq!(tables, expected_tables());
    assert_eq!(agent.reports(), ["usmStatsUnknownEngineIDs"]);
}

#[tokio::test]
async fn small_and_large_bulk_sizes_give_the_same_tables() {
    let agent = agent().await;
    let credentials = credentials_for("sha256-priv");
    for max_repetitions in [1, 3, 100] {
        let options = PollOptions {
            max_repetitions,
            ..options()
        };
        let tables = poll_as(&agent, &credentials, &options).await.expect("poll");
        assert_eq!(
            tables,
            expected_tables(),
            "max-repetitions {max_repetitions}"
        );
    }
}

#[tokio::test]
async fn one_slot_in_the_pacer_is_enough() {
    let agent = agent().await;
    let pacer = Pacer::new(PaceLimits {
        per_second: None,
        per_host_interval: Duration::ZERO,
        concurrency: 1,
    });
    let tables = poll(
        agent.addr(),
        &credentials_for("sha1-priv"),
        &options(),
        &pacer,
        &Cancel::never(),
    )
    .await
    .expect("poll");
    assert_eq!(tables, expected_tables());
}

#[tokio::test]
async fn the_bridge_mib_is_used_without_the_q_bridge_table() {
    let mut mib = switch_a();
    let q_bridge = oid("1.3.6.1.2.1.17.7");
    mib.retain(|name, _| !name.starts_with(&q_bridge));
    let dot1d = parse_walk(
        ".1.3.6.1.2.1.17.4.3.1.2.0.0.94.0.83.64 = INTEGER: 5\n\
         .1.3.6.1.2.1.17.4.3.1.2.0.0.94.0.83.16 = INTEGER: 1\n\
         .1.3.6.1.2.1.17.4.3.1.2.0.0.94.0.83.65 = INTEGER: 9\n\
         .1.3.6.1.2.1.17.4.3.1.3.0.0.94.0.83.64 = INTEGER: 3\n\
         .1.3.6.1.2.1.17.4.3.1.3.0.0.94.0.83.16 = INTEGER: 4\n\
         .1.3.6.1.2.1.17.4.3.1.3.0.0.94.0.83.65 = INTEGER: 5\n",
    );
    mib.extend(dot1d);
    let agent = FakeAgent::start(AgentConfig::new(mib)).await;
    let tables = poll_as(&agent, &credentials_for("sha256-auth"), &options())
        .await
        .expect("poll");
    assert_eq!(
        tables.fdb,
        vec![
            FdbEntry {
                mac: mac(0x40),
                vlan: None,
                bridge_port: 5,
                if_index: Some(5)
            },
            FdbEntry {
                mac: mac(0x41),
                vlan: None,
                bridge_port: 9,
                if_index: None
            },
        ]
    );
    assert!(tables.failures.is_empty(), "{:?}", tables.failures);
}

#[tokio::test]
async fn a_device_without_the_optional_tables_gives_empty_ones() {
    let mut mib = switch_a();
    for subtree in ["1.0.8802", "1.3.6.1.2.1.4", "1.3.6.1.2.1.17"] {
        let subtree = oid(subtree);
        mib.retain(|name, _| !name.starts_with(&subtree));
    }
    let agent = FakeAgent::start(AgentConfig::new(mib)).await;
    let tables = poll_as(&agent, &credentials_for("sha1-auth"), &options())
        .await
        .expect("poll");
    assert_eq!(tables.interfaces.len(), 8);
    assert!(
        tables.arp.is_empty() && tables.fdb.is_empty() && tables.lldp.is_empty(),
        "{tables:?}"
    );
    assert!(tables.failures.is_empty(), "{:?}", tables.failures);
    assert!(!tables.truncated);
}

fn assert_auth_error(error: &ScanError, counter: &str) {
    assert_eq!(error.code(), "scan.snmp.auth", "{error}");
    assert!(error.detail().contains(counter), "{error}");
    assert!(!error.detail().contains(AUTH_PASSWORD), "{error}");
    assert!(!error.detail().contains(PRIV_PASSWORD), "{error}");
}

#[tokio::test]
async fn a_wrong_authentication_password_is_reported_as_wrong_digest() {
    let agent = agent().await;
    let credentials = Credentials::auth_priv(
        "sha256-priv",
        AuthProtocol::Sha256,
        "not the password",
        PrivProtocol::Aes128,
        PRIV_PASSWORD,
    );
    let error = poll_as(&agent, &credentials, &options())
        .await
        .expect_err("refused");
    assert_auth_error(&error, "usmStatsWrongDigests");
    assert!(!error.detail().contains("not the password"));
    assert!(agent.reports().contains(&"usmStatsWrongDigests"));
}

#[tokio::test]
async fn a_wrong_authentication_protocol_is_reported_as_wrong_digest() {
    let agent = agent().await;
    let credentials = Credentials::auth_no_priv("sha256-auth", AuthProtocol::Sha1, AUTH_PASSWORD);
    let error = poll_as(&agent, &credentials, &options())
        .await
        .expect_err("refused");
    assert_auth_error(&error, "usmStatsWrongDigests");
}

#[tokio::test]
async fn a_wrong_privacy_password_is_reported_as_decryption_error() {
    let agent = agent().await;
    let credentials = Credentials::auth_priv(
        "sha512-priv",
        AuthProtocol::Sha512,
        AUTH_PASSWORD,
        PrivProtocol::Aes128,
        "another privacy password",
    );
    let error = poll_as(&agent, &credentials, &options())
        .await
        .expect_err("refused");
    assert_auth_error(&error, "usmStatsDecryptionErrors");
    assert!(!error.detail().contains("another privacy password"));
}

#[tokio::test]
async fn an_unknown_user_is_reported() {
    let agent = agent().await;
    let credentials = Credentials::auth_no_priv("nobody", AuthProtocol::Sha256, AUTH_PASSWORD);
    let error = poll_as(&agent, &credentials, &options())
        .await
        .expect_err("refused");
    assert_auth_error(&error, "usmStatsUnknownUserNames");
    assert!(error.detail().contains("nobody"));
}

#[tokio::test]
async fn a_security_level_the_user_does_not_allow_is_reported() {
    let agent = agent().await;
    // The user needs authentication and privacy; the client offers authentication only.
    let credentials = Credentials::auth_no_priv("sha256-priv", AuthProtocol::Sha256, AUTH_PASSWORD);
    let error = poll_as(&agent, &credentials, &options())
        .await
        .expect_err("refused");
    assert_auth_error(&error, "usmStatsUnsupportedSecLevels");
    // And without any authentication.
    let error = poll_as(&agent, &Credentials::no_auth("sha1-auth"), &options())
        .await
        .expect_err("refused");
    assert_auth_error(&error, "usmStatsUnsupportedSecLevels");
}

#[tokio::test]
async fn switches_for_a_wrong_digest_and_an_unknown_user_work_for_correct_credentials() {
    let agent = agent().await;
    agent.set(|switches| switches.wrong_digest = true);
    let error = poll_as(&agent, &credentials_for("sha1-auth"), &options())
        .await
        .expect_err("refused");
    assert_auth_error(&error, "usmStatsWrongDigests");
    agent.set(|switches| {
        switches.wrong_digest = false;
        switches.unknown_user = true;
    });
    let error = poll_as(&agent, &credentials_for("sha1-auth"), &options())
        .await
        .expect_err("refused");
    assert_auth_error(&error, "usmStatsUnknownUserNames");
    // The switch is a property of the agent: without it the same credentials work.
    agent.set(|switches| switches.unknown_user = false);
    poll_as(&agent, &credentials_for("sha1-auth"), &options())
        .await
        .expect("poll");
}

#[tokio::test]
async fn a_time_window_report_is_answered_with_one_retry() {
    let agent = agent().await;
    agent.set(|switches| switches.time_window = TimeWindow::Once);
    let tables = poll_as(&agent, &credentials_for("sha256-priv"), &options())
        .await
        .expect("poll");
    assert_eq!(tables, expected_tables());
    let reports = agent.reports();
    assert_eq!(
        reports
            .iter()
            .filter(|name| **name == "usmStatsNotInTimeWindows")
            .count(),
        1,
        "{reports:?}"
    );
}

#[tokio::test]
async fn a_second_time_window_report_is_an_error() {
    let agent = agent().await;
    agent.set(|switches| switches.time_window = TimeWindow::Always);
    let error = poll_as(&agent, &credentials_for("sha256-auth"), &options())
        .await
        .expect_err("refused");
    assert_auth_error(&error, "usmStatsNotInTimeWindows");
    let sent = agent
        .reports()
        .iter()
        .filter(|name| **name == "usmStatsNotInTimeWindows")
        .count();
    assert_eq!(sent, 2);
}

#[tokio::test]
async fn a_restarted_engine_is_followed() {
    let agent = agent().await;
    let credentials = credentials_for("sha384-priv");
    let (pacer, cancel) = (pacer(), Cancel::never());
    let mut client = Client::connect(agent.addr(), &credentials, &options(), &pacer, &cancel)
        .await
        .expect("connect");
    client.discover().await.expect("discover");
    let name = oid("1.3.6.1.2.1.1.5.0");
    client
        .get(std::slice::from_ref(&name))
        .await
        .expect("get before the restart");
    agent.reboot();
    let bindings = client
        .get(std::slice::from_ref(&name))
        .await
        .expect("get after the restart");
    assert_eq!(
        bindings[0].value,
        Value::OctetString(b"switch-a.example.net".to_vec())
    );
    // The first report answered the discovery.
    assert_eq!(
        agent.reports(),
        ["usmStatsUnknownEngineIDs", "usmStatsNotInTimeWindows"]
    );
    // The client now has the new values and needs no further report.
    client.get(std::slice::from_ref(&name)).await.expect("get");
    assert_eq!(agent.reports().len(), 2);
}

#[tokio::test]
async fn a_changed_engine_id_is_discovered_again() {
    let agent = agent().await;
    let credentials = credentials_for("sha1-priv");
    let (pacer, cancel) = (pacer(), Cancel::never());
    let mut client = Client::connect(agent.addr(), &credentials, &options(), &pacer, &cancel)
        .await
        .expect("connect");
    client.discover().await.expect("discover");
    let real = client.engine_id().expect("engine id").to_vec();
    client.pretend_engine_id(&[0x80, 0x00, 0x00, 0x00, 0x05, 0x01]);
    let name = oid("1.3.6.1.2.1.1.5.0");
    let bindings = client.get(std::slice::from_ref(&name)).await.expect("get");
    assert_eq!(
        bindings[0].value,
        Value::OctetString(b"switch-a.example.net".to_vec())
    );
    assert_eq!(client.engine_id(), Some(real.as_slice()));
    assert_eq!(
        agent
            .reports()
            .iter()
            .filter(|name| **name == "usmStatsUnknownEngineIDs")
            .count(),
        3,
        "the first discovery, the stale engine id and the second discovery"
    );
}

#[tokio::test]
async fn a_silent_device_times_out_after_the_retries() {
    let agent = agent().await;
    agent.set(|switches| switches.drop_all = true);
    let started = Instant::now();
    let error = poll_as(&agent, &credentials_for("sha1-auth"), &quick(2))
        .await
        .expect_err("timeout");
    assert_eq!(error.code(), "scan.snmp.timeout", "{error}");
    assert!(
        started.elapsed() >= Duration::from_millis(280),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(agent.datagrams(), 3);
}

#[tokio::test]
async fn a_dropped_datagram_is_sent_again() {
    let agent = agent().await;
    agent.set(|switches| switches.drop_next = 2);
    let started = Instant::now();
    let tables = poll_as(&agent, &credentials_for("sha1-priv"), &patient(2))
        .await
        .expect("poll");
    assert_eq!(tables, expected_tables());
    assert!(
        started.elapsed() >= Duration::from_millis(580),
        "{:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn a_request_that_goes_unanswered_mid_poll_times_out_too() {
    let agent = agent().await;
    let credentials = credentials_for("sha256-auth");
    let (pacer, cancel) = (pacer(), Cancel::never());
    let options = patient(1);
    let mut client = Client::connect(agent.addr(), &credentials, &options, &pacer, &cancel)
        .await
        .expect("connect");
    client.discover().await.expect("discover");
    agent.set(|switches| switches.drop_all = true);
    let error = client
        .get(&[oid("1.3.6.1.2.1.1.5.0")])
        .await
        .expect_err("timeout");
    assert_eq!(error.code(), "scan.snmp.timeout");
    // The agent recovers and the same client carries on.
    agent.set(|switches| switches.drop_all = false);
    client.get(&[oid("1.3.6.1.2.1.1.5.0")]).await.expect("get");
}

#[tokio::test]
async fn a_closed_port_ends_in_a_timeout() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    let closed: SocketAddr = socket.local_addr().expect("address");
    drop(socket);
    let error = poll(
        closed,
        &credentials_for("sha1-auth"),
        &quick(1),
        &pacer(),
        &Cancel::never(),
    )
    .await
    .expect_err("nothing listens");
    assert_eq!(error.code(), "scan.snmp.timeout", "{error}");
}

#[tokio::test]
async fn responses_with_a_wrong_digest_are_dropped() {
    let agent = agent().await;
    agent.set(|switches| switches.corrupt_digest = true);
    let error = poll_as(&agent, &credentials_for("sha256-priv"), &patient(1))
        .await
        .expect_err("nothing authentic arrives");
    assert_eq!(error.code(), "scan.snmp.timeout", "{error}");
    // Discovery needs no digest: one datagram, then two attempts at the request.
    assert!(agent.datagrams() >= 3, "{}", agent.datagrams());
}

#[tokio::test]
async fn walks_stop_at_the_row_limit() {
    let agent = agent().await;
    let credentials = credentials_for("sha256-auth");
    let (pacer, cancel) = (pacer(), Cancel::never());
    let mut client = Client::connect(agent.addr(), &credentials, &options(), &pacer, &cancel)
        .await
        .expect("connect");
    let root = oid("1.3.6.1.2.1.2.2.1.2");
    for (limit, rows, truncated) in [
        (3, 3, true),
        (0, 0, true),
        (7, 7, true),
        (8, 8, false),
        (100, 8, false),
    ] {
        let walk = client.walk(&root, limit).await.expect("walk");
        assert_eq!(
            (walk.rows.len(), walk.truncated),
            (rows, truncated),
            "limit {limit}"
        );
        assert!(walk.rows.iter().all(|row| row.oid.starts_with(&root)));
    }
    let walk = client.walk(&root, 3).await.expect("walk");
    let names: Vec<_> = walk.rows.iter().map(|row| row.oid.to_string()).collect();
    assert_eq!(
        names,
        [
            "1.3.6.1.2.1.2.2.1.2.1",
            "1.3.6.1.2.1.2.2.1.2.2",
            "1.3.6.1.2.1.2.2.1.2.3"
        ]
    );
}

#[tokio::test]
async fn a_poll_with_a_row_limit_is_marked_truncated() {
    let agent = agent().await;
    let options = PollOptions {
        max_rows: 3,
        ..options()
    };
    let tables = poll_as(&agent, &credentials_for("sha1-auth"), &options)
        .await
        .expect("poll");
    assert!(tables.truncated);
    assert_eq!(
        tables.interfaces.keys().copied().collect::<Vec<_>>(),
        [1, 2, 3]
    );
    assert!(tables.failures.is_empty(), "{:?}", tables.failures);
    // A limit of exactly the size of the largest table is not a truncation.
    let options = PollOptions {
        max_rows: 16,
        ..self::options()
    };
    let tables = poll_as(&agent, &credentials_for("sha1-auth"), &options)
        .await
        .expect("poll");
    assert!(!tables.truncated, "{:?}", tables.failures);
    assert_eq!(tables.interfaces.len(), 8);
}

#[tokio::test]
async fn a_table_that_does_not_advance_ends_the_walk() {
    let agent = agent().await;
    let root = oid("1.3.6.1.2.1.2.2.1.2");
    agent.set(|switches| switches.loop_subtree = Some(root.clone()));
    let credentials = credentials_for("sha256-priv");
    let (pacer, cancel) = (pacer(), Cancel::never());
    let mut client = Client::connect(agent.addr(), &credentials, &options(), &pacer, &cancel)
        .await
        .expect("connect");
    let walk = client.walk(&root, 1000).await.expect("walk");
    assert!(walk.truncated);
    assert_eq!(walk.rows.len(), 2);
    // Other tables are not affected.
    let walk = client
        .walk(&oid("1.3.6.1.2.1.31.1.1.1.1"), 1000)
        .await
        .expect("walk");
    assert!(!walk.truncated);
    assert_eq!(walk.rows.len(), 8);
}

#[tokio::test]
async fn missing_subtrees_are_empty_walks() {
    let agent = agent().await;
    let credentials = credentials_for("sha1-auth");
    let (pacer, cancel) = (pacer(), Cancel::never());
    let mut client = Client::connect(agent.addr(), &credentials, &options(), &pacer, &cancel)
        .await
        .expect("connect");
    // Between two tables, and past the end of the MIB view.
    for root in ["1.3.6.1.2.1.99", "1.3.9.9"] {
        let walk = client.walk(&oid(root), 100).await.expect("walk");
        assert!(walk.rows.is_empty() && !walk.truncated, "{root}");
    }
}

#[tokio::test]
async fn get_returns_values_and_exceptions() {
    let agent = agent().await;
    let credentials = credentials_for("sha224-priv");
    let (pacer, cancel) = (pacer(), Cancel::never());
    let mut client = Client::connect(agent.addr(), &credentials, &options(), &pacer, &cancel)
        .await
        .expect("connect");
    let bindings = client
        .get(&[
            oid("1.3.6.1.2.1.1.5.0"),
            oid("1.3.6.1.2.1.1.3.0"),
            oid("1.3.6.1.2.1.1.99.0"),
            oid("1.3.6.1.2.1.31.1.1.1.6.1"),
        ])
        .await
        .expect("get");
    let values: Vec<_> = bindings.into_iter().map(|binding| binding.value).collect();
    assert_eq!(
        values,
        vec![
            Value::OctetString(b"switch-a.example.net".to_vec()),
            Value::TimeTicks(123_456),
            Value::NoSuchObject,
            Value::Counter64(123_456_789_012),
        ]
    );
}

#[tokio::test]
async fn an_error_status_in_a_table_is_recorded_and_the_rest_is_read() {
    let agent = agent().await;
    agent.set(|switches| switches.error_subtree = Some(oid("1.0.8802.1.1.2.1.4")));
    let tables = poll_as(&agent, &credentials_for("sha256-auth"), &options())
        .await
        .expect("poll");
    let expected = expected_tables();
    assert_eq!(tables.interfaces, expected.interfaces);
    assert_eq!(tables.arp, expected.arp);
    assert_eq!(tables.fdb, expected.fdb);
    assert!(tables.lldp.is_empty(), "{:?}", tables.lldp);
    assert_eq!(tables.failures.len(), 6, "{:?}", tables.failures);
    for failure in &tables.failures {
        assert!(failure.starts_with("lldpRem"), "{failure}");
        assert!(
            failure.contains("scan.snmp.protocol") && failure.contains("genErr"),
            "{failure}"
        );
    }
}

#[tokio::test]
async fn cancellation_stops_the_poll_between_datagrams() {
    let agent = agent().await;
    agent.set(|switches| switches.drop_all = true);
    let (sender, receiver) = watch::channel(false);
    let cancel = Cancel::new(receiver);
    let options = PollOptions {
        timeout: Duration::from_secs(10),
        retries: 3,
        ..options()
    };
    let canceller = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(150)).await;
        let _ = sender.send(true);
    });
    let started = Instant::now();
    let error = poll(
        agent.addr(),
        &credentials_for("sha1-auth"),
        &options,
        &pacer(),
        &cancel,
    )
    .await
    .expect_err("cancelled");
    canceller.await.expect("canceller");
    assert_eq!(error.code(), "scan.cancelled", "{error}");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn a_poll_that_is_cancelled_beforehand_sends_nothing() {
    let agent = agent().await;
    let (sender, receiver) = watch::channel(true);
    let error = poll(
        agent.addr(),
        &credentials_for("sha1-auth"),
        &options(),
        &pacer(),
        &Cancel::new(receiver),
    )
    .await
    .expect_err("cancelled");
    drop(sender);
    assert_eq!(error.code(), "scan.cancelled");
    assert_eq!(agent.datagrams(), 0);
}

#[tokio::test]
async fn unusable_credentials_are_refused_before_anything_is_sent() {
    let agent = agent().await;
    let cases = [
        Credentials::auth_no_priv("sha1-auth", AuthProtocol::Sha1, "short"),
        Credentials::auth_priv(
            "sha1-priv",
            AuthProtocol::Sha1,
            AUTH_PASSWORD,
            PrivProtocol::Aes128,
            "tiny",
        ),
        Credentials {
            privacy: Some((
                PrivProtocol::Aes128,
                zeroize::Zeroizing::new(PRIV_PASSWORD.to_owned()),
            )),
            ..Credentials::no_auth("sha1-priv")
        },
        Credentials::auth_no_priv("", AuthProtocol::Sha1, AUTH_PASSWORD),
        Credentials::no_auth("a-user-name-that-is-longer-than-32-octets"),
    ];
    for credentials in cases {
        let error = poll_as(&agent, &credentials, &options())
            .await
            .expect_err("refused");
        assert_eq!(error.code(), "scan.config", "{credentials:?}: {error}");
        assert!(!error.detail().contains(AUTH_PASSWORD) && !error.detail().contains("short"));
    }
    assert_eq!(agent.datagrams(), 0);
}

#[test]
fn credentials_never_show_passwords() {
    let credentials = Credentials::auth_priv(
        "monitor",
        AuthProtocol::Sha256,
        "a secret authentication password",
        PrivProtocol::Aes128,
        "a secret privacy password",
    );
    let text = format!("{credentials:?}");
    assert!(text.contains("monitor") && text.contains("Sha256") && text.contains("Aes128"));
    assert!(!text.contains("secret"), "{text}");
}

#[test]
fn protocol_names_parse_and_unsupported_ones_are_explained() {
    for (text, protocol) in [
        ("sha1", AuthProtocol::Sha1),
        ("SHA-1", AuthProtocol::Sha1),
        ("sha", AuthProtocol::Sha1),
        ("sha_224", AuthProtocol::Sha224),
        ("SHA256", AuthProtocol::Sha256),
        ("hmac-sha-384", AuthProtocol::Sha384),
        ("sha-512", AuthProtocol::Sha512),
    ] {
        assert_eq!(text.parse::<AuthProtocol>().expect(text), protocol);
    }
    for protocol in AuthProtocol::ALL {
        assert_eq!(protocol.name().parse::<AuthProtocol>(), Ok(protocol));
    }
    let md5 = "md5".parse::<AuthProtocol>().expect_err("md5");
    assert_eq!(md5.code(), "scan.config");
    assert!(md5.detail().contains("MD5") && md5.detail().contains("not supported"));
    assert!("whirlpool".parse::<AuthProtocol>().is_err());

    for text in ["aes128", "AES-128", "aes"] {
        assert_eq!(text.parse::<PrivProtocol>(), Ok(PrivProtocol::Aes128));
    }
    for text in ["des", "3des", "aes192", "aes256", "rot13"] {
        let error = text.parse::<PrivProtocol>().expect_err(text);
        assert_eq!(error.code(), "scan.config");
    }
    assert!(
        "des"
            .parse::<PrivProtocol>()
            .expect_err("des")
            .detail()
            .contains("not supported")
    );
}

#[test]
fn protocols_use_snake_case_names_in_configuration() {
    assert_eq!(
        serde_json::to_string(&AuthProtocol::Sha256).expect("json"),
        "\"sha256\""
    );
    assert_eq!(
        serde_json::to_string(&PrivProtocol::Aes128).expect("json"),
        "\"aes128\""
    );
    assert_eq!(
        serde_json::from_str::<AuthProtocol>("\"sha512\"").expect("json"),
        AuthProtocol::Sha512
    );
    assert!(serde_json::from_str::<AuthProtocol>("\"md5\"").is_err());
}

#[test]
fn default_options_are_the_documented_ones() {
    let defaults = PollOptions::default();
    assert_eq!(defaults.timeout, Duration::from_secs(2));
    assert_eq!(defaults.retries, 2);
    assert_eq!(defaults.max_repetitions, 20);
    assert_eq!(defaults.max_rows, 20_000);
}
