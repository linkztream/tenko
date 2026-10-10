//! The conformance suite of the plugin SDK against the UniFi plugin's executable, started as
//! the host starts an installed plugin: without settings (every remote check answers with a
//! coded settings error) it must pass every check.

mod support;

use std::{path::PathBuf, time::Duration};

use tenko_connect::{
    conformance::{Outcome, SuiteOptions, run},
    host::launch::LaunchSpec,
};

fn spec() -> LaunchSpec {
    LaunchSpec {
        expected: Some(tenko_connect_unifi::manifest()),
        program: PathBuf::from(env!("CARGO_BIN_EXE_tenko-plugin-unifi")),
        args: Vec::new(),
        cwd: None,
        env: Vec::new(),
    }
}

#[tokio::test]
async fn the_plugin_passes_the_conformance_suite_without_a_controller() {
    let options = SuiteOptions {
        call_timeout: Duration::from_secs(10),
        ..SuiteOptions::default()
    };
    let report = run(&spec(), &options).await;
    assert!(report.passed(), "{report}");
    for id in [
        "launch",
        "manifest",
        "token",
        "concurrency",
        "check",
        "capability.inventory",
        "capability.network_controller",
        "undeclared",
        "malformed_request",
        "shutdown",
        "protocol_mismatch",
        "stdin_close",
    ] {
        assert_eq!(
            report.check(id).map(|check| check.outcome),
            Some(Outcome::Pass),
            "{id}: {report}"
        );
    }
    assert_eq!(report.plugin.as_deref(), Some("unifi"));
}

#[tokio::test]
async fn the_plugin_passes_the_conformance_suite_against_the_fake_controller() {
    let fake = support::FakeController::start_tls(support::Flavor::SelfHosted).await;
    let mut secrets = tenko_connect::Secrets::new();
    secrets.insert_bytes("password", support::PASSWORD.as_bytes().to_vec());
    let options = SuiteOptions {
        settings: Some(fake.settings()),
        secrets,
        call_timeout: Duration::from_secs(10),
        ..SuiteOptions::default()
    };
    let report = run(&spec(), &options).await;
    assert!(report.passed(), "{report}");
    let inventory = report.check("capability.inventory").expect("inventory");
    assert!(inventory.detail.contains("hosts"), "{report}");
    assert!(fake.logins() >= 3, "the suite reached the controller");
    assert_eq!(fake.logins(), fake.logouts(), "every session ended");
    assert_eq!(fake.writes().len(), 0, "the suite never writes");
}
