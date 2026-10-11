//! `Config.Secrets` over mutual TLS: the vault secrets a node's configuration names, the
//! audit record of the hand-over and what is refused.

use tenko_core::{RequestCtx, SecretId, SystemComponent};
use tenko_vault::{SecretBytes, SecretPurpose, SecretSpec, Vault, operator::OPERATOR_PURPOSE};

use super::harness::{Controller, FIRST_NODE, Options, Row, Running, wait_for};
use crate::{
    identity::AgentState,
    node_sync::{
        codes,
        secrets::{SECRETS_ACTION, SecretUse},
    },
    proto::v1,
    server::code_of,
};

const COMMUNITY: &str = "community-example-test";

fn ctx() -> RequestCtx {
    RequestCtx::system(SystemComponent::Api)
}

/// Stores an operator secret and returns its id.
async fn operator_secret(controller: &Controller, label: &str, value: &str) -> SecretId {
    controller
        .vault
        .put_operator(
            &ctx(),
            SecretSpec::new(SecretPurpose::from_static(OPERATOR_PURPOSE)).labelled(label),
            SecretBytes::from(value.to_owned()),
        )
        .await
        .expect("operator secret")
        .secret
}

fn snmp(secret: SecretId) -> SecretUse {
    SecretUse {
        purpose: "snmp".to_owned(),
        secret,
    }
}

async fn ask_as(
    controller: &Controller,
    credentials: &crate::identity::Credentials,
    purposes: &[&str],
) -> Result<Vec<v1::NodeSecret>, tonic::Status> {
    let channel = controller.channel(credentials).await;
    let mut client = v1::config_client::ConfigClient::new(channel);
    client
        .secrets(v1::SecretsRequest {
            purposes: purposes
                .iter()
                .map(|purpose| (*purpose).to_owned())
                .collect(),
        })
        .await
        .map(|response| response.into_inner().secrets)
}

async fn hand_overs(controller: &Controller) -> usize {
    controller
        .audit_actions()
        .await
        .iter()
        .filter(|action| action.as_str() == SECRETS_ACTION.as_str())
        .count()
}

#[tokio::test]
async fn a_probe_gets_the_secret_its_configuration_names_and_the_hand_over_is_audited() {
    let controller = Controller::start().await;
    let dir = tempfile::tempdir().expect("dir");
    controller.enrol(dir.path(), "probe-secrets").await;
    let named = operator_secret(&controller, "switches.example.test", COMMUNITY).await;
    let unnamed = operator_secret(&controller, "other.example.test", "not-for-this-node").await;
    controller
        .put_config(FIRST_NODE, &Row::naming(1, vec![snmp(named)]))
        .await;
    assert_eq!(hand_overs(&controller).await, 0);

    let running = Running::start(dir.path());
    let agent = &running.agent;
    wait_for("the node to connect and sync", || {
        agent.status().state == AgentState::Connected && !agent.config().borrow().rows.is_empty()
    })
    .await;
    let held = agent.secrets(&["snmp"]).await.expect("secrets");
    assert_eq!(held.len(), 1);
    assert_eq!(held.get("snmp", named), Some(COMMUNITY.as_bytes()));
    assert_eq!(held.get("snmp", unnamed), None, "its row does not name it");
    assert_eq!(hand_overs(&controller).await, 1, "one audit record");

    // The record names the node's purposes, and no value anywhere in the audit log.
    let view = {
        use tenko_store::{ReadConsistency, Store};
        controller
            .store
            .read(ReadConsistency::Local)
            .await
            .expect("view")
    };
    let records = {
        use tenko_store::{KeyRange, ReadViewExt, tables};
        view.scan_typed(&tables::AUDIT, KeyRange::all(), usize::MAX, false)
            .expect("audit")
    };
    let record = records
        .iter()
        .map(|(_, record, _)| &record.draft)
        .find(|draft| draft.action.as_str() == SECRETS_ACTION.as_str())
        .expect("the hand-over record");
    let text = format!("{record:?}");
    assert!(text.contains("probe-secrets"), "{text}");
    assert!(text.contains("snmp"), "{text}");
    assert!(!text.contains(COMMUNITY), "a value in the audit record");
    running.stop().await;
}

#[tokio::test]
async fn a_secret_the_configuration_does_not_name_or_that_is_not_an_operator_secret_is_not_handed_out()
 {
    let controller = Controller::start().await;
    let dir = tempfile::tempdir().expect("dir");
    let credentials = controller.enrol(dir.path(), "probe-names").await;
    let other_dir = tempfile::tempdir().expect("dir");
    let other = controller.enrol(other_dir.path(), "probe-bystander").await;
    let named = operator_secret(&controller, "named.example.test", COMMUNITY).await;
    let system = controller
        .vault
        .put_system(
            &ctx(),
            SecretSpec::new(SecretPurpose::from_static("auth.totp")),
            SecretBytes::from("system-value".to_owned()),
        )
        .await
        .expect("system secret")
        .secret;
    let missing = SecretId::generate();

    // A row naming nothing, then a row naming only secrets that may not leave.
    controller.put_config(FIRST_NODE, &Row::plain(1)).await;
    let none = ask_as(&controller, &credentials, &["snmp"])
        .await
        .expect("answer");
    assert!(none.is_empty(), "the row names no secret");
    controller
        .put_config(
            FIRST_NODE,
            &Row::naming(2, vec![snmp(system), snmp(missing)]),
        )
        .await;
    let none = ask_as(&controller, &credentials, &["snmp"])
        .await
        .expect("answer");
    assert!(
        none.is_empty(),
        "a system secret and a missing one stay put"
    );
    assert_eq!(
        hand_overs(&controller).await,
        0,
        "nothing left, nothing audited"
    );

    // Another node asks for the purpose and gets nothing: it has no configuration.
    let none = ask_as(&controller, &other, &["snmp"])
        .await
        .expect("answer");
    assert_eq!(none.len(), 0);

    // Named beside the others, only the operator secret is handed out.
    controller
        .put_config(
            FIRST_NODE,
            &Row::naming(3, vec![snmp(system), snmp(named), snmp(missing)]),
        )
        .await;
    let secrets = ask_as(&controller, &credentials, &["snmp"])
        .await
        .expect("answer");
    assert_eq!(secrets.len(), 1);
    assert_eq!(secrets[0].purpose, "snmp");
    assert_eq!(secrets[0].name, named.to_string());
    assert_eq!(secrets[0].value, COMMUNITY.as_bytes());
    assert_eq!(hand_overs(&controller).await, 1);

    // No purpose asked for, nothing handed out.
    let none = ask_as(&controller, &credentials, &[])
        .await
        .expect("answer");
    assert_eq!(none.len(), 0);
    assert_eq!(hand_overs(&controller).await, 1);
}

#[tokio::test]
async fn a_purpose_the_roles_of_the_node_do_not_use_is_refused() {
    let controller = Controller::start().await;
    let dir = tempfile::tempdir().expect("dir");
    let credentials = controller.enrol(dir.path(), "probe-purpose").await;
    let named = operator_secret(&controller, "named.example.test", COMMUNITY).await;
    controller
        .put_config(FIRST_NODE, &Row::naming(1, vec![snmp(named)]))
        .await;

    for purposes in [&["tsig"][..], &["snmp", "tsig"][..], &[""][..]] {
        let status = ask_as(&controller, &credentials, purposes)
            .await
            .expect_err("refused");
        assert_eq!(status.code(), tonic::Code::PermissionDenied, "{status:?}");
        assert_eq!(code_of(&status), Some(codes::SECRETS_PURPOSE));
    }
    assert_eq!(
        hand_overs(&controller).await,
        0,
        "a refusal hands out nothing"
    );
}

#[tokio::test]
async fn more_than_sixteen_purposes_in_one_request_are_refused() {
    let controller = Controller::start().await;
    let dir = tempfile::tempdir().expect("dir");
    let credentials = controller.enrol(dir.path(), "probe-many").await;
    let named = operator_secret(&controller, "named.example.test", COMMUNITY).await;
    controller
        .put_config(FIRST_NODE, &Row::naming(1, vec![snmp(named)]))
        .await;

    let sixteen = ["snmp"; 16];
    let secrets = ask_as(&controller, &credentials, &sixteen)
        .await
        .expect("sixteen are fine");
    assert_eq!(secrets.len(), 1, "a repeated purpose is one secret");
    assert_eq!(hand_overs(&controller).await, 1);

    let seventeen = ["snmp"; 17];
    let status = ask_as(&controller, &credentials, &seventeen)
        .await
        .expect_err("refused");
    assert_eq!(status.code(), tonic::Code::InvalidArgument, "{status:?}");
    assert_eq!(code_of(&status), Some(codes::SECRETS_PURPOSE));
    assert_eq!(
        hand_overs(&controller).await,
        1,
        "the refusal wrote nothing"
    );
}

#[tokio::test]
async fn a_controller_without_a_vault_serves_no_secrets() {
    let controller = Controller::start_with(Options {
        vault: false,
        ..Options::default()
    })
    .await;
    let dir = tempfile::tempdir().expect("dir");
    let credentials = controller.enrol(dir.path(), "probe-novault").await;

    // Nothing named: nothing to serve, and nothing to complain about.
    controller.put_config(FIRST_NODE, &Row::plain(1)).await;
    let none = ask_as(&controller, &credentials, &["snmp"])
        .await
        .expect("answer");
    assert_eq!(none.len(), 0);

    let named = operator_secret(&controller, "named.example.test", COMMUNITY).await;
    controller
        .put_config(FIRST_NODE, &Row::naming(2, vec![snmp(named)]))
        .await;
    let status = ask_as(&controller, &credentials, &["snmp"])
        .await
        .expect_err("no vault");
    assert_eq!(status.code(), tonic::Code::Unavailable, "{status:?}");
    assert_eq!(code_of(&status), Some(codes::SECRETS_UNAVAILABLE));
    assert_eq!(hand_overs(&controller).await, 0);
}
