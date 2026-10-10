//! Route tests of the remote access hand-off (API-11): the `.rdp` file and the `ssh://`
//! URI of a host, the target, port and user name they carry, and that neither carries a
//! secret.

use serde_json::json;
use tenko_auth::settings::Profile;

use crate::routes::{auth::testkit::Credential, secrets::tests::Harness};

const VALUE: &str = "example-remote-secret";

/// A host `nas01` with `eth0` at 192.0.2.10 (`nas01.example.test`), a credential with the
/// user `admin` bound as `admin` and one with the user `rdpuser` bound as `rdp`.
async fn host_with_credentials(h: &Harness) -> (String, String) {
    let admin = h.create_secret("nas admin", "admin", VALUE).await;
    let rdp = h.create_secret("nas rdp", "rdpuser", VALUE).await;
    let (host, interface) = h
        .create_host("nas01", "192.0.2.0/24", "192.0.2.10", true)
        .await;
    h.bind(
        &host,
        json!([{ "secret": admin, "role": "admin" }, { "secret": rdp, "role": "rdp" }]),
    )
    .await
    .assert_status(200);
    (host, interface)
}

#[tokio::test]
async fn an_rdp_file_carries_the_target_port_and_bound_user_but_no_secret() {
    let h = Harness::new(Profile::Home).await;
    let (host, interface) = host_with_credentials(&h).await;
    let admin = Credential::Cookie(&h.admin);
    let (status, headers, text) = h
        .raw(&format!("/hosts/{host}/remote?protocol=rdp"), admin)
        .await;
    assert_eq!(status, 200, "{text}");
    assert_eq!(
        headers.get("content-type").and_then(|v| v.to_str().ok()),
        Some("application/x-rdp")
    );
    assert_eq!(
        headers
            .get("content-disposition")
            .and_then(|v| v.to_str().ok()),
        Some("attachment; filename=\"nas01.rdp\"")
    );
    assert_eq!(
        text,
        "full address:s:nas01.example.test:3389\r\nusername:s:rdpuser\r\nprompt for credentials:i:1\r\nadministrative session:i:0\r\nscreen mode id:i:2\r\nauthentication level:i:2\r\n"
    );
    assert!(!text.contains(VALUE));

    let (status, _, text) = h
        .raw(
            &format!(
                "/hosts/{host}/remote?protocol=rdp&interface={interface}&address=192.0.2.10&port=3390&user=EXAMPLE%5Cops"
            ),
            admin,
        )
        .await;
    assert_eq!(status, 200, "{text}");
    assert!(text.starts_with("full address:s:192.0.2.10:3390\r\nusername:s:EXAMPLE\\ops\r\n"));

    // The DNS name of an address of the host serves as the target too.
    let (status, _, text) = h
        .raw(
            &format!("/hosts/{host}/remote?protocol=rdp&address=NAS01.example.test"),
            admin,
        )
        .await;
    assert_eq!(status, 200, "{text}");
    assert!(
        text.starts_with("full address:s:NAS01.example.test:3389\r\n"),
        "{text}"
    );
}

#[tokio::test]
async fn an_ssh_uri_takes_the_ssh_credential_or_the_admin_one() {
    let h = Harness::new(Profile::Home).await;
    let (host, _) = host_with_credentials(&h).await;
    let admin = Credential::Cookie(&h.admin);
    let reply = h
        .call(
            "GET",
            &format!("/hosts/{host}/remote?protocol=ssh"),
            admin,
            None,
        )
        .await;
    reply.assert_status(200);
    assert_eq!(reply.body["uri"], "ssh://admin@nas01.example.test");
    assert_eq!(reply.body["port"], 22);
    assert_eq!(reply.body["username"], "admin");
    assert!(!reply.body.to_string().contains(VALUE));

    let reply = h
        .call(
            "GET",
            &format!("/hosts/{host}/remote?protocol=ssh&port=2222&user=root"),
            admin,
            None,
        )
        .await;
    assert_eq!(reply.body["uri"], "ssh://root@nas01.example.test:2222");
}

#[tokio::test]
async fn an_ipv6_address_is_bracketed_and_a_host_without_addresses_uses_its_name() {
    let h = Harness::new(Profile::Home).await;
    let (host, _) = h
        .create_host("router", "2001:db8::/64", "2001:db8::10", false)
        .await;
    let admin = Credential::Cookie(&h.admin);
    let (status, _, text) = h
        .raw(&format!("/hosts/{host}/remote?protocol=rdp"), admin)
        .await;
    assert_eq!(status, 200, "{text}");
    assert!(
        text.starts_with("full address:s:[2001:db8::10]:3389\r\nprompt"),
        "{text}"
    );
    let reply = h
        .call(
            "GET",
            &format!("/hosts/{host}/remote?protocol=ssh"),
            admin,
            None,
        )
        .await;
    assert_eq!(reply.body["uri"], "ssh://[2001:db8::10]");

    let bare = h
        .call("POST", "/hosts", admin, Some(&json!({ "name": "printer" })))
        .await;
    bare.assert_status(201);
    let bare = bare.body["item"]["id"].as_str().expect("id").to_owned();
    let reply = h
        .call(
            "GET",
            &format!("/hosts/{bare}/remote?protocol=ssh"),
            admin,
            None,
        )
        .await;
    assert_eq!(reply.body["uri"], "ssh://printer");
}

#[tokio::test]
async fn a_viewer_gets_the_hand_off_without_the_bound_user() {
    let h = Harness::new(Profile::Home).await;
    let (host, _) = host_with_credentials(&h).await;
    h.create_user("vera", &["viewer"]).await;
    let vera = h
        .login("vera", super::super::secrets::tests::USER_PIN)
        .await;
    let reply = h
        .call(
            "GET",
            &format!("/hosts/{host}/remote?protocol=ssh"),
            Credential::Cookie(&vera),
            None,
        )
        .await;
    reply.assert_status(200);
    assert_eq!(reply.body["uri"], "ssh://nas01.example.test");
    assert!(reply.body.get("username").is_none());
}

#[tokio::test]
async fn bad_parameters_and_foreign_addresses_are_refused() {
    let h = Harness::new(Profile::Home).await;
    let (host, _) = host_with_credentials(&h).await;
    let admin = Credential::Cookie(&h.admin);
    for query in [
        "",
        "?protocol=vnc",
        "?protocol=rdp&port=0",
        "?protocol=rdp&color=1",
    ] {
        h.call("GET", &format!("/hosts/{host}/remote{query}"), admin, None)
            .await
            .assert_problem(400, "sys.invalid_query");
    }
    h.call(
        "GET",
        &format!("/hosts/{host}/remote?protocol=rdp&address=198.51.100.7"),
        admin,
        None,
    )
    .await
    .assert_problem(422, "remote.address_unknown");
    let other = uuid::Uuid::now_v7();
    h.call(
        "GET",
        &format!("/hosts/{host}/remote?protocol=rdp&interface={other}"),
        admin,
        None,
    )
    .await
    .assert_problem(422, "remote.interface_unknown");
    h.call(
        "GET",
        &format!("/hosts/{other}/remote?protocol=rdp"),
        admin,
        None,
    )
    .await
    .assert_problem(404, "ipam.not_found");
}
