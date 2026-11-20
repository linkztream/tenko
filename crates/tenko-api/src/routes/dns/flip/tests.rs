//! The flip and the release of a zone through the router with the real authenticator and
//! authorizer: a viewer is refused both, a key named in a flip to secondary needs the key
//! right, a personal token is refused the flip, a primary on a refused address names its
//! field, a sign-in older than five minutes needs a step-up for the flip and the release (a
//! dry run apart), and a zone goes to secondary and back. What the zone service does behind them is
//! `tenko-dns/tests/flip.rs`. Zones are kinds no scoped grant reaches, so a principal with
//! the DNS rights reaches every tenant's zones and none without them.

use std::{sync::Arc, time::Duration};

use axum::Extension;
use serde_json::{Value, json};
use tenko_core::Timestamp;
use tenko_dns::zone::{ZoneConfig, ZoneService};
use tenko_store::{ReadConsistency, ReadViewExt as _, Store, WriteBatch};

use crate::routes::auth::testkit::{Credential::*, Harness};

const PIN: &str = "739158";

/// The harness with the zone service, the administrator's session, an operator's and a
/// viewer's.
async fn harness() -> (Harness, String, String, String) {
    let (plain, admin) = Harness::installed().await;
    let env = plain.env;
    let store: Arc<dyn Store> = env.store.clone();
    let zones = ZoneService::with_direct_jobs(store, None, ZoneConfig::default());
    let harness = Harness::wired(env, move |state| {
        crate::api(state).0.layer(Extension(zones))
    });
    harness
        .create_user(&admin, "olle", PIN, &["operator"])
        .await;
    harness.create_user(&admin, "vera", PIN, &["viewer"]).await;
    let operator = harness.login("olle", PIN).await;
    let viewer = harness.login("vera", PIN).await;
    (harness, admin, operator, viewer)
}

fn to_primary() -> Value {
    json!({"to": "primary", "soa": {"mname": "ns1.example.test", "rname": "hostmaster.example.test"}, "ns": ["ns1.example.test"]})
}

fn to_secondary(primary: &Value) -> Value {
    json!({"to": "secondary", "primaries": [primary]})
}

/// Creates the primary zone `example.test` and returns its id.
async fn zone(h: &Harness, admin: &str) -> String {
    let created = h
        .call(
            "POST",
            "/dns/zones",
            Cookie(admin),
            Some(&json!({"name": "example.test", "kind": "primary", "name_servers": ["ns1.example.test"],
                          "soa": {"mname": "ns1.example.test", "rname": "hostmaster.example.test"}})),
        )
        .await;
    created.assert_status(201);
    created.body["id"].as_str().expect("id").to_owned()
}

/// Moves the sign-in of the session `secret` ten minutes back.
async fn age(h: &Harness, secret: &str) {
    let key = tenko_auth::secret::hash_secret(secret);
    let view = h
        .env
        .store
        .read(ReadConsistency::Local)
        .await
        .expect("a view");
    let (mut record, _) = view
        .get_typed(&tenko_auth::model::SESSIONS, &key)
        .expect("read")
        .expect("the session");
    let now = Timestamp::now();
    let age = Duration::from_secs(600);
    record.authenticated_at = now.checked_sub(age).expect("a time");
    let mut batch = WriteBatch::new(
        tenko_core::Principal::system(tenko_core::SystemComponent::Auth),
        now,
    );
    batch
        .put_typed(&tenko_auth::model::SESSIONS, &key, &record)
        .expect("encode");
    h.env.store.propose(batch).await.expect("aged");
}

#[tokio::test]
#[allow(clippy::too_many_lines, reason = "every principal in one sequence")]
async fn the_flip_and_the_release_check_who_asks() {
    let (h, admin, operator, viewer) = harness().await;
    let id = zone(&h, &admin).await;
    let (flip, release) = (
        format!("/dns/zones/{id}/flip"),
        format!("/dns/zones/{id}/release"),
    );
    let plain = to_secondary(&json!({"address": "192.0.2.5"}));

    h.call("POST", &flip, Cookie(&viewer), Some(&plain))
        .await
        .assert_problem(403, "auth.forbidden");
    h.call(
        "POST",
        &release,
        Cookie(&viewer),
        Some(&json!({"dry_run": true})),
    )
    .await
    .assert_problem(403, "auth.forbidden");
    let keyed = to_secondary(&json!({"address": "192.0.2.5", "key": "xfr.example.test"}));
    h.call("POST", &flip, Cookie(&operator), Some(&keyed))
        .await
        .assert_problem(403, "auth.forbidden");
    h.call("POST", &flip, Cookie(&admin), Some(&keyed))
        .await
        .assert_problem(404, "dns.key.not_found");
    let token = h
        .call(
            "POST",
            "/auth/tokens",
            Cookie(&admin),
            Some(&json!({ "name": "ci", "expires_in_days": 30 })),
        )
        .await;
    token.assert_status(201);
    let token = token.body["token"].as_str().expect("token").to_owned();
    h.call("POST", &flip, Bearer(&token), Some(&plain))
        .await
        .assert_problem(403, "auth.forbidden");
    h.call("POST", &release, Bearer(&token), Some(&json!({})))
        .await
        .assert_problem(403, "auth.forbidden");
    h.call(
        "POST",
        &release,
        Bearer(&token),
        Some(&json!({"delete": true})),
    )
    .await
    .assert_problem(403, "auth.forbidden");
    h.call(
        "POST",
        &release,
        Bearer(&token),
        Some(&json!({"dry_run": true})),
    )
    .await
    .assert_status(200);
    h.call("POST", &flip, Cookie(&admin), Some(&to_primary()))
        .await
        .assert_problem(409, "dns.zone.flip.not_secondary");
    for address in ["127.0.0.1", "169.254.169.254", "fe80::1"] {
        let refused = h
            .call(
                "POST",
                &flip,
                Cookie(&admin),
                Some(&to_secondary(&json!({"address": address}))),
            )
            .await;
        refused.assert_problem(400, "dns.zone.invalid");
        assert_eq!(
            refused.body["params"]["field"], "source.primaries",
            "{address}"
        );
    }
    let listed = h
        .call(
            "POST",
            &release,
            Cookie(&operator),
            Some(&json!({"dry_run": true})),
        )
        .await;
    listed.assert_status(200);
    assert_eq!(
        (&listed.body["rrsets"], &listed.body["dry_run"]),
        (&json!(0), &json!(true))
    );

    // To secondary and back before any transfer: the records stay, the SOA moves on.
    let back = h.call("POST", &flip, Cookie(&operator), Some(&plain)).await;
    back.assert_status(200);
    assert_eq!(back.body["kind"], "secondary");
    let serial = back.body["serial"].as_u64().expect("serial");
    h.call("POST", &release, Cookie(&operator), Some(&json!({})))
        .await
        .assert_problem(409, "dns.zone.flip.not_primary");
    let again = h
        .call("POST", &flip, Cookie(&operator), Some(&to_primary()))
        .await;
    again.assert_status(200);
    assert_eq!(again.body["kind"], "primary");
    assert!(again.body["serial"].as_u64().expect("serial") > serial);
    assert_eq!(
        again.body["origins"],
        json!([{"origin": "manual", "rrsets": 2}])
    );
}

#[tokio::test]
async fn a_sign_in_older_than_five_minutes_needs_a_step_up() {
    let (h, admin, operator, _) = harness().await;
    let id = zone(&h, &admin).await;
    age(&h, &operator).await;
    h.call(
        "POST",
        &format!("/dns/zones/{id}/flip"),
        Cookie(&operator),
        Some(&to_secondary(&json!({"address": "192.0.2.5"}))),
    )
    .await
    .assert_problem(403, "auth.step_up_required");
    let release = format!("/dns/zones/{id}/release");
    h.call(
        "POST",
        &release,
        Cookie(&operator),
        Some(&json!({"delete": true})),
    )
    .await
    .assert_problem(403, "auth.step_up_required");
    h.call(
        "POST",
        &release,
        Cookie(&operator),
        Some(&json!({"dry_run": true})),
    )
    .await
    .assert_status(200);
}
