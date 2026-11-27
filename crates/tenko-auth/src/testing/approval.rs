//! A takeover script for tests (ADR 0038): its key, its request, its code and its collect,
//! and the steps that turn a person's approval into a delegated session.

use aws_lc_rs::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tenko_core::{ApprovalId, RequestCtx};

use super::TestEnv;
use crate::{
    approval::{ApprovalTicket, DelegatedSession},
    error::AuthError,
    service::SecretString,
};

/// The SHA-256 of a fictitious TLS root that test installations bind codes to.
pub const ROOT_SHA256: [u8; 32] = [0x5a; 32];

/// The reference plan: the domain `corp.example.test` with two controllers, two DHCP servers
/// in failover and one scope.
pub fn plan() -> Value {
    json!({
        "domain": "corp.example.test",
        "forest_root": "corp.example.test",
        "controllers": [
            { "name": "dc1.corp.example.test", "addresses": ["192.0.2.11"], "pdc": true },
            { "name": "dc2.corp.example.test", "addresses": ["192.0.2.12"] }
        ],
        "zones": ["corp.example.test", "_msdcs.corp.example.test", "2.0.192.in-addr.arpa"],
        "forwarders": [{ "zone": ".", "servers": ["198.51.100.53"] }],
        "dhcp_servers": [
            { "name": "dhcp1.corp.example.test", "address": "192.0.2.21" },
            { "name": "dhcp2.corp.example.test", "address": "192.0.2.22" }
        ],
        "relationship": "dhcp1-dhcp2",
        "scopes": ["192.0.2.0/24"],
        "mirror_host": { "name": "mgmt1.corp.example.test", "address": "192.0.2.30" },
        "node_name": "tenko",
        "operations": [
            "mirrors", "secondary_zones", "forwarding_rules", "kerberos_adopt", "prepare", "flip",
            "takeover"
        ],
        "kerberos": {
            "realm": "CORP.EXAMPLE.TEST",
            "account": "TENKO$",
            "spns": ["DNS/tenko.corp.example.test"]
        }
    })
}

/// A script: a P-256 key made in memory.
#[derive(Debug)]
pub struct Script(EcdsaKeyPair);

impl Default for Script {
    fn default() -> Self {
        Self(EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).expect("a P-256 key"))
    }
}

impl Script {
    /// The public key in base64url, as the request carries it.
    pub fn key(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0.public_key().as_ref())
    }

    /// The request body for `plan`, as sent.
    pub fn request_for(&self, plan: &Value) -> String {
        json!({
            "purpose": "windows-takeover",
            "plan": plan,
            "key": self.key(),
            "client": { "machine": "ADM1", "user": "CORP\\admin", "version": "0.1.0" }
        })
        .to_string()
    }

    /// The request body for the reference plan.
    pub fn request(&self) -> String {
        self.request_for(&plan())
    }

    /// The code of the approval `id` of `body`, over [`ROOT_SHA256`].
    ///
    /// # Panics
    ///
    /// If `body` is not a request.
    pub fn code(&self, body: &str, id: ApprovalId) -> String {
        let domain: Value = serde_json::from_str(body).expect("a JSON body");
        crate::approval::code(
            domain["plan"]["domain"].as_str().expect("a domain"),
            &ROOT_SHA256,
            &Sha256::digest(body.as_bytes()).into(),
            self.0.public_key().as_ref(),
            id,
        )
    }

    /// The collect body: the signature of the nonce of `ticket`.
    ///
    /// # Panics
    ///
    /// If the nonce is not base64url or signing fails.
    pub fn collect(&self, ticket: &ApprovalTicket) -> String {
        let nonce = URL_SAFE_NO_PAD.decode(&ticket.nonce).expect("a nonce");
        let message = crate::approval::collect_message(ticket.id, &nonce);
        let signature = self
            .0
            .sign(&SystemRandom::new(), &message)
            .expect("a signature");
        json!({ "signature": URL_SAFE_NO_PAD.encode(signature.as_ref()) }).to_string()
    }
}

impl TestEnv {
    /// A delegated session of the administrator of `admin` (a fresh session's context) for
    /// `script`'s reference request: request, approve and collect at the service, from
    /// `source`, the only address the session is then accepted from.
    ///
    /// # Errors
    ///
    /// The first step's refusal.
    pub async fn delegate(
        &self,
        admin: &RequestCtx,
        script: &Script,
        source: std::net::IpAddr,
    ) -> Result<DelegatedSession, AuthError> {
        self.delegate_for(admin, script, source, &plan()).await
    }

    /// As [`TestEnv::delegate`], for `plan`.
    ///
    /// # Errors
    ///
    /// The first step's refusal.
    pub async fn delegate_for(
        &self,
        admin: &RequestCtx,
        script: &Script,
        source: std::net::IpAddr,
        plan: &Value,
    ) -> Result<DelegatedSession, AuthError> {
        let body = script.request_for(plan);
        let from = self.public_ctx().with_source_ip(source);
        let ticket = self
            .service
            .request_approval(&from, body.as_bytes())
            .await?;
        let code = SecretString::new(script.code(&body, ticket.id));
        self.service
            .approve(admin, ticket.id, &code, &ROOT_SHA256)
            .await?;
        self.service
            .collect_approval(&from, ticket.id, script.collect(&ticket).as_bytes())
            .await
    }
}
