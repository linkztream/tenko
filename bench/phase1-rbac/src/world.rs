//! Setup shared by the subcommands: the stack with the synthetic tree, scoped principals,
//! HTTP calls through the router and the machine load.

use std::fmt::Write as _;

use anyhow::{Context as _, Result, bail};
use axum::{
    Router,
    body::Body,
    http::{Request, header},
};
use serde::Deserialize;
use tenko_auth::roles::RoleName;
use tenko_core::PrefixId;
use tower::ServiceExt as _;

use crate::{
    TreeArgs,
    data::{self, Dataset},
    env::{self, Stack},
};

/// Builds the stack and loads the tree.
pub async fn prepare(tree: &TreeArgs) -> Result<(Stack, Dataset)> {
    let stack = env::build_stack(tree.store, &tree.data_dir).await?;
    let dataset = data::load(
        &stack.ipam,
        &stack.admin,
        tree.mids,
        tree.leaves_per_mid,
        tree.hosts_per_leaf,
    )
    .await?;
    Ok((stack, dataset))
}

/// A scoped principal: its user name and the secret of one session.
#[derive(Debug, Clone)]
pub struct Scoped {
    pub label: String,
    pub grants: usize,
    pub secret: String,
}

/// Creates an operator-like user holding `role` on each of `grants` (with subtree) and signs
/// it in once.
pub async fn scoped(
    stack: &Stack,
    number: usize,
    label: &str,
    role: RoleName,
    grants: &[PrefixId],
) -> Result<Scoped> {
    let name = format!("user{number:03}");
    let passphrase = env::passphrase(number);
    env::create_operator(stack, &name, &passphrase, role, grants).await?;
    let secret = env::login(&stack.auth, &name, &passphrase).await?;
    Ok(Scoped {
        label: label.to_owned(),
        grants: grants.len(),
        secret,
    })
}

/// A page of a list answer: only what the timing loop needs.
#[derive(Debug, Deserialize)]
struct PageOut {
    items: Vec<serde::de::IgnoredAny>,
    next_cursor: Option<String>,
}

/// Percent-encodes a query value.
fn encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

/// Reads all pages of `path` (`/api/v1/hosts`) with the session `secret`, `limit` items per
/// page, through the router. Returns the number of items and pages.
pub async fn list_all(
    router: &Router,
    secret: &str,
    path: &str,
    limit: usize,
) -> Result<(usize, usize)> {
    let (mut items, mut pages) = (0, 0);
    let mut cursor: Option<String> = None;
    loop {
        let mut uri = format!("{path}?limit={limit}");
        if let Some(cursor) = &cursor {
            uri.push_str("&cursor=");
            uri.push_str(&encode(cursor));
        }
        let request = Request::builder()
            .uri(&uri)
            .header(header::COOKIE, format!("tenko_session={secret}"))
            .body(Body::empty())?;
        let response = router.clone().oneshot(request).await?;
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        if !status.is_success() {
            bail!("GET {uri}: {status}: {}", String::from_utf8_lossy(&body));
        }
        let page: PageOut = serde_json::from_slice(&body).with_context(|| format!("GET {uri}"))?;
        items += page.items.len();
        pages += 1;
        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => return Ok((items, pages)),
        }
    }
}

/// The 1, 5 and 15 minute load averages as the kernel reports them.
pub fn loadavg() -> String {
    std::fs::read_to_string("/proc/loadavg").map_or_else(
        |_| "unknown".to_owned(),
        |text| {
            text.split_whitespace()
                .take(3)
                .collect::<Vec<_>>()
                .join(" ")
        },
    )
}
