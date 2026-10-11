//! `list`: a full listing of hosts (and addresses) as an administrator and as scoped
//! principals, through the router, with the two sides interleaved per iteration.

use std::time::Instant;

use anyhow::{Result, ensure};
use serde::Serialize;
use tenko_auth::roles::RoleName;
use tenko_core::{Action, AnchorMode, ObjectKind, ObjectRef, PrefixId};

use crate::{
    ListArgs,
    common::{self, median, quantile, round1},
    env::{self, principal_of},
    world,
};

#[derive(Debug, Serialize)]
struct Series {
    path: &'static str,
    unscoped_ms: Vec<f64>,
    scoped_ms: Vec<f64>,
    unscoped_items: usize,
    scoped_items: usize,
    pages_unscoped: usize,
    pages_scoped: usize,
    unscoped_median: f64,
    unscoped_p95: f64,
    scoped_median: f64,
    scoped_p95: f64,
    ratio_median: f64,
    ratio_p95: f64,
}

#[derive(Debug, Serialize)]
struct Case {
    label: String,
    grants: usize,
    coverage_percent: f64,
    series: Vec<Series>,
    profile: Profile,
}

/// Microseconds the scope machinery costs for one pass over all hosts, outside the router.
#[derive(Debug, Serialize)]
struct Profile {
    hosts: usize,
    scope_lookup_us: f64,
    anchors_total_ms: f64,
    anchors_per_host_us: f64,
    admits_total_ms: f64,
    admits_per_host_us: f64,
    admitted: usize,
}

#[derive(Debug, Serialize)]
struct Report {
    machine: common::Machine,
    store: String,
    hosts: usize,
    leaves: usize,
    iterations: usize,
    loadavg_start: String,
    loadavg_end: String,
    setup_secs: f64,
    cases: Vec<Case>,
}

async fn timed(
    router: &axum::Router,
    admin: &str,
    scoped: &str,
    path: &'static str,
    args: &ListArgs,
) -> Result<Series> {
    let (mut unscoped, mut scoped_ms) = (Vec::new(), Vec::new());
    let (mut u_items, mut s_items, mut u_pages, mut s_pages) = (0, 0, 0, 0);
    for round in 0..args.warmup + args.iterations {
        // Alternate which side goes first so that neither one always follows the other.
        let order = if round % 2 == 0 {
            [false, true]
        } else {
            [true, false]
        };
        for is_scoped in order {
            let secret = if is_scoped { scoped } else { admin };
            let started = Instant::now();
            let (items, pages) = world::list_all(router, secret, path, args.limit).await?;
            let ms = started.elapsed().as_secs_f64() * 1000.0;
            if is_scoped {
                (s_items, s_pages) = (items, pages);
            } else {
                (u_items, u_pages) = (items, pages);
            }
            if round >= args.warmup {
                if is_scoped {
                    scoped_ms.push(ms);
                } else {
                    unscoped.push(ms);
                }
            }
        }
    }
    let (um, sm) = (median(&unscoped), median(&scoped_ms));
    let (up, sp) = (quantile(&unscoped, 0.95), quantile(&scoped_ms, 0.95));
    Ok(Series {
        path,
        unscoped_median: um,
        unscoped_p95: up,
        scoped_median: sm,
        scoped_p95: sp,
        ratio_median: sm / um,
        ratio_p95: sp / up,
        unscoped_ms: unscoped,
        scoped_ms,
        unscoped_items: u_items,
        scoped_items: s_items,
        pages_unscoped: u_pages,
        pages_scoped: s_pages,
    })
}

async fn profile(stack: &env::Stack, secret: &str, hosts: &[ObjectRef]) -> Result<Profile> {
    let principal = principal_of(&stack.auth, secret).await?;
    let authorizer = stack.auth.authorizer();
    let started = Instant::now();
    let rounds = 1000;
    let mut scope = authorizer.scope(&principal, Action::Read, ObjectKind::Host);
    for _ in 0..rounds {
        scope = authorizer.scope(&principal, Action::Read, ObjectKind::Host);
    }
    let scope_lookup_us = started.elapsed().as_secs_f64() * 1e6 / f64::from(rounds + 1);
    let started = Instant::now();
    let anchors: Vec<_> = hosts.iter().map(|host| stack.scope.anchors(host)).collect();
    let anchors_total = started.elapsed().as_secs_f64() * 1000.0;
    let started = Instant::now();
    let admitted = anchors
        .iter()
        .filter(|anchors| scope.admits(anchors, AnchorMode::Any))
        .count();
    let admits_total = started.elapsed().as_secs_f64() * 1000.0;
    let n = hosts.len() as f64;
    Ok(Profile {
        hosts: hosts.len(),
        scope_lookup_us,
        anchors_total_ms: anchors_total,
        anchors_per_host_us: anchors_total * 1000.0 / n,
        admits_total_ms: admits_total,
        admits_per_host_us: admits_total * 1000.0 / n,
        admitted,
    })
}

pub async fn run(args: ListArgs) -> Result<()> {
    let loadavg_start = world::loadavg();
    let started = Instant::now();
    let (stack, dataset) = world::prepare(&args.tree).await?;
    let hosts: Vec<ObjectRef> = dataset
        .hosts
        .iter()
        .flatten()
        .map(|id| ObjectRef::new(ObjectKind::Host, id.uuid()))
        .collect();
    println!(
        "store {}: {} hosts, {} leaf prefixes, loaded in {:.1} s",
        args.tree.store.describe(),
        hosts.len(),
        dataset.leaves.len(),
        dataset.load_secs
    );

    let n = args.tree.grants;
    let step = (dataset.leaves.len() / n.max(1)).max(1);
    let few: Vec<PrefixId> = dataset
        .leaves
        .iter()
        .copied()
        .step_by(step)
        .take(n)
        .collect();
    let half: Vec<PrefixId> = dataset.mids.iter().copied().step_by(2).take(n).collect();
    let mut all: Vec<PrefixId> = vec![dataset.supernet];
    all.extend(dataset.leaves.iter().copied().take(n.saturating_sub(1)));
    let plans = [
        (
            "about 10% (50 leaf prefixes, operator)",
            RoleName::Operator,
            few,
        ),
        (
            "about 50% (50 of 100 /56 prefixes, viewer)",
            RoleName::Viewer,
            half,
        ),
        (
            "100% (supernet plus 49 leaves, operator)",
            RoleName::Operator,
            all,
        ),
    ];
    let mut principals = Vec::new();
    for (number, (label, role, grants)) in plans.iter().enumerate() {
        principals.push(world::scoped(&stack, number + 1, label, *role, grants).await?);
    }
    let api = env::build_api(&stack);
    let setup_secs = started.elapsed().as_secs_f64();
    println!("setup {setup_secs:.1} s, load average {}", world::loadavg());

    let mut cases = Vec::new();
    for scoped in &principals {
        println!("case: {}", scoped.label);
        let mut series = Vec::new();
        for path in ["/api/v1/hosts", "/api/v1/addresses"] {
            let s = timed(
                &api.router,
                &stack.admin_secret,
                &scoped.secret,
                path,
                &args,
            )
            .await?;
            ensure!(
                s.unscoped_items == hosts.len(),
                "{path}: the administrator saw {} items",
                s.unscoped_items
            );
            println!(
                "  {path}: unscoped median {:.1} ms p95 {:.1} ms ({} items); scoped median {:.1} ms p95 {:.1} ms ({} items, {} pages); ratio median {:.2} p95 {:.2}",
                s.unscoped_median,
                s.unscoped_p95,
                s.unscoped_items,
                s.scoped_median,
                s.scoped_p95,
                s.scoped_items,
                s.pages_scoped,
                s.ratio_median,
                s.ratio_p95
            );
            series.push(s);
        }
        let coverage = series[0].scoped_items as f64 * 100.0 / hosts.len() as f64;
        let p = profile(&stack, &scoped.secret, &hosts).await?;
        println!("  profile: {p:?}");
        cases.push(Case {
            label: scoped.label.clone(),
            grants: scoped.grants,
            coverage_percent: round1(coverage),
            series,
            profile: p,
        });
    }
    let report = Report {
        machine: common::machine(),
        store: args.tree.store.describe().to_owned(),
        hosts: hosts.len(),
        leaves: dataset.leaves.len(),
        iterations: args.iterations,
        loadavg_start,
        loadavg_end: world::loadavg(),
        setup_secs,
        cases,
    };
    if let Some(out) = &args.tree.out {
        std::fs::write(out, serde_json::to_string_pretty(&report)?)?;
    }
    Ok(())
}
