//! `sse`: the CPU cost of the scoped event filter for 1,000 subscribers at 100 events per
//! second, measured in two ways: `select` calls on the filter alone, and real event streams
//! through the router and the event hub.

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Result, bail, ensure};
use axum::{
    body::Body,
    http::{Request, header},
};
use futures::StreamExt as _;
use serde::Serialize;
use tenko_api::sse::{EventFilter as _, Topic, filter::ScopedEvents};
use tenko_auth::roles::RoleName;
use tenko_core::{ObjectKind, ObjectRef, Principal};
use tenko_ipam::{
    IpamCommand, PlanOptions,
    command::{HostPatch, UpdateHost},
};
use tokio::time::{MissedTickBehavior, interval, sleep};
use tower::ServiceExt as _;

use crate::{
    SseArgs,
    common::{self, CpuClock, Rng, round1},
    env::{self, Stack, principal_of},
    world,
};

#[derive(Debug, Serialize)]
struct Row {
    label: String,
    subscribers: usize,
    events: u64,
    wall_secs: f64,
    achieved_events_per_sec: f64,
    cpu_secs: f64,
    cores: f64,
    delivered: u64,
    resets: u64,
    streams_ended: u64,
    slowest_publish_ms: f64,
    loadavg: String,
    frames_published: u64,
}

#[derive(Debug, Serialize)]
struct Report {
    machine: common::Machine,
    principals: usize,
    grants_each: usize,
    rows: Vec<Row>,
}

/// The filter alone: `subscribers` calls of `select` per event, no router, no hub.
async fn direct(
    stack: &Stack,
    hosts: &[ObjectRef],
    principals: &[Principal],
    args: &SseArgs,
    scoped: bool,
) -> Result<Row> {
    let filter = ScopedEvents::new(
        stack.auth.authorizer(),
        Arc::clone(&stack.scope),
        Arc::clone(&stack.store),
    );
    let admin = principal_of(&stack.auth, &stack.admin_secret).await?;
    let mut rng = Rng::new(7);
    let events = args.seconds * args.rate;
    let mut tick = interval(Duration::from_micros(1_000_000 / args.rate));
    tick.set_missed_tick_behavior(MissedTickBehavior::Burst);
    let mut clock = CpuClock::new();
    let (mut delivered, mut slowest) = (0_u64, 0.0_f64);
    let cpu0 = clock.cpu_ms();
    let started = Instant::now();
    for _ in 0..events {
        tick.tick().await;
        let object = [hosts[rng.below(hosts.len())]];
        let at = Instant::now();
        for subscriber in 0..args.subscribers {
            let principal = if scoped {
                &principals[subscriber % principals.len()]
            } else {
                &admin
            };
            if !matches!(
                filter.select(principal, Topic::Ipam, &object),
                tenko_api::sse::Admission::None
            ) {
                delivered += 1;
            }
        }
        slowest = slowest.max(at.elapsed().as_secs_f64() * 1000.0);
    }
    let wall = started.elapsed().as_secs_f64();
    let cpu = (clock.cpu_ms() - cpu0) as f64 / 1000.0;
    Ok(Row {
        label: format!(
            "filter only: select() x {} per event, {}",
            args.subscribers,
            if scoped {
                "scoped principals"
            } else {
                "administrator"
            }
        ),
        subscribers: args.subscribers,
        events,
        wall_secs: wall,
        achieved_events_per_sec: events as f64 / wall,
        cpu_secs: cpu,
        cores: cpu / wall,
        delivered,
        resets: 0,
        streams_ended: 0,
        slowest_publish_ms: slowest,
        loadavg: world::loadavg(),
        frames_published: 0,
    })
}

/// Counts the `event: ` fields of a chunk: the hub writes every frame that is ready for a
/// subscriber in one chunk, so a chunk can hold several events.
fn count_events(chunk: &[u8]) -> (u64, u64) {
    let (mut events, mut resets) = (0, 0);
    for (at, window) in chunk.windows(7).enumerate() {
        if window == b"event: " {
            if chunk[at + 7..].starts_with(b"reset") {
                resets += 1;
            } else {
                events += 1;
            }
        }
    }
    (events, resets)
}

/// Real streams: `subscribers` GET /api/v1/events?topics=ipam through the router, shared
/// sessions round robin, and `rate` `UpdateHost` commands per second from the administrator.
async fn streams(
    stack: &Stack,
    hosts: &[ObjectRef],
    secrets: &[String],
    subscribers: usize,
    args: &SseArgs,
    label: &str,
) -> Result<Row> {
    let api = env::build_api(stack);
    let hub = api.hub();
    let feeder = env::spawn_feeder(hub.clone(), &stack.store)?;
    let delivered = Arc::new(AtomicU64::new(0));
    let resets = Arc::new(AtomicU64::new(0));
    let ended = Arc::new(AtomicU64::new(0));
    let mut tasks = Vec::new();
    for i in 0..subscribers {
        let request = Request::builder()
            .uri("/api/v1/events?topics=ipam")
            .header(
                header::COOKIE,
                format!("tenko_session={}", secrets[i % secrets.len()]),
            )
            .body(Body::empty())?;
        let response = api.router.clone().oneshot(request).await?;
        ensure!(
            response.status().is_success(),
            "events: {}",
            response.status()
        );
        let mut body = response.into_body().into_data_stream();
        let (delivered, resets, ended) = (
            Arc::clone(&delivered),
            Arc::clone(&resets),
            Arc::clone(&ended),
        );
        tasks.push(tokio::spawn(async move {
            while let Some(Ok(chunk)) = body.next().await {
                if chunk.first() == Some(&b':') {
                    continue;
                }
                let (events, reset) = count_events(&chunk);
                delivered.fetch_add(events, Ordering::Relaxed);
                resets.fetch_add(reset, Ordering::Relaxed);
            }
            ended.fetch_add(1, Ordering::Relaxed);
        }));
    }
    for _ in 0..100 {
        if hub.subscribers() == subscribers {
            break;
        }
        sleep(Duration::from_millis(100)).await;
    }
    ensure!(
        hub.subscribers() == subscribers,
        "{} subscribers registered",
        hub.subscribers()
    );
    // Settle: the replay and the first frames of every stream are not part of the window.
    sleep(Duration::from_secs(2)).await;
    let (d0, r0) = (
        delivered.load(Ordering::Relaxed),
        resets.load(Ordering::Relaxed),
    );

    let events = args.seconds * args.rate;
    // A text no earlier run wrote: a command that changes nothing commits nothing.
    let run = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    let mut rng = Rng::new(11);
    let mut tick = interval(Duration::from_micros(1_000_000 / args.rate));
    tick.set_missed_tick_behavior(MissedTickBehavior::Burst);
    let mut clock = CpuClock::new();
    let mut slowest = 0.0_f64;
    let cpu0 = clock.cpu_ms();
    let started = Instant::now();
    for n in 0..events {
        tick.tick().await;
        let host = hosts[rng.below(hosts.len())];
        let command = IpamCommand::UpdateHost(UpdateHost {
            id: tenko_core::HostId::from_uuid(host.id),
            expected: None,
            patch: HostPatch {
                description: Some(Some(format!("m13 {run} event {n}"))),
                ..HostPatch::default()
            },
        });
        let at = Instant::now();
        stack
            .ipam
            .execute(&[command], &stack.admin, &PlanOptions::default())
            .await
            .map_err(|error| anyhow::anyhow!("update host: {error:?}"))?;
        slowest = slowest.max(at.elapsed().as_secs_f64() * 1000.0);
    }
    let wall = started.elapsed().as_secs_f64();
    let cpu = (clock.cpu_ms() - cpu0) as f64 / 1000.0;
    let loadavg = world::loadavg();
    // Let the hub finish the last frames before counting them (not part of the CPU window).
    sleep(Duration::from_secs(2)).await;
    let row = Row {
        label: label.to_owned(),
        subscribers,
        events,
        wall_secs: wall,
        achieved_events_per_sec: events as f64 / wall,
        cpu_secs: cpu,
        cores: cpu / wall,
        delivered: delivered.load(Ordering::Relaxed) - d0,
        resets: resets.load(Ordering::Relaxed) - r0,
        streams_ended: ended.load(Ordering::Relaxed),
        slowest_publish_ms: slowest,
        loadavg,
        frames_published: hub.published(),
    };
    if hub.published() == 0 {
        bail!("the hub published nothing");
    }
    for task in &tasks {
        task.abort();
    }
    feeder.abort();
    Ok(row)
}

pub async fn run(args: SseArgs) -> Result<()> {
    println!("load average at start {}", world::loadavg());
    let (stack, dataset) = world::prepare(&args.tree).await?;
    let hosts: Vec<ObjectRef> = dataset
        .hosts
        .iter()
        .flatten()
        .map(|id| ObjectRef::new(ObjectKind::Host, id.uuid()))
        .collect();
    // `principals` users, each with `grants` grants on a random half-ish sample of the /56
    // prefixes (50 of 100 by default): about half of the events concern a covered host.
    let mut rng = Rng::new(3);
    let mut secrets = Vec::new();
    for number in 0..args.principals {
        let picks = rng.sample(dataset.mids.len(), args.tree.grants);
        let grants: Vec<_> = picks.iter().map(|&i| dataset.mids[i]).collect();
        let scoped = world::scoped(&stack, number + 1, "sse", RoleName::Viewer, &grants).await?;
        secrets.push(scoped.secret);
    }
    let mut principals = Vec::new();
    for secret in &secrets {
        principals.push(principal_of(&stack.auth, secret).await?);
    }
    println!(
        "{} principals with {} grants each ready",
        secrets.len(),
        args.tree.grants
    );

    let mut rows = Vec::new();
    let admin = vec![stack.admin_secret.clone()];
    for scoped in [false, true] {
        let row = direct(&stack, &hosts, &principals, &args, scoped).await?;
        println!("{row:?}");
        rows.push(row);
    }
    let plan: [(&str, usize, &[String]); 3] = [
        ("hub, no subscribers (publisher and feeder only)", 0, &admin),
        (
            "hub, administrator streams (no filtering work)",
            args.subscribers,
            &admin,
        ),
        ("hub, scoped streams", args.subscribers, &secrets),
    ];
    for (label, subscribers, secrets) in plan {
        let row = streams(&stack, &hosts, secrets, subscribers, &args, label).await?;
        println!("{row:?}");
        rows.push(row);
    }
    for row in &mut rows {
        row.cores = (row.cores * 1000.0).round() / 1000.0;
        row.wall_secs = round1(row.wall_secs);
    }
    let report = Report {
        machine: common::machine(),
        principals: args.principals,
        grants_each: args.tree.grants,
        rows,
    };
    if let Some(out) = &args.tree.out {
        std::fs::write(out, serde_json::to_string_pretty(&report)?)?;
    }
    Ok(())
}
