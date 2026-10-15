//! The quick cost check of the traces (OPS-05, `docs/observability.md` section 8.7): 2,000
//! `GET /api/v1/prefixes` from one client in sequence against a fresh server with the
//! endpoint set (the test collector on loopback) and without, printing the p99 of
//! `tenko_http_request_duration_seconds{class="prefixes"}` and the CPU time of the server
//! process over the requests. A measurement, not a test: it asserts nothing about the
//! numbers and runs only when asked for:
//!
//! ```sh
//! cargo nextest run -p tenko --test serve_telemetry_cost --run-ignored only --no-capture
//! ```

mod serve_support;

use serve_support::{Node, api::Api, otlp::Receiver, wait_for_setup_token};

const REQUESTS: usize = 2_000;

/// The CPU time of process `pid` in milliseconds (user and kernel).
fn cpu_ms(pid: u32) -> f64 {
    let output = if cfg!(windows) {
        std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!("(Get-Process -Id {pid}).TotalProcessorTime.TotalMilliseconds"),
            ])
            .output()
    } else {
        std::process::Command::new("sh")
            .args(["-c", &format!("cut -d' ' -f14,15 /proc/{pid}/stat")])
            .output()
    };
    let text = String::from_utf8_lossy(&output.expect("the CPU time").stdout).into_owned();
    if cfg!(windows) {
        text.trim().replace(',', ".").parse().expect("milliseconds")
    } else {
        // Clock ticks, 100 per second on Linux.
        text.split_whitespace()
            .map(|ticks| ticks.parse::<f64>().expect("ticks") * 10.0)
            .sum()
    }
}

/// The p99 in milliseconds of the histogram class `class` in the text of the metrics,
/// interpolated inside its bucket.
fn p99_ms(text: &str, class: &str) -> f64 {
    let prefix = format!("tenko_http_request_duration_seconds_bucket{{class=\"{class}\",le=\"");
    let buckets: Vec<(f64, f64)> = text
        .lines()
        .filter_map(|line| line.strip_prefix(&prefix))
        .filter_map(|rest| {
            let (le, count) = rest.split_once("\"} ")?;
            let le = if le == "+Inf" {
                f64::INFINITY
            } else {
                le.parse().ok()?
            };
            Some((le, count.trim().parse().ok()?))
        })
        .collect();
    let total = buckets.last().map_or(0.0, |(_, count)| *count);
    let rank = total * 0.99;
    let mut previous = (0.0, 0.0);
    for (le, count) in buckets {
        if count >= rank {
            let upper = if le.is_finite() { le } else { previous.0 };
            let share = if count > previous.1 {
                (rank - previous.1) / (count - previous.1)
            } else {
                1.0
            };
            return (previous.0 + (upper - previous.0) * share) * 1000.0;
        }
        previous = (le, count);
    }
    f64::NAN
}

fn measure(config: Option<&str>) -> (f64, f64) {
    // One client sends faster than the rate limit of one address allows.
    let mut node = Node::new().with_config("[rate_limit]\nenabled = false\n");
    if let Some(config) = config {
        node = node.with_config(config);
    }
    let mut server = node.start();
    let token = wait_for_setup_token(&server);
    let mut api = Api::new(&node);
    api.setup(&token);
    let before = cpu_ms(server.id());
    for _ in 0..REQUESTS {
        api.get("/prefixes").expect(200);
    }
    let cpu = cpu_ms(server.id()) - before;
    let metrics = api.get("/metrics");
    assert_eq!(metrics.status, 200, "{}", metrics.text);
    let text = metrics.text;
    server.stop().assert_graceful_shutdown();
    (p99_ms(&text, "prefixes"), cpu)
}

#[test]
#[ignore = "a measurement; run it with --run-ignored only"]
fn trace_cost_of_two_thousand_reads() {
    let receiver = Receiver::start();
    let (p99_off, cpu_off) = measure(None);
    let (p99_on, cpu_on) = measure(Some(&receiver.config(1.0)));
    println!("traces off: p99 {p99_off:.3} ms, server CPU {cpu_off:.0} ms over {REQUESTS} reads");
    println!("traces on:  p99 {p99_on:.3} ms, server CPU {cpu_on:.0} ms over {REQUESTS} reads");
    println!("spans received: {:?}", receiver.counts());
}
