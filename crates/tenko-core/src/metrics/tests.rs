//! Tests of the metrics core: exact sums across threads, stripe alignment, histogram
//! buckets, gauges and slots, the registry, and the encoder against a strict line checker.

use std::sync::Arc;

use super::*;

const LATENCY_BOUNDS: &[u64] = &[250, 500, 1_000, 2_500, 1_000_000];

#[test]
fn sharded_sums_are_exact_across_threads() {
    static FAMILY: CounterVec = CounterVec::new(
        Desc::counter("test_sharded_sums", "Sums across threads.").labels(&["series"]),
    );
    assert!(FAMILY.seal_with_shards(&[&["a"], &["b"], &["c"]], 4));
    assert_eq!(FAMILY.shards(), 4);
    let threads = 12_u64;
    let per_thread = 30_000_u64;
    let handles: Vec<_> = (0..threads)
        .map(|thread| {
            std::thread::spawn(move || {
                for i in 0..per_thread {
                    FAMILY.inc(u16::try_from(i % 3).expect("small"));
                    FAMILY.add(2, thread);
                }
            })
        })
        .collect();
    for handle in handles {
        handle.join().expect("worker");
    }
    let per_series = threads * per_thread / 3;
    assert_eq!(FAMILY.get(0), per_series);
    assert_eq!(FAMILY.get(1), per_series);
    let added: u64 = (0..threads).map(|thread| thread * per_thread).sum();
    assert_eq!(FAMILY.get(2), per_series + added);
    // An index the family does not have is dropped, not a panic.
    FAMILY.inc(3);
    assert_eq!(FAMILY.get(3), 0);
}

#[test]
fn the_default_shard_count_is_a_power_of_two_up_to_the_maximum() {
    static FAMILY: Counter = Counter::new(Desc::counter("test_default_shards", "Shards."));
    let shards = default_shards();
    assert!(shards.is_power_of_two());
    assert!((1..=MAX_SHARDS).contains(&shards));
    FAMILY.inc();
    assert_eq!(FAMILY.get(), 1);
    assert_eq!(FAMILY.shards(), shards);
}

#[test]
fn stripes_start_on_their_own_cache_lines() {
    static FAMILY: CounterVec =
        CounterVec::new(Desc::counter("test_stripes", "Stripes.").labels(&["series"]));
    let series: Vec<String> = (0..11).map(|i| i.to_string()).collect();
    let rows: Vec<[&str; 1]> = series.iter().map(|s| [s.as_str()]).collect();
    let rows: Vec<&[&str]> = rows.iter().map(<[&str; 1]>::as_slice).collect();
    FAMILY.seal_with_shards(&rows, 8);
    let addrs = FAMILY.stripe_addrs();
    assert_eq!(addrs.len(), 8);
    for pair in addrs.windows(2) {
        assert_eq!(pair[0] % 64, 0);
        // 11 series need two lines per stripe.
        assert_eq!(pair[1] - pair[0], 128);
    }
}

#[test]
fn sealing_twice_keeps_the_first_series() {
    static FAMILY: CounterVec =
        CounterVec::new(Desc::counter("test_seal_twice", "Sealed once.").labels(&["x"]));
    FAMILY.inc(0);
    assert_eq!(FAMILY.get(0), 0, "updates before sealing are dropped");
    assert!(FAMILY.seal(&[&["one"]]));
    assert!(!FAMILY.seal(&[&["one"], &["two"]]));
    assert_eq!(FAMILY.len(), 1);
}

#[test]
fn histogram_buckets_are_cumulative_and_inf_equals_the_count() {
    static FAMILY: HistogramVec = HistogramVec::new(
        Desc::histogram(
            "test_latency_seconds",
            "Latency.",
            LATENCY_BOUNDS,
            1_000_000,
        )
        .labels(&["class"]),
    );
    FAMILY.seal_with_shards(&[&["a"], &["b"]], 2);
    let values = [0, 250, 251, 999, 1_000, 2_600, 5_000_000, 7];
    let handles: Vec<_> = (0..4)
        .map(|_| {
            std::thread::spawn(move || {
                for value in values {
                    FAMILY.observe(0, value);
                }
            })
        })
        .collect();
    for handle in handles {
        handle.join().expect("worker");
    }
    let value = FAMILY.get(0);
    // 0, 250 and 7 fall into le=250; 251 into 500; 999 and 1000 into 1000; 2600 into
    // 1000000; 5000000 into +Inf. Four threads each.
    assert_eq!(value.buckets, vec![12, 16, 24, 24, 28, 32]);
    assert_eq!(value.count(), 32);
    assert_eq!(value.sum, 4 * values.iter().sum::<u64>());
    assert_eq!(FAMILY.get(1).count(), 0);
    assert!(value.buckets.windows(2).all(|pair| pair[0] <= pair[1]));
}

#[test]
fn a_gauge_round_trips_an_f64_and_can_be_unset() {
    static GAUGE: Gauge = Gauge::new(Desc::gauge("test_gauge", "A gauge."));
    static TOTAL: Gauge = Gauge::new(Desc::counter("test_mirrored", "A mirrored total."));
    assert_eq!(GAUGE.get(), None);
    for value in [
        0.0,
        -1.5,
        1e300,
        f64::MIN_POSITIVE,
        123_456.789,
        f64::INFINITY,
    ] {
        GAUGE.set(value);
        assert_eq!(GAUGE.get().map(f64::to_bits), Some(value.to_bits()));
    }
    GAUGE.set(f64::NAN);
    assert!(GAUGE.get().is_some_and(f64::is_nan));
    GAUGE.set(f64::from_bits(u64::MAX));
    assert!(
        GAUGE.get().is_some_and(f64::is_nan),
        "the unset pattern stays a NaN"
    );
    GAUGE.unset();
    assert_eq!(GAUGE.get(), None);

    TOTAL.set_total(41);
    assert_eq!(TOTAL.get(), Some(41.0));
    let mut series = Vec::new();
    TOTAL.collect(&mut series);
    assert_eq!(series[0].value, Value::Counter(41));
}

#[test]
fn slots_assign_label_sets_and_sweep_the_ones_not_seen() {
    static FAMILY: GaugeVec =
        GaugeVec::new(Desc::gauge("test_slots", "Slots.").labels(&["node", "state"]));
    assert!(!FAMILY.set_labels(&["1", "up"], 1.0), "not sealed yet");
    FAMILY.seal_slots(2);
    assert!(FAMILY.set_labels(&["1", "up"], 1.0));
    assert!(FAMILY.set_labels(&["2", "up"], 2.0));
    assert!(!FAMILY.set_labels(&["3", "up"], 3.0), "two slots only");
    assert!(
        FAMILY.set_labels(&["1", "up"], 1.5),
        "a known label set keeps its slot"
    );
    let collected = |family: &GaugeVec| {
        let mut series = Vec::new();
        family.collect(&mut series);
        series
            .into_iter()
            .map(|series| {
                let labels: Vec<String> = series.labels.iter().map(str::to_owned).collect();
                (labels.join("/"), series.value)
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(
        collected(&FAMILY),
        vec![
            ("1/up".to_owned(), Value::Gauge(1.5)),
            ("2/up".to_owned(), Value::Gauge(2.0)),
        ]
    );
    FAMILY.sweep();
    assert!(FAMILY.set_labels(&["2", "up"], 2.5));
    FAMILY.sweep();
    assert_eq!(
        collected(&FAMILY),
        vec![("2/up".to_owned(), Value::Gauge(2.5))]
    );
    assert!(
        FAMILY.set_labels(&["3", "up"], 3.0),
        "the freed slot is reused"
    );
    assert_eq!(collected(&FAMILY).len(), 2);
}

#[test]
fn a_state_gauge_has_exactly_one_series_at_one() {
    static ROLE: GaugeVec = GaugeVec::fixed(
        Desc::gauge("test_role", "Role.").labels(&["role"]),
        &[&["leader"], &["follower"], &["learner"]],
    );
    ROLE.set_one_of(0..3, 1);
    assert_eq!(ROLE.get(0), Some(0.0));
    assert_eq!(ROLE.get(1), Some(1.0));
    assert_eq!(ROLE.get(2), Some(0.0));
}

#[test]
fn the_registry_skips_a_family_registered_twice_and_keeps_the_order() {
    static A: Counter = Counter::new(Desc::counter("test_order_a", "A."));
    static B: Gauge = Gauge::new(Desc::gauge("test_order_b", "B."));
    let registry = Registry::new();
    assert!(registry.register(&B));
    assert!(registry.register(&A));
    assert!(!registry.register(&B));
    assert_eq!(registry.names(), vec!["test_order_b", "test_order_a"]);
    B.set(2.0);
    let snapshot = registry.snapshot();
    assert_eq!(snapshot.families.len(), 2);
    assert_eq!(
        snapshot.family("test_order_b").expect("b").series[0].value,
        Value::Gauge(2.0)
    );
    assert_eq!(
        snapshot.family("test_order_a").expect("a").series[0].value,
        Value::Counter(0)
    );
}

#[test]
fn a_sparse_family_leaves_zero_series_out() {
    static FAMILY: CounterVec =
        CounterVec::new(Desc::counter("test_sparse", "Sparse.").labels(&["route", "status"]))
            .sparse();
    FAMILY.seal(&[&["/a", "200"], &["/a", "404"], &["/b", "200"]]);
    FAMILY.inc(1);
    let mut series = Vec::new();
    FAMILY.collect(&mut series);
    assert_eq!(series.len(), 1);
    assert!(series[0].labels.matches(&["/a", "404"]));
}

#[test]
fn seconds_are_written_exactly() {
    let cases = [
        (250, 1_000_000, "0.00025"),
        (500, 1_000_000, "0.0005"),
        (1_000, 1_000_000, "0.001"),
        (2_500, 1_000_000, "0.0025"),
        (1_000_000, 1_000_000, "1.0"),
        (2_500_000, 1_000_000, "2.5"),
        (10_000_000, 1_000_000, "10.0"),
        (12_345_678, 1_000_000, "12.345678"),
        (0, 1_000_000, "0.0"),
        (7, 1, "7.0"),
        (1_500, 1_000, "1.5"),
    ];
    for (value, per_second, text) in cases {
        let mut out = String::new();
        encode::seconds(value, per_second, &mut out);
        assert_eq!(out, text, "{value} / {per_second}");
    }
}

#[test]
fn a_snapshot_serializes_with_its_descriptions_and_labels() {
    static FAMILY: CounterVec = CounterVec::fixed(
        Desc::counter("test_serialize", "Serialized.").labels(&["outcome"]),
        &[&["ok"]],
    );
    let registry = Registry::new();
    registry.register(&FAMILY);
    FAMILY.add(0, 3);
    let json = serde_json::to_value(registry.snapshot()).expect("serializes");
    let family = &json["families"][0];
    assert_eq!(family["desc"]["name"], "test_serialize");
    assert_eq!(family["desc"]["kind"]["type"], "counter");
    assert_eq!(family["desc"]["labels"][0], "outcome");
    assert_eq!(family["series"][0]["labels"][0], "ok");
    assert_eq!(family["series"][0]["value"]["counter"], 3);
}

/// A registry with one family of every kind, some values and awkward label values.
fn sample_registry() -> Registry {
    static REQUESTS: CounterVec = CounterVec::new(
        Desc::counter(
            "enc_requests",
            "Requests by \"route\".\nSecond line \\ end.",
        )
        .labels(&["route", "method"]),
    );
    static REPLAYS: Counter = Counter::new(Desc::counter("enc_replays", "Replays."));
    static LATENCY: HistogramVec = HistogramVec::new(
        Desc::histogram("enc_latency_seconds", "Latency.", LATENCY_BOUNDS, 1_000_000)
            .labels(&["class"]),
    );
    static SINGLE: Histogram = Histogram::new(Desc::histogram(
        "enc_single_seconds",
        "One.",
        &[1, 10],
        1_000,
    ));
    static BYTES: Gauge = Gauge::new(Desc::gauge("enc_data_bytes", "Bytes.").unit("bytes"));
    static ROLES: GaugeVec = GaugeVec::fixed(
        Desc::gauge("enc_role", "Role.").labels(&["role"]),
        &[&["leader"], &["follower"]],
    );
    static LAG: GaugeVec = GaugeVec::new(Desc::gauge("enc_lag_entries", "Lag.").labels(&["node"]));
    static EMPTY: GaugeVec = GaugeVec::new(Desc::gauge("enc_empty", "Never set."));

    REQUESTS.seal(&[
        &["/api/v1/health", "GET"],
        &["odd\"route\\with\nbreak", "OTHER"],
    ]);
    LATENCY.seal(&[&["auth"], &["prefixes"]]);
    LAG.seal_slots(4);
    let registry = Registry::new();
    for family in [
        &REQUESTS as &'static dyn Collect,
        &REPLAYS,
        &LATENCY,
        &SINGLE,
        &BYTES,
        &ROLES,
        &LAG,
        &EMPTY,
    ] {
        registry.register(family);
    }
    REQUESTS.add(0, 2);
    REQUESTS.inc(1);
    LATENCY.observe(0, 300);
    LATENCY.observe(0, 2_000_000);
    LATENCY.observe(1, 100);
    SINGLE.observe(5);
    BYTES.set(1_048_576.0);
    ROLES.set_one_of(0..2, 0);
    LAG.set_labels(&["2"], 0.0);
    LAG.set_labels(&["3"], f64::INFINITY);
    registry
}

#[test]
fn the_encoder_writes_openmetrics_that_a_strict_checker_accepts() {
    let registry = sample_registry();
    let mut text = String::new();
    encode(&registry.snapshot(), &mut text);
    check(&text).unwrap_or_else(|error| panic!("{error}\n{text}"));
    for line in [
        "# TYPE enc_requests counter\n",
        "# HELP enc_requests Requests by \\\"route\\\".\\nSecond line \\\\ end.\n",
        "enc_requests_total{route=\"/api/v1/health\",method=\"GET\"} 2\n",
        "enc_requests_total{route=\"odd\\\"route\\\\with\\nbreak\",method=\"OTHER\"} 1\n",
        "enc_replays_total 0\n",
        "# UNIT enc_latency_seconds seconds\n",
        "enc_latency_seconds_bucket{class=\"auth\",le=\"0.00025\"} 0\n",
        "enc_latency_seconds_bucket{class=\"auth\",le=\"0.0005\"} 1\n",
        "enc_latency_seconds_bucket{class=\"auth\",le=\"1.0\"} 1\n",
        "enc_latency_seconds_bucket{class=\"auth\",le=\"+Inf\"} 2\n",
        "enc_latency_seconds_sum{class=\"auth\"} 2.0003\n",
        "enc_latency_seconds_count{class=\"auth\"} 2\n",
        "enc_single_seconds_bucket{le=\"0.01\"} 1\n",
        "enc_single_seconds_sum 0.005\n",
        "# UNIT enc_data_bytes bytes\n",
        "enc_data_bytes 1048576\n",
        "enc_role{role=\"leader\"} 1\n",
        "enc_role{role=\"follower\"} 0\n",
        "enc_lag_entries{node=\"3\"} +Inf\n",
        "# TYPE enc_empty gauge\n",
    ] {
        assert!(text.contains(line), "missing {line:?} in\n{text}");
    }
    assert!(
        text.ends_with("enc_lag_entries{node=\"3\"} +Inf\n# HELP enc_empty Never set.\n# EOF\n")
            || text.ends_with("# EOF\n")
    );
}

#[test]
fn the_checker_refuses_broken_text() {
    let good = "# TYPE a counter\n# HELP a A.\na_total 1\n# EOF\n";
    check(good).expect("good text");
    for bad in [
        "# TYPE a counter\na_total 1\n",
        "a_total 1\n# EOF\n",
        "# TYPE a counter\na 1\n# EOF\n",
        "# TYPE a counter\na_total 1\na_total 2\n# EOF\n",
        "# TYPE a counter\na_total 1\n# TYPE a counter\n# EOF\n",
        "# TYPE h histogram\nh_bucket{le=\"1.0\"} 1\nh_bucket{le=\"0.5\"} 1\nh_bucket{le=\"+Inf\"} 1\nh_sum 1\nh_count 1\n# EOF\n",
        "# TYPE h histogram\nh_bucket{le=\"1.0\"} 1\nh_sum 1\nh_count 1\n# EOF\n",
        "# TYPE h histogram\nh_bucket{le=\"+Inf\"} 2\nh_sum 1\nh_count 1\n# EOF\n",
        "# TYPE g gauge\n# UNIT g bytes\ng 1\n# EOF\n",
        "# TYPE g gauge\ng{x=\"unterminated} 1\n# EOF\n",
        "# TYPE g gauge\ng one\n# EOF\n",
    ] {
        assert!(check(bad).is_err(), "accepted:\n{bad}");
    }
}

#[test]
fn labels_compare_and_serialize_in_order() {
    let owned = Labels::owned(&["a", "b"]);
    assert_eq!(owned.len(), 2);
    assert_eq!(owned.get(1), Some("b"));
    assert!(owned.matches(&["a", "b"]));
    assert!(!owned.matches(&["a"]));
    assert!(Labels::owned(&[]).is_empty());
    let shared = Arc::new(owned.clone());
    assert_eq!(*shared, owned);
    assert_eq!(
        serde_json::to_string(&owned).expect("serializes"),
        "[\"a\",\"b\"]"
    );
}
