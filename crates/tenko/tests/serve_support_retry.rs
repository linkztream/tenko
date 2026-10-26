//! The start retry and the port picker of the test harness (`serve_support`), without a
//! server: a start that loses the race for its API port once is started again on a new
//! port, any other failure fails at once, and the picker hands out distinct ports below
//! the ephemeral ranges that can be bound.

mod serve_support;

use std::net::{TcpListener, UdpSocket};

use serve_support::{Outcome, START_ATTEMPTS, free_port, is_port_race, retry_on_bind};

/// What a server that exited during start leaves behind.
fn failed(stderr: &str) -> Outcome {
    Outcome {
        code: Some(4),
        stdout: String::new(),
        stderr: stderr.to_owned(),
    }
}

/// The failure of a lost port race, as `tenko serve` reports it.
const LOST_RACE: &str = "ERROR step 13/15 api failed: cannot listen on 127.0.0.1:42113: \
                         Address already in use (os error 98) step=\"api\" code=start.api.bind\n\
                         tenko serve: start step `api` failed [start.api.bind]: cannot listen";

#[test]
fn only_the_api_bind_failure_counts_as_a_lost_race() {
    assert!(is_port_race(LOST_RACE));
    assert!(!is_port_race(
        "tenko serve: start step `kek` failed [vault.kek_unavailable]: no usable key"
    ));
    assert!(!is_port_race(
        "tenko serve: start step `dns` failed [start.dns.bind]: cannot listen"
    ));
    assert!(!is_port_race(""));
}

#[test]
fn a_lost_race_is_started_again_on_a_new_port() {
    let mut port = 1000_u16;
    let mut repicks = 0;
    let started = retry_on_bind(
        &mut port,
        |port, attempt| {
            if attempt == 1 {
                assert_eq!(*port, 1000, "the first attempt uses the picked port");
                Err(failed(LOST_RACE))
            } else {
                assert_eq!(*port, 2000, "the second attempt uses the new port");
                Ok(format!("ready on {port} after {attempt} attempts"))
            }
        },
        |port| {
            repicks += 1;
            *port = 2000;
        },
    );
    assert_eq!(started, "ready on 2000 after 2 attempts");
    assert_eq!(repicks, 1);
}

#[test]
fn a_start_that_works_is_not_repeated() {
    let mut attempts = 0;
    let started = retry_on_bind(
        &mut attempts,
        |attempts, _| {
            *attempts += 1;
            Ok("ready")
        },
        |_| panic!("nothing to pick again"),
    );
    assert_eq!(started, "ready");
    assert_eq!(attempts, 1);
}

#[test]
#[should_panic(expected = "vault.kek_unavailable")]
fn any_other_failure_fails_at_once_with_the_output_of_the_server() {
    let mut attempts = 0;
    retry_on_bind::<_, ()>(
        &mut attempts,
        |attempts, _| {
            *attempts += 1;
            assert_eq!(*attempts, 1, "no second attempt after another failure");
            Err(failed(
                "tenko serve: start step `kek` failed [vault.kek_unavailable]: no usable key",
            ))
        },
        |_| panic!("nothing to pick again"),
    );
}

#[test]
#[should_panic(expected = "the API port was taken in all 3 attempts")]
fn a_port_that_is_lost_every_time_fails_after_the_last_attempt() {
    assert_eq!(START_ATTEMPTS, 3, "the message above names the count");
    let mut attempts = 0;
    retry_on_bind::<_, ()>(
        &mut attempts,
        |attempts, _| {
            *attempts += 1;
            Err(failed(LOST_RACE))
        },
        |_| {},
    );
}

#[test]
fn a_real_server_whose_port_is_taken_starts_on_another_one() {
    let mut node = serve_support::Node::new();
    let taken = node.port;
    let holder = TcpListener::bind(("127.0.0.1", taken)).expect("take the picked port");
    let mut server = node.start();
    assert_ne!(node.port, taken, "the node moved to another port");
    assert_eq!(node.get(serve_support::READY_PATH).expect("ready").0, 200);
    server.stop().assert_graceful_shutdown();
    drop(holder);
}

#[test]
fn free_ports_are_distinct_below_the_ephemeral_ranges_and_bindable() {
    let ports: Vec<u16> = (0..200).map(|_| free_port()).collect();
    let mut sorted = ports.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), ports.len(), "a port was handed out twice");
    for port in ports {
        assert!(
            (20_000..32_768).contains(&port),
            "{port} is in an ephemeral range"
        );
        TcpListener::bind(("127.0.0.1", port)).expect("a TCP port that can be bound");
        UdpSocket::bind(("127.0.0.1", port)).expect("a UDP port that can be bound");
    }
}
