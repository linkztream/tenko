//! The quick cluster signal of every push (WP3.1c): a cluster of real `tenko serve`
//! processes grows from one controller to three through `tenko cluster join`, the leader
//! promotes both learners together, a write on a follower is read on every member and the
//! state digests agree. Also the unit tests of the lab's fault proxy, which an integration
//! test helper module cannot hold itself.

mod cluster_support;
mod serve_support;

use std::{
    io::{Read, Write},
    net::{Shutdown, TcpStream},
    thread,
    time::{Duration, Instant},
};

use cluster_support::{ClusterLab, Echo, Fault, Relay, learners, voters};
use serde_json::json;

/// The whole grow scenario, including the build-up of the lab.
const GROW_LIMIT: Duration = Duration::from_secs(170);

#[test]
fn a_cluster_grows_from_one_controller_to_three() {
    let begun = Instant::now();
    let mut lab = ClusterLab::start(1);
    assert_eq!(lab.quorum(1).as_deref(), Some("single"));
    let single = lab.members(1).expect("the members view");
    assert_eq!(voters(&single), vec![1], "{single}");

    // The first join: a learner, and the leader waits for a second one.
    let second = lab.add_controller();
    let first_join = lab.last_join_time().expect("a join");
    let view = lab.wait_until(
        "the first joined controller as a learner",
        Duration::from_secs(60),
        || {
            let view = lab.members(1)?;
            (learners(&view) == vec![second]).then_some(view)
        },
    );
    assert_eq!(
        voters(&view),
        vec![1],
        "one voter and one learner stay so: {view}"
    );

    // The second join: both learners become voters together.
    let third = lab.add_controller();
    let view = lab.wait_for_members(3);
    let mut all = voters(&view);
    all.sort_unstable();
    let mut expected = vec![1, second, third];
    expected.sort_unstable();
    assert_eq!(all, expected, "three voters: {view}");
    assert!(learners(&view).is_empty(), "{view}");
    let grown = begun.elapsed();

    // A write on a follower is read on every member.
    let leader = lab.leader();
    let follower = lab.followers()[0];
    let api = lab.api(follower);
    api.post("/prefixes", &json!({ "cidr": "198.51.100.0/24" }))
        .expect(201);
    let created = api
        .post(
            "/addresses",
            &json!({ "ip": "198.51.100.10", "description": "written on a follower" }),
        )
        .expect(201);
    let id = created["item"]["id"].as_str().expect("an id").to_owned();
    let revision = created["revision"].as_u64().expect("a revision");
    // Read-your-writes on the follower that answered.
    let own = api.get(&format!("/addresses/{id}")).expect(200);
    assert_eq!(own["meta"]["description"], "written on a follower", "{own}");
    for member in lab.ids() {
        let read = lab
            .api(member)
            .get(&format!("/addresses/{id}?at_least={revision}"))
            .expect(200);
        assert_eq!(
            read["meta"]["description"], "written on a follower",
            "controller {member}: {read}"
        );
    }

    let agreement = lab.digests_agree(revision);
    assert_eq!(agreement.members.len(), 3);
    let total = begun.elapsed();
    println!(
        "grow 1 to 3: first join {first_join:?}, three voters after {grown:?}, \
         leader {leader}, digests agree at revision {} after {total:?}",
        agreement.revision
    );
    assert!(
        total < GROW_LIMIT,
        "the grow scenario took {total:?}, more than its budget of {GROW_LIMIT:?}"
    );
}

/// Writes to `stream` until a write fails; the number of bytes written.
fn write_until_failure(mut stream: TcpStream, limit: Duration) -> (usize, bool) {
    let chunk = [7_u8; 4096];
    let deadline = Instant::now() + limit;
    let mut written = 0;
    while Instant::now() < deadline {
        match stream.write(&chunk) {
            Ok(count) => written += count,
            Err(_) => return (written, true),
        }
    }
    (written, false)
}

#[test]
fn a_cut_relay_closes_a_streaming_connection_and_refuses_new_ones() {
    let echo = Echo::start();
    let relay = Relay::start(echo.addr());
    let stream = TcpStream::connect(relay.addr()).expect("connect through the relay");
    let reader = stream.try_clone().expect("clone");
    // Drain the echoes so the echo server never blocks.
    let drain = thread::spawn(move || {
        let mut reader = reader;
        let mut buffer = vec![0_u8; 65536];
        let mut read = 0;
        while let Ok(count) = reader.read(&mut buffer) {
            if count == 0 {
                break;
            }
            read += count;
        }
        read
    });
    let writer = {
        let stream = stream.try_clone().expect("clone");
        thread::spawn(move || write_until_failure(stream, Duration::from_secs(20)))
    };
    thread::sleep(Duration::from_millis(300));
    assert_eq!(relay.open(), 1, "the streaming connection is open");
    let cut = Instant::now();
    relay.set(Fault::Cut);
    let (written, failed) = writer.join().expect("the writer");
    assert!(failed, "the writer kept writing through a cut relay");
    assert!(
        cut.elapsed() < Duration::from_secs(5),
        "the cut took {:?}",
        cut.elapsed()
    );
    let echoed = drain.join().expect("the reader");
    assert!(written > 0 && echoed > 0, "bytes flowed before the cut");
    let _ = stream.shutdown(Shutdown::Both);

    // A new connection is accepted and closed at once.
    let mut again = TcpStream::connect(relay.addr()).expect("the relay still listens");
    again
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("a timeout");
    let _ = again.write_all(b"ping");
    let mut buffer = [0_u8; 4];
    let answer = again.read(&mut buffer);
    assert!(
        matches!(answer, Ok(0) | Err(_)),
        "a cut relay answered: {answer:?}"
    );
    assert!(relay.refused() >= 1);

    // Back to pass: the link works again.
    relay.set(Fault::Pass);
    let mut healed = TcpStream::connect(relay.addr()).expect("connect");
    healed.write_all(b"ping").expect("write");
    let mut buffer = [0_u8; 4];
    healed.read_exact(&mut buffer).expect("the echo");
    assert_eq!(&buffer, b"ping");
}

#[test]
fn a_delayed_relay_holds_each_direction_for_the_delay() {
    let echo = Echo::start();
    let relay = Relay::start(echo.addr());
    let round_trip = |relay: &Relay| {
        let mut stream = TcpStream::connect(relay.addr()).expect("connect");
        stream.set_nodelay(true).expect("no delay");
        let mut buffer = [0_u8; 4];
        // The first exchange includes the relay's connect to the target.
        stream.write_all(b"warm").expect("write");
        stream.read_exact(&mut buffer).expect("echo");
        let begun = Instant::now();
        stream.write_all(b"ping").expect("write");
        stream.read_exact(&mut buffer).expect("echo");
        assert_eq!(&buffer, b"ping");
        begun.elapsed()
    };
    let plain = round_trip(&relay);
    relay.set(Fault::Delay(Duration::from_millis(150)));
    let delayed = round_trip(&relay);
    println!("round trip through the relay: {plain:?} plain, {delayed:?} with 150 ms each way");
    assert!(
        delayed >= Duration::from_millis(300),
        "a round trip with 150 ms each way took {delayed:?}"
    );
    assert!(
        delayed < Duration::from_millis(300) + plain + Duration::from_millis(400),
        "a round trip with 150 ms each way took {delayed:?} (plain {plain:?})"
    );
}

#[test]
fn a_dropping_relay_closes_new_connections_at_its_ratio() {
    let echo = Echo::start();
    let relay = Relay::start(echo.addr());
    relay.set(Fault::Drop(0.5));
    let total = 200;
    let mut served = 0;
    for _ in 0..total {
        let mut stream = TcpStream::connect(relay.addr()).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("a timeout");
        let mut buffer = [0_u8; 4];
        if stream.write_all(b"ping").is_ok()
            && stream.read_exact(&mut buffer).is_ok()
            && &buffer == b"ping"
        {
            served += 1;
        }
    }
    let dropped = total - served;
    println!(
        "drop 0.5 over {total} connections: {dropped} dropped, relay counted {}",
        relay.refused()
    );
    assert!(
        (80..=120).contains(&dropped),
        "{dropped} of {total} connections dropped at a ratio of 0.5"
    );
    assert_eq!(u64::try_from(dropped).expect("a count"), relay.refused());
}
