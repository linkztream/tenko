//! Black-box test of the systemd integration (Linux only): under `Type=notify` the server
//! sends `READY=1` once the API listens and `STOPPING=1` when the shutdown begins, to the
//! datagram socket named by `NOTIFY_SOCKET`.

#![cfg(target_os = "linux")]

mod serve_support;

use std::{
    io::ErrorKind,
    os::unix::net::UnixDatagram,
    time::{Duration, Instant},
};

use serve_support::{Node, READY_PATH, READY_TIMEOUT, STOP_TIMEOUT, tenko};

/// Reads datagrams until one contains `wanted`; returns it. Other datagrams (`STATUS=`
/// only) are skipped.
#[track_caller]
fn receive_until(socket: &UnixDatagram, wanted: &str, timeout: Duration) -> String {
    let deadline = Instant::now() + timeout;
    let mut seen = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        let left = deadline
            .checked_duration_since(Instant::now())
            .unwrap_or_else(|| panic!("no `{wanted}` within {timeout:?}; received {seen:?}"));
        socket
            .set_read_timeout(Some(left.max(Duration::from_millis(1))))
            .expect("set the read timeout");
        match socket.recv(&mut buffer) {
            Ok(length) => {
                let message = String::from_utf8_lossy(&buffer[..length]).into_owned();
                if message.lines().any(|line| line == wanted) {
                    return message;
                }
                seen.push(message);
            }
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                panic!("no `{wanted}` within {timeout:?}; received {seen:?}")
            }
            Err(error) => panic!("receiving from the notify socket: {error}"),
        }
    }
}

/// Whether a datagram is waiting, within a short time.
fn datagram_pending(socket: &UnixDatagram, wait: Duration) -> Option<String> {
    let mut buffer = [0_u8; 4096];
    socket
        .set_read_timeout(Some(wait))
        .expect("set the read timeout");
    socket
        .recv(&mut buffer)
        .ok()
        .map(|length| String::from_utf8_lossy(&buffer[..length]).into_owned())
}

#[test]
fn ready_and_stopping_are_sent_to_the_notify_socket() {
    let node = Node::new();
    let dir = tempfile::Builder::new()
        .prefix("tenko-notify-")
        .tempdir()
        .expect("temporary directory");
    let socket_path = dir.path().join("notify.sock");
    let socket = UnixDatagram::bind(&socket_path).expect("bind the notify socket");

    node.write_config();
    let mut command = tenko();
    command
        .arg("serve")
        .arg("--config")
        .arg(node.config_path())
        .arg("--stop-on-eof")
        .env("NOTIFY_SOCKET", &socket_path);
    let mut server = serve_support::Proc::spawn(command);

    // READY=1 comes once the API listens: the probe answers as soon as it arrives.
    let ready = receive_until(&socket, "READY=1", READY_TIMEOUT);
    assert!(
        ready
            .lines()
            .any(|line| line.starts_with("STATUS=listening on 127.0.0.1:")),
        "the ready message does not say where the server listens: {ready:?}"
    );
    let (status, body) = node
        .get(READY_PATH)
        .expect("the probe answers after READY=1");
    assert_eq!(status, 200, "{body}");
    assert!(
        server
            .wait_stdout_line(Duration::from_secs(30), |line| line.contains(" ready at "))
            .is_some(),
        "{}",
        server.diagnostics()
    );

    // Nothing announces a stop while the server runs.
    assert_eq!(datagram_pending(&socket, Duration::from_millis(500)), None);

    // STOPPING=1 comes when the shutdown begins, not at the exit.
    server.close_stdin();
    let stopping = receive_until(&socket, "STOPPING=1", STOP_TIMEOUT);
    assert!(!stopping.contains("READY=1"), "{stopping:?}");
    let outcome = server.finish(STOP_TIMEOUT);
    outcome.assert_graceful_shutdown();
}

#[test]
fn nothing_is_sent_without_a_notify_socket() {
    // The harness removes NOTIFY_SOCKET from the environment of the server; a server
    // outside systemd must run and stop without complaining about it.
    let mut node = Node::new();
    let mut server = node.start();
    let outcome = server.stop();
    outcome.assert_graceful_shutdown();
    assert!(!outcome.stderr.contains("sd_notify"), "{}", outcome.stderr);
}
