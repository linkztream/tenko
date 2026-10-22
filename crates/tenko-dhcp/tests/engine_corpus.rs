//! The corpus test of the engine (WP7.3 acceptance): every request of
//! `fixtures/requests/*.hex` runs through the engine in the world of `engine_world` and the
//! answer must match `fixtures/requests/expected/<name>.hex` octet for octet: the action
//! and destination on the `# action:` line, the reply's octets after it (none for a request
//! that gets no reply). Every reply is also decoded by `dhcproto` (the differential crate of
//! ADR 0019) and checked against the rules that hold for every reply: the message type
//! first, the client identifier echoed (RFC 6842), option 82 echoed and last (RFC 3046),
//! the size within the client's limit.
//!
//! The requests are modelled by hand on the option order and the parameter request lists
//! the clients send (Windows, ISC dhclient, systemd-networkd, Android, macOS, PXE
//! firmware, relays with option 82), with documentation addresses and MACs; the lab capture
//! of WP7.6 adds captured requests to the same directory. `TENKO_BLESS=1` rewrites the
//! expected files after a deliberate change, which the diff then shows.

mod engine_world;

use std::{
    fmt::Write as _,
    net::{Ipv4Addr, SocketAddrV4},
    path::{Path, PathBuf},
};

use dhcproto::{Decodable, Decoder, v4};
use engine_world::{RELAY, World, t0};
use tenko_dhcp::v4::{
    Message,
    engine::{Action, Answer, Scratch},
};

fn dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/requests")
}

/// Hex pairs, `vv*N`, `#` comments: the fixture format.
fn read_hex(text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for line in text.lines() {
        let data = line.split('#').next().unwrap_or_default();
        for token in data.split_whitespace() {
            let (octet, count) = token.split_once('*').map_or((token, 1), |(octet, count)| {
                (octet, count.parse().expect("a repeat count"))
            });
            let octet = u8::from_str_radix(octet, 16).expect("a hex octet");
            out.extend(std::iter::repeat_n(octet, count));
        }
    }
    out
}

fn names() -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir())
        .expect("the corpus")
        .filter_map(|entry| {
            let name = entry.ok()?.file_name().into_string().ok()?;
            name.strip_suffix(".hex").map(str::to_owned)
        })
        .collect();
    names.sort();
    names
}

/// Where the request came from: the relay, or the client's address, or no address yet.
fn source(message: &Message<'_>) -> SocketAddrV4 {
    if message.giaddr().is_unspecified() {
        SocketAddrV4::new(message.ciaddr(), 68)
    } else {
        SocketAddrV4::new(RELAY, 67)
    }
}

fn summary(answer: &Answer) -> String {
    match answer.action {
        Action::Reply { kind, dest, .. } => format!("reply {kind:?} to {dest:?}"),
        Action::CommitThenReply { kind, dest, .. } => {
            format!("commit, then reply {kind:?} to {dest:?}")
        }
        Action::Commit => "commit, no reply".to_owned(),
        Action::Drop(reason) => format!("drop ({reason:?})"),
        Action::Ignore(reason) => format!("ignore ({reason:?})"),
    }
}

fn render(name: &str, summary: &str, reply: &[u8]) -> String {
    let mut out = format!(
        "# The engine's answer to requests/{name}.hex in the world of tests/engine_world.\n\
         # Written by tests/engine_corpus.rs with TENKO_BLESS=1; checked octet for octet.\n\
         # action: {summary}\n"
    );
    for line in reply.chunks(16) {
        let hex: Vec<String> = line.iter().map(|b| format!("{b:02x}")).collect();
        let _ = writeln!(out, "{}", hex.join(" "));
    }
    out
}

/// The rules every reply keeps, read through `dhcproto`.
fn check_reply(name: &str, request: &Message<'_>, reply: &[u8]) {
    let decoded = v4::Message::decode(&mut Decoder::new(reply))
        .unwrap_or_else(|error| panic!("{name}: dhcproto decodes the reply: {error}"));
    assert_eq!(decoded.xid(), request.xid(), "{name}: xid");
    assert_eq!(decoded.opcode(), v4::Opcode::BootReply, "{name}: op");
    assert_eq!(
        decoded.chaddr(),
        request.chaddr().expect("chaddr"),
        "{name}: chaddr"
    );
    assert_eq!(decoded.giaddr(), request.giaddr(), "{name}: giaddr");
    assert!(reply.len() <= request.max_reply_len(), "{name}: size");
    let ours = Message::parse(reply).expect("our codec reads it");
    let codes: Vec<u8> = ours
        .options()
        .map(|option| option.expect("well formed").code)
        .collect();
    assert_eq!(codes.first(), Some(&53), "{name}: option 53 first");
    if let Ok(Some(id)) = request.client_identifier() {
        assert_eq!(
            ours.client_identifier()
                .expect("61")
                .map(|echoed| echoed.as_bytes()),
            Some(id.as_bytes()),
            "{name}: option 61 echoed"
        );
    }
    if let Ok(Some(info)) = request.relay_agent_info() {
        assert_eq!(codes.last(), Some(&82), "{name}: option 82 last");
        assert_eq!(
            ours.relay_agent_info()
                .expect("82")
                .map(|echoed| echoed.as_bytes()),
            Some(info.as_bytes()),
            "{name}: option 82 unchanged"
        );
    }
    // Option 55's order is kept among the options the reply carries.
    let mut buf = [0u8; 512];
    if let Ok(Some(asked)) = request.option_data(55, &mut buf) {
        let asked: Vec<u8> = asked
            .iter()
            .copied()
            .filter(|code| ![1, 3, 6, 15, 51, 54, 58, 59, 61, 81, 82].contains(code))
            .collect();
        let carried: Vec<u8> = codes
            .iter()
            .copied()
            .filter(|code| asked.contains(code))
            .fold(Vec::new(), |mut seen, code| {
                if seen.last() != Some(&code) {
                    seen.push(code);
                }
                seen
            });
        let order: Vec<u8> = asked
            .iter()
            .copied()
            .filter(|code| carried.contains(code))
            .collect();
        assert_eq!(carried, order, "{name}: the order of option 55");
    }
}

#[test]
fn the_engine_answers_the_corpus_as_recorded() {
    let bless = std::env::var_os("TENKO_BLESS").is_some();
    let expected_dir = dir().join("expected");
    let names = names();
    assert!(
        names.len() >= 24,
        "the corpus holds {} requests",
        names.len()
    );
    let mut mismatches = Vec::new();
    let mut replies = 0;
    for name in &names {
        let text = std::fs::read_to_string(dir().join(format!("{name}.hex"))).expect("read");
        let bytes = read_hex(&text);
        let request = Message::parse(&bytes).unwrap_or_else(|_| panic!("{name} parses"));
        let world = World::new();
        let mut scratch = Scratch::new();
        let answer = world.run_from(&bytes, source(&request), t0(), &mut scratch);
        let reply: &[u8] = match answer.action {
            Action::Reply { len, .. } | Action::CommitThenReply { len, .. } => {
                &scratch.reply[..len]
            }
            _ => &[],
        };
        if !reply.is_empty() {
            replies += 1;
            check_reply(name, &request, reply);
        }
        // WP8.4: a Windows-style client (option 61 of type 1 and the MAC) holds the
        // reservation keyed by its MAC.
        if name == "windows-reserved-discover" {
            let offered = Message::parse(reply).expect("an offer");
            assert_eq!(offered.yiaddr(), Ipv4Addr::new(192, 0, 2, 20), "{name}");
        }
        let rendered = render(name, &summary(&answer), reply);
        let path = expected_dir.join(format!("{name}.hex"));
        if bless {
            std::fs::create_dir_all(&expected_dir).expect("the directory");
            std::fs::write(&path, &rendered).expect("write");
            continue;
        }
        let expected = std::fs::read_to_string(&path).unwrap_or_default();
        let want_summary = expected
            .lines()
            .find_map(|line| line.strip_prefix("# action: "))
            .unwrap_or("(no expected file)");
        if want_summary != summary(&answer) || read_hex(&expected) != reply {
            mismatches.push(format!(
                "{name}: expected `{want_summary}`, got `{}`",
                summary(&answer)
            ));
        }
    }
    assert!(mismatches.is_empty(), "{mismatches:#?}");
    assert!(replies >= 18, "{replies} replies");
}

#[test]
fn the_corpus_covers_every_message_type_and_both_paths() {
    let mut kinds = std::collections::BTreeSet::new();
    let mut relayed = 0;
    for name in names() {
        let text = std::fs::read_to_string(dir().join(format!("{name}.hex"))).expect("read");
        let bytes = read_hex(&text);
        let message = Message::parse(&bytes).expect("parses");
        kinds.insert(message.message_type().expect("53").expect("a type").code());
        relayed += usize::from(message.giaddr() != Ipv4Addr::UNSPECIFIED);
    }
    assert_eq!(kinds.into_iter().collect::<Vec<_>>(), [1, 3, 4, 7, 8]);
    assert!(relayed > 10);
}
