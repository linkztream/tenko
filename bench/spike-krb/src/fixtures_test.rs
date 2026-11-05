//! Replays the recorded MIT and Samba exchanges under `fixtures/` through the (b') acceptor
//! with the recorded clock and the recorded acceptor subkey, so that the acceptor's MIC must
//! come out octet for octet as the one MIT verified at recording time.

use std::fs;
use std::path::{Path, PathBuf};

use crate::acceptor::{Acceptor, Enctype, ServiceKey, Step};
use crate::hex;
use crate::mic::ContextMicKeys;
use crate::own::{Config, OwnAcceptor, ReplayCache};

pub struct Fixture {
    pub name: String,
    pub spn: Vec<String>,
    pub realm: String,
    pub recorded_unix: i64,
    pub keys: Vec<ServiceKey>,
    pub init0: Vec<u8>,
    pub msg: Vec<u8>,
    pub initmic: Vec<u8>,
    pub accmsg: Vec<u8>,
    pub accmic: Vec<u8>,
    pub ctxkey: Vec<u8>,
    pub msg2: Vec<u8>,
    pub initmic2: Vec<u8>,
}

fn read_hex(dir: &Path, name: &str) -> Vec<u8> {
    let text = fs::read_to_string(dir.join(format!("{name}.hex")))
        .unwrap_or_else(|e| panic!("{name}: {e}"));
    hex::decode(&text).unwrap_or_else(|e| panic!("{name}: {e}"))
}

pub fn load(dir: &Path) -> Fixture {
    let meta = fs::read_to_string(dir.join("meta.txt")).expect("meta.txt");
    let field = |k: &str| -> String {
        meta.lines()
            .find_map(|l| l.strip_prefix(&format!("{k}=")))
            .unwrap_or_else(|| panic!("{k} in meta.txt"))
            .to_owned()
    };
    let keys = fs::read_to_string(dir.join("keys.txt"))
        .expect("keys.txt")
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let mut it = l.split_whitespace();
            let et: i64 = it.next().unwrap().parse().unwrap();
            let kvno: u32 = it.next().unwrap().parse().unwrap();
            let key = hex::decode(it.next().unwrap()).unwrap();
            ServiceKey {
                enctype: Enctype::from_number(et).unwrap(),
                kvno: Some(kvno),
                key,
            }
        })
        .collect();
    Fixture {
        name: dir.file_name().unwrap().to_string_lossy().into_owned(),
        spn: field("spn").split('/').map(str::to_owned).collect(),
        realm: field("realm"),
        recorded_unix: field("recorded_unix").parse().unwrap(),
        keys,
        init0: read_hex(dir, "init0"),
        msg: read_hex(dir, "msg"),
        initmic: read_hex(dir, "initmic"),
        accmsg: read_hex(dir, "accmsg"),
        accmic: read_hex(dir, "accmic"),
        ctxkey: read_hex(dir, "ctxkey"),
        msg2: read_hex(dir, "msg2"),
        initmic2: read_hex(dir, "initmic2"),
    }
}

pub fn all() -> Vec<Fixture> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures");
    let mut dirs: Vec<PathBuf> = fs::read_dir(&root)
        .expect("fixtures/")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();
    dirs.iter().map(|d| load(d)).collect()
}

#[test]
fn own_acceptor_replays_every_recorded_exchange() {
    let fixtures = all();
    assert!(fixtures.len() >= 10, "fixtures missing");
    for f in &fixtures {
        // The recorded acceptor MIC carries the acceptor's sequence number in its header.
        let acc_seq =
            u32::try_from(u64::from_be_bytes(f.accmic[8..16].try_into().unwrap())).unwrap();
        let spn: Vec<&str> = f.spn.iter().map(String::as_str).collect();
        let mut cfg = Config::new(&spn, &f.realm, f.keys.clone());
        let when = f.recorded_unix + 1;
        cfg.clock = Some(Box::new(move || when));
        cfg.fixed_subkey = Some((f.ctxkey.clone(), acc_seq));
        let mut replay = ReplayCache::new();
        let mut acc = OwnAcceptor::new(&cfg, &mut replay);
        let Step::Established { context, .. } = acc
            .step(&f.init0)
            .unwrap_or_else(|e| panic!("{}: {e}", f.name))
        else {
            panic!("{}: not established in one leg", f.name)
        };
        assert_eq!(context.key, f.ctxkey, "{}: context key", f.name);
        assert_eq!(context.client, "alice", "{}", f.name);
        assert_eq!(
            context.gss_flags,
            Some(0x13e),
            "{}: MIT asked mutual, replay, sequence, conf, integ",
            f.name
        );
        let keys = ContextMicKeys::new(&context.key, context.key_enctype);
        let h1 = keys
            .initiator
            .verify(&f.initmic, &f.msg)
            .unwrap_or_else(|e| panic!("{}: MIC 1 {e:?}", f.name));
        assert_eq!(
            Some(u32::try_from(h1.seq).unwrap()),
            context.initiator_seq,
            "{}: initiator seq",
            f.name
        );
        let h2 = keys
            .initiator
            .verify(&f.initmic2, &f.msg2)
            .unwrap_or_else(|e| panic!("{}: MIC 2 {e:?}", f.name));
        assert_eq!(h2.seq, h1.seq + 1, "{}", f.name);
        let ours = keys.acceptor.sign(
            keys.acceptor.sender_flags(true),
            u64::from(acc_seq),
            &f.accmsg,
        );
        assert_eq!(
            ours.to_vec(),
            f.accmic,
            "{}: the acceptor MIC MIT verified",
            f.name
        );
        // A second presentation of the same AP-REQ is a replay.
        let err = OwnAcceptor::new(&cfg, &mut replay)
            .step(&f.init0)
            .expect_err("replay");
        assert!(err.0.contains("replayed"), "{}: {err}", f.name);
        // Outside the skew the token is refused: recorded tokens cannot be replayed later.
        let mut late = Config::new(&spn, &f.realm, f.keys.clone());
        let later = f.recorded_unix + 301;
        late.clock = Some(Box::new(move || later));
        let mut replay2 = ReplayCache::new();
        let err = OwnAcceptor::new(&late, &mut replay2)
            .step(&f.init0)
            .expect_err("skew");
        assert!(err.0.contains("skew"), "{}: {err}", f.name);
    }
}

/// `sspi` reads the system clock, so this test only passes under libfaketime:
/// `scripts/replay-sspi.sh` runs it once per fixture with the recorded time.
#[cfg(feature = "sspi")]
#[test]
#[ignore = "needs the recorded clock: run through scripts/replay-sspi.sh"]
fn sspi_acceptor_replays_the_recorded_exchange_named_in_env() {
    use crate::sspi_acceptor::SspiAcceptor;
    let name = std::env::var("SPIKE_FIXTURE").expect("SPIKE_FIXTURE");
    let f = all().into_iter().find(|f| f.name == name).expect("fixture");
    let spn: Vec<&str> = f.spn.iter().map(String::as_str).collect();
    // sspi takes one key: the one the ticket is encrypted under (the first listed).
    let mut acc = SspiAcceptor::new(&spn, &f.keys[0], std::time::Duration::from_secs(300)).unwrap();
    match acc.step(&f.init0) {
        Ok(Step::Established { context, .. }) => {
            println!(
                "{name}: established, client {}@{}, key {:?}",
                context.client, context.realm, context.key_enctype
            );
        }
        other => panic!("{name}: {other:?}"),
    }
}
