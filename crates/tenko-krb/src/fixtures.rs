//! The recorded exchanges of `tests/fixtures/exchanges/`, for the tests.

use std::{
    fs,
    path::{Path, PathBuf},
};

/// One recorded exchange.
#[allow(dead_code)] // Each module's tests read the fields they need.
pub(crate) struct Fixture {
    pub name: String,
    pub mech: String,
    pub spn: Vec<String>,
    pub realm: String,
    pub recorded_unix: i64,
    /// `(enctype, kvno, key)`.
    pub keys: Vec<(i32, u32, Vec<u8>)>,
    pub init0: Vec<u8>,
    pub accept0: Vec<u8>,
    pub msg: Vec<u8>,
    pub initmic: Vec<u8>,
    pub accmsg: Vec<u8>,
    pub accmic: Vec<u8>,
    pub ctxkey: Vec<u8>,
    pub msg2: Vec<u8>,
    pub initmic2: Vec<u8>,
}

/// Decodes hex, ignoring whitespace.
pub(crate) fn hex(text: &str) -> Vec<u8> {
    let digits: Vec<u8> = text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    assert!(digits.len().is_multiple_of(2), "odd number of hex digits");
    digits
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).expect("ascii"), 16).expect("hex"))
        .collect()
}

fn read_hex(dir: &Path, name: &str) -> Vec<u8> {
    hex(&fs::read_to_string(dir.join(format!("{name}.hex"))).expect("fixture file"))
}

fn load(dir: &Path) -> Fixture {
    let meta = fs::read_to_string(dir.join("meta.txt")).expect("meta.txt");
    let field = |key: &str| -> String {
        meta.lines()
            .find_map(|line| line.strip_prefix(&format!("{key}=")))
            .unwrap_or_else(|| panic!("{key} in meta.txt"))
            .to_owned()
    };
    let keys = fs::read_to_string(dir.join("keys.txt"))
        .expect("keys.txt")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let mut parts = line.split_whitespace();
            let enctype = parts.next().expect("enctype").parse().expect("enctype");
            let kvno = parts.next().expect("kvno").parse().expect("kvno");
            (enctype, kvno, hex(parts.next().expect("key")))
        })
        .collect();
    Fixture {
        name: dir
            .file_name()
            .expect("name")
            .to_string_lossy()
            .into_owned(),
        mech: field("mech"),
        spn: field("spn").split('/').map(str::to_owned).collect(),
        realm: field("realm"),
        recorded_unix: field("recorded_unix").parse().expect("time"),
        keys,
        init0: read_hex(dir, "init0"),
        accept0: read_hex(dir, "accept0"),
        msg: read_hex(dir, "msg"),
        initmic: read_hex(dir, "initmic"),
        accmsg: read_hex(dir, "accmsg"),
        accmic: read_hex(dir, "accmic"),
        ctxkey: read_hex(dir, "ctxkey"),
        msg2: read_hex(dir, "msg2"),
        initmic2: read_hex(dir, "initmic2"),
    }
}

/// Every recorded exchange, sorted by name.
pub(crate) fn all() -> Vec<Fixture> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/exchanges");
    let mut dirs: Vec<PathBuf> = fs::read_dir(&root)
        .expect("tests/fixtures/exchanges")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect();
    dirs.sort();
    let fixtures: Vec<Fixture> = dirs.iter().map(|dir| load(dir)).collect();
    assert_eq!(fixtures.len(), 10, "the ten recorded exchanges");
    fixtures
}

/// Encodes bytes as lowercase hex.
pub(crate) fn hex_string(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// The octets of a file under `tests/fixtures/`.
pub(crate) fn file(path: &str) -> Vec<u8> {
    fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(path),
    )
    .unwrap_or_else(|e| panic!("{path}: {e}"))
}
