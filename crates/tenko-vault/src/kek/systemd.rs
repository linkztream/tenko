//! The `systemd-creds` KEK sealer (Linux).
//!
//! [`SystemdCredsSealer`] runs the `systemd-creds` command line tool:
//!
//! ```text
//! systemd-creds encrypt --with-key=<auto|tpm2|host> [--user] --name=<label> - -
//! systemd-creds decrypt                             [--user] --name=<label> - -
//! ```
//!
//! The plaintext goes to the tool on standard input only (never in an argument or in the
//! environment) and the ciphertext, which is Base64 text, comes back on standard output.
//! `--name=<label>` binds the file stem (`kek-000001`) into the credential, so a sealed file
//! renamed to another generation does not unseal.
//!
//! [`SystemdCredsSealer::probe`] decides whether the tool works for the account that runs
//! the vault by sealing and unsealing a random value. The host key lives in
//! `/var/lib/systemd/credential.secret`, readable by root only, so an unprivileged service
//! account usually cannot use the `host` key. The probe therefore walks a short list of
//! variants and takes the first that round-trips:
//!
//! 1. the requested `--with-key=` value (`auto`, `tpm2` or `host`);
//! 2. when `auto` was requested and the host has a complete TPM2 stack: `tpm2` alone (the
//!    TPM2 needs no root-only secret), then `host` alone (the TPM2 is present but this
//!    account cannot use it);
//! 3. the same list again with `--user` (systemd 256 and later: a credential scoped to the
//!    calling user).
//!
//! A tool that falls back to a null key (`--with-key=null`, which gives no confidentiality)
//! is refused, and the probe never asks for one.

use std::{
    env,
    ffi::OsStr,
    fs,
    io::{self, Read, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use zeroize::Zeroizing;

use super::{CredsKey, KekDir, KekProtection, KekSealer, PlainSealer};
use crate::VaultError;

/// The provider tag in [`VaultError::Provider`].
const PROVIDER: &str = "systemd-creds";
/// The command looked up on `PATH` when no tool is configured.
const TOOL_NAME: &str = "systemd-creds";
/// The sealer name: the extension of the generation files and part of the KEK identifier.
const SEALER_NAME: &str = "cred";
/// The label of the value the probe seals.
const PROBE_LABEL: &str = "kek-probe";
/// How long one run of the tool may take before it is killed.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
/// The most standard output read from the tool (a sealed KEK is a few hundred bytes).
const MAX_OUTPUT: usize = 4 << 20;
/// The most standard error kept from the tool.
const STDERR_LIMIT: u64 = 4096;
/// The longest failure text carried in an error or a log line.
const REASON_LIMIT: usize = 300;

/// Seals KEK generation files with `systemd-creds encrypt`.
#[derive(Debug, Clone)]
pub struct SystemdCredsSealer {
    tool: PathBuf,
    key: CredsKey,
    user: bool,
    tpm2: bool,
    timeout: Duration,
}

impl SystemdCredsSealer {
    /// Probes the tool; `None` when it is missing or cannot seal for this account.
    ///
    /// `tool` is the `systemd-creds` binary; `None` (or a bare command name) looks it up on
    /// `PATH`. The probe seals and unseals a random value, so a tool that is present but not
    /// allowed to use any key for this account (an unprivileged service without a TPM2, for
    /// example) is reported as unusable. The reason is logged at `warn` level.
    ///
    /// `with_key` is the preferred key; see the module documentation for the variants the
    /// probe falls back to. [`key`](Self::key) and [`is_user_scoped`](Self::is_user_scoped)
    /// report what it settled on.
    pub fn probe(tool: Option<&Path>, with_key: CredsKey) -> Option<Self> {
        match Self::try_probe(tool, with_key) {
            Ok(sealer) => Some(sealer),
            Err(reason) => {
                warn_unusable(&reason);
                None
            }
        }
    }

    /// The resolved `systemd-creds` binary.
    pub fn tool(&self) -> &Path {
        &self.tool
    }

    /// The key new credentials are sealed with. It is the configured key unless the probe
    /// had to fall back (see the module documentation).
    pub fn key(&self) -> CredsKey {
        self.key
    }

    /// Whether credentials are sealed with `--user` (scoped to the calling user).
    pub fn is_user_scoped(&self) -> bool {
        self.user
    }

    /// The same sealer with another limit for one run of the tool (default 30 seconds). A
    /// tool that does not finish in time is killed and the call fails.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    fn try_probe(tool: Option<&Path>, with_key: CredsKey) -> Result<Self, String> {
        let path = locate(tool)?;
        let full_tpm2 = with_key == CredsKey::Auto && has_tpm2(&path);
        let keys: &[CredsKey] = match with_key {
            CredsKey::Auto if full_tpm2 => &[CredsKey::Auto, CredsKey::Tpm2, CredsKey::Host],
            CredsKey::Auto => &[CredsKey::Auto],
            CredsKey::Tpm2 => &[CredsKey::Tpm2],
            CredsKey::Host => &[CredsKey::Host],
        };
        let mut failures = Vec::new();
        for user in [false, true] {
            for &key in keys {
                let candidate = Self {
                    tool: path.clone(),
                    key,
                    user,
                    tpm2: match key {
                        CredsKey::Tpm2 => true,
                        CredsKey::Host => false,
                        CredsKey::Auto => full_tpm2,
                    },
                    timeout: DEFAULT_TIMEOUT,
                };
                match candidate.self_test() {
                    Ok(()) => {
                        candidate.log_choice(with_key);
                        return Ok(candidate);
                    }
                    Err(reason) => failures.push(format!("{}: {reason}", candidate.mode())),
                }
            }
        }
        Err(format!(
            "{} cannot seal for this account ({})",
            path.display(),
            failures.join("; ")
        ))
    }

    /// Seals and unseals a random value.
    fn self_test(&self) -> Result<(), String> {
        let mut value = Zeroizing::new([0u8; 32]);
        aws_lc_rs::rand::fill(value.as_mut())
            .map_err(|_| "the random generator failed".to_owned())?;
        let sealed = self.run_seal(PROBE_LABEL, value.as_ref())?;
        let opened = self.run_unseal(PROBE_LABEL, &sealed)?;
        if opened.as_slice() == value.as_slice() {
            Ok(())
        } else {
            Err("the probe value did not survive a round trip".to_owned())
        }
    }

    /// The options that select the key and scope, for logs and failure texts.
    fn mode(&self) -> String {
        let user = if self.user { " --user" } else { "" };
        format!("--with-key={}{user}", key_flag(self.key))
    }

    fn log_choice(&self, requested: CredsKey) {
        if self.key == requested && !self.user {
            tracing::debug!(tool = %self.tool.display(), mode = %self.mode(), "systemd-creds works");
        } else if requested == CredsKey::Auto && self.key == CredsKey::Host {
            tracing::warn!(
                tool = %self.tool.display(),
                mode = %self.mode(),
                "this host has a TPM2 but this account cannot use it; sealing with the host key only"
            );
        } else {
            tracing::info!(
                tool = %self.tool.display(),
                mode = %self.mode(),
                "systemd-creds works with a different key or scope than the default for this account"
            );
        }
    }

    fn run_seal(&self, label: &str, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let mut args = vec![
            "encrypt".to_owned(),
            format!("--with-key={}", key_flag(self.key)),
        ];
        if self.user {
            args.push("--user".to_owned());
        }
        args.extend([format!("--name={label}"), "-".to_owned(), "-".to_owned()]);
        let done = run_tool(&self.tool, &args, plaintext, self.timeout, 0)?;
        done.check()?;
        if done.stdout.is_empty() {
            return Err("the tool produced no output".to_owned());
        }
        Ok(done.stdout.to_vec())
    }

    fn run_unseal(&self, label: &str, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
        let mut args = vec!["decrypt".to_owned()];
        if self.user {
            args.push("--user".to_owned());
        }
        args.extend([format!("--name={label}"), "-".to_owned(), "-".to_owned()]);
        let done = run_tool(&self.tool, &args, sealed, self.timeout, sealed.len())?;
        done.check()?;
        Ok(done.stdout)
    }
}

impl KekSealer for SystemdCredsSealer {
    fn name(&self) -> &'static str {
        SEALER_NAME
    }

    fn protection(&self) -> KekProtection {
        KekProtection::SystemdCreds { tpm2: self.tpm2 }
    }

    fn seal(&self, label: &str, plaintext: &[u8]) -> Result<Vec<u8>, VaultError> {
        self.run_seal(label, plaintext).map_err(|reason| {
            VaultError::provider(PROVIDER, format!("cannot seal {label}: {reason}"))
        })
    }

    fn unseal(&self, label: &str, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        self.run_unseal(label, sealed).map_err(|reason| {
            VaultError::kek_unavailable(format!(
                "systemd-creds cannot unseal {label} for this account: {reason}"
            ))
        })
    }
}

/// Stands in for [`SystemdCredsSealer`] when generations sealed with it exist but the tool is
/// not usable now: it keeps those files from being ignored (and a fresh KEK from silently
/// replacing them) by failing the load.
#[derive(Debug)]
struct UnusableCreds {
    reason: String,
}

impl KekSealer for UnusableCreds {
    fn name(&self) -> &'static str {
        SEALER_NAME
    }

    fn protection(&self) -> KekProtection {
        KekProtection::SystemdCreds { tpm2: false }
    }

    fn seal(&self, label: &str, _plaintext: &[u8]) -> Result<Vec<u8>, VaultError> {
        Err(VaultError::provider(
            PROVIDER,
            format!("cannot seal {label}: {}", self.reason),
        ))
    }

    fn unseal(&self, label: &str, _sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        Err(VaultError::kek_unavailable(format!(
            "{label} was sealed with systemd-creds, which is not usable now ({}); make \
             systemd-creds work for this account on the host that sealed it, or restore the \
             KEK directory and its host key from backup",
            self.reason
        )))
    }
}

/// The generation directory for the `systemd-creds` provider: sealed with the tool when it
/// works, plain files with a warning otherwise; plain generations stay readable, and
/// generations sealed earlier with the tool are never ignored.
pub(crate) fn kek_dir(dir: &Path, with_key: CredsKey, tool: Option<&Path>) -> KekDir {
    match SystemdCredsSealer::try_probe(tool, with_key) {
        Ok(sealer) => KekDir::new(dir, Arc::new(sealer)).also_reading(Arc::new(PlainSealer)),
        Err(reason) => {
            warn_unusable(&reason);
            KekDir::new(dir, Arc::new(PlainSealer)).also_reading(Arc::new(UnusableCreds { reason }))
        }
    }
}

fn warn_unusable(reason: &str) {
    tracing::warn!(
        reason = %reason,
        "systemd-creds is not usable; key-encryption keys cannot be sealed with it"
    );
}

/// The `--with-key=` value of a key.
fn key_flag(key: CredsKey) -> &'static str {
    match key {
        CredsKey::Auto => "auto",
        CredsKey::Tpm2 => "tpm2",
        CredsKey::Host => "host",
    }
}

/// Finds the tool: `tool` as given when it has a directory part, otherwise (a bare name, or
/// none for `systemd-creds`) the first executable of that name in an absolute `PATH` entry.
fn locate(tool: Option<&Path>) -> Result<PathBuf, String> {
    let wanted = tool.unwrap_or_else(|| Path::new(TOOL_NAME));
    let bare = wanted
        .parent()
        .is_some_and(|parent| parent.as_os_str().is_empty());
    if bare {
        let search = env::var_os("PATH");
        return find_in_path(wanted, search.as_deref())
            .ok_or_else(|| format!("{} was not found on PATH", wanted.display()));
    }
    match fs::metadata(wanted) {
        Err(e) => Err(format!("cannot use {}: {e}", wanted.display())),
        Ok(meta) if meta.is_file() && meta.permissions().mode() & 0o111 != 0 => {
            Ok(wanted.to_path_buf())
        }
        Ok(_) => Err(format!("{} is not an executable file", wanted.display())),
    }
}

/// The first executable `name` in an absolute entry of the `search` path list. Relative
/// entries (including the empty one, which means the current directory) are skipped: a
/// program that guards key material must not be picked up from the working directory.
fn find_in_path(name: &Path, search: Option<&OsStr>) -> Option<PathBuf> {
    env::split_paths(search?)
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join(name))
        .find(|candidate| is_executable_file(candidate))
}

fn is_executable_file(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}

/// Whether `systemd-creds has-tpm2` reports full TPM2 support (exit status 0; `partial` and
/// `no` exit non-zero).
fn has_tpm2(tool: &Path) -> bool {
    run_tool(tool, &["has-tpm2".to_owned()], &[], DEFAULT_TIMEOUT, 0)
        .is_ok_and(|done| done.status.success())
}

/// What a finished run of the tool left behind.
struct Finished {
    status: ExitStatus,
    stdout: Zeroizing<Vec<u8>>,
    /// Standard error, trimmed and on one line.
    stderr: String,
}

impl Finished {
    /// Fails on a non-zero exit (with the tool's own message) and on a null key.
    fn check(&self) -> Result<(), String> {
        if !self.status.success() {
            return Err(if self.stderr.is_empty() {
                self.status.to_string()
            } else {
                format!("{}: {}", self.status, self.stderr)
            });
        }
        if self.stderr.contains("null key") {
            return Err("the tool used a null key, which gives no confidentiality".to_owned());
        }
        Ok(())
    }
}

/// Runs `tool args…` with `input` on standard input and collects standard output and error.
///
/// Standard input is written from its own thread and both outputs are read from theirs, so
/// a tool that exits without reading its input (a broken pipe on our side) or that fills a
/// pipe cannot deadlock the caller. A run that outlasts `timeout` is killed. Standard output
/// may hold a plaintext key: it is read into zeroized buffers only.
fn run_tool(
    tool: &Path,
    args: &[String],
    input: &[u8],
    timeout: Duration,
    stdout_hint: usize,
) -> Result<Finished, String> {
    let mut child = Command::new(tool)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot start {}: {e}", tool.display()))?;
    let (Some(stdin), Some(stdout), Some(stderr)) =
        (child.stdin.take(), child.stdout.take(), child.stderr.take())
    else {
        let _ = child.kill();
        let _ = child.wait();
        return Err("cannot open the pipes of the tool".to_owned());
    };
    thread::scope(|scope| {
        let writer = scope.spawn(move || {
            let mut stdin = stdin;
            // A tool that exits early closes the pipe; its exit status tells the story.
            let _ = stdin.write_all(input);
        });
        let out = scope.spawn(move || read_secret(stdout, stdout_hint));
        let err = scope.spawn(move || read_text(stderr));
        let waited = wait_with_deadline(&mut child, timeout);
        let _ = writer.join();
        let stdout = out.join();
        let stderr = err.join().unwrap_or_default();
        let status = waited?;
        let stdout = stdout
            .map_err(|_| "the output reader failed".to_owned())?
            .map_err(|e| format!("cannot read the output of the tool: {e}"))?;
        Ok(Finished {
            status,
            stdout,
            stderr,
        })
    })
}

/// Waits for the child; kills it when it outlasts `timeout`.
fn wait_with_deadline(child: &mut Child, timeout: Duration) -> Result<ExitStatus, String> {
    let deadline = Instant::now() + timeout;
    let mut pause = Duration::from_millis(1);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => {}
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("cannot wait for the tool: {e}"));
            }
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("the tool did not finish within {timeout:?}"));
        }
        thread::sleep(pause);
        pause = (pause * 2).min(Duration::from_millis(25));
    }
}

/// Reads to the end into a buffer that is zeroized on every reallocation and on drop.
fn read_secret(mut reader: impl Read, hint: usize) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut buf = Zeroizing::new(vec![0u8; hint.clamp(256, MAX_OUTPUT)]);
    let mut len = 0;
    loop {
        if len == buf.len() {
            if len >= MAX_OUTPUT {
                return Err(io::Error::other("more output than a sealed key can be"));
            }
            let mut grown = Zeroizing::new(vec![0u8; len.saturating_mul(2).min(MAX_OUTPUT)]);
            grown[..len].copy_from_slice(&buf[..len]);
            buf = grown;
        }
        match reader.read(&mut buf[len..]) {
            Ok(0) => break,
            Ok(read) => len += read,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    buf.truncate(len);
    Ok(buf)
}

/// Reads standard error: the first `STDERR_LIMIT` bytes, tidied; the rest is drained.
fn read_text(reader: impl Read) -> String {
    let mut bytes = Vec::new();
    let mut limited = reader.take(STDERR_LIMIT);
    let _ = limited.read_to_end(&mut bytes);
    let _ = io::copy(&mut limited.into_inner(), &mut io::sink());
    tidy(&String::from_utf8_lossy(&bytes))
}

/// One short line: trimmed lines joined with ` | `, control characters replaced, length
/// limited.
fn tidy(text: &str) -> String {
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    let mut out: String = lines
        .join(" | ")
        .chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect();
    if let Some((cut, _)) = out.char_indices().nth(REASON_LIMIT) {
        out.truncate(cut);
        out.push_str("...");
    }
    out
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;
    use crate::kek::KekInit;

    /// The marker the tests seal; it must never show up in an argument, the environment or
    /// an error text.
    const MARKER: &str = "hunter2-plaintext-marker";

    /// A stand-in for `systemd-creds`: `encrypt` prefixes the label and Base64-encodes the
    /// input, `decrypt` checks the label and decodes, `has-tpm2` exits with a fixed status.
    /// It records its argument vector and its environment in `<script>.log`.
    const FAKE: &str = r#"#!/bin/sh
cmd="$1"
shift
name=""
key=""
user=no
for arg in "$@"; do
  case "$arg" in
    --name=*) name="${arg#--name=}" ;;
    --with-key=*) key="${arg#--with-key=}" ;;
    --user) user=yes ;;
  esac
done
{ echo "$cmd $*"; env; } >> "$0.log"
@GATE@
case "$cmd" in
  has-tpm2) exit @TPM2_EXIT@ ;;
  encrypt)
    printf 'FAKE:%s:' "$name"
    base64 | tr -d '\n'
    ;;
  decrypt)
    data=$(cat)
    case "$data" in
      FAKE:*) ;;
      *) echo "Failed to read encrypted credential data: Invalid argument" >&2; exit 1 ;;
    esac
    rest="${data#FAKE:}"
    embedded="${rest%%:*}"
    body="${rest#*:}"
    if [ "$embedded" != "$name" ]; then
      echo "Embedded credential name '$embedded' does not match filename '$name', refusing." >&2
      exit 1
    fi
    printf '%s' "$body" | base64 -d
    ;;
  *) exit 2 ;;
esac
"#;

    const NO_GATE: &str = "";
    /// Everything but `has-tpm2` needs `--user`, like a host key only root can read.
    const USER_ONLY: &str = r#"[ "$cmd" = has-tpm2 ] || [ "$user" = yes ] || { echo "Failed to determine local credential host secret: Permission denied" >&2; exit 1; }"#;
    /// `encrypt` works with `--with-key=tpm2` only.
    const TPM2_KEY_ONLY: &str = r#"[ "$cmd" != encrypt ] || [ "$key" = tpm2 ] || { echo "Failed to determine local credential host secret: Permission denied" >&2; exit 1; }"#;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "tenko-vault-creds-{name}-{}",
                tenko_core::SecretId::generate()
            ));
            fs::create_dir_all(&dir).expect("temp dir");
            Self(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// Writes an executable script (`text` starts with its `#!` line) and waits until the
    /// kernel lets it run: a `fork` in a parallel test can briefly keep the write handle
    /// open ("text file busy"). The script answers the argument `noop` with exit status 0
    /// before doing anything else, which is what the wait runs.
    fn install(dir: &Path, name: &str, text: &str) -> PathBuf {
        let path = dir.join(name);
        {
            let mut file = fs::File::create_new(&path).expect("create script");
            let text = text.replacen('\n', "\n[ \"$1\" = noop ] && exit 0\n", 1);
            file.write_all(text.as_bytes()).expect("write script");
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("chmod");
        for _ in 0..500 {
            let started = Command::new(&path)
                .arg("noop")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            match started {
                Err(e) if e.raw_os_error() == Some(26) => {
                    thread::sleep(Duration::from_millis(10));
                }
                _ => break,
            }
        }
        path
    }

    fn fake_tool(dir: &TempDir, name: &str, tpm2: bool, gate: &str) -> PathBuf {
        let text = FAKE
            .replace("@TPM2_EXIT@", if tpm2 { "0" } else { "1" })
            .replace("@GATE@", gate);
        install(dir.path(), name, &text)
    }

    fn log_of(tool: &Path) -> String {
        let mut log = tool.as_os_str().to_owned();
        log.push(".log");
        fs::read_to_string(log).unwrap_or_default()
    }

    fn creds(tool: &Path) -> SystemdCredsSealer {
        SystemdCredsSealer::probe(Some(tool), CredsKey::Auto).expect("the fake tool works")
    }

    #[test]
    fn probe_accepts_a_working_tool_without_tpm2() {
        let dir = TempDir::new("probe-ok");
        let tool = fake_tool(&dir, "creds", false, NO_GATE);
        let creds = creds(&tool);
        assert_eq!(creds.name(), "cred");
        assert_eq!(creds.tool(), tool);
        assert_eq!(creds.key(), CredsKey::Auto);
        assert!(!creds.is_user_scoped());
        assert_eq!(
            creds.protection(),
            KekProtection::SystemdCreds { tpm2: false }
        );
    }

    #[test]
    fn tpm2_follows_has_tpm2_and_the_requested_key() {
        let dir = TempDir::new("probe-tpm2");
        let with = fake_tool(&dir, "with-tpm2", true, NO_GATE);
        let without = fake_tool(&dir, "without-tpm2", false, NO_GATE);
        let tpm2 = |tool: &Path, key| {
            SystemdCredsSealer::probe(Some(tool), key)
                .expect("works")
                .protection()
        };
        let yes = KekProtection::SystemdCreds { tpm2: true };
        let no = KekProtection::SystemdCreds { tpm2: false };
        assert_eq!(tpm2(&with, CredsKey::Auto), yes);
        assert_eq!(tpm2(&with, CredsKey::Tpm2), yes);
        assert_eq!(tpm2(&with, CredsKey::Host), no);
        assert_eq!(tpm2(&without, CredsKey::Auto), no);
        assert_eq!(tpm2(&without, CredsKey::Host), no);
    }

    #[test]
    fn probe_passes_the_requested_key() {
        let dir = TempDir::new("probe-key");
        let tool = fake_tool(&dir, "creds", false, NO_GATE);
        let host = SystemdCredsSealer::probe(Some(&tool), CredsKey::Host).expect("host");
        host.seal("kek-000001", b"x").expect("seal");
        assert_eq!(host.key(), CredsKey::Host);
        assert!(log_of(&tool).contains("encrypt --with-key=host --name=kek-000001 - -"));
    }

    #[test]
    fn auto_falls_back_to_the_tpm2_alone_for_an_account_without_the_host_key() {
        let dir = TempDir::new("fallback-tpm2");
        let tool = fake_tool(&dir, "creds", true, TPM2_KEY_ONLY);
        let creds = creds(&tool);
        assert_eq!(creds.key(), CredsKey::Tpm2);
        assert_eq!(
            creds.protection(),
            KekProtection::SystemdCreds { tpm2: true }
        );
        // Without a TPM2 nothing else is tried: auto means the host key alone.
        let host_only = fake_tool(&dir, "no-tpm2", false, TPM2_KEY_ONLY);
        assert!(SystemdCredsSealer::probe(Some(&host_only), CredsKey::Auto).is_none());
    }

    #[test]
    fn probe_falls_back_to_the_user_scope() {
        let dir = TempDir::new("fallback-user");
        let tool = fake_tool(&dir, "creds", false, USER_ONLY);
        let creds = creds(&tool);
        assert!(creds.is_user_scoped());
        let sealed = creds.seal("kek-000001", MARKER.as_bytes()).expect("seal");
        let opened = creds.unseal("kek-000001", &sealed).expect("unseal");
        assert_eq!(opened.as_slice(), MARKER.as_bytes());
        let log = log_of(&tool);
        assert!(log.contains("encrypt --with-key=auto --user --name=kek-000001 - -"));
        assert!(log.contains("decrypt --user --name=kek-000001 - -"));
    }

    #[test]
    fn probe_rejects_a_tool_that_fails() {
        let dir = TempDir::new("probe-fails");
        let tool = install(
            dir.path(),
            "creds",
            "#!/bin/sh\necho 'Failed to determine local credential host secret: Permission denied' >&2\nexit 1\n",
        );
        assert!(SystemdCredsSealer::probe(Some(&tool), CredsKey::Auto).is_none());
        let reason = SystemdCredsSealer::try_probe(Some(&tool), CredsKey::Auto).unwrap_err();
        assert!(reason.contains("Permission denied"), "{reason}");
        assert!(reason.contains("--with-key=auto"), "{reason}");
        assert!(reason.contains("--user"), "{reason}");
    }

    #[test]
    fn probe_rejects_a_tool_that_does_not_round_trip() {
        let dir = TempDir::new("probe-wrong");
        let tool = install(
            dir.path(),
            "creds",
            "#!/bin/sh\ncase \"$1\" in encrypt) cat ;; decrypt) cat >/dev/null; printf wrong ;; *) exit 1 ;; esac\n",
        );
        let reason = SystemdCredsSealer::try_probe(Some(&tool), CredsKey::Host).unwrap_err();
        assert!(reason.contains("round trip"), "{reason}");
    }

    #[test]
    fn probe_rejects_a_missing_or_non_executable_tool() {
        let dir = TempDir::new("probe-missing");
        let missing = dir.join("nothing-here");
        assert!(SystemdCredsSealer::probe(Some(&missing), CredsKey::Auto).is_none());
        let plain = dir.join("data");
        fs::write(&plain, "not a program").expect("write");
        fs::set_permissions(&plain, fs::Permissions::from_mode(0o644)).expect("chmod");
        let reason = SystemdCredsSealer::try_probe(Some(&plain), CredsKey::Auto).unwrap_err();
        assert!(reason.contains("not an executable"), "{reason}");
    }

    #[test]
    fn path_lookup_takes_absolute_executable_entries_only() {
        let dir = TempDir::new("path-lookup");
        let bin = dir.join("bin");
        let skipped = dir.join("skipped");
        fs::create_dir_all(&bin).expect("bin");
        fs::create_dir_all(&skipped).expect("skipped");
        let tool = install(&bin, "systemd-creds", "#!/bin/sh\nexit 0\n");
        fs::write(skipped.join("other"), "data").expect("data");
        let search = env::join_paths([skipped.clone(), bin.clone()]).expect("join");
        let name = Path::new("systemd-creds");
        assert_eq!(find_in_path(name, Some(&search)), Some(tool));
        // A file without the execute bit and a missing name are not found.
        assert_eq!(find_in_path(Path::new("other"), Some(&search)), None);
        assert_eq!(find_in_path(Path::new("nope"), Some(&search)), None);
        assert_eq!(find_in_path(name, None), None);
        // A relative entry never counts, even when it holds the tool.
        let relative = env::join_paths(["bin"]).expect("join");
        assert_eq!(find_in_path(name, Some(&relative)), None);
    }

    #[test]
    fn seal_and_unseal_round_trip_binary_data() {
        let dir = TempDir::new("round-trip");
        let tool = fake_tool(&dir, "creds", false, NO_GATE);
        let creds = creds(&tool);
        let mut plaintext = vec![0u8, 1, 10, 13, 255, 0, 10, 10];
        plaintext.extend(0..=255u8);
        let sealed = creds.seal("kek-000007", &plaintext).expect("seal");
        assert!(!sealed.windows(4).any(|w| w == b"\x00\x01\n\r"));
        let opened = creds.unseal("kek-000007", &sealed).expect("unseal");
        assert_eq!(opened.as_slice(), plaintext.as_slice());
    }

    #[test]
    fn unseal_with_another_label_fails() {
        let dir = TempDir::new("label");
        let tool = fake_tool(&dir, "creds", false, NO_GATE);
        let creds = creds(&tool);
        let sealed = creds.seal("kek-000001", b"secret").expect("seal");
        let error = creds.unseal("kek-000002", &sealed).expect_err("label");
        let VaultError::KekUnavailable { reason } = error else {
            panic!("expected KekUnavailable");
        };
        assert!(reason.contains("kek-000002"), "{reason}");
        assert!(reason.contains("does not match"), "{reason}");
        assert!(creds.unseal("kek-000001", b"FAKE:kek-000001:@@@").is_err());
    }

    #[test]
    fn the_plaintext_travels_on_standard_input_only() {
        let dir = TempDir::new("stdin-only");
        let tool = fake_tool(&dir, "creds", false, NO_GATE);
        let creds = creds(&tool);
        let sealed = creds.seal("kek-000001", MARKER.as_bytes()).expect("seal");
        creds.unseal("kek-000001", &sealed).expect("unseal");
        let log = log_of(&tool);
        assert!(log.contains("encrypt --with-key=auto --name=kek-000001 - -"));
        assert!(log.contains("decrypt --name=kek-000001 - -"));
        assert!(!log.contains(MARKER), "plaintext leaked into argv or env");
        assert!(!log.contains(&sealed_text(&sealed)), "ciphertext in argv");
    }

    fn sealed_text(sealed: &[u8]) -> String {
        String::from_utf8_lossy(sealed).into_owned()
    }

    #[test]
    fn a_failing_tool_gives_typed_errors_with_trimmed_stderr_and_no_data() {
        let dir = TempDir::new("errors");
        let tool = fake_tool(&dir, "creds", false, NO_GATE);
        let working = creds(&tool);
        let failing = install(
            dir.path(),
            "failing",
            "#!/bin/sh\ncat >/dev/null\nprintf '  denied: no key for you  \\n\\n' >&2\nexit 1\n",
        );
        let broken = SystemdCredsSealer {
            tool: failing,
            ..working
        };
        let seal = broken.seal("kek-000001", MARKER.as_bytes()).unwrap_err();
        let VaultError::Provider { provider, reason } = seal else {
            panic!("expected Provider");
        };
        assert_eq!(provider, "systemd-creds");
        assert!(reason.contains("kek-000001"), "{reason}");
        assert!(
            reason.contains("exit status: 1: denied: no key for you"),
            "{reason}"
        );
        assert!(!reason.contains(MARKER));
        let unseal = broken.unseal("kek-000001", b"whatever").unwrap_err();
        let VaultError::KekUnavailable { reason } = unseal else {
            panic!("expected KekUnavailable");
        };
        assert!(reason.contains("denied: no key for you"), "{reason}");
        assert!(!reason.ends_with(' '));
    }

    #[test]
    fn a_null_key_is_refused() {
        let dir = TempDir::new("null-key");
        let tool = fake_tool(&dir, "creds", false, NO_GATE);
        let working = creds(&tool);
        let nulled = install(
            dir.path(),
            "nulled",
            "#!/bin/sh\ncat\necho 'Using a null key for encryption and signing. Confidentiality or authenticity will not be provided.' >&2\n",
        );
        let nulled = SystemdCredsSealer {
            tool: nulled,
            ..working
        };
        let error = nulled.seal("kek-000001", b"secret").unwrap_err();
        assert!(error.to_string().contains("null key"), "{error}");
        assert!(SystemdCredsSealer::try_probe(Some(&nulled.tool), CredsKey::Host).is_err());
    }

    #[test]
    fn a_tool_that_exits_without_reading_does_not_block() {
        let dir = TempDir::new("early-exit");
        let tool = fake_tool(&dir, "creds", false, NO_GATE);
        let working = creds(&tool);
        let early = install(
            dir.path(),
            "early",
            "#!/bin/sh\necho 'refusing to read' >&2\nexit 3\n",
        );
        let early = SystemdCredsSealer {
            tool: early,
            ..working
        };
        // Far more than a pipe holds, so an unread write would block forever.
        let big = vec![0x41u8; 1 << 20];
        let started = Instant::now();
        let error = early.seal("kek-000001", &big).unwrap_err();
        assert!(started.elapsed() < Duration::from_secs(20));
        assert!(error.to_string().contains("refusing to read"), "{error}");
        assert!(error.to_string().contains("exit status: 3"), "{error}");
    }

    #[test]
    fn a_tool_that_floods_its_output_does_not_block() {
        let dir = TempDir::new("flood");
        let tool = fake_tool(&dir, "creds", false, NO_GATE);
        let working = creds(&tool);
        let flood = install(
            dir.path(),
            "flood",
            "#!/bin/sh\nhead -c 300000 /dev/zero >&2\nhead -c 300000 /dev/zero | tr '\\0' 'a'\nexit 0\n",
        );
        let flood = SystemdCredsSealer {
            tool: flood,
            ..working
        };
        let sealed = flood
            .seal("kek-000001", b"x")
            .expect("a long answer is fine");
        assert_eq!(sealed.len(), 300_000);
    }

    #[test]
    fn a_hung_tool_is_killed_after_the_timeout() {
        let dir = TempDir::new("timeout");
        let tool = fake_tool(&dir, "creds", false, NO_GATE);
        let working = creds(&tool);
        let hung = install(dir.path(), "hung", "#!/bin/sh\nexec sleep 60\n");
        let hung = SystemdCredsSealer {
            tool: hung,
            ..working
        }
        .with_timeout(Duration::from_millis(300));
        let started = Instant::now();
        let error = hung.unseal("kek-000001", b"x").unwrap_err();
        assert!(started.elapsed() < Duration::from_secs(20));
        assert!(matches!(error, VaultError::KekUnavailable { .. }));
        assert!(error.to_string().contains("did not finish"), "{error}");
    }

    #[test]
    fn long_and_multiline_messages_are_tidied() {
        assert_eq!(tidy("  a \n\n b\t\n"), "a | b");
        assert_eq!(tidy("x\u{1b}[31my"), "x?[31my");
        let long = "z".repeat(1000);
        let short = tidy(&long);
        assert_eq!(short.len(), REASON_LIMIT + 3);
        assert!(short.ends_with("..."));
    }

    #[test]
    fn kek_dir_without_the_tool_falls_back_to_plain_files() {
        let dir = TempDir::new("dir-missing");
        let kek_dir = kek_dir(
            &dir.join("kek"),
            CredsKey::Auto,
            Some(&dir.join("no-such-tool")),
        );
        let ring = kek_dir.load(KekInit::CreateIfMissing).expect("create");
        assert!(ring.active().protection().is_weak());
        assert!(ring.active().id().starts_with("plain-1-"));
        assert!(dir.join("kek").join("kek-000001.plain").exists());
        assert!(!dir.join("kek").join("kek-000001.cred").exists());
        assert!(kek_dir.load(KekInit::Require).is_ok());
    }

    #[test]
    fn kek_dir_with_a_working_tool_seals_the_generations() {
        let dir = TempDir::new("dir-sealed");
        let tool = fake_tool(&dir, "creds", false, NO_GATE);
        let kek_dir = kek_dir(&dir.join("kek"), CredsKey::Auto, Some(&tool));
        let ring = kek_dir.load(KekInit::CreateIfMissing).expect("create");
        assert!(ring.active().id().starts_with("cred-1-"));
        assert_eq!(
            ring.active().protection(),
            KekProtection::SystemdCreds { tpm2: false }
        );
        let file = fs::read(dir.join("kek").join("kek-000001.cred")).expect("sealed file");
        assert!(
            !file.starts_with(b"TKEK"),
            "the file holds the plain format"
        );
        assert!(file.starts_with(b"FAKE:kek-000001:"), "the label is bound");
        assert!(!dir.join("kek").join("kek-000001.plain").exists());
        let again = kek_dir.load(KekInit::Require).expect("load");
        assert_eq!(again.active().id(), ring.active().id());
        // The ring still works: the sealed KEK wraps and unwraps.
        let dek = crate::DataKey::generate().expect("dek");
        let wrapped = again.active().wrap(&dek, b"aad").expect("wrap");
        let back = ring.active().unwrap(&wrapped, b"aad").expect("unwrap");
        assert_eq!(back.as_bytes(), dek.as_bytes());
    }

    #[test]
    fn rotation_with_the_tool_adds_sealed_generations() {
        let dir = TempDir::new("dir-rotate");
        let tool = fake_tool(&dir, "creds", false, NO_GATE);
        let kek_dir = kek_dir(&dir.join("kek"), CredsKey::Auto, Some(&tool));
        let first = kek_dir.load(KekInit::CreateIfMissing).expect("create");
        let second = kek_dir.create_next().expect("next");
        assert!(second.id().starts_with("cred-2-"));
        assert!(dir.join("kek").join("kek-000002.cred").exists());
        let ring = kek_dir.load(KekInit::Require).expect("load");
        assert_eq!(ring.active().id(), second.id());
        assert_eq!(
            ring.retired_ids().collect::<Vec<_>>(),
            [first.active().id()]
        );
    }

    #[test]
    fn a_sealed_generation_without_a_usable_tool_fails_the_load() {
        let dir = TempDir::new("dir-lost-tool");
        let kek = dir.join("kek");
        let tool = fake_tool(&dir, "creds", false, NO_GATE);
        kek_dir(&kek, CredsKey::Auto, Some(&tool))
            .load(KekInit::CreateIfMissing)
            .expect("create");
        let sealed = fs::read(kek.join("kek-000001.cred")).expect("sealed file");

        let broken = kek_dir(&kek, CredsKey::Auto, Some(&dir.join("gone")));
        for init in [KekInit::Require, KekInit::CreateIfMissing] {
            let Err(VaultError::KekUnavailable { reason }) = broken.load(init) else {
                panic!("a sealed generation must stop the load");
            };
            assert!(reason.contains("kek-000001"), "{reason}");
            assert!(reason.contains("sealed with systemd-creds"), "{reason}");
            assert!(reason.contains("not usable now"), "{reason}");
        }
        // No plain generation is created beside the sealed one (R15)...
        assert!(matches!(
            broken.create_next(),
            Err(VaultError::PlainRefused { .. })
        ));
        // ...unless allowed; numbering continues above the sealed file, nothing is
        // overwritten.
        broken
            .clone()
            .allowing_plain(true)
            .create_next()
            .expect("next generation");
        assert!(kek.join("kek-000002.plain").exists());
        assert_eq!(fs::read(kek.join("kek-000001.cred")).expect("kept"), sealed);
        assert!(broken.load(KekInit::Require).is_err());
        // A working tool reads the sealed file again and refuses the newer plain one.
        let ring = kek_dir(&kek, CredsKey::Auto, Some(&tool))
            .load(KekInit::Require)
            .expect("load");
        assert!(ring.active().id().starts_with("cred-1-"));
        assert_eq!(ring.refused().len(), 1);
        assert_eq!(ring.refused()[0].generation, 2);
    }

    #[test]
    fn plain_generations_stay_readable_once_the_tool_works() {
        let dir = TempDir::new("dir-plain-then-tool");
        let kek = dir.join("kek");
        let before = kek_dir(&kek, CredsKey::Auto, Some(&dir.join("gone")));
        let plain = before.load(KekInit::CreateIfMissing).expect("create");
        assert!(kek.join("kek-000001.plain").exists());

        let tool = fake_tool(&dir, "creds", false, NO_GATE);
        let after = kek_dir(&kek, CredsKey::Auto, Some(&tool));
        let ring = after.load(KekInit::Require).expect("plain still loads");
        assert_eq!(ring.active().id(), plain.active().id());
        assert!(ring.active().protection().is_weak());
        // The next rotation seals with the tool and retires the plain one.
        let next = after.create_next().expect("rotate");
        assert!(next.id().starts_with("cred-2-"));
        assert!(kek.join("kek-000002.cred").exists());
        let ring = after.load(KekInit::Require).expect("load");
        assert_eq!(ring.active().id(), next.id());
        assert_eq!(
            ring.retired_ids().collect::<Vec<_>>(),
            [plain.active().id()]
        );
    }

    /// Runs against the real tool when it works for the account running the tests (root, or
    /// a TPM2 the account may use); prints why and passes otherwise.
    #[test]
    fn the_real_systemd_creds_round_trips_when_it_is_usable() {
        let creds = match SystemdCredsSealer::try_probe(None, CredsKey::Auto) {
            Ok(creds) => creds,
            Err(reason) => {
                eprintln!("skipped: systemd-creds is not usable here: {reason}");
                return;
            }
        };
        eprintln!(
            "systemd-creds at {} ({}{}, tpm2: {})",
            creds.tool().display(),
            creds.mode(),
            if creds.is_user_scoped() {
                ""
            } else {
                ", system scope"
            },
            creds.protection() == KekProtection::SystemdCreds { tpm2: true },
        );
        let mut plaintext = vec![0u8, 10, 255, 7];
        plaintext.extend_from_slice(MARKER.as_bytes());
        let sealed = creds.seal("kek-000001", &plaintext).expect("seal");
        assert!(
            !String::from_utf8_lossy(&sealed).contains(MARKER),
            "the credential holds the plaintext"
        );
        let opened = creds.unseal("kek-000001", &sealed).expect("unseal");
        assert_eq!(opened.as_slice(), plaintext.as_slice());
        assert!(
            creds.unseal("kek-000002", &sealed).is_err(),
            "the label must be bound"
        );
        let mut damaged = sealed.clone();
        let middle = damaged.len() / 2;
        damaged[middle] = if damaged[middle] == b'A' { b'B' } else { b'A' };
        assert!(creds.unseal("kek-000001", &damaged).is_err());

        let dir = TempDir::new("real");
        let kek_dir = kek_dir(&dir.join("kek"), CredsKey::Auto, None);
        let ring = kek_dir.load(KekInit::CreateIfMissing).expect("create");
        let file = fs::read(dir.join("kek").join("kek-000001.cred")).expect("sealed file");
        assert!(!file.starts_with(b"TKEK"));
        let again = kek_dir.load(KekInit::Require).expect("load");
        assert_eq!(again.active().id(), ring.active().id());
    }
}
