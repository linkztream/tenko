//! Test support for every crate of the workspace (feature `testing`, never in a release build):
//! a wait for a named condition, a free loopback port that stays held until the server takes
//! it, and a temporary directory that is removed when the test ends. These are the only copies:
//! `scripts/test-lint.mjs` reports a local `wait_until`, `wait_for`, `eventually`, `until`,
//! `udp_port` or `free_port` in test code (`docs/testing/rules.md`).
//!
//! # Waiting
//!
//! A test that needs another thread, task or process to reach a state waits until a check says
//! it has, never for a guessed time. [`wait_until`] (and [`wait_until_async`] in an async test)
//! calls the check until it is ready and returns at once, so a quiet machine pays nothing for
//! the generous limit ([`WAIT_LIMIT`], 30 s) that a loaded one needs. A check answers
//! - `bool`: ready when `true`;
//! - `Option<T>`: ready with the value when `Some`;
//! - `Result<T, E>`: ready with the value when `Ok`; an `Err` is the state observed so far,
//!   and the last one is printed when the wait gives up.
//!
//! The wait returns only after a check said ready: when the limit is reached it panics with
//! the condition's name, the caller's place, the time waited, the number of checks and the
//! last observed state. The limit is measured in real time, also under a paused Tokio clock,
//! where the pauses between checks advance the clock instead.

use std::{
    fmt::Debug,
    net::{Ipv4Addr, Ipv6Addr, TcpListener, UdpSocket},
    panic::Location,
    path::{Path, PathBuf},
    sync::{
        Mutex, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

/// How long a wait lasts before it fails the test.
pub const WAIT_LIMIT: Duration = Duration::from_secs(30);

/// The first pause between two checks; it doubles up to [`LONGEST_PAUSE`].
const FIRST_PAUSE: Duration = Duration::from_millis(5);

/// The longest pause between two checks.
const LONGEST_PAUSE: Duration = Duration::from_millis(100);

/// What a check of a wait answers: ready with a value, or the state observed so far.
pub trait Ready {
    /// What the wait returns once the check is ready.
    type Value;

    /// `Ok` with the value when ready, otherwise the observed state, if the check names one.
    ///
    /// # Errors
    ///
    /// The observed state when the condition does not hold yet.
    fn ready(self) -> Result<Self::Value, Option<String>>;
}

impl Ready for bool {
    type Value = ();

    fn ready(self) -> Result<(), Option<String>> {
        if self { Ok(()) } else { Err(None) }
    }
}

impl<T> Ready for Option<T> {
    type Value = T;

    fn ready(self) -> Result<T, Option<String>> {
        self.ok_or(None)
    }
}

impl<T, E: Debug> Ready for Result<T, E> {
    type Value = T;

    fn ready(self) -> Result<T, Option<String>> {
        self.map_err(|state| Some(format!("{state:?}")))
    }
}

/// The pacing of one wait: when to check again, and when to give up.
struct Pace {
    what: String,
    at: &'static Location<'static>,
    limit: Duration,
    started: Instant,
    pause: Duration,
    checks: u32,
}

impl Pace {
    fn new(what: &str, at: &'static Location<'static>, limit: Duration) -> Self {
        Self {
            what: what.to_owned(),
            at,
            limit,
            started: Instant::now(),
            pause: FIRST_PAUSE,
            checks: 0,
        }
    }

    /// Records a check that was not ready; answers the pause before the next check, or panics
    /// with the diagnostics when the limit is reached.
    fn after_miss(&mut self, state: Option<String>) -> Duration {
        self.checks += 1;
        let waited = self.started.elapsed();
        if waited >= self.limit {
            let state = state.unwrap_or_else(|| "the check names none".to_owned());
            panic!(
                "gave up waiting for {} (at {}) after {waited:?} (limit {:?}, {} checks); \
                 last observed state: {state}",
                self.what, self.at, self.limit, self.checks
            );
        }
        let pause = self.pause.min(self.limit.saturating_sub(waited));
        self.pause = (self.pause * 2).min(LONGEST_PAUSE);
        pause
    }
}

/// Waits up to [`WAIT_LIMIT`] until `check` is ready (see [`Ready`]) and returns its value.
/// `what` names the condition for the failure message. Not for async tests: it blocks the
/// thread, use [`wait_until_async`] there.
///
/// # Panics
///
/// When the check is not ready within the limit, with the diagnostics of the module
/// documentation; a panic of the check itself passes through.
#[track_caller]
pub fn wait_until<R: Ready>(what: &str, check: impl FnMut() -> R) -> R::Value {
    wait_until_within(what, WAIT_LIMIT, check)
}

/// [`wait_until`] with a limit of its own, for a wait that legitimately takes longer than
/// [`WAIT_LIMIT`] (a cluster election under load, a backoff the product must sit out).
///
/// # Panics
///
/// As [`wait_until`].
#[track_caller]
pub fn wait_until_within<R: Ready>(
    what: &str,
    limit: Duration,
    mut check: impl FnMut() -> R,
) -> R::Value {
    let mut pace = Pace::new(what, Location::caller(), limit);
    loop {
        match check().ready() {
            Ok(value) => return value,
            Err(state) => std::thread::sleep(pace.after_miss(state)),
        }
    }
}

/// [`wait_until`] for async tests: `check` is an async closure (`async || ...`), and the pauses
/// between checks are Tokio sleeps, so the runtime keeps driving the tasks the test waits for.
///
/// # Panics
///
/// As [`wait_until`]. The failure message names the caller's place, since an async function
/// cannot carry it in its panic location.
#[track_caller]
pub fn wait_until_async<R: Ready>(
    what: &str,
    check: impl AsyncFnMut() -> R,
) -> impl Future<Output = R::Value> {
    wait_until_async_within(what, WAIT_LIMIT, check)
}

/// [`wait_until_async`] with a limit of its own (see [`wait_until_within`]).
///
/// # Panics
///
/// As [`wait_until`].
#[track_caller]
pub fn wait_until_async_within<R: Ready>(
    what: &str,
    limit: Duration,
    mut check: impl AsyncFnMut() -> R,
) -> impl Future<Output = R::Value> {
    let mut pace = Pace::new(what, Location::caller(), limit);
    async move {
        loop {
            match check().await.ready() {
                Ok(value) => return value,
                Err(state) => tokio::time::sleep(pace.after_miss(state)).await,
            }
        }
    }
}

/// The ports [`free_port`] hands out: below the ephemeral range of Linux (32768 and up, the
/// ports the kernel gives to `bind(0)` and to every outgoing connection), of Windows and of
/// macOS (49152 and up), so that no client or server of the suite is given a picked port by
/// the system.
const PORT_POOL: std::ops::Range<u16> = 20_000..32_000;

/// How often a pick is tried before the helper gives up (a pool full of ports in use is a
/// broken machine, not a race).
const PORT_PICKS: u32 = 500;

/// A loopback port for TCP and UDP alike, held by a bound TCP listener and a bound UDP socket
/// on `127.0.0.1` until [`release`](Self::release) or the drop, so that no other test, of this
/// process or another, can take it in the meantime. Release it right before the server under
/// test binds it.
#[derive(Debug)]
pub struct FreePort {
    port: u16,
    held: Option<(TcpListener, UdpSocket)>,
}

impl FreePort {
    /// The port number; the port stays held.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Stops holding the port and answers its number, for a server that binds it next.
    pub fn release(mut self) -> u16 {
        self.held = None;
        self.port
    }
}

/// A free loopback port, held until released (see [`FreePort`]). The port is drawn at random
/// from a pool below the ephemeral ranges, was free on `127.0.0.1` and `::1` (where the machine
/// has IPv6) for TCP and UDP when picked, and is never handed out twice in a process. Between
/// the release and the server's bind another process can still take it; a harness that starts
/// a server on a picked port retries the start on a new port when the bind fails.
///
/// # Panics
///
/// When no port of the pool is free after 500 picks.
pub fn free_port() -> FreePort {
    static PICKS: AtomicU64 = AtomicU64::new(0);
    static HANDED_OUT: Mutex<Vec<u16>> = Mutex::new(Vec::new());
    let span = u64::from(PORT_POOL.end - PORT_POOL.start);
    for _ in 0..PORT_PICKS {
        // Random per process (the hasher's keys) and different on every call.
        let draw = std::hash::BuildHasher::hash_one(
            &std::hash::RandomState::new(),
            PICKS.fetch_add(1, Ordering::Relaxed),
        );
        let port = PORT_POOL.start + u16::try_from(draw % span).expect("below the pool's end");
        let mut handed_out = HANDED_OUT.lock().unwrap_or_else(PoisonError::into_inner);
        if handed_out.contains(&port) {
            continue;
        }
        let Some(held) = hold(port) else { continue };
        handed_out.push(port);
        return FreePort {
            port,
            held: Some(held),
        };
    }
    panic!("no free loopback port in {PORT_POOL:?} after {PORT_PICKS} picks");
}

/// Binds `port` on `127.0.0.1` for TCP and UDP and keeps both, when `::1` (where the machine has
/// IPv6 on the loopback) is free for both as well.
fn hold(port: u16) -> Option<(TcpListener, UdpSocket)> {
    let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).ok()?;
    let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).ok()?;
    // A machine without IPv6 on the loopback cannot bind there at all: no reason to skip.
    let v6_usable = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).is_ok();
    let v6_free = !v6_usable
        || (TcpListener::bind((Ipv6Addr::LOCALHOST, port)).is_ok()
            && UdpSocket::bind((Ipv6Addr::LOCALHOST, port)).is_ok());
    v6_free.then_some((tcp, udp))
}

/// A directory under the system's temporary directory, made by [`TempDir::new`] and removed
/// with its contents when dropped.
///
/// A removal that fails (on Windows, a file another process still holds open) is retried
/// until [`WAIT_LIMIT`], then fails the test with the path and the error: a test that leaves
/// a handle behind has a fault worth seeing. When the test is failing already the directory is
/// kept for inspection and its path printed, so the guard never replaces the test's own
/// failure with its own.
#[derive(Debug)]
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// Creates an empty directory named after `label`, the process and a counter.
    ///
    /// # Panics
    ///
    /// When the directory cannot be created.
    pub fn new(label: &str) -> Self {
        static MADE: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_nanos());
        let path = std::env::temp_dir().join(format!(
            "tenko-{label}-{}-{}-{nanos}",
            std::process::id(),
            MADE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path)
            .unwrap_or_else(|error| panic!("create {}: {error}", path.display()));
        Self { path }
    }

    /// The directory.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// A path inside the directory.
    pub fn join(&self, name: impl AsRef<Path>) -> PathBuf {
        self.path.join(name)
    }
}

impl AsRef<Path> for TempDir {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!(
                "the test failed: its temporary directory is kept at {}",
                self.path.display()
            );
            return;
        }
        let path = &self.path;
        wait_until(
            &format!("the removal of {}", path.display()),
            || match std::fs::remove_dir_all(path) {
                Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error),
                _ => Ok(()),
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cell::Cell,
        panic::{AssertUnwindSafe, catch_unwind},
    };

    use super::*;

    fn panic_text(payload: &(dyn std::any::Any + Send)) -> String {
        payload
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_owned()))
            .unwrap_or_default()
    }

    #[test]
    fn a_wait_returns_the_value_of_the_first_ready_check() {
        let calls = Cell::new(0);
        let value = wait_until("the third call", || {
            calls.set(calls.get() + 1);
            (calls.get() == 3).then_some(calls.get() * 10)
        });
        assert_eq!(value, 30);
        assert_eq!(calls.get(), 3);
    }

    #[test]
    fn a_wait_that_never_holds_fails_with_its_name_and_last_state() {
        let calls = Cell::new(0_u32);
        let failure = catch_unwind(AssertUnwindSafe(|| {
            // test-lint: allow deadline the giving up is what this test checks
            wait_until_within("a door that stays shut", Duration::from_millis(50), || {
                calls.set(calls.get() + 1);
                Err::<(), _>(format!("shut after {} looks", calls.get()))
            });
        }))
        .expect_err("the wait gives up");
        let text = panic_text(failure.as_ref());
        assert!(text.contains("a door that stays shut"), "{text}");
        assert!(
            text.contains(&format!("\"shut after {} looks\"", calls.get())),
            "{text}"
        );
        assert!(text.contains(file!()), "names the caller: {text}");
    }

    #[test]
    fn a_wait_checks_at_least_once_even_with_no_time_left() {
        let value = wait_until_within("an immediate answer", Duration::ZERO, || Some(7));
        assert_eq!(value, 7);
        let failure = catch_unwind(|| wait_until_within("never", Duration::ZERO, || false))
            .expect_err("a false check with no time left fails");
        assert!(panic_text(failure.as_ref()).contains("1 checks"));
    }

    #[tokio::test]
    async fn an_async_wait_lets_the_runtime_drive_what_it_waits_for() {
        let (sender, receiver) = tokio::sync::watch::channel(0_u32);
        tokio::spawn(async move {
            for n in 1..=3 {
                tokio::task::yield_now().await;
                sender.send(n).expect("the receiver lives");
            }
        });
        let seen = wait_until_async("the third value", async || {
            let now = *receiver.borrow();
            (now == 3).then_some(now)
        })
        .await;
        assert_eq!(seen, 3);
    }

    #[test]
    fn a_held_port_cannot_be_bound_until_released() {
        let held = free_port();
        let port = held.port();
        let in_use = std::io::ErrorKind::AddrInUse;
        let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).expect_err("TCP is held");
        assert_eq!(tcp.kind(), in_use, "{tcp}");
        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).expect_err("UDP is held");
        assert_eq!(udp.kind(), in_use, "{udp}");
        assert_ne!(free_port().port(), port, "never handed out twice");
        assert_eq!(held.release(), port);
        UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).expect("free after the release");
    }

    #[test]
    fn a_temporary_directory_is_removed_with_its_contents() {
        let dir = TempDir::new("guard");
        let path = dir.path().to_owned();
        std::fs::create_dir(dir.join("inner")).expect("a subdirectory");
        std::fs::write(dir.join("inner").join("file"), b"x").expect("a file");
        drop(dir);
        assert!(!path.exists());
    }

    #[test]
    fn a_failing_test_keeps_its_directory_and_its_own_failure() {
        let mut kept = None;
        let failure = catch_unwind(AssertUnwindSafe(|| {
            let dir = TempDir::new("guard-failing");
            kept = Some(dir.path().to_owned());
            panic!("the test's own failure");
        }))
        .expect_err("the test fails");
        assert_eq!(panic_text(failure.as_ref()), "the test's own failure");
        let kept = kept.expect("the directory was made");
        assert!(kept.exists());
        std::fs::remove_dir_all(&kept).expect("clean up");
    }
}
