//! The clock guard: whether this node's wall clock may be believed (OPS-09).
//!
//! A **look** reads the monotonic clock, the wall clock and the monotonic clock again; a look
//! whose two monotonic reads lie more than 100 ms apart is dropped, since a pause between the
//! reads would read as a jump. The **offset** of a look is its wall time minus the monotonic
//! time since the first look. The wall clock **jumped** when the offset differs by more than
//! [`TOLERANCE`] from the previous look's, or from the **mark**: the offset of a look taken
//! while trusted and refreshed once it is [`WINDOW`] old, so that small steps that add up are
//! seen too. The jump `J` is the offset now minus the mark's, the offset at which the clock was
//! last trusted; the mark stays where it was while the clock is held, and `J` is measured
//! again at every look.
//!
//! While held, [`trusted_now`] refuses, so a round that destroys by the wall clock (expiry,
//! purges, prunes) waits; [`plausible_now`] refuses what other machines judge by this time
//! (certificates, signatures). A hold ends when a person confirms the clock ([`confirm`]), or
//! when a hold made while the node ran sees `J` fall back within [`TOLERANCE`]. For destruction
//! only, it also ends after the node waited, in monotonic time, as long as the largest `|J|`
//! since the wait began, when that is at most [`SELF_RELEASE_MAX`]; a further step of the
//! clock during a hold holds issuing too, and growth past the tolerance starts the wait again.
//! Issuing stays held until a person confirms. Agreement with the clocks of other nodes is a
//! further way out ([`Release::Reference`]) that this module does not decide yet.
//!
//! The server binary carries the state across a restart ([`saved`], [`restore`]): a saved hold
//! is held again from the start of its wait, both answers as they were, and a start more than
//! [`TOLERANCE`] away from the last trusted time is a hold of that gap ([`Reason::StartGap`]).
//! A start gap never widens [`forward_hold`], since it is mostly real downtime, and a forward
//! one holds destruction only, unless issuing was held already. A forward jump made while the
//! node ran keeps feeding [`forward_hold`] across a restart, by its own saved amount and from
//! its own saved reading.
//!
//! One guard per process, behind one lock: every call looks. Tests drive [`Guard`] with
//! synthetic instants; [`testing::hold`] and [`testing::hold_issuing`] hold the clock for the
//! calling thread alone.

use std::{
    sync::{
        LazyLock, Mutex, PoisonError,
        atomic::{AtomicI64, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};

use crate::Timestamp;

/// How far two readings of the time may differ and still agree: a jump of the wall clock, and
/// the clocks of two controllers (R35).
pub const TOLERANCE: Duration = Duration::from_secs(5);

/// How old the mark of a trusted look becomes before it is refreshed.
pub const WINDOW: Duration = Duration::from_secs(60);

/// The largest jump after which destruction resumes by itself, after waiting as long.
pub const SELF_RELEASE_MAX: Duration = Duration::from_secs(24 * 60 * 60);

/// Finding code of a hold that ends by itself.
pub const JUMPED: &str = "sys.clock.jumped";

/// Finding code of a hold that a person ends (`POST /system/clock/confirm`).
pub const HELD: &str = "sys.clock.held";

/// A look whose two monotonic reads lie further apart is dropped.
const TORN: Duration = Duration::from_millis(100);

const TOLERANCE_NS: u128 = TOLERANCE.as_nanos();

/// Why the clock is held.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    /// The wall clock jumped while the node ran.
    Jump,
    /// The node started away from the last time it trusted.
    StartGap,
    /// The clocks of other nodes disagree with this one.
    Disagrees,
}

impl Reason {
    /// The `snake_case` name, as stored and in finding parameters.
    // copy-lint: allow name-ladder three names; the code-list macro is planned and not yet built
    pub const fn as_str(self) -> &'static str {
        match self {
            Reason::Jump => "jump",
            Reason::StartGap => "start_gap",
            Reason::Disagrees => "disagrees",
        }
    }
}

/// What ends a hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Release {
    /// Waiting until [`Held::until`].
    Wait,
    /// A person confirming the clock.
    Person,
    /// The clocks of other nodes agreeing.
    Reference,
}

/// A held clock: why, by how much, since when and what ends it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Held {
    /// Why.
    pub reason: Reason,
    /// The jump `J` in milliseconds, negative when the clock went back.
    pub jump_ms: i64,
    /// When the hold began, by the wall clock.
    pub since: Timestamp,
    /// What ends it.
    pub release: Release,
    /// When the wait ends, by the wall clock, while it is [`Release::Wait`].
    pub until: Option<Timestamp>,
}

const fn held_before() -> bool {
    true
}

/// A hold as the server binary keeps it across a restart. A file without the two answers
/// holds both.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedHold {
    /// Why.
    pub reason: Reason,
    /// The jump in milliseconds.
    pub jump_ms: i64,
    /// When the hold began.
    pub since: Timestamp,
    /// Whether destruction is held.
    #[serde(default = "held_before")]
    pub destroy: bool,
    /// Whether issuing is held.
    #[serde(default = "held_before")]
    pub issue: bool,
    /// The forward jump made while the node ran, in milliseconds, which [`forward_hold`]
    /// waits out.
    #[serde(default)]
    pub forward_ms: i64,
    /// The wall reading [`forward_hold`] counts from, while it has a forward amount; a file
    /// without it counts from `last_trusted_at`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forward_from: Option<Timestamp>,
}

/// The guard's state as the server binary keeps it across a restart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Saved {
    /// The wall time of the last look made while destruction was trusted.
    pub last_trusted_at: Timestamp,
    /// The hold, if any.
    pub held: Option<SavedHold>,
}

#[derive(Debug, Clone)]
struct Hold {
    reason: Reason,
    since: Timestamp,
    /// The offset at which the clock was last trusted.
    base: i128,
    /// `J` at the last look.
    jump: i128,
    /// When the wait began, and `J` then.
    wait: (Instant, Timestamp, i128),
    destroy: bool,
    issue: bool,
    /// The forward part of a jump made while running; a start gap never sets it.
    forward: i128,
    /// The last wall reading before the jump, or before its last growth past the tolerance:
    /// what was written at or before it is judged by the clock before the jump.
    from: Timestamp,
}

impl Hold {
    fn new(
        reason: Reason,
        since: Timestamp,
        (base, jump): (i128, i128),
        at: (Instant, Timestamp),
        issue: bool,
    ) -> Self {
        Self {
            reason,
            since,
            base,
            jump,
            wait: (at.0, at.1, jump),
            destroy: true,
            issue,
            forward: if reason == Reason::Jump {
                jump.max(0)
            } else {
                0
            },
            from: since,
        }
    }

    /// How long destruction waits from the start of the wait: the largest `|J|` since.
    fn need(&self) -> u128 {
        self.jump.unsigned_abs().max(self.wait.2.unsigned_abs())
    }

    fn held(&self, release: Release) -> Held {
        let need = Duration::from_nanos(u64::try_from(self.need()).unwrap_or(u64::MAX));
        Held {
            reason: self.reason,
            jump_ms: i64::try_from(self.jump / 1_000_000).unwrap_or(i64::MAX),
            since: self.since,
            release,
            until: (release == Release::Wait)
                .then(|| self.wait.1.checked_add(need))
                .flatten(),
        }
    }
}

/// The state and the rule, driven by looks. Pure: the tests give it synthetic instants.
#[derive(Debug, Clone)]
pub struct Guard {
    anchor: Instant,
    prev: i128,
    mark: (Instant, i128),
    last: (Instant, Timestamp),
    last_trusted: Timestamp,
    hold: Option<Hold>,
}

fn nanos(duration: Duration) -> i128 {
    i128::try_from(duration.as_nanos()).unwrap_or(i128::MAX)
}

impl Guard {
    /// A guard whose first look is (`mono`, `wall`), restored from `saved`. A saved hold of
    /// destruction at least as large as the gap since the last trusted time is held again with
    /// its wait from the start; a larger gap is a [`Reason::StartGap`] hold that keeps a held
    /// issuing; a short restart keeps a hold of issuing alone as it was. Without a saved hold,
    /// a gap over [`TOLERANCE`] is a [`Reason::StartGap`].
    pub fn start(saved: Option<Saved>, mono: Instant, wall: Timestamp) -> Self {
        let offset = wall.unix_nanos();
        let mut guard = Self {
            anchor: mono,
            prev: offset,
            mark: (mono, offset),
            last: (mono, wall),
            last_trusted: wall,
            hold: None,
        };
        let Some(saved) = saved else { return guard };
        let gap = offset - saved.last_trusted_at.unix_nanos();
        let far = gap.unsigned_abs() > TOLERANCE_NS;
        let from = saved
            .held
            .as_ref()
            .and_then(|held| held.forward_from)
            .unwrap_or(saved.last_trusted_at);
        let (reason, since, jump, destroy, issue, forward_ms) = match saved.held {
            Some(held) => {
                let jump = i128::from(held.jump_ms) * 1_000_000;
                // Never more than the saved jump forward, whatever the file says.
                let forward_ms = held.forward_ms.clamp(0, held.jump_ms.max(0));
                if held.destroy && jump.unsigned_abs() >= gap.unsigned_abs() {
                    (held.reason, held.since, jump, true, held.issue, forward_ms)
                } else if far {
                    let issue = held.issue || gap < 0;
                    (Reason::StartGap, wall, gap, true, issue, forward_ms)
                } else {
                    let (destroy, issue) = (held.destroy, held.issue);
                    (held.reason, held.since, jump, destroy, issue, forward_ms)
                }
            }
            None if far => (Reason::StartGap, wall, gap, true, gap < 0, 0),
            None => return guard,
        };
        guard.last_trusted = saved.last_trusted_at;
        let mut hold = Hold::new(reason, since, (offset - jump, jump), (mono, wall), issue);
        hold.destroy = destroy;
        hold.forward = i128::from(forward_ms) * 1_000_000;
        hold.from = from;
        guard.hold = (destroy || issue).then_some(hold);
        guard
    }

    /// One look: `before` and `after` are the monotonic reads around the wall read `wall`.
    pub fn look_at(&mut self, before: Instant, wall: Timestamp, after: Instant) {
        if after.saturating_duration_since(before) > TORN {
            return;
        }
        let offset = wall.unix_nanos() - nanos(before.saturating_duration_since(self.anchor));
        let previous = self.last.1;
        self.last = (before, wall);
        if let Some(hold) = &mut self.hold {
            let jump = offset - hold.base;
            // Only a hold made while running knows the offset at which it was trusted.
            if hold.reason != Reason::StartGap && jump.unsigned_abs() <= TOLERANCE_NS {
                self.release(offset);
                return;
            }
            if hold.destroy {
                hold.jump = jump;
                if hold.reason == Reason::Jump {
                    hold.forward = jump.max(0);
                }
                if (jump - hold.wait.2).unsigned_abs() > TOLERANCE_NS {
                    // The clock stepped again: what this node issues is held too.
                    hold.issue = true;
                }
                if jump.unsigned_abs() > hold.wait.2.unsigned_abs() + TOLERANCE_NS {
                    hold.wait = (before, wall, jump);
                    // What was written before this step counts as from before the jump.
                    hold.from = previous;
                } else if hold.need() <= SELF_RELEASE_MAX.as_nanos()
                    && before.saturating_duration_since(hold.wait.0).as_nanos() >= hold.need()
                {
                    hold.destroy = false;
                    // Waited out: a later restart must not bring it back.
                    hold.forward = 0;
                    if !hold.issue {
                        self.hold = None;
                    }
                    self.mark = (before, offset);
                    self.last_trusted = wall;
                }
                self.prev = offset;
                return;
            }
        }
        if (offset - self.prev).unsigned_abs() > TOLERANCE_NS
            || (offset - self.mark.1).unsigned_abs() > TOLERANCE_NS
        {
            let base = self.mark.1;
            self.hold = Some(Hold {
                from: self.last_trusted,
                ..Hold::new(
                    Reason::Jump,
                    wall,
                    (base, offset - base),
                    (before, wall),
                    true,
                )
            });
        } else {
            self.last_trusted = wall;
            if before.saturating_duration_since(self.mark.0) >= WINDOW {
                self.mark = (before, offset);
            }
        }
        self.prev = offset;
    }

    fn release(&mut self, offset: i128) {
        self.hold = None;
        self.mark = (self.last.0, offset);
        self.prev = offset;
        self.last_trusted = self.last.1;
    }

    /// Ends every hold: a person confirmed the clock as of the last look.
    pub fn confirm(&mut self) {
        let offset =
            self.last.1.unix_nanos() - nanos(self.last.0.saturating_duration_since(self.anchor));
        self.release(offset);
    }

    /// Whether a round may destroy by the wall clock.
    ///
    /// # Errors
    ///
    /// The hold, with [`Release::Wait`] and its end, or [`Release::Person`] above
    /// [`SELF_RELEASE_MAX`].
    pub fn trusted(&self) -> Result<(), Held> {
        match &self.hold {
            Some(hold) if hold.destroy => {
                Err(hold.held(if hold.need() <= SELF_RELEASE_MAX.as_nanos() {
                    Release::Wait
                } else {
                    Release::Person
                }))
            }
            _ => Ok(()),
        }
    }

    /// Whether this time may go into something other machines judge.
    ///
    /// # Errors
    ///
    /// The hold; a person ends it.
    pub fn plausible(&self) -> Result<(), Held> {
        match &self.hold {
            Some(hold) if hold.issue => Err(hold.held(Release::Person)),
            _ => Ok(()),
        }
    }

    /// The forward jump that the reuse of another client's address waits out, while a runtime
    /// jump holds destruction, and the reading it counts from: what was written at or before
    /// it is from before the jump.
    ///
    /// The reading is the last trusted look before the jump plus [`TOLERANCE`], so the second
    /// between that look and the jump counts as before it, and never after the current wait
    /// began. When the jump grows past the tolerance, it moves to the look before that further
    /// step: what was written between the steps is then judged earlier by the whole jump, so
    /// it is kept up to the first jump too long, never freed early.
    pub fn forward_hold(&self) -> Option<(Duration, Timestamp)> {
        self.hold
            .as_ref()
            .filter(|hold| hold.destroy && hold.forward > 0)
            .map(|hold| {
                let jump = Duration::from_nanos(u64::try_from(hold.forward).unwrap_or(u64::MAX));
                let from = hold.from.checked_add(TOLERANCE).unwrap_or(hold.from);
                (jump, from.min(hold.wait.1))
            })
    }

    /// The state to keep across a restart.
    pub fn saved(&self) -> Saved {
        Saved {
            last_trusted_at: self.last_trusted,
            held: self.hold.as_ref().map(|hold| {
                let held = hold.held(Release::Person);
                SavedHold {
                    reason: held.reason,
                    jump_ms: held.jump_ms,
                    since: held.since,
                    destroy: hold.destroy,
                    issue: hold.issue,
                    forward_ms: i64::try_from(hold.forward / 1_000_000).unwrap_or(i64::MAX),
                    forward_from: (hold.forward > 0).then_some(hold.from),
                }
            }),
        }
    }

    fn look(&mut self) -> Timestamp {
        let before = Instant::now();
        let wall = Timestamp::now();
        let after = Instant::now();
        self.look_at(before, wall, after);
        wall
    }
}

static GUARD: LazyLock<Mutex<Guard>> =
    LazyLock::new(|| Mutex::new(Guard::start(None, Instant::now(), Timestamp::now())));

/// The jump of [`forward_hold`] in milliseconds, 0 for none.
static FORWARD_MS: AtomicU64 = AtomicU64::new(0);

/// The trusted reading of [`forward_hold`] in Unix nanoseconds, read only while
/// [`FORWARD_MS`] is not 0; stored before it.
static FORWARD_FROM_NS: AtomicI64 = AtomicI64::new(0);

fn with<T>(f: impl FnOnce(&mut Guard) -> T) -> T {
    let mut guard = GUARD.lock().unwrap_or_else(PoisonError::into_inner);
    let out = f(&mut guard);
    let (ms, from) = guard.forward_hold().map_or((0, 0), |(jump, from)| {
        (
            u64::try_from(jump.as_millis()).unwrap_or(u64::MAX),
            // Out of range reads as late: more is judged from before the jump, never less.
            i64::try_from(from.unix_nanos()).unwrap_or(i64::MAX),
        )
    });
    FORWARD_FROM_NS.store(from, Ordering::Relaxed);
    FORWARD_MS.store(ms, Ordering::Release);
    out
}

/// Takes a look (the server's sampler, every second).
pub fn look() {
    with(|guard| {
        guard.look();
    });
}

/// The wall time, when a round may destroy by it.
///
/// # Errors
///
/// The hold while the clock is held for destruction.
pub fn trusted_now() -> Result<Timestamp, Held> {
    if let Some((held, destroy)) = testing::current() {
        return if destroy {
            Err(held)
        } else {
            Ok(Timestamp::now())
        };
    }
    with(|guard| {
        let wall = guard.look();
        guard.trusted().map(|()| wall)
    })
}

/// The wall time, when it may go into something other machines judge (a certificate, a
/// signature).
///
/// # Errors
///
/// The hold while the clock is held for issuing.
pub fn plausible_now() -> Result<Timestamp, Held> {
    if let Some((held, destroy)) = testing::current() {
        return if destroy && held.reason == Reason::StartGap && held.jump_ms > 0 {
            Ok(Timestamp::now())
        } else {
            Err(held)
        };
    }
    with(|guard| {
        let wall = guard.look();
        guard.plausible().map(|()| wall)
    })
}

/// The forward jump during a runtime hold of destruction and the reading it counts from
/// ([`Guard::forward_hold`]). A binding whose client time is not later than that reading is
/// from before the jump, so its end is on the clock before it and its reuse is judged earlier
/// by the jump; one written since, also in the second before the guard's next look, carries
/// the jumped clock and is judged as it is. One atomic load, and a second only while a jump
/// is held.
pub fn forward_hold() -> Option<(Duration, Timestamp)> {
    if let Some((held, destroy)) = testing::current() {
        return (destroy && held.reason == Reason::Jump && held.jump_ms > 0).then(|| {
            (
                Duration::from_millis(held.jump_ms.unsigned_abs()),
                held.since,
            )
        });
    }
    match FORWARD_MS.load(Ordering::Acquire) {
        0 => None,
        ms => {
            let from = i128::from(FORWARD_FROM_NS.load(Ordering::Relaxed));
            let from = Timestamp::from_unix_nanos(from).unwrap_or(Timestamp::UNIX_EPOCH);
            Some((Duration::from_millis(ms), from))
        }
    }
}

/// Ends every hold: a person confirmed the clock (on this thread, a test's hold too).
pub fn confirm() {
    testing::clear();
    with(|guard| {
        guard.look();
        guard.confirm();
    });
}

/// The state to keep across a restart, after a look.
pub fn saved() -> Saved {
    with(|guard| {
        guard.look();
        guard.saved()
    })
}

/// Starts the guard again from the state a previous run kept (`None`: no file).
pub fn restore(saved: Option<Saved>) {
    with(|guard| *guard = Guard::start(saved, Instant::now(), Timestamp::now()));
}

/// A held clock for one test thread (feature `testing`): [`trusted_now`], [`plausible_now`]
/// and [`forward_hold`] answer from the value of [`hold`] or [`hold_issuing`] on the thread
/// that set it, read before the guard, until the returned [`Override`] is dropped or
/// [`confirm`] runs there. A `#[tokio::test]` runs on one thread, so other tests never see it.
#[cfg(any(test, feature = "testing"))]
pub mod testing {
    use std::{cell::RefCell, marker::PhantomData};

    use super::{Held, Reason, Release};
    use crate::Timestamp;

    thread_local! {
        static HELD: RefCell<Option<(Held, bool)>> = const { RefCell::new(None) };
    }

    /// Holds destruction on this thread, and issuing as `held` says (all but a forward start
    /// gap), until the value is dropped. A forward `Jump` gives `forward_hold` its `jump_ms`
    /// and its `since` as the last reading trusted before it.
    #[must_use = "the hold ends when the value is dropped"]
    pub fn hold(held: Held) -> Override {
        set(held, true)
    }

    /// Holds destruction and issuing on this thread as a forward jump of `jump_ms` made
    /// while running does, until the value is dropped; `forward_hold` answers the jump and
    /// `trusted` as the last reading before it.
    #[must_use = "the hold ends when the value is dropped"]
    pub fn hold_jump(jump_ms: i64, trusted: Timestamp) -> Override {
        hold(Held {
            reason: Reason::Jump,
            jump_ms,
            since: trusted,
            release: Release::Wait,
            until: None,
        })
    }

    /// Holds issuing alone on this thread, as after a wait that ended, until the value is
    /// dropped.
    #[must_use = "the hold ends when the value is dropped"]
    pub fn hold_issuing(held: Held) -> Override {
        set(held, false)
    }

    fn set(held: Held, destroy: bool) -> Override {
        HELD.with(|cell| *cell.borrow_mut() = Some((held, destroy)));
        Override(PhantomData)
    }

    /// The hold of [`hold`]; it stays on its thread.
    #[derive(Debug)]
    pub struct Override(PhantomData<*const ()>);

    impl Drop for Override {
        fn drop(&mut self) {
            clear();
        }
    }

    pub(super) fn current() -> Option<(Held, bool)> {
        HELD.with(|cell| cell.borrow().clone())
    }

    pub(super) fn clear() {
        HELD.with(|cell| cell.borrow_mut().take());
    }
}

#[cfg(not(any(test, feature = "testing")))]
mod testing {
    pub(super) fn current() -> Option<(super::Held, bool)> {
        None
    }

    pub(super) fn clear() {}
}

#[cfg(test)]
mod tests;
