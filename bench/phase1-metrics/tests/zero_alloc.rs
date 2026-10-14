//! The zero-allocation check of the metrics core: a counting global allocator around a
//! million `inc` and `observe` calls on sealed families, on one thread and on four.
//!
//! The Tenko workspace forbids `unsafe` code. A global allocator can only be written as an
//! `unsafe impl GlobalAlloc`, so this check lives in this benchmark package, outside the
//! workspace, and this file is the only one of the package that allows `unsafe`. The
//! allocator forwards every call to the system allocator unchanged and only counts.
#![allow(unsafe_code)]

use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};

use tenko_core::metrics::{Counter, CounterVec, Desc, Histogram, HistogramVec};

thread_local! {
    /// Whether this thread's allocations are counted. Both thread-locals are
    /// const-initialized without a destructor, so reading them never allocates.
    static COUNTING: Cell<bool> = const { Cell::new(false) };
    /// The allocations this thread made while it counted.
    static ALLOCATIONS: Cell<u64> = const { Cell::new(0) };
}

fn note() {
    if COUNTING.with(Cell::get) {
        ALLOCATIONS.with(|count| count.set(count.get() + 1));
    }
}

/// The allocations this thread made while it counted.
fn allocations() -> u64 {
    ALLOCATIONS.with(Cell::get)
}

struct CountingAllocator;

// SAFETY: every method forwards to `System` with the same arguments; the counting touches
// only const-initialized thread-locals, which never allocate.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        note();
        // SAFETY: the caller's contract is passed on unchanged.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        note();
        // SAFETY: as above.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        note();
        // SAFETY: as above.
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: as above.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

const BOUNDS: &[u64] = &[
    250, 500, 1_000, 2_500, 5_000, 10_000, 25_000, 50_000, 100_000, 250_000, 500_000, 1_000_000,
    2_500_000, 5_000_000, 10_000_000,
];

static REQUESTS: CounterVec =
    CounterVec::new(Desc::counter("alloc_requests", "Requests.").labels(&["route", "status"]));
static DURATION: HistogramVec = HistogramVec::new(
    Desc::histogram("alloc_duration_seconds", "Duration.", BOUNDS, 1_000_000).labels(&["class"]),
);
static EVENTS: Counter = Counter::new(Desc::counter("alloc_events", "Events."));
static SINGLE: Histogram = Histogram::new(Desc::histogram(
    "alloc_single_seconds",
    "One.",
    BOUNDS,
    1_000_000,
));

/// Seals the families (this allocates, once).
fn seal() {
    let routes = ["/api/v1/health", "/api/v1/prefixes/{id}", "other"];
    let statuses = ["200", "404", "other"];
    let rows: Vec<[&str; 2]> = routes
        .iter()
        .flat_map(|route| statuses.iter().map(move |status| [*route, *status]))
        .collect();
    let rows: Vec<&[&str]> = rows.iter().map(<[&str; 2]>::as_slice).collect();
    REQUESTS.seal(&rows);
    DURATION.seal(&[&["health"], &["prefixes"], &["other"]]);
    // A family that seals itself does so at its first use, before any counting.
    EVENTS.inc();
    SINGLE.observe(1);
}

/// `n` updates of every family on the calling thread; returns the allocations they made.
fn updates(n: u64) -> u64 {
    // The first update picks the thread's shard; do it before counting.
    REQUESTS.inc(0);
    COUNTING.with(|counting| counting.set(true));
    let before = allocations();
    for i in 0..n {
        let series = u16::try_from(i % 9).expect("small");
        let class = u16::try_from(i % 3).expect("small");
        REQUESTS.inc(series);
        REQUESTS.add(series, 2);
        DURATION.observe(class, i % 12_000_000);
        EVENTS.inc();
        SINGLE.observe(i % 3_000);
    }
    let after = allocations();
    COUNTING.with(|counting| counting.set(false));
    after - before
}

#[test]
fn a_million_updates_on_one_thread_and_on_four_allocate_nothing() {
    seal();
    assert_eq!(updates(1_000_000), 0, "allocations on one thread");

    let threads: Vec<_> = (0..4)
        .map(|_| std::thread::spawn(|| updates(250_000)))
        .collect();
    let allocations: u64 = threads
        .into_iter()
        .map(|thread| thread.join().expect("worker"))
        .sum();
    assert_eq!(allocations, 0, "allocations on four threads");

    // The updates were all counted: 2,000,000 iterations of three units each, plus the
    // five warm-up increments of series 0.
    let total: u64 = (0..9).map(|series| REQUESTS.get(series)).sum();
    assert_eq!(total, 2_000_000 * 3 + 5);
    let observed: u64 = (0..3).map(|class| DURATION.get(class).count()).sum();
    assert_eq!(observed, 2_000_000);
    assert_eq!(EVENTS.get(), 2_000_001);
    assert_eq!(SINGLE.get().count(), 2_000_001);
}

#[test]
fn the_counting_allocator_counts() {
    COUNTING.with(|counting| counting.set(true));
    let before = allocations();
    let boxed = std::hint::black_box(Box::new(42_u64));
    let after = allocations();
    COUNTING.with(|counting| counting.set(false));
    drop(boxed);
    assert!(after > before, "a box is an allocation");
}
