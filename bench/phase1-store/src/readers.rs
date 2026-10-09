//! Paced reader threads that look up random existing keys in a [`BenchIndex`] and record the
//! latency of every lookup.
//!
//! The lookups of a window are paced against the clock: every thread issues the number of
//! lookups that are due each millisecond, back to back, and times each one. The latency is the
//! time of one lookup, not the time since it was due. A lookup that finds nothing is an
//! "empty read"; a lookup that finds a value for another record is a "mismatch".

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use hdrhistogram::Histogram;
use serde::{Deserialize, Serialize};

use crate::{
    common::{Latency, Rng, count_f64, due_count, new_hist, record_ns, summarize},
    data,
    index::BenchIndex,
};

/// What a window of lookups measured.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Window {
    pub secs: f64,
    pub lookups: u64,
    pub lookups_per_s: f64,
    pub latency: Latency,
    pub empty_reads: u64,
    pub mismatches: u64,
}

#[derive(Debug)]
struct Outcome {
    hist: Histogram<u64>,
    empty: u64,
    mismatches: u64,
}

/// Reader threads running against one index.
#[derive(Debug)]
pub struct ReaderPool {
    stop: Arc<AtomicBool>,
    recording: Arc<AtomicBool>,
    handles: Vec<JoinHandle<Outcome>>,
    recording_since: Option<Instant>,
}

impl ReaderPool {
    /// Starts `threads` readers that together issue `total_rate` lookups per second for
    /// random ids in `0..id_space`. Nothing is recorded until [`ReaderPool::record`].
    pub fn start(
        index: &Arc<BenchIndex>,
        threads: usize,
        total_rate: u64,
        id_space: u64,
        seed: u64,
    ) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let recording = Arc::new(AtomicBool::new(false));
        let per_thread = (total_rate / u64::try_from(threads.max(1)).unwrap_or(1)).max(1);
        let handles = (0..threads)
            .map(|thread_no| {
                let index = Arc::clone(index);
                let stop = Arc::clone(&stop);
                let recording = Arc::clone(&recording);
                let seed = seed ^ (u64::try_from(thread_no).unwrap_or(0) << 32);
                thread::spawn(move || reader(&index, &stop, &recording, per_thread, id_space, seed))
            })
            .collect();
        Self {
            stop,
            recording,
            handles,
            recording_since: None,
        }
    }

    /// Starts recording latencies from now on.
    pub fn record(&mut self) {
        self.recording_since = Some(Instant::now());
        self.recording.store(true, Ordering::SeqCst);
    }

    /// Stops the readers and returns what they recorded.
    pub fn finish(self) -> Window {
        self.stop.store(true, Ordering::SeqCst);
        let secs = self
            .recording_since
            .map_or(0.0, |since| since.elapsed().as_secs_f64());
        let mut hist = new_hist();
        let (mut empty, mut mismatches) = (0, 0);
        for handle in self.handles {
            if let Ok(outcome) = handle.join() {
                let _ = hist.add(&outcome.hist);
                empty += outcome.empty;
                mismatches += outcome.mismatches;
            }
        }
        let latency = summarize(&hist);
        Window {
            secs,
            lookups: latency.count,
            lookups_per_s: if secs > 0.0 {
                count_f64(latency.count) / secs
            } else {
                0.0
            },
            latency,
            empty_reads: empty,
            mismatches,
        }
    }
}

fn reader(
    index: &BenchIndex,
    stop: &AtomicBool,
    recording: &AtomicBool,
    rate: u64,
    id_space: u64,
    seed: u64,
) -> Outcome {
    let mut rng = Rng::new(seed);
    let mut outcome = Outcome {
        hist: new_hist(),
        empty: 0,
        mismatches: 0,
    };
    let start = Instant::now();
    let mut issued = 0_u64;
    // A stall never turns into a longer burst than this many lookups.
    let max_burst = (rate / 10).max(16);
    while !stop.load(Ordering::Relaxed) {
        let due = due_count(start.elapsed(), rate);
        let burst = due.saturating_sub(issued).min(max_burst);
        issued = due;
        let active = recording.load(Ordering::Relaxed);
        for _ in 0..burst {
            let id = rng.below(id_space);
            let key = data::key_array(id);
            let began = Instant::now();
            let found = index.get(&key);
            let elapsed = began.elapsed();
            if !active {
                continue;
            }
            record_ns(&mut outcome.hist, elapsed.as_nanos());
            match found {
                None => outcome.empty += 1,
                Some(value) => {
                    if data::id_of(&value) != Some(id) {
                        outcome.mismatches += 1;
                    }
                }
            }
        }
        thread::sleep(Duration::from_micros(500));
    }
    outcome
}
