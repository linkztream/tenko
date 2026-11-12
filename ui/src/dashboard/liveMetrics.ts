// The `metrics` stream of a page (OPS-20): one stream of its own on the topic while the calling
// component is mounted, the samples kept as a `MetricsHistory`, and the tiles' two days of history
// (history.ts): the stream's first event `metrics.history`, then the `closed` buckets of each
// snapshot. A hole in the buckets, a figure or tier the history lacks, or the stream's `reset`
// opens the stream again, and the server's next first event is a fresh history. The start page
// opens one and hands it to its DNS and DHCP panels, its controller blocks and, behind "Show all
// metrics", the tiles (U3), so one page never listens twice; the tiles open their own where they
// stand alone (the cluster page).
import { createSignal, onCleanup, onMount, type Accessor } from "solid-js";
import { EventStream, type EventStreamOptions } from "../api/events";
import { heldOf, HISTORY_KIND, withClosed, type HeldHistory, type HistoryFrame } from "./history";
import { emptyHistory, HISTORY, pushSnapshot, snapshotOf, type MetricsHistory } from "./metrics";

/** How far the drawn moment may run past the newest sample: a late sample pauses the chart rather than leaving a gap. */
const CLOCK_LEAD = 1.5;
/**
 * The waits before the stream is opened again for a fresh history: at once the first time, then
 * from 5 s doubling to a minute, so a mismatch that persists does not fetch the history every second;
 * a minute without one starts over.
 */
const REOPEN_FIRST_MS = 5000;
const REOPEN_MAX_MS = 60_000;

export interface LiveMetrics {
  history: Accessor<MetricsHistory>;
  /** The stream's connection state (`idle` before it started). */
  state: Accessor<string>;
  /** The tiles' history; null until the stream's first `metrics.history`. */
  tiers: Accessor<HeldHistory | null>;
  /**
   * The moment the charts are drawn at, in seconds on the controller's clock: the end of the newest
   * sample plus the time since it arrived, at most `CLOCK_LEAD` past it and never back within one
   * stream; null before the first.
   */
  clock: () => number | null;
}

/**
 * Opens the stream when the calling component mounts and closes it when it goes. The cluster's
 * series keeps `clusterLimit` samples (a minute by default).
 */
export function createLiveMetrics(options?: EventStreamOptions, clusterLimit = HISTORY): LiveMetrics {
  const [history, setHistory] = createSignal<MetricsHistory>(emptyHistory());
  const [tiers, setTiers] = createSignal<HeldHistory | null>(null);
  const [stream, setStream] = createSignal<EventStream>();
  let sampleAt: number | null = null;
  let arrived = 0;
  let shown = -Infinity;

  /**
   * The controller's time of the newest sample, with the browser's monotonic time it arrived at. A
   * sample a little older than the newest is out of order and ignored; a history (another controller
   * may serve it) or a clock that stepped back by more starts the moment over.
   */
  const mark = (stamp: string, fresh: boolean) => {
    const at = Date.parse(stamp) / 1000;
    const back = sampleAt !== null && at < sampleAt;
    if (!Number.isFinite(at) || (back && !fresh && sampleAt! - at < 5)) return;
    sampleAt = at;
    arrived = performance.now();
    if (fresh || back) shown = -Infinity;
  };

  onMount(() => {
    const own = new EventStream({ baseTopics: [], ...options });
    // The held history no longer matches the stream: no `closed` is applied until a fresh history.
    let stale = false;
    let reopens = 0;
    let lastReopen = -Infinity;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const reopen = () => {
      stale = true;
      if (timer !== undefined) return;
      const now = performance.now();
      if (now - lastReopen > REOPEN_MAX_MS) reopens = 0;
      const wait = reopens === 0 ? 0 : Math.min(REOPEN_MAX_MS, REOPEN_FIRST_MS * 2 ** (reopens - 1));
      reopens += 1;
      timer = setTimeout(() => {
        timer = undefined;
        lastReopen = performance.now();
        own.stop();
        own.start();
      }, wait);
    };
    // An event handler: it reads the history it appends to, it does not track it.
    // eslint-disable-next-line solid/reactivity
    const off = own.subscribe("metrics", (event) => {
      if (event.data.kind === HISTORY_KIND) {
        const frame = event.data.history as HistoryFrame | undefined;
        if (frame?.figures) {
          stale = false;
          setTiers(heldOf(frame));
          mark(frame.at, true);
        }
        return;
      }
      const snapshot = snapshotOf(event.data);
      if (!snapshot) return;
      setHistory((h) => pushSnapshot(h, snapshot, clusterLimit));
      mark(snapshot.cluster.at, false);
      const held = tiers();
      if (held && !stale && snapshot.closed) {
        const next = withClosed(held, snapshot.closed);
        if (next) setTiers(next);
        else reopen();
      }
    });
    const offReset = own.onReset("metrics", reopen);
    own.start();
    setStream(own);
    onCleanup(() => {
      clearTimeout(timer);
      off();
      offReset();
      own.stop();
    });
  });

  return {
    history,
    state: () => stream()?.state() ?? "idle",
    tiers,
    clock: () => {
      if (sampleAt === null) return null;
      // A sample that arrives late but ends little later would step the charts back: they wait instead.
      shown = Math.max(shown, sampleAt + Math.min(CLOCK_LEAD, (performance.now() - arrived) / 1000));
      return shown;
    },
  };
}
