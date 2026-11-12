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

export interface LiveMetrics {
  history: Accessor<MetricsHistory>;
  /** The stream's connection state (`idle` before it started). */
  state: Accessor<string>;
  /** The tiles' history; null until the stream's first `metrics.history`. */
  tiers: Accessor<HeldHistory | null>;
  /**
   * The moment the charts are drawn at, in seconds on the controller's clock: the end of the newest
   * sample plus the time since it arrived, at most `CLOCK_LEAD` past it; null before the first.
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

  /** The controller's time of the newest sample or history, kept with the browser's monotonic time it arrived at. */
  const mark = (stamp: string) => {
    const at = Date.parse(stamp) / 1000;
    if (!Number.isFinite(at) || (sampleAt !== null && at < sampleAt)) return;
    sampleAt = at;
    arrived = performance.now();
  };

  onMount(() => {
    const own = new EventStream({ baseTopics: [], ...options });
    const reopen = () => {
      setTiers(null);
      own.stop();
      own.start();
    };
    // An event handler: it reads the history it appends to, it does not track it.
    // eslint-disable-next-line solid/reactivity
    const off = own.subscribe("metrics", (event) => {
      if (event.data.kind === HISTORY_KIND) {
        const frame = event.data.history as HistoryFrame | undefined;
        if (frame?.figures) {
          setTiers(heldOf(frame));
          mark(frame.at);
        }
        return;
      }
      const snapshot = snapshotOf(event.data);
      if (!snapshot) return;
      setHistory((h) => pushSnapshot(h, snapshot, clusterLimit));
      mark(snapshot.cluster.at);
      const held = tiers();
      if (held && snapshot.closed) {
        const next = withClosed(held, snapshot.closed);
        if (next) setTiers(next);
        else reopen();
      }
    });
    const offReset = own.onReset("metrics", reopen);
    own.start();
    setStream(own);
    onCleanup(() => {
      off();
      offReset();
      own.stop();
    });
  });

  return {
    history,
    state: () => stream()?.state() ?? "idle",
    tiers,
    clock: () => (sampleAt === null ? null : sampleAt + Math.min(CLOCK_LEAD, (performance.now() - arrived) / 1000)),
  };
}
