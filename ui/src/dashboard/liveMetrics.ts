// The `metrics` stream of a page (OPS-20): one stream of its own on the topic while the calling
// component is mounted (the server samples only while someone listens), the samples kept as a
// `MetricsHistory`. The start page opens one and hands it to its DNS and DHCP panels, its
// controller blocks and, behind "Show all metrics", the tiles (U3), so one page never listens
// twice; the tiles open their own where they stand alone (the cluster page).
import { createSignal, onCleanup, onMount, type Accessor } from "solid-js";
import { EventStream, type EventStreamOptions } from "../api/events";
import { emptyHistory, HISTORY, pushSnapshot, snapshotOf, type MetricsHistory } from "./metrics";

export interface LiveMetrics {
  history: Accessor<MetricsHistory>;
  /** The stream's connection state (`idle` before it started). */
  state: Accessor<string>;
}

/**
 * Opens the stream when the calling component mounts and closes it when it goes. The cluster's
 * series keeps `clusterLimit` samples (a minute by default).
 */
export function createLiveMetrics(options?: EventStreamOptions, clusterLimit = HISTORY): LiveMetrics {
  const [history, setHistory] = createSignal<MetricsHistory>(emptyHistory());
  const [stream, setStream] = createSignal<EventStream>();

  onMount(() => {
    const own = new EventStream({ baseTopics: [], ...options });
    const off = own.subscribe("metrics", (event) => {
      const snapshot = snapshotOf(event.data);
      if (snapshot) setHistory((h) => pushSnapshot(h, snapshot, clusterLimit));
    });
    own.start();
    setStream(own);
    onCleanup(() => {
      off();
      own.stop();
    });
  });

  return { history, state: () => stream()?.state() ?? "idle" };
}
