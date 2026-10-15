// The live metrics of the start page (WP3.5, OPS-20), for administrators: a stream of its own
// on the `metrics` topic while the page is open (the server samples only while someone
// listens), the last minute of samples per controller and for the cluster, and one tile per
// figure: a number with an SI suffix and a sparkline of the minute, never a dial. A cluster
// shows the cluster's sum on every tile and one row per controller on the Raft tile; a single
// controller shows itself.
//
// Test ids: `metrics-tiles` (`data-state` the stream's connection state, `data-controllers`
// once a sample arrived), `metrics-waiting` until then, `metrics-tile-<name>` with `data-value`
// (the raw number, absent while unknown), `metrics-sparkline-<name>`, and on the Raft tile
// `metrics-raft-node` per controller (`data-node`, `data-role`, `data-lag`, `data-state`
// current, stale or unsupported).
import { createMemo, createSignal, For, onCleanup, onMount, Show, type JSX } from "solid-js";
import { EventStream, type EventStreamOptions } from "../api/events";
import { si } from "../app/format/si";
import { Si } from "../components/Si";
import { Sparkline } from "../components/Sparkline";
import { formatList, formatNumber, locale, t } from "../i18n";
import { storeRoleLabel } from "../shell/TopBar";
import {
  droppedBatches,
  emptyHistory,
  lagOf,
  pushSnapshot,
  sampleState,
  snapshotOf,
  tileValue,
  type MetricsHistory,
  type MetricsSample,
  type TileName,
} from "./metrics";
import "./metrics.css";

/** A quantile or rate in milliseconds or per second, with one decimal below ten. */
function decimal(value: number): string {
  return formatNumber(value, { maximumFractionDigits: Math.abs(value) < 10 ? 1 : 0 });
}

function Tile(props: {
  name: TileName;
  title: string;
  value: number | null | undefined;
  unit?: string;
  series: readonly (number | null)[];
  hint: string;
  children?: JSX.Element;
}) {
  const values = () =>
    formatList(
      props.series.filter((v): v is number => v !== null).map((v) => si(v, locale())),
      "unit",
    );
  return (
    <section class="card tile metrics-tile" data-testid={`metrics-tile-${props.name}`} data-value={props.value ?? undefined}>
      <h3>{props.title}</h3>
      <div class="tile-value">
        <Si value={props.value ?? null} />
        <Show when={props.unit && props.value != null}>
          <span class="metrics-unit">{props.unit}</span>
        </Show>
      </div>
      <Sparkline values={props.series} title={t("metrics.sparkline", { name: props.title, values: values() })} testId={`metrics-sparkline-${props.name}`} />
      <p class="muted">{props.hint}</p>
      {props.children}
    </section>
  );
}

export default function MetricsTiles(props: { streamOptions?: EventStreamOptions }) {
  const [history, setHistory] = createSignal<MetricsHistory>(emptyHistory());
  const [stream, setStream] = createSignal<EventStream>();

  onMount(() => {
    const own = new EventStream({ baseTopics: [], ...props.streamOptions });
    const off = own.subscribe("metrics", (event) => {
      const snapshot = snapshotOf(event.data);
      if (snapshot) setHistory((h) => pushSnapshot(h, snapshot));
    });
    own.start();
    setStream(own);
    onCleanup(() => {
      off();
      own.stop();
    });
  });

  const latest = () => history().latest;
  const cluster = (): MetricsSample | undefined => latest()?.cluster;
  const series = (name: TileName) => history().cluster.map((sample) => tileValue(name, sample));
  const value = (name: TileName) => {
    const sample = cluster();
    return sample ? tileValue(name, sample) : null;
  };
  const p = (key: "p50_ms" | "p99_ms") => cluster()?.api[key];
  const rows = createMemo(() => latest()?.nodes ?? []);

  return (
    <section class="dash-metrics" aria-labelledby="dash-metrics" data-testid="metrics-tiles" data-state={stream()?.state() ?? "idle"} data-controllers={latest() ? rows().length : undefined}>
      <h2 id="dash-metrics">
        {t("metrics.title")}
        <span class="aside">{t("metrics.sub")}</span>
      </h2>
      <Show when={!latest()}>
        <p class="muted" data-testid="metrics-waiting">
          {t("metrics.waiting")}
        </p>
      </Show>
      <div class="tiles">
        <Tile
          name="requests"
          title={t("metrics.tile.requests")}
          value={value("requests")}
          unit={t("metrics.unit.per_second")}
          series={series("requests")}
          hint={
            p("p50_ms") != null && p("p99_ms") != null
              ? t("metrics.tile.requests_hint", { p50: decimal(p("p50_ms")!), p99: decimal(p("p99_ms")!) })
              : t("metrics.tile.requests_idle")
          }
        />
        <Tile
          name="commit"
          title={t("metrics.tile.commit")}
          value={value("commit")}
          unit={t("metrics.unit.ms")}
          series={series("commit")}
          hint={cluster()?.store.commit_p99_ms != null ? t("metrics.tile.commit_hint") : t("metrics.tile.commit_idle")}
        />
        <Tile
          name="store"
          title={t("metrics.tile.store")}
          value={value("store")}
          unit={t("metrics.unit.bytes")}
          series={series("store")}
          hint={
            cluster()?.store.file_bytes != null
              ? t("metrics.tile.store_hint", { data: si(cluster()?.store.data_bytes ?? 0, locale()) })
              : t("metrics.tile.store_memory")
          }
        />
        <Tile
          name="raft"
          title={t("metrics.tile.raft")}
          value={value("raft")}
          series={series("raft")}
          hint={t("metrics.tile.raft_hint", { term: cluster()?.raft.term ?? 0 })}
        >
          <ul class="metrics-raft">
            <For each={rows()}>
              {(sample) => {
                const node = sample.node ?? 0;
                const lag = () => {
                  const snapshot = latest();
                  return snapshot ? lagOf(snapshot, node) : null;
                };
                return (
                  <li
                    data-testid="metrics-raft-node"
                    data-node={node}
                    data-role={sample.raft.role ?? undefined}
                    data-lag={lag() ?? undefined}
                    data-state={sampleState(sample)}
                  >
                    <span class="mono">{t("metrics.raft.node", { node: String(node) })}</span>
                    <span>
                      {sampleState(sample) === "unsupported"
                        ? t("metrics.raft.unsupported")
                        : sampleState(sample) === "stale"
                          ? t("metrics.raft.stale")
                          : storeRoleLabel(sample.raft.role ?? undefined)}
                    </span>
                    <span class="lag">{lag() == null ? "–" : t("metrics.raft.lag", { entries: lag()! })}</span>
                  </li>
                );
              }}
            </For>
          </ul>
        </Tile>
        <Tile
          name="jobs"
          title={t("metrics.tile.jobs")}
          value={value("jobs")}
          series={series("jobs")}
          hint={t("metrics.tile.jobs_hint", { waiting: cluster()?.jobs.waiting ?? 0 })}
        />
        <Tile
          name="ingest"
          title={t("metrics.tile.ingest")}
          value={value("ingest")}
          unit={t("metrics.unit.per_second")}
          series={series("ingest")}
          hint={t("metrics.tile.ingest_hint", { batches: decimal(cluster()?.ingest.batches_per_second ?? 0) })}
        />
        <Tile name="sse" title={t("metrics.tile.sse")} value={value("sse")} series={series("sse")} hint={t("metrics.tile.sse_hint")} />
        <Tile
          name="nodes"
          title={t("metrics.tile.nodes")}
          value={value("nodes")}
          series={series("nodes")}
          hint={(() => {
            const sample = cluster();
            const nodes = sample?.nodes.length ?? 0;
            const drops = sample ? droppedBatches(sample) : null;
            return drops == null ? t("metrics.tile.nodes_hint_unknown", { nodes }) : t("metrics.tile.nodes_hint", { nodes, drops });
          })()}
        />
      </div>
    </section>
  );
}
