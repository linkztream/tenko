// The live metrics of the start page (WP3.5, OPS-20), for administrators: a stream of its own
// on the `metrics` topic while the page is open (the server samples only while someone
// listens), the last minute of samples per controller and for the cluster, and one tile per
// figure: a number with an SI suffix and a sparkline of the minute, never a dial. A cluster
// shows the cluster's sum on every tile and one row per controller on the Raft tile; a single
// controller shows itself.
//
// Every tile has the same shape and height whatever it holds: the title, the value line, a chart
// area of fixed height (the sparkline or the bars, with a list under them where the tile has
// one: the controllers, the RCODEs, the busiest lists) and a footer of two lines. A tile without
// data draws the empty baseline of its chart, so it looks like a full one. The tiles come in two
// groups, the controller's eight and, with the `dns` role, the DNS six; metrics.css sizes the
// columns so that every row of a group is full.
//
// Test ids: `metrics-tiles` (`data-state` the stream's connection state, `data-controllers`
// once a sample arrived), `metrics-waiting` until then, `metrics-tile-<name>` with `data-value`
// (the raw number, absent while unknown), `metrics-sparkline-<name>` (the ratio tiles draw `metrics-bars` instead,
// with `metrics-window` for the line that says the window), and on the Raft tile
// `metrics-raft-node` per controller (`data-node`, `data-role`, `data-lag`, `data-state`
// current, stale or unsupported).
//
// The group headings are `metrics-group-controller` and `metrics-group-dns`.
// While the cluster's sample has `dns` (a controller runs the `dns` role) the DNS tiles follow:
// `metrics-tile-dns-queries` (with `metrics-dns-log-dropped`, always present: `data-state` dropping
// or idle, hidden while idle; the second line of the footer), `-dns-cache` (the hit ratio of the last 30 seconds in percent, and a `metrics-bars` chart of 12 buckets of 5 seconds),
// `-dns-answers` (the NOERROR share of the last 30 seconds, with the same `metrics-bars`, and `metrics-dns-rcode` per RCODE with `data-rcode` and `data-rate`), `-dns-blocked` (the top
// three lists as `metrics-dns-list` with `data-list` and `data-rate`), `-dns-upstreams`, and
// `-dns-encrypted` (without a number while the role serves neither DoT nor DoH).
import { createMemo, createSignal, For, onCleanup, onMount, Show, type JSX } from "solid-js";
import { EventStream, type EventStreamOptions } from "../api/events";
import { si } from "../app/format/si";
import { Si } from "../components/Si";
import { Bars } from "../components/Bars";
import { Sparkline } from "../components/Sparkline";
import { formatList, formatNumber, locale, t } from "../i18n";
import { storeRoleLabel } from "../shell/TopBar";
import {
  BUCKET_SECONDS,
  BUCKETS,
  droppedBatches,
  emptyHistory,
  lagOf,
  pushSnapshot,
  ratioBuckets,
  RCODES,
  sampleState,
  snapshotOf,
  tileValue,
  windowRatio,
  topLists,
  type MetricsHistory,
  type RatioTile,
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
  series?: readonly (number | null)[];
  /** The bars of a ratio tile (fractions, oldest first) instead of the sparkline; then `windowHint` says the window. */
  bars?: readonly (number | null)[];
  windowHint?: string;
  /** The line under the chart; with a `windowHint` or a `note` both are short and get one line each, alone it may take two. */
  hint: string;
  /** A second line of the footer, under the hint (the warning of the queries tile). */
  note?: JSX.Element;
  /** A list under the chart, inside the chart area: the chart gives it the room it needs. */
  children?: JSX.Element;
}) {
  const values = () =>
    formatList(
      (props.series ?? []).filter((v): v is number => v !== null).map((v) => si(v, locale())),
      "unit",
    );
  const shares = () =>
    formatList(
      (props.bars ?? []).filter((v): v is number => v !== null).map((v) => formatNumber(v, { style: "percent", maximumFractionDigits: 0 })),
      "unit",
    );
  return (
    <section class="card tile metrics-tile" data-testid={`metrics-tile-${props.name}`} data-value={props.value ?? undefined}>
      <h4>{props.title}</h4>
      <div class="tile-value">
        <Si value={props.value ?? null} />
        <Show when={props.unit && props.value != null}>
          <span class="metrics-unit">{props.unit}</span>
        </Show>
      </div>
      <div class="metrics-chart">
        <div class="metrics-plot">
          <Show
            when={props.bars}
            fallback={<Sparkline values={props.series ?? []} title={t("metrics.sparkline", { name: props.title, values: values() })} testId={`metrics-sparkline-${props.name}`} />}
          >
            {(bars) => <Bars values={bars()} buckets={BUCKETS} title={t("metrics.bars", { name: props.title, seconds: BUCKET_SECONDS, values: shares() })} testId="metrics-bars" />}
          </Show>
        </div>
        {props.children}
      </div>
      <div class="metrics-foot">
        <Show when={props.windowHint}>
          <p class="muted" data-testid="metrics-window">
            {props.windowHint}
          </p>
        </Show>
        <Show when={props.hint}>
          <p class="muted">{props.hint}</p>
        </Show>
        {props.note}
      </div>
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
  const ratioValue = (name: RatioTile) => (cluster()?.dns ? windowRatio(history(), name) : null);
  const ratioBars = (name: RatioTile) => ratioBuckets(history(), BUCKET_SECONDS, BUCKETS, name);
  const value = (name: TileName) => {
    const sample = cluster();
    return sample ? tileValue(name, sample) : null;
  };
  const p = (key: "p50_ms" | "p99_ms") => cluster()?.api[key];
  const dns = () => cluster()?.dns ?? undefined;
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
      <div class="metrics-grid">
        <h3 class="metrics-group" data-testid="metrics-group-controller">
          {t("metrics.group.controller")}
        </h3>
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
        <Show when={dns()}>
          {(d) => (
            <>
              <h3 class="metrics-group" data-testid="metrics-group-dns">
                {t("metrics.group.dns")}
              </h3>
              <Tile
                name="dns-queries"
                title={t("metrics.dns.queries")}
                value={value("dns-queries")}
                unit={t("metrics.unit.per_second")}
                series={series("dns-queries")}
                hint={
                  d().p50_ms != null && d().p99_ms != null
                    ? t("metrics.dns.queries_hint", { p50: decimal(d().p50_ms!), p99: decimal(d().p99_ms!) })
                    : t("metrics.dns.queries_idle")
                }
                note={
                  <p class="metrics-warn" data-testid="metrics-dns-log-dropped" data-state={d().log_dropped_per_second > 0 ? "dropping" : "idle"}>
                    {d().log_dropped_per_second > 0 ? t("metrics.dns.log_dropped", { rate: decimal(d().log_dropped_per_second) }) : ""}
                  </p>
                }
              />
              <Tile
                name="dns-cache"
                title={t("metrics.dns.cache")}
                value={ratioValue("dns-cache")}
                unit={t("metrics.unit.percent")}
                bars={ratioBars("dns-cache")}
                windowHint={t("metrics.dns.cache_window")}
                hint={t("metrics.dns.cache_hint", { entries: si(d().cache.entries, locale()), stale: decimal(d().cache.stale_per_second) })}
              />
              <Tile
                name="dns-answers"
                title={t("metrics.dns.answers")}
                value={ratioValue("dns-answers")}
                unit={t("metrics.unit.percent")}
                bars={ratioBars("dns-answers")}
                windowHint={t("metrics.dns.answers_hint")}
                hint=""
              >
                <ul class="metrics-rows metrics-rows-pairs">
                  <For each={RCODES}>
                    {(rcode) => (
                      <li data-testid="metrics-dns-rcode" data-rcode={rcode} data-rate={d().rcodes[rcode]}>
                        <span class={rcode === "other" ? undefined : "mono"}>{rcode === "other" ? t("metrics.dns.rcode_other") : rcode.toUpperCase()}</span>
                        <span class="rate">{t("metrics.dns.rate", { rate: decimal(d().rcodes[rcode]) })}</span>
                      </li>
                    )}
                  </For>
                </ul>
              </Tile>
              <Tile
                name="dns-blocked"
                title={t("metrics.dns.blocked")}
                value={value("dns-blocked")}
                unit={t("metrics.unit.per_second")}
                series={series("dns-blocked")}
                hint={d().blocked.length > 0 ? t("metrics.dns.blocked_hint", { lists: d().blocked.length }) : t("metrics.dns.blocked_none")}
              >
                <ul class="metrics-rows">
                  <For each={topLists(d())}>
                    {(list) => (
                      <li data-testid="metrics-dns-list" data-list={list.list} data-rate={list.per_second}>
                        <span class="mono">{list.list}</span>
                        <span class="rate">{t("metrics.dns.rate", { rate: decimal(list.per_second) })}</span>
                      </li>
                    )}
                  </For>
                </ul>
              </Tile>
              <Tile
                name="dns-upstreams"
                title={t("metrics.dns.upstreams")}
                value={value("dns-upstreams")}
                unit={t("metrics.unit.per_second")}
                series={series("dns-upstreams")}
                hint={d().upstreams.p99_ms != null ? t("metrics.dns.upstreams_hint", { p99: decimal(d().upstreams.p99_ms!) }) : t("metrics.dns.upstreams_idle")}
              />
              <Tile
                name="dns-encrypted"
                title={t("metrics.dns.encrypted")}
                value={value("dns-encrypted")}
                series={series("dns-encrypted")}
                hint={(() => {
                  const c = d().connections;
                  return c ? t("metrics.dns.encrypted_hint", { dot: c.dot, doh: c.doh }) : t("metrics.dns.encrypted_none");
                })()}
              />
            </>
          )}
        </Show>
      </div>
    </section>
  );
}
