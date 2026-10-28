// The live metrics (WP3.5, OPS-20), for administrators. U3: the start page draws them behind
// "Show all metrics" on its own stream (the `live` prop), the cluster page draws the controller's
// tiles alone (`only="controller"`) on a stream the tiles open themselves. The tiles keep their
// shape: a stream on the `metrics` topic while the page is open (the server samples only while
// someone listens), the last minute of samples per controller and for the cluster, and one tile per
// figure: a number with an SI suffix and a sparkline of the minute, never a dial. A cluster
// shows the cluster's sum on every tile and one row per controller on the Raft tile; a single
// controller shows itself.
//
// Every tile has the same shape and height whatever it holds: the title, the value line, a chart
// area of fixed height (the sparkline or the bars, with a list under them where the tile has
// one: the controllers, the RCODEs, the busiest lists) and a footer of two lines. A tile without
// data draws the empty baseline of its chart, so it looks like a full one. The tiles come in two
// groups, the controller's eight and, with the `dns` role, the DNS six (eight with the resolver's
// two of WP10.4, four to a row); metrics.css sizes the
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
// or idle, hidden while idle; the second line of the footer), `-dns-cache` (the hit ratio over the six completed buckets of 5 seconds in percent, and a `metrics-bars` chart of those six and the bucket in progress, drawn lighter; the buckets have fixed edges on the controller's clock and the chart shifts one step when a bucket completes),
// `-dns-answers` (the NOERROR share of the same 30 seconds, with the same `metrics-bars`, and `metrics-dns-rcode` per RCODE with `data-rcode` and `data-rate`, the mean per second over those 30 seconds), `-dns-blocked` (the top
// three lists as `metrics-dns-list` with `data-list` and `data-rate`), `-dns-upstreams`, and
// `-dns-encrypted` (without a number while the role serves neither DoT nor DoH).
//
// OPS-20: while the cluster's sample has `host` (the node read its CPU, memory or disk) the three host
// tiles follow the controller's under `metrics-group-host`: `metrics-tile-host-cpu` (the busy share
// of the CPU since the last reading, the 60 s sparkline), `-host-memory` (the share in use, the GiB
// in the hint) and `-host-disk` (the GiB available on the data directory's file system, the total in
// the hint). A figure the node did not read shows no number. While the status warns `node.disk.low`
// the disk tile has `data-state="low"` and the line `metrics-host-disk-low`.
//
// WP8.7: while the cluster's sample has `dhcp` (a controller runs the `dhcp` role) the six DHCP
// tiles follow under `metrics-group-dhcp`: `metrics-tile-dhcp-leases` (leases granted per second,
// the 60 s sparkline), `-dhcp-ack` (the REQUEST to ACK p99), `-dhcp-active` (active leases, the
// abandoned ones in the hint), `-dhcp-pools` (the fullest pool in percent, the three fullest as
// `metrics-dhcp-pool` with `data-scope` and `data-value` and a bar each), `-dhcp-naks` (NAKs and
// DECLINEs per second, `metrics-dhcp-nak` and `metrics-dhcp-decline`), `-dhcp-ddns` (names written
// per second, `metrics-dhcp-ddns` per outcome with `data-outcome`, the queue in the hint).
import { createMemo, For, Show, type JSX } from "solid-js";
import type { EventStreamOptions } from "../api/events";
import { si } from "../app/format/si";
import { Si } from "../components/Si";
import { Bars } from "../components/Bars";
import { Sparkline } from "../components/Sparkline";
import { formatList, formatNumber, locale, t } from "../i18n";
import { storeRoleLabel } from "../shell/TopBar";
import {
  BUCKET_SECONDS,
  BUCKETS,
  // WP8.7: the outcomes of the DDNS tile.
  DDNS_OUTCOMES,
  droppedBatches,
  // OPS-20: the host tiles' figures.
  GIB,
  HISTORY,
  lagOf,
  memoryUsed,
  ratioBuckets,
  RCODES,
  sampleState,
  tileValue,
  windowRate,
  windowRatio,
  topLists,
  // WP10.4
  VALIDATION_STATES,
  type MetricsDns,
  type RatioTile,
  type MetricsSample,
  type TileName,
} from "./metrics";
import { createLiveMetrics, type LiveMetrics } from "./liveMetrics";
import "./metrics.css";

/** A quantile or rate in milliseconds or per second, with one decimal below ten. */
function decimal(value: number): string {
  return formatNumber(value, { maximumFractionDigits: Math.abs(value) < 10 ? 1 : 0 });
}

/**
 * A mean rate per second: as `decimal`, but a rate below one keeps two decimals and a rate that is
 * not zero never reads as zero, so a tile with a few answers in half a minute does not show "0/s"
 * beside bars that show those answers.
 */
function rate(value: number): string {
  if (value > 0 && value < 0.01) return `<${formatNumber(0.01, { minimumFractionDigits: 2 })}`;
  if (value > 0 && value < 1) return formatNumber(value, { maximumFractionDigits: 2 });
  return decimal(value);
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
  /** The tile shows a condition the status warns about (the disk tile while `node.disk.low` is active): the warning style. */
  low?: boolean;
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
    <section
      class="card tile metrics-tile"
      classList={{ "metrics-low": props.low }}
      data-testid={`metrics-tile-${props.name}`}
      data-value={props.value ?? undefined}
      data-state={props.low ? "low" : undefined}
    >
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
            {(bars) => <Bars values={bars()} buckets={BUCKETS} partialLast title={t("metrics.bars", { name: props.title, seconds: BUCKET_SECONDS, values: shares() })} testId="metrics-bars" />}
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

/** The GiB of a byte count with one decimal. */
function gib(bytes: number | null | undefined): string {
  return formatNumber((bytes ?? 0) / GIB, { maximumFractionDigits: 1 });
}

/**
 * `diskLow` is the status warning `node.disk.low` of this node: the disk tile turns to the warning
 * style. U3: `live` is the stream of the page that shows the tiles (the start page shares its own);
 * without it the tiles open one of their own. `only="controller"` draws the controller's tiles
 * alone (the cluster page).
 */
export default function MetricsTiles(props: { streamOptions?: EventStreamOptions; diskLow?: boolean; live?: LiveMetrics; only?: "controller" }) {
  // The stream is chosen once, when the tiles mount.
  // eslint-disable-next-line solid/reactivity
  const live = props.live ?? createLiveMetrics(props.streamOptions);
  const history = live.history;
  const all = () => props.only !== "controller";

  const latest = () => history().latest;
  const cluster = (): MetricsSample | undefined => latest()?.cluster;
  // The newest minute: the start page keeps five minutes for its queries chart.
  const series = (name: TileName) => history().cluster.slice(-HISTORY).map((sample) => tileValue(name, sample));
  const ratioValue = (name: RatioTile) => (cluster()?.dns ? windowRatio(history(), name) : null);
  const ratioBars = (name: RatioTile) => ratioBuckets(history(), BUCKET_SECONDS, BUCKETS, name);
  // The rates beside the ratio tiles are means over the window of the headline (the completed buckets
  // of the last 30 seconds), so the numbers and the bars are made of the same samples.
  const meanRate = (pick: (dns: MetricsDns) => number) => windowRate(history(), pick) ?? 0;
  const value = (name: TileName) => {
    const sample = cluster();
    return sample ? tileValue(name, sample) : null;
  };
  const p = (key: "p50_ms" | "p99_ms") => cluster()?.api[key];
  const dns = () => cluster()?.dns ?? undefined;
  // WP8.7: the `dhcp` part of the cluster's sample.
  const dhcp = () => cluster()?.dhcp ?? undefined;
  // OPS-20: the `host` part of the cluster's sample.
  const host = () => cluster()?.host ?? undefined;
  const rows = createMemo(() => latest()?.nodes ?? []);

  return (
    <section class="dash-metrics" aria-labelledby="dash-metrics" data-testid="metrics-tiles" data-state={live.state()} data-controllers={latest() ? rows().length : undefined}>
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
        {/* OPS-20: the host's CPU, memory and disk, while a controller reports them. */}
        <Show when={all() && host()}>
          {(h) => (
            <>
              <h3 class="metrics-group" data-testid="metrics-group-host">
                {t("metrics.group.host")}
              </h3>
              <Tile
                name="host-cpu"
                title={t("metrics.host.cpu")}
                value={value("host-cpu")}
                unit={t("metrics.unit.percent")}
                series={series("host-cpu")}
                hint={h().cpu_percent != null ? t("metrics.host.cpu_hint") : t("metrics.host.cpu_none")}
              />
              <Tile
                name="host-memory"
                title={t("metrics.host.memory")}
                value={value("host-memory")}
                unit={t("metrics.unit.percent")}
                series={series("host-memory")}
                hint={
                  memoryUsed(h()) != null
                    ? t("metrics.host.memory_hint", { used: gib(memoryUsed(h())), total: gib(h().memory_total) })
                    : t("metrics.host.memory_none")
                }
              />
              <Tile
                name="host-disk"
                title={t("metrics.host.disk")}
                value={value("host-disk")}
                unit={t("metrics.host.unit_gib")}
                series={series("host-disk")}
                low={props.diskLow}
                hint={h().disk_total != null ? t("metrics.host.disk_hint", { total: gib(h().disk_total) }) : t("metrics.host.disk_none")}
                note={
                  <Show when={props.diskLow}>
                    <p class="metrics-warn" data-testid="metrics-host-disk-low">
                      {t("metrics.host.disk_low")}
                    </p>
                  </Show>
                }
              />
            </>
          )}
        </Show>
        <Show when={all() && dns()}>
          {(d) => (
            <>
              {/* WP10.4: with the resolver's two tiles the group has eight, laid out four to a row. */}
              <h3 class="metrics-group" classList={{ "metrics-group-wide": d().recursion != null }} data-testid="metrics-group-dns">
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
                hint={t("metrics.dns.cache_hint", { entries: si(d().cache.entries, locale()), stale: rate(meanRate((x) => x.cache.stale_per_second)) })}
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
                      <li data-testid="metrics-dns-rcode" data-rcode={rcode} data-rate={meanRate((x) => x.rcodes[rcode])}>
                        <span class={rcode === "other" ? undefined : "mono"}>{rcode === "other" ? t("metrics.dns.rcode_other") : rcode.toUpperCase()}</span>
                        <span class="rate">{t("metrics.dns.rate", { rate: rate(meanRate((x) => x.rcodes[rcode])) })}</span>
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
              {/* WP10.4: the resolver's sub-queries and validation outcomes, while it runs. */}
              <Show when={d().recursion}>
                {(r) => (
                  <>
                    <Tile
                      name="dns-subqueries"
                      title={t("metrics.dns.subqueries")}
                      value={value("dns-subqueries")}
                      unit={t("metrics.unit.per_second")}
                      series={series("dns-subqueries")}
                      hint={t("metrics.dns.subqueries_hint")}
                    />
                    <Tile
                      name="dns-validation"
                      title={t("metrics.dns.validation")}
                      value={value("dns-validation")}
                      unit={t("metrics.unit.per_second")}
                      series={series("dns-validation")}
                      hint={t("metrics.dns.validation_hint", { rate: decimal(r().validation.indeterminate) })}
                    >
                      <ul class="metrics-rows">
                        <For each={VALIDATION_STATES}>
                          {(state) => (
                            <li data-testid="metrics-dns-validation" data-state={state} data-rate={r().validation[state]}>
                              <span>{t(`metrics.dns.validation_${state}`)}</span>
                              <span class="rate">{t("metrics.dns.rate", { rate: decimal(r().validation[state]) })}</span>
                            </li>
                          )}
                        </For>
                      </ul>
                    </Tile>
                  </>
                )}
              </Show>
              {/* WP10.4: end. */}
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
        {/* WP8.7: the DHCP tiles, while a controller runs the `dhcp` role. */}
        <Show when={all() && dhcp()}>
          {(d) => (
            <>
              <h3 class="metrics-group" data-testid="metrics-group-dhcp">
                {t("metrics.group.dhcp")}
              </h3>
              <Tile
                name="dhcp-leases"
                title={t("metrics.dhcp.leases")}
                value={value("dhcp-leases")}
                unit={t("metrics.unit.per_second")}
                series={series("dhcp-leases")}
                hint={t("metrics.dhcp.leases_hint")}
              />
              <Tile
                name="dhcp-ack"
                title={t("metrics.dhcp.ack")}
                value={value("dhcp-ack")}
                unit={t("metrics.unit.ms")}
                series={series("dhcp-ack")}
                hint={d().ack_p99_ms != null ? t("metrics.dhcp.ack_hint") : t("metrics.dhcp.ack_idle")}
              />
              <Tile
                name="dhcp-active"
                title={t("metrics.dhcp.active")}
                value={value("dhcp-active")}
                series={series("dhcp-active")}
                hint={t("metrics.dhcp.active_hint", { abandoned: d().abandoned_leases })}
              />
              <Tile
                name="dhcp-pools"
                title={t("metrics.dhcp.pools")}
                value={value("dhcp-pools")}
                unit={t("metrics.unit.percent")}
                series={series("dhcp-pools")}
                hint={d().scopes > 0 ? t("metrics.dhcp.pools_hint", { scopes: d().scopes }) : t("metrics.dhcp.pools_none")}
              >
                <ul class="metrics-rows">
                  <For each={d().fullest}>
                    {(pool) => (
                      <li data-testid="metrics-dhcp-pool" data-scope={pool.scope} data-value={pool.utilization}>
                        <span class="mono">{pool.scope}</span>
                        <span class="metrics-pool-bar" aria-hidden="true">
                          <span style={{ "inline-size": `${Math.round(Math.min(1, Math.max(0, pool.utilization)) * 100)}%` }} />
                        </span>
                        <span class="rate">{formatNumber(pool.utilization, { style: "percent", maximumFractionDigits: 0 })}</span>
                      </li>
                    )}
                  </For>
                </ul>
              </Tile>
              <Tile
                name="dhcp-naks"
                title={t("metrics.dhcp.naks")}
                value={value("dhcp-naks")}
                unit={t("metrics.unit.per_second")}
                series={series("dhcp-naks")}
                hint={t("metrics.dhcp.naks_hint")}
              >
                <ul class="metrics-rows">
                  <li data-testid="metrics-dhcp-nak" data-rate={d().naks_per_second}>
                    <span>{t("metrics.dhcp.nak_row")}</span>
                    <span class="rate">{t("metrics.dns.rate", { rate: decimal(d().naks_per_second) })}</span>
                  </li>
                  <li data-testid="metrics-dhcp-decline" data-rate={d().declines_per_second}>
                    <span>{t("metrics.dhcp.decline_row")}</span>
                    <span class="rate">{t("metrics.dns.rate", { rate: decimal(d().declines_per_second) })}</span>
                  </li>
                </ul>
              </Tile>
              <Tile
                name="dhcp-ddns"
                title={t("metrics.dhcp.ddns")}
                value={value("dhcp-ddns")}
                unit={t("metrics.unit.per_second")}
                series={series("dhcp-ddns")}
                hint={t("metrics.dhcp.ddns_hint", { queue: d().ddns.queue, skipped: decimal(d().ddns.skipped), dropped: decimal(d().ddns.dropped) })}
              >
                <ul class="metrics-rows metrics-rows-pairs">
                  <For each={DDNS_OUTCOMES}>
                    {(outcome) => (
                      <li data-testid="metrics-dhcp-ddns" data-outcome={outcome} data-rate={d().ddns[outcome]}>
                        <span>{t(`metrics.dhcp.ddns_outcome.${outcome}`)}</span>
                        <span class="rate">{t("metrics.dns.rate", { rate: decimal(d().ddns[outcome]) })}</span>
                      </li>
                    )}
                  </For>
                </ul>
              </Tile>
            </>
          )}
        </Show>
      </div>
    </section>
  );
}
