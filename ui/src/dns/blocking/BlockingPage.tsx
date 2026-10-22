// The blocking view of the DNS area (/dns/blocking): the home view of the node's query log and
// the block lists. For a window of 24 hours or 7 days (`?window=7d`) it shows the pause of the
// block lists with its buttons for those who may write DNS, four figures (queries, blocked with
// its share, answered from the cache, clients), the queries per hour as bars with the blocked
// part marked, the queries blocked per list, the names blocked and asked most often, the
// clients that asked most often and the newest blocked queries, each with an "Allow" button
// that adds the name to an allow list and starts the compile job of its next version.
//
// The figures are read from the log of the node, so a node whose log is off shows a notice that
// says where the log is turned on. What the log keeps of the client decides what the client
// columns show: a pseudonym (one per client and day), an address (only for those who may update
// the node) or nothing. Nothing is drawn with a chart library: the bars are boxes.
//
// Test ids: `page-dns-blocking`; `blocking-window-24h` and `-7d`, `blocking-short-log`,
// `blocking-truncated`, `blocking-period`, `blocking-sample`; `blocking-pause` (`data-state`
// on, timed or open) with `blocking-pause-status`, `blocking-pause-left`, `blocking-pause-5`,
// `-15`, `-60`, `-open` and `blocking-resume`; `blocking-tile-queries`, `-blocked` (with
// `blocking-share`), `-cached` and `-clients`; `blocking-hours` with `blocking-hour` per hour;
// `blocking-lists` with `blocking-list` per list; `blocking-top-blocked` and `blocking-top-names`
// with `blocking-name`; `blocking-clients` with `blocking-client` and `blocking-clients-note`;
// `blocking-recent` with `blocking-recent-row`, `blocking-allow` per row and
// `blocking-allow-result` (`data-state` added or already) with `blocking-allow-job`;
// `blocking-log-off` with `blocking-settings-link`; `blocking-next`.
import { A, useSearchParams } from "@solidjs/router";
import { createEffect, createMemo, createResource, createSignal, For, Match, on, onCleanup, Show, Switch, type JSX } from "solid-js";
import { ApiError } from "../../api/problem";
import { paths } from "../../app/paths";
import { Icon } from "../../components/Icon";
import { ErrorNotice, Notice } from "../../components/Notice";
import { PageHead } from "../../components/PageHead";
import { formatDateTime, formatDuration, formatNumber, t } from "../../i18n";
import { mayWriteDns } from "../access";
import { DnsNav } from "../DnsNav";
import { DnsProblem, unavailable } from "../Parts";
import { dnsPaths } from "../paths";
import {
  allowName,
  blockingStats,
  pauseBlocking,
  resumeBlocking,
  type BlockingAllowed,
  type BlockingPause,
  type BlockingStats,
  type BlockingWindow,
  type QueryLogLine,
} from "./api";
import { clientKind, hourBars, listName, logIsShort, pauseEnded, pauseState, PAUSES, pct, secondsLeft, share, WINDOWS, windowOf } from "./model";
import "../dns.css";
import "./blocking.css";

const SHORT: Intl.DateTimeFormatOptions = { dateStyle: "short", timeStyle: "short" };
const MEDIUM: Intl.DateTimeFormatOptions = { dateStyle: "short", timeStyle: "medium" };

function hasCode(err: unknown, code: string): boolean {
  return err instanceof ApiError && err.code === code;
}

function percent(fraction: number | null | undefined): string {
  return fraction === null || fraction === undefined ? "–" : formatNumber(fraction, { style: "percent", maximumFractionDigits: 1 });
}

function Tile(props: { name: string; title: string; value: number; hint: string; extra?: JSX.Element }) {
  return (
    <div class="card tile blocking-tile" data-testid={`blocking-tile-${props.name}`} data-value={props.value}>
      <p class="blocking-tile-title">{props.title}</p>
      <div class="tile-value">
        {formatNumber(props.value)}
        {props.extra}
      </div>
      <p class="muted">{props.hint}</p>
    </div>
  );
}

function Hours(props: { stats: BlockingStats }) {
  const bars = createMemo(() => hourBars(props.stats.hours));
  const first = () => props.stats.hours[0]?.start ?? props.stats.from;
  return (
    <section class="blocking-section" aria-labelledby="blocking-hours-title">
      <h2 id="blocking-hours-title">{t("dns.blocking.hours.title")}</h2>
      <div class="blocking-legend muted">
        <span class="blocking-key" data-series="queries">
          {t("dns.blocking.hours.queries")}
        </span>
        <span class="blocking-key" data-series="blocked">
          {t("dns.blocking.hours.blocked")}
        </span>
      </div>
      <div class="blocking-hours" role="group" aria-label={t("dns.blocking.hours.label")} data-testid="blocking-hours" data-hours={bars().length} data-dense={bars().length > 48 ? "true" : "false"}>
        <For each={bars()}>
          {(bar) => {
            const label = t("dns.blocking.hours.bar", { time: formatDateTime(bar.start, SHORT), queries: bar.queries, blocked: bar.blocked });
            return (
              <div class="blocking-hour" role="img" aria-label={label} title={label} data-testid="blocking-hour" data-queries={bar.queries} data-blocked={bar.blocked}>
                <span class="blocking-hour-queries" style={{ "block-size": pct(bar.total) }}>
                  <span class="blocking-hour-blocked" style={{ "block-size": pct(bar.part) }} />
                </span>
              </div>
            );
          }}
        </For>
      </div>
      <div class="blocking-axis muted" aria-hidden="true">
        <span>{formatDateTime(first(), SHORT)}</span>
        <span>{formatDateTime(props.stats.until, SHORT)}</span>
      </div>
    </section>
  );
}

function ListsBlocked(props: { stats: BlockingStats }) {
  const peak = () => Math.max(1, ...props.stats.lists.map((l) => l.blocked));
  return (
    <section class="blocking-section" aria-labelledby="blocking-lists-title">
      <div class="blocking-heading">
        <h2 id="blocking-lists-title">{t("dns.blocking.lists.title")}</h2>
        <A class="btn sm" href={dnsPaths.lists()} data-testid="blocking-lists-link">
          {t("dns.blocking.lists.manage")}
        </A>
      </div>
      <Show
        when={props.stats.lists.length > 0}
        fallback={
          <p class="muted" data-testid="blocking-lists-empty">
            {t("dns.blocking.lists.empty")}
          </p>
        }
      >
        <div class="table-wrap">
          <table class="plain" data-testid="blocking-lists">
            <caption class="sr-only">{t("dns.blocking.lists.table")}</caption>
            <thead>
              <tr>
                <th scope="col">{t("dns.blocking.col.list")}</th>
                <th scope="col" class="r">
                  {t("dns.blocking.col.blocked")}
                </th>
                <th scope="col" class="blocking-meter-col">
                  <span class="sr-only">{t("dns.blocking.col.share")}</span>
                </th>
              </tr>
            </thead>
            <tbody>
              <For each={props.stats.lists}>
                {(list) => (
                  <tr data-testid="blocking-list" data-list={list.list} data-blocked={list.blocked}>
                    <td data-col="list">
                      <Show when={list.name} fallback={<ListId id={list.list} />}>
                        {list.name}
                      </Show>
                    </td>
                    <td data-col="blocked" class="r">
                      {formatNumber(list.blocked)}
                    </td>
                    <td class="blocking-meter-col" aria-hidden="true">
                      <span class="blocking-meter">
                        <span style={{ "inline-size": pct(share(list.blocked, peak())) }} />
                      </span>
                    </td>
                  </tr>
                )}
              </For>
            </tbody>
          </table>
        </div>
      </Show>
    </section>
  );
}

/** A list the log names that does not exist any more: its id. */
function ListId(props: { id: string }) {
  return (
    <>
      <span class="mono" title={props.id}>
        {props.id}
      </span>{" "}
      <span class="muted">{t("dns.blocking.list_deleted")}</span>
    </>
  );
}

function NameTable(props: { id: string; title: string; caption: string; rows: BlockingStats["top_names"] }) {
  return (
    <section class="blocking-section" aria-labelledby={`blocking-${props.id}-title`}>
      <h2 id={`blocking-${props.id}-title`}>{props.title}</h2>
      <Show
        when={props.rows.length > 0}
        fallback={
          <p class="muted" data-testid={`blocking-${props.id}-empty`}>
            {t("dns.blocking.top.empty")}
          </p>
        }
      >
        <div class="table-wrap">
          <table class="plain" data-testid={`blocking-${props.id}`}>
            <caption class="sr-only">{props.caption}</caption>
            <thead>
              <tr>
                <th scope="col">{t("dns.blocking.col.name")}</th>
                <th scope="col" class="r">
                  {t("dns.blocking.col.queries")}
                </th>
                <th scope="col" class="r">
                  {t("dns.blocking.col.blocked")}
                </th>
              </tr>
            </thead>
            <tbody>
              <For each={props.rows}>
                {(row) => (
                  <tr data-testid="blocking-name" data-key={row.name} data-queries={row.queries} data-blocked={row.blocked}>
                    <td data-col="name" class="mono blocking-name">
                      {row.name}
                    </td>
                    <td data-col="queries" class="r">
                      {formatNumber(row.queries)}
                    </td>
                    <td data-col="blocked" class="r">
                      {formatNumber(row.blocked)}
                    </td>
                  </tr>
                )}
              </For>
            </tbody>
          </table>
        </div>
      </Show>
    </section>
  );
}

/** A client as the log keeps it: a pseudonym, an address, or withheld when the field is absent. */
function Client(props: { client: string | null | undefined }) {
  const kind = () => clientKind(props.client);
  return (
    <Show when={kind() !== "withheld"} fallback={<span class="muted" data-kind="withheld" title={t("dns.blocking.client.withheld_hint")}>{t("dns.blocking.client.withheld")}</span>}>
      <span class="mono" data-kind={kind()} title={kind() === "pseudonym" ? t("dns.log.pseudonym_hint") : undefined}>
        {props.client}
      </span>
    </Show>
  );
}

function Clients(props: { stats: BlockingStats }) {
  return (
    <section class="blocking-section" aria-labelledby="blocking-clients-title">
      <h2 id="blocking-clients-title">{t("dns.blocking.clients.title")}</h2>
      <Show when={props.stats.log_client !== "address"}>
        <p class="muted" data-testid="blocking-clients-note" data-client={props.stats.log_client}>
          {props.stats.log_client === "hidden" ? t("dns.blocking.clients.note_hidden") : t("dns.blocking.clients.note_pseudonym")}
        </p>
      </Show>
      <Show
        when={props.stats.top_clients.length > 0}
        fallback={
          <p class="muted" data-testid="blocking-clients-empty">
            {t("dns.blocking.clients.empty")}
          </p>
        }
      >
        <div class="table-wrap">
          <table class="plain" data-testid="blocking-clients">
            <caption class="sr-only">{t("dns.blocking.clients.table")}</caption>
            <thead>
              <tr>
                <th scope="col">{t("dns.blocking.col.client")}</th>
                <th scope="col">{t("dns.blocking.col.ipam")}</th>
                <th scope="col" class="r">
                  {t("dns.blocking.col.queries")}
                </th>
                <th scope="col" class="r">
                  {t("dns.blocking.col.blocked")}
                </th>
              </tr>
            </thead>
            <tbody>
              <For each={props.stats.top_clients}>
                {(row) => (
                  <tr data-testid="blocking-client" data-key={row.client ?? ""} data-kind={clientKind(row.client)} data-queries={row.queries} data-blocked={row.blocked}>
                    <td data-col="client">
                      <Client client={row.client} />
                    </td>
                    <td data-col="name" class="mono">
                      {row.name}
                    </td>
                    <td data-col="queries" class="r">
                      {formatNumber(row.queries)}
                    </td>
                    <td data-col="blocked" class="r">
                      {formatNumber(row.blocked)}
                    </td>
                  </tr>
                )}
              </For>
            </tbody>
          </table>
        </div>
      </Show>
    </section>
  );
}

function Recent(props: {
  stats: BlockingStats;
  outcomes: Record<string, BlockingAllowed>;
  allowing: string | undefined;
  onAllow: (line: QueryLogLine) => void;
}) {
  return (
    <section class="blocking-section" aria-labelledby="blocking-recent-title">
      <h2 id="blocking-recent-title">{t("dns.blocking.recent.title")}</h2>
      <Show
        when={props.stats.recent_blocked.length > 0}
        fallback={
          <p class="muted" data-testid="blocking-recent-empty">
            {t("dns.blocking.recent.empty")}
          </p>
        }
      >
        <div class="table-wrap">
          <table class="plain" data-testid="blocking-recent">
            <caption class="sr-only">{t("dns.blocking.recent.table")}</caption>
            <thead>
              <tr>
                <th scope="col">{t("dns.blocking.col.time")}</th>
                <th scope="col">{t("dns.blocking.col.client")}</th>
                <th scope="col">{t("dns.blocking.col.name")}</th>
                <th scope="col">{t("dns.blocking.col.list")}</th>
                <Show when={mayWriteDns()}>
                  <th scope="col">
                    <span class="sr-only">{t("dns.blocking.col.action")}</span>
                  </th>
                </Show>
              </tr>
            </thead>
            <tbody>
              <For each={props.stats.recent_blocked}>
                {(line) => {
                  const list = () => listName(props.stats.lists, line.blocked);
                  const outcome = () => props.outcomes[line.qname];
                  return (
                    <tr data-testid="blocking-recent-row" data-key={line.qname} data-list={line.blocked ?? ""}>
                      <td data-col="time" class="nowrap">
                        {formatDateTime(line.at, MEDIUM)}
                      </td>
                      <td data-col="client">
                        <Client client={line.client} />
                      </td>
                      <td data-col="name" class="mono blocking-name">
                        {line.qname}
                      </td>
                      <td data-col="list">
                        <Show when={line.blocked} fallback={<span class="muted">{"–"}</span>}>
                          {(id) => (
                            <Show when={list()} fallback={<ListId id={id()} />}>
                              {list()}
                            </Show>
                          )}
                        </Show>
                      </td>
                      <Show when={mayWriteDns()}>
                        <td data-col="action">
                          <Show
                            when={outcome()}
                            fallback={
                              <button
                                type="button"
                                class="btn sm"
                                data-testid="blocking-allow"
                                data-key={line.qname}
                                aria-label={t("dns.blocking.allow_label", { name: line.qname })}
                                disabled={props.allowing !== undefined}
                                onClick={() => props.onAllow(line)}
                              >
                                {t("dns.blocking.allow")}
                              </button>
                            }
                          >
                            {(done) => (
                              <span class="blocking-outcome" role="status" data-testid="blocking-allow-result" data-state={done().already ? "already" : "added"}>
                                {done().already ? t("dns.blocking.allow.already") : t("dns.blocking.allow.added", { list: done().list_name })}
                                <Show when={done().job}>
                                  {(job) => (
                                    <>
                                      {" "}
                                      <A href={paths.job(job())} data-testid="blocking-allow-job">
                                        {t("dns.blocking.allow.job")}
                                      </A>
                                    </>
                                  )}
                                </Show>
                              </span>
                            )}
                          </Show>
                        </td>
                      </Show>
                    </tr>
                  );
                }}
              </For>
            </tbody>
          </table>
        </div>
      </Show>
    </section>
  );
}

function PauseCard(props: { paused: BlockingPause | null; now: number; busy: boolean; onPause: (minutes?: number) => void; onResume: () => void }) {
  const state = () => pauseState(props.paused);
  const left = () => secondsLeft(props.paused, props.now);
  // A pause that ends today names the time, any other the date as well.
  const until = (stamp: string) =>
    formatDateTime(stamp, new Date(stamp).toDateString() === new Date(props.now).toDateString() ? { timeStyle: "short" } : SHORT);
  return (
    <section class="card blocking-pause" aria-labelledby="blocking-pause-title" data-testid="blocking-pause" data-state={state()}>
      <h2 id="blocking-pause-title" class="sr-only">
        {t("dns.blocking.pause.title")}
      </h2>
      <div class="blocking-pause-line">
        <p class="blocking-pause-status" role="status" data-testid="blocking-pause-status" data-state={state()}>
          <Icon name={state() === "on" ? "check" : "alert"} size="sm" />
          <span>
            {state() === "on"
              ? t("dns.blocking.pause.on")
              : state() === "open"
                ? t("dns.blocking.pause.open")
                : t("dns.blocking.pause.until", { time: until(props.paused?.until ?? "") })}
          </span>
        </p>
        <Show when={state() === "timed" && left() !== null}>
          <span class="muted" data-testid="blocking-pause-left" data-seconds={left() ?? undefined}>
            {t("dns.blocking.pause.left", { left: formatDuration(left() ?? 0) })}
          </span>
        </Show>
      </div>
      <Show when={state() !== "on"}>
        <p class="muted blocking-pause-hint">{t("dns.blocking.pause.hint")}</p>
      </Show>
      <Show when={mayWriteDns()}>
        <div class="blocking-pause-buttons">
          <span class="muted">{t("dns.blocking.pause.for")}</span>
          <div class="blocking-pause-group" role="group" aria-label={t("dns.blocking.pause.label")}>
            <For each={PAUSES}>
              {(pause) => (
                <button type="button" class="btn sm" data-testid={`blocking-pause-${pause.id}`} disabled={props.busy} onClick={() => props.onPause(pause.minutes)}>
                  {t(`dns.blocking.pause.btn.${pause.id}` as "dns.blocking.pause.btn.5")}
                </button>
              )}
            </For>
          </div>
          <Show when={state() !== "on"}>
            <button type="button" class="btn sm primary" data-testid="blocking-resume" disabled={props.busy} onClick={() => props.onResume()}>
              {t("dns.blocking.resume")}
            </button>
          </Show>
        </div>
      </Show>
    </section>
  );
}

export default function BlockingPage() {
  const [search, setSearch] = useSearchParams();
  const range = createMemo<BlockingWindow>(() => windowOf(search.window));
  const [stats, { refetch }] = createResource(range, (w) => blockingStats(w));
  const data = () => (stats.error ? undefined : stats.latest);

  // The pause as the node last said: the figures, or the answer of the last pause or resume.
  const [paused, setPaused] = createSignal<BlockingPause | null>(null);
  createEffect(
    on(data, (d) => {
      if (d) setPaused(d.paused ?? null);
    }),
  );

  // A timed pause counts down; when it ends the figures are read again. The end handled once,
  // so a clock that runs ahead of the node's does not read in a loop.
  const [now, setNow] = createSignal(Date.now());
  createEffect(() => {
    if (!paused()?.until) return;
    setNow(Date.now());
    const timer = setInterval(() => setNow(Date.now()), 1000);
    onCleanup(() => clearInterval(timer));
  });
  let handledEnd: string | undefined;
  createEffect(() => {
    const current = paused();
    if (current?.until && handledEnd !== current.until && pauseEnded(current, now())) {
      handledEnd = current.until;
      setPaused(null);
      void refetch();
    }
  });

  const [busy, setBusy] = createSignal(false);
  const [failure, setFailure] = createSignal<unknown>();
  const [outcomes, setOutcomes] = createSignal<Record<string, BlockingAllowed>>({});
  const [allowing, setAllowing] = createSignal<string>();

  const act = async (run: () => Promise<void>) => {
    if (busy()) return;
    setBusy(true);
    setFailure(undefined);
    try {
      await run();
    } catch (err) {
      setFailure(err);
    } finally {
      setBusy(false);
    }
  };
  const pause = (minutes?: number) =>
    act(async () => {
      const state = await pauseBlocking(minutes);
      setPaused(state.paused ?? null);
      void refetch();
    });
  const resume = () =>
    act(async () => {
      const state = await resumeBlocking();
      setPaused(state.paused ?? null);
      void refetch();
    });
  const allow = (line: QueryLogLine) =>
    act(async () => {
      setAllowing(line.qname);
      try {
        const done = await allowName(line.qname);
        setOutcomes((all) => ({ ...all, [line.qname]: done }));
        void refetch();
      } finally {
        setAllowing(undefined);
      }
    });

  const chooseWindow = (next: BlockingWindow) => setSearch({ window: next === "24h" ? undefined : next });

  return (
    <div class="page dns-page" data-testid="page-dns-blocking">
      <DnsNav />
      <PageHead
        title={t("dns.blocking.title")}
        sub={t("dns.blocking.sub")}
        actions={
          <Show when={data()}>
            <button type="button" class="btn" data-testid="blocking-refresh" onClick={() => void refetch()}>
              <Icon name="refresh" />
              {t("dns.blocking.refresh")}
            </button>
          </Show>
        }
      />
      <div class="page-body blocking-body" data-loading={stats.loading ? "true" : undefined}>
        <Switch fallback={<p class="muted" data-testid="blocking-loading">{t("dns.blocking.loading")}</p>}>
          <Match when={stats.error && unavailable(stats.error)}>
            <DnsProblem error={stats.error} />
          </Match>
          <Match when={stats.error && hasCode(stats.error, "dns.blocking.log_off")}>
            <div class="empty" data-testid="blocking-log-off">
              <h2>{t("dns.blocking.log_off.title")}</h2>
              <p>{t("dns.blocking.log_off.body")}</p>
              <A class="btn" href={dnsPaths.settings()} data-testid="blocking-settings-link">
                {t("dns.blocking.log_off.link")}
              </A>
            </div>
          </Match>
          <Match when={stats.error && hasCode(stats.error, "dns.node.not_dns")}>
            <Notice kind="info" role="status" title={t("dns.log.not_dns_title")} testid="blocking-not-dns">
              {t("dns.log.not_dns_body")}
            </Notice>
          </Match>
          <Match when={stats.error}>
            <ErrorNotice error={stats.error} />
          </Match>
          <Match when={data()}>
            {(d) => (
              <>
                <div class="blocking-controls">
                  <div class="seg" role="group" aria-label={t("dns.blocking.window.label")}>
                    <For each={WINDOWS}>
                      {(w) => (
                        <button type="button" aria-pressed={w === range()} data-testid={`blocking-window-${w}`} onClick={() => chooseWindow(w)}>
                          {t(`dns.blocking.window.${w}` as "dns.blocking.window.24h")}
                        </button>
                      )}
                    </For>
                  </div>
                  <span class="muted" data-testid="blocking-period">
                    {t("dns.blocking.period", { from: formatDateTime(d().from, SHORT), until: formatDateTime(d().until, SHORT) })}
                  </span>
                </div>
                <Show when={range() === "7d" && logIsShort(range(), d().log_days)}>
                  <p class="muted" data-testid="blocking-short-log" data-days={d().log_days}>
                    {t("dns.blocking.short_log", { days: d().log_days })}
                  </p>
                </Show>
                <Show when={d().truncated}>
                  <p class="muted" data-testid="blocking-truncated">
                    {t("dns.blocking.truncated")}
                  </p>
                </Show>
                <Show when={d().log_sample > 1}>
                  <p class="muted" data-testid="blocking-sample" data-sample={d().log_sample}>
                    {t("dns.blocking.sample", { sample: d().log_sample })}
                  </p>
                </Show>

                <PauseCard paused={paused()} now={now()} busy={busy()} onPause={(minutes) => void pause(minutes)} onResume={() => void resume()} />
                <Show when={failure()}>
                  <ErrorNotice error={failure()} />
                </Show>

                <div class="blocking-tiles">
                  <Tile name="queries" title={t("dns.blocking.tile.queries")} value={d().queries} hint={t("dns.blocking.tile.queries_hint", { window: range() })} />
                  <Tile
                    name="blocked"
                    title={t("dns.blocking.tile.blocked")}
                    value={d().blocked}
                    hint={t("dns.blocking.tile.blocked_hint")}
                    extra={
                      <span class="blocking-share" data-testid="blocking-share" data-share={d().blocked_share ?? undefined}>
                        {percent(d().blocked_share)}
                      </span>
                    }
                  />
                  <Tile
                    name="cached"
                    title={t("dns.blocking.tile.cached")}
                    value={d().cached}
                    hint={t("dns.blocking.tile.cached_hint", { share: percent(d().queries > 0 ? share(d().cached, d().queries) : null) })}
                  />
                  <Tile name="clients" title={t("dns.blocking.tile.clients")} value={d().clients} hint={t("dns.blocking.tile.clients_hint", { mode: d().log_client })} />
                </div>

                <Hours stats={d()} />
                <ListsBlocked stats={d()} />
                <div class="blocking-pair">
                  <NameTable id="top-blocked" title={t("dns.blocking.top_blocked.title")} caption={t("dns.blocking.top_blocked.table")} rows={d().top_blocked} />
                  <NameTable id="top-names" title={t("dns.blocking.top_names.title")} caption={t("dns.blocking.top_names.table")} rows={d().top_names} />
                </div>
                <Clients stats={d()} />
                <Recent stats={d()} outcomes={outcomes()} allowing={allowing()} onAllow={(line) => void allow(line)} />

                <Notice kind="info" testid="blocking-next">
                  {t("dns.blocking.next")}
                </Notice>
              </>
            )}
          </Match>
        </Switch>
      </div>
    </div>
  );
}
