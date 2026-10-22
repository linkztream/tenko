// The status block of the recursion page (WP10.1): the recursive resolver of this server's node
// as `GET /nodes/{id}/dns/recursion` reports it. Whether the resolver runs, where the root
// hints come from and their date, the last priming (when, how it ended, how long it took) with
// a "Prime now" button for those who may write DNS, the root servers with their smoothed
// round-trip times, the sizes of the infrastructure cache against their bounds, and the counters
// since the role started. What the node reports as wrong (`priming_failed`) is a warning. A
// node whose resolver is off says so and where to switch it on.
import { createResource, createSignal, For, Match, Show, Switch } from "solid-js";
import { errorMessage } from "../../api/problem";
import { ErrorNotice, Notice } from "../../components/Notice";
import { toast } from "../../components/toast";
import { formatDateTime, formatNumber, formatRelative, t } from "../../i18n";
import { mayWriteDns } from "../access";
import { primeRecursion, readRecursion, recursionNode, type RecursionStatus } from "./api";
import "./recursion.css";

/** Milliseconds as the tables show them: `12.5 ms`. */
function ms(value: number): string {
  return t("dns.recursion.ms", { ms: formatNumber(value, { maximumFractionDigits: 2 }) });
}

/** What the node reports as wrong: its words, or the code itself for one this version does not know. */
function Problem(props: { code: string }) {
  return <Show when={props.code === "priming_failed"} fallback={props.code}>{t("dns.recursion.problem.priming_failed")}</Show>;
}

function Facts(props: { status: RecursionStatus }) {
  const priming = () => props.status.last_priming;
  return (
    <section class="card page-section" data-testid="dns-recursion-facts" aria-labelledby="dns-recursion-facts-title">
      <h3 id="dns-recursion-facts-title">{t("dns.recursion.facts.title")}</h3>
      <dl class="kv">
        <dt>{t("dns.recursion.root_hints")}</dt>
        <dd data-testid="dns-recursion-hints" data-source={props.status.hints_source}>
          <Show when={props.status.hints_source === "shipped"} fallback={<span class="mono">{props.status.hints_source}</span>}>
            {t("dns.recursion.hints.shipped")}
          </Show>
        </dd>
        <dt>{t("dns.recursion.hints.date")}</dt>
        <dd data-testid="dns-recursion-hints-date">{props.status.hints_date}</dd>
        <dt>{t("dns.recursion.priming.last")}</dt>
        <dd data-testid="dns-recursion-priming" data-outcome={priming()?.outcome ?? "never"}>
          <Show when={priming()} fallback={<span class="muted">{t("dns.recursion.priming.never")}</span>}>
            {(last) => (
              <>
                {formatDateTime(last().at)}{" "}
                <span class="tag" classList={{ discrepancy: last().outcome !== "ok" }}>
                  {last().outcome === "ok" ? t("dns.recursion.priming.ok") : t("dns.recursion.priming.failed")}
                </span>{" "}
                <span class="muted">{t("dns.recursion.priming.duration", { ms: formatNumber(last().duration_ms, { maximumFractionDigits: 1 }) })}</span>
              </>
            )}
          </Show>
        </dd>
        <Show when={props.status.root_expires_secs != null}>
          <dt>{t("dns.recursion.priming.expires")}</dt>
          <dd data-testid="dns-recursion-expires">{formatRelative(Date.now() + (props.status.root_expires_secs ?? 0) * 1000)}</dd>
        </Show>
      </dl>
    </section>
  );
}

function Roots(props: { status: RecursionStatus }) {
  return (
    <section class="card page-section" data-testid="dns-recursion-roots" aria-labelledby="dns-recursion-roots-title">
      <h3 id="dns-recursion-roots-title">{t("dns.recursion.roots.title")}</h3>
      <div class="table-wrap">
        <table class="plain rec-table">
          <caption class="sr-only">{t("dns.recursion.roots.title")}</caption>
          <thead>
            <tr>
              <th scope="col">{t("dns.recursion.roots.col.name")}</th>
              <th scope="col">{t("dns.recursion.roots.col.address")}</th>
              <th scope="col" class="r">
                {t("dns.recursion.roots.col.srtt")}
              </th>
            </tr>
          </thead>
          <tbody>
            <For each={props.status.root_servers}>
              {(server, index) => (
                <tr data-testid="dns-recursion-root" data-index={index()} data-key={server.address}>
                  <td class="mono">{server.name}</td>
                  <td class="mono">{server.address}</td>
                  <td class="r nowrap" data-col="srtt">
                    <Show when={server.srtt_ms != null} fallback={<span class="muted">{t("dns.recursion.roots.srtt_none")}</span>}>
                      {ms(server.srtt_ms ?? 0)}
                    </Show>
                  </td>
                </tr>
              )}
            </For>
          </tbody>
        </table>
      </div>
    </section>
  );
}

function Infra(props: { status: RecursionStatus }) {
  const sizes = () => props.status.infra;
  const of = (count: number, max: number) => t("dns.recursion.infra.of", { count: formatNumber(count), max: formatNumber(max) });
  return (
    <section class="card page-section" data-testid="dns-recursion-infra" aria-labelledby="dns-recursion-infra-title">
      <h3 id="dns-recursion-infra-title">{t("dns.recursion.infra.title")}</h3>
      <dl class="kv">
        <dt>{t("dns.recursion.infra.zones")}</dt>
        <dd data-testid="dns-recursion-infra-zones" data-value={sizes().zones} data-max={sizes().max_zones}>
          {of(sizes().zones, sizes().max_zones)}
        </dd>
        <dt>{t("dns.recursion.infra.servers")}</dt>
        <dd data-testid="dns-recursion-infra-servers" data-value={sizes().servers} data-max={sizes().max_servers}>
          {of(sizes().servers, sizes().max_servers)}
        </dd>
        <dt>{t("dns.recursion.infra.names")}</dt>
        <dd data-testid="dns-recursion-infra-names" data-value={sizes().names}>
          {formatNumber(sizes().names)}
        </dd>
      </dl>
    </section>
  );
}

function Counters(props: { status: RecursionStatus }) {
  const rows = () => {
    const c = props.status.counters;
    return [
      { id: "answered", label: t("dns.recursion.counter.answered"), value: c.answered },
      { id: "servfail", label: t("dns.recursion.counter.servfail"), value: c.servfail },
      { id: "budget", label: t("dns.recursion.counter.budget"), value: c.budget },
      { id: "timeout", label: t("dns.recursion.counter.timeout"), value: c.timeout },
      { id: "local", label: t("dns.recursion.counter.local"), value: c.local },
      { id: "failure_cache_hits", label: t("dns.recursion.counter.failure_cache_hits"), value: c.failure_cache_hits },
      { id: "subqueries", label: t("dns.recursion.counter.subqueries"), value: c.subqueries },
      { id: "unwanted", label: t("dns.recursion.counter.unwanted"), value: c.unwanted },
    ];
  };
  return (
    <section class="card page-section" data-testid="dns-recursion-counters" aria-labelledby="dns-recursion-counters-title">
      <h3 id="dns-recursion-counters-title">{t("dns.recursion.counters.title")}</h3>
      <dl class="kv">
        <For each={rows()}>
          {(row) => (
            <>
              <dt>{row.label}</dt>
              <dd data-testid="dns-recursion-counter" data-key={row.id} data-value={row.value}>
                {formatNumber(row.value)}
              </dd>
            </>
          )}
        </For>
      </dl>
    </section>
  );
}

export function RecursionStatusBlock() {
  const [node] = createResource(() => recursionNode());
  const here = () => (node.error ? undefined : node.latest);
  const [status, { refetch }] = createResource(
    () => here() ?? undefined,
    (id) => readRecursion(id),
  );
  const current = () => (status.error ? undefined : status.latest);
  const [busy, setBusy] = createSignal(false);

  const prime = async () => {
    const id = here();
    if (id == null || busy()) return;
    setBusy(true);
    try {
      await primeRecursion(id);
      toast({ kind: "ok", title: t("dns.recursion.prime.sent") });
      await refetch();
    } catch (err) {
      toast({ kind: "bad", title: t("dns.recursion.prime.failed"), body: errorMessage(err) });
    } finally {
      setBusy(false);
    }
  };

  return (
    <section class="rec-status page-section" data-testid="dns-recursion-status" aria-labelledby="dns-recursion-status-title">
      <div class="rec-status-head">
        <h2 id="dns-recursion-status-title">{t("dns.recursion.status.title")}</h2>
        <Show when={current()?.enabled}>
          <span class="tag" data-testid="dns-recursion-running">
            {t("dns.recursion.status.running")}
          </span>
          <Show when={mayWriteDns()}>
            <button type="button" class="btn" data-testid="dns-recursion-prime" disabled={busy()} onClick={() => void prime()}>
              {t("dns.recursion.prime.button")}
            </button>
          </Show>
        </Show>
      </div>
      <ErrorNotice error={node.error} />
      <ErrorNotice error={status.error} />
      <Switch>
        <Match when={here() === null}>
          <Notice kind="info" role="status" testid="dns-recursion-no-node">
            {t("dns.recursion.status.no_node")}
          </Notice>
        </Match>
        <Match when={current()}>
          {(shown) => (
            <Show
              when={shown().enabled}
              fallback={
                <Notice kind="info" role="status" title={t("dns.recursion.status.off.title")} testid="dns-recursion-off">
                  {t("dns.recursion.status.off.body")}
                </Notice>
              }
            >
              <Show when={shown().problems.length > 0}>
                <Notice kind="warn" role="status" title={t("dns.recursion.problems.title")} testid="dns-recursion-problems">
                  <ul class="rec-problems">
                    <For each={shown().problems}>
                      {(code) => (
                        <li data-testid="dns-recursion-problem" data-code={code}>
                          <Problem code={code} />
                        </li>
                      )}
                    </For>
                  </ul>
                </Notice>
              </Show>
              <div class="rec-grid">
                <Facts status={shown()} />
                <Infra status={shown()} />
                <Counters status={shown()} />
              </div>
              <Roots status={shown()} />
            </Show>
          )}
        </Match>
        <Match when={!node.error && !status.error}>
          <p class="muted" data-testid="dns-recursion-status-loading" aria-busy="true">
            {t("dns.recursion.status.loading")}
          </p>
        </Match>
      </Switch>
    </section>
  );
}
