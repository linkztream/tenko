// The service panels of the start page (U3, ui-plan section 5.1), from the page's `metrics`
// stream (administrators only). Each panel has its status as a glyph and a word (the findings of
// its area to act on, else Healthy; never a green fill) and one link to its area.
//
// DNS: the queries per second over the last 30 seconds with the p50 and p99 of the newest sample,
// the queries chart of the last five minutes (QueriesChart.tsx), the response codes of the last
// 30 seconds as one bar with the four codes, the cache hit ratio with the entries and the stale
// answers, blocked per second, upstream and sub-queries, the DNSSEC outcomes, and the encrypted
// connections or "Not served". Rates are means over the 30 seconds of the ratio tiles
// (`windowRate`), so a quiet second never reads zero beside bars of queries.
//
// DHCP: the active leases, leases granted per second with the REQUEST to ACK p99, NAKs and
// DECLINEs, DDNS written and removed. While no scope has a pool the panel is one empty state
// ("Create a scope") instead of eight zeros; the figures take over once a pool exists.
//
// A panel is drawn while the newest sample has its part (a controller runs the role); otherwise the
// Hidden line names it.
//
// Test ids: `dashboard-dns` and `dashboard-dhcp` (`data-status` healthy or attention), the figures
// `dashboard-dns-<name>` and `dashboard-dhcp-<name>` with `data-value`, `dashboard-dns-rcode` per
// code (`data-rcode`, `data-rate`), `dashboard-dhcp-empty`.
import { A } from "@solidjs/router";
import { createMemo, createUniqueId, For, Show, type JSX } from "solid-js";
import { paths } from "../app/paths";
import { si } from "../app/format/si";
import { EmptyState } from "../components/EmptyState";
import { Icon } from "../components/Icon";
import { Si } from "../components/Si";
import { formatNumber, locale, t } from "../i18n";
import { areaCounts, type FindingArea, type FindingCounts } from "../shell/findings";
import type { LiveMetrics } from "./liveMetrics";
import { blockedTotal, rateBuckets, RCODES, topLists, windowMean, windowRate, windowRatio, type MetricsDhcp, type MetricsDns } from "./metrics";
import { QueriesChart } from "./QueriesChart";

/** The codes the response bar draws; the rest count in the total only. */
const SHOWN_RCODES = ["noerror", "nxdomain", "servfail", "refused"] as const;

/** A rate per second: two decimals below one (never zero for a rate that is not), one below ten. */
export function rate(value: number | null | undefined): string {
  const v = value ?? 0;
  if (v > 0 && v < 0.01) return `<${formatNumber(0.01, { minimumFractionDigits: 2 })}`;
  if (v > 0 && v < 1) return formatNumber(v, { maximumFractionDigits: 2 });
  // From a thousand up an SI number, so the figure never grows its block (1.2K).
  if (v >= 1000) return si(v, locale());
  return formatNumber(v, { maximumFractionDigits: v < 10 ? 1 : 0 });
}

function ms(value: number): string {
  return formatNumber(value, { maximumFractionDigits: value < 10 ? 1 : 0 });
}

/** A panel's status: a finding to act on in its area, else healthy. */
function PanelStatus(props: { counts: FindingCounts | null; area: FindingArea }) {
  const act = () => areaCounts(props.counts, props.area).act;
  return (
    <Show
      when={act() > 0}
      fallback={
        <span class="dpanel-status ok">
          <Icon name="check" size="xs" />
          {t("dashboard.panel.healthy")}
        </span>
      }
    >
      <span class="dpanel-status act">
        <Icon name="conflict" size="xs" />
        {t("dashboard.panel.attention", { count: act() })}
      </span>
    </Show>
  );
}

/** One figure of a panel: a label, the value, and an optional line under it. */
function Figure(props: { label: string; value: string; note?: string; testid: string; data?: number | null; quiet?: boolean }) {
  return (
    <div class="dpanel-figure" data-testid={props.testid} data-value={props.data ?? undefined}>
      <dt>{props.label}</dt>
      <dd class="dpanel-figure-value" classList={{ quiet: props.quiet }}>
        {props.value}
      </dd>
      <Show when={props.note}>
        <dd class="dpanel-figure-note">{props.note}</dd>
      </Show>
    </div>
  );
}

function Panel(props: { title: string; area: FindingArea; counts: FindingCounts | null; href: string; link: string; testid: string; status: string; wide?: boolean; children: JSX.Element }) {
  const id = createUniqueId();
  return (
    <article class="dpanel dash-service" classList={{ wide: props.wide }} aria-labelledby={id} data-testid={props.testid} data-status={props.status}>
      <div class="dpanel-head">
        <h2 id={id}>{props.title}</h2>
        <PanelStatus counts={props.counts} area={props.area} />
        <A class="dpanel-link" href={props.href} data-testid={`${props.testid}-open`}>
          {props.link}
        </A>
      </div>
      {props.children}
    </article>
  );
}

export function DnsPanel(props: { live: LiveMetrics; counts: FindingCounts | null }) {
  const history = () => props.live.history();
  const dns = (): MetricsDns | undefined => history().latest?.cluster.dns ?? undefined;
  const mean = (pick: (d: MetricsDns) => number) => windowRate(history(), pick);
  const bars = createMemo(() => rateBuckets(history(), (d) => d.queries_per_second));
  const rcodes = createMemo(() => {
    const rates = Object.fromEntries(RCODES.map((code) => [code, mean((d) => d.rcodes[code]) ?? 0])) as Record<(typeof RCODES)[number], number>;
    const all = RCODES.reduce((sum, code) => sum + rates[code], 0);
    return { rates, all };
  });
  const status = () => (areaCounts(props.counts, "dns").act > 0 ? "attention" : "healthy");
  return (
    <Show when={dns()}>
      {(d) => (
        <Panel title={t("dashboard.dns.title")} area="dns" counts={props.counts} href={paths.dns()} link={t("dashboard.dns.open")} testid="dashboard-dns" status={status()} wide>
          <div class="dash-dns">
            <div class="dash-dns-chart">
              <div class="dash-headline" data-testid="dashboard-dns-qps" data-value={mean((x) => x.queries_per_second) ?? undefined}>
                <span class="dash-headline-value">{rate(mean((x) => x.queries_per_second))}</span>
                <span class="dash-headline-unit">{t("dashboard.dns.qps")}</span>
                <span class="dash-headline-note">
                  {d().p50_ms != null && d().p99_ms != null ? t("dashboard.dns.latency", { p50: ms(d().p50_ms!), p99: ms(d().p99_ms!) }) : t("dashboard.dns.idle")}
                </span>
              </div>
              <QueriesChart values={bars()} />
            </div>
            <div class="dash-dns-side">
              <div class="dash-rcodes">
                <span class="dpanel-caption">{t("dashboard.dns.rcodes")}</span>
                <div class="dash-rcode-bar" aria-hidden="true">
                  <For each={SHOWN_RCODES}>
                    {(code) => (
                      <span
                        class={`rcode-${code}`}
                        style={{ "inline-size": `${rcodes().all > 0 ? (rcodes().rates[code] * 100) / rcodes().all : 0}%` }}
                      />
                    )}
                  </For>
                </div>
                <ul class="dash-rcode-list">
                  <For each={SHOWN_RCODES}>
                    {(code) => (
                      <li data-testid="dashboard-dns-rcode" data-rcode={code} data-rate={rcodes().rates[code]} classList={{ quiet: rcodes().rates[code] === 0 }}>
                        <span class={`swatch rcode-${code}`} aria-hidden="true" />
                        <span class="mono">{code.toUpperCase()}</span>
                        <span class="rate">{t("dashboard.dns.rate", { rate: rate(rcodes().rates[code]) })}</span>
                      </li>
                    )}
                  </For>
                </ul>
              </div>
              <dl class="dpanel-figures">
                <Figure
                  testid="dashboard-dns-cache"
                  label={t("dashboard.dns.cache")}
                  data={windowRatio(history(), "dns-cache")}
                  value={(() => {
                    const ratio = windowRatio(history(), "dns-cache");
                    return ratio == null ? "–" : t("dashboard.dns.percent", { value: formatNumber(ratio, { maximumFractionDigits: 0 }) });
                  })()}
                  note={t("dashboard.dns.cache_note", { entries: si(d().cache.entries, locale()), stale: rate(mean((x) => x.cache.stale_per_second)) })}
                />
                <Figure
                  testid="dashboard-dns-blocked"
                  label={t("dashboard.dns.blocked")}
                  data={mean(blockedTotal)}
                  value={t("dashboard.dns.rate", { rate: rate(mean(blockedTotal)) })}
                  note={topLists(d())[0] ? t("dashboard.dns.blocked_top", { list: topLists(d())[0]!.list }) : t("dashboard.dns.blocked_none")}
                />
                <Figure
                  testid="dashboard-dns-upstreams"
                  label={d().recursion ? t("dashboard.dns.upstreams_subqueries") : t("dashboard.dns.upstreams")}
                  data={mean((x) => x.upstreams.queries_per_second)}
                  value={
                    d().recursion
                      ? t("dashboard.dns.pair", { first: rate(mean((x) => x.upstreams.queries_per_second)), second: rate(mean((x) => x.recursion?.subqueries_per_second ?? 0)) })
                      : t("dashboard.dns.rate", { rate: rate(mean((x) => x.upstreams.queries_per_second)) })
                  }
                  note={d().upstreams.p99_ms != null ? t("dashboard.dns.upstreams_p99", { p99: ms(d().upstreams.p99_ms!) }) : undefined}
                />
                <Show when={d().recursion}>
                  {(r) => (
                    <Figure
                      testid="dashboard-dns-validation"
                      label={t("dashboard.dns.dnssec")}
                      data={r().validation.secure + r().validation.insecure + r().validation.bogus}
                      value={t("dashboard.dns.triple", {
                        secure: rate(mean((x) => x.recursion?.validation.secure ?? 0)),
                        insecure: rate(mean((x) => x.recursion?.validation.insecure ?? 0)),
                        bogus: rate(mean((x) => x.recursion?.validation.bogus ?? 0)),
                      })}
                      note={t("dashboard.dns.indeterminate", { rate: rate(mean((x) => x.recursion?.validation.indeterminate ?? 0)) })}
                    />
                  )}
                </Show>
                <Figure
                  testid="dashboard-dns-encrypted"
                  label={t("dashboard.dns.encrypted")}
                  data={d().connections ? d().connections!.dot + d().connections!.doh : null}
                  quiet={!d().connections}
                  value={d().connections ? t("dashboard.dns.encrypted_value", { dot: d().connections!.dot, doh: d().connections!.doh }) : t("dashboard.dns.not_served")}
                />
              </dl>
            </div>
          </div>
        </Panel>
      )}
    </Show>
  );
}

export function DhcpPanel(props: { live: LiveMetrics; counts: FindingCounts | null }) {
  const history = () => props.live.history();
  const dhcp = () => history().latest?.cluster.dhcp ?? undefined;
  const status = () => (areaCounts(props.counts, "dhcp").act > 0 ? "attention" : "healthy");
  // Means over the 30 seconds of the DNS rates, so a quiet second never reads zero.
  const mean = (pick: (x: MetricsDhcp) => number) => windowMean(history(), (s) => (s.dhcp ? pick(s.dhcp) : null)) ?? 0;
  return (
    <Show when={dhcp()}>
      {(d) => (
        <Panel title={t("dashboard.dhcp.title")} area="dhcp" counts={props.counts} href={paths.dhcp()} link={t("dashboard.dhcp.open")} testid="dashboard-dhcp" status={status()}>
          <Show
            when={d().scopes > 0}
            fallback={
              <EmptyState
                testid="dashboard-dhcp-empty"
                text={t("dashboard.dhcp.empty")}
                action={{ label: t("dashboard.dhcp.create_scope"), href: paths.dhcp(), testid: "dashboard-dhcp-create" }}
              />
            }
          >
            <div class="dash-headline" data-testid="dashboard-dhcp-active" data-value={d().active_leases}>
              <span class="dash-headline-value"><Si value={d().active_leases} /></span>
              <span class="dash-headline-unit">{t("dashboard.dhcp.active")}</span>
              <span class="dash-headline-note">{t("dashboard.dhcp.scopes", { count: d().scopes })}</span>
            </div>
            <dl class="dpanel-figures">
              <Figure
                testid="dashboard-dhcp-leases"
                label={t("dashboard.dhcp.leases")}
                data={mean((x) => x.leases_per_second)}
                value={t("dashboard.dns.rate", { rate: rate(mean((x) => x.leases_per_second)) })}
                note={d().ack_p99_ms != null ? t("dashboard.dhcp.ack", { p99: ms(d().ack_p99_ms!) }) : t("dashboard.dhcp.ack_none")}
              />
              <Figure
                testid="dashboard-dhcp-naks"
                label={t("dashboard.dhcp.naks")}
                data={mean((x) => x.naks_per_second + x.declines_per_second)}
                value={t("dashboard.dns.pair", { first: rate(mean((x) => x.naks_per_second)), second: rate(mean((x) => x.declines_per_second)) })}
                note={t("dashboard.dhcp.abandoned", { count: d().abandoned_leases })}
              />
              <Figure
                testid="dashboard-dhcp-ddns"
                label={t("dashboard.dhcp.ddns")}
                data={mean((x) => x.ddns.written)}
                value={t("dashboard.dns.pair", { first: rate(mean((x) => x.ddns.written)), second: rate(mean((x) => x.ddns.removed)) })}
                note={t("dashboard.dhcp.ddns_note", { refused: rate(mean((x) => x.ddns.refused)), failed: rate(mean((x) => x.ddns.failed)), queue: d().ddns.queue })}
              />
            </dl>
          </Show>
        </Panel>
      )}
    </Show>
  );
}
