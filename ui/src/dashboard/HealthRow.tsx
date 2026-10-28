// The health row of the start page (U3, ui-plan section 5.1): metric blocks in one row, each a
// link to where its number is explained. IPv4 and IPv6 addresses in use (with the network count
// and, for IPv4, the fullest network), the findings to act on (with those to review and the
// information), the jobs running (with those waiting for you) and the connectors healthy (n of m,
// their names) under Standard and Hardened, and the utilization alarms. The findings and the jobs
// waiting for you are the counts of the one findings store, so they equal the strip, the rail and
// the status bar.
//
// Test ids: `dashboard-health`; `dashboard-health-v4`, `-v6`, `-findings`, `-jobs`, `-alarms` and
// `dashboard-connectors` (each with `data-value`); `dashboard-connectors-hint` (`data-total`,
// `data-failing`, absent until the connectors were read).
import { createMemo, Show } from "solid-js";
import { createLiveQuery } from "../api/live";
import { paths } from "../app/paths";
import { Metric } from "../components/Metric";
import { listConnectors, type ConnectorView } from "../connectors/api";
import { connectorHealth } from "../connectors/model";
import { formatList, formatNumber, t } from "../i18n";
import type { FindingCounts } from "../shell/findings";
import { moduleRunning } from "../updates/modules";
import type { VrfUse } from "./utilization";

/** Names of connectors the block lists before "and N more". */
const NAMES = 3;

/** A count of addresses: a bigint beyond the safe integers reads as the largest, which SI shows as such. */
function count(value: bigint): number {
  return value > BigInt(Number.MAX_SAFE_INTEGER) ? Number.MAX_SAFE_INTEGER : Number(value);
}

export function HealthRow(props: {
  vrfs: readonly VrfUse[] | undefined;
  counts: FindingCounts | null;
  /** Jobs running now; null while unknown. */
  running: number | null;
  /** The Jobs and Connectors blocks (Standard and Hardened, or Show all). */
  operations: boolean;
}) {
  const ipam = () => moduleRunning("ipam");
  const families = createMemo(() => {
    const list = props.vrfs ?? [];
    const v4 = list.reduce((n, v) => n + v.families.v4.used, 0n);
    const v6 = list.reduce((n, v) => n + v.families.v6.used, 0n);
    const v4Networks = list.reduce((n, v) => n + v.families.v4.networks, 0);
    const v6Networks = list.reduce((n, v) => n + v.families.v6.networks, 0);
    const fullest = list
      .flatMap((v) => v.networks)
      .filter((n) => !n.cidr.includes(":"))
      .reduce((max, n) => Math.max(max, n.utilization.percent), 0);
    return { v4, v6, v4Networks, v6Networks, fullest };
  });
  const alarms = createMemo(() => (props.vrfs ?? []).flatMap((v) => v.networks.filter((n) => n.level !== "normal")));
  const critical = () => alarms().filter((n) => n.level === "critical").length;

  const connectors = createLiveQuery<ConnectorView[] | null>({
    topics: ["connectors"],
    debounceMs: 500,
    fetch: async (signal) => {
      try {
        return { value: await listConnectors(signal) };
      } catch {
        return { value: null };
      }
    },
  });
  const health = createMemo(() => {
    const list = (connectors.latest() ?? []).filter((c) => c.enabled);
    const healthy = list.filter((c) => connectorHealth(c) === "healthy");
    return { total: list.length, healthy: healthy.length, names: list.map((c) => c.name) };
  });
  const names = () => {
    const all = health().names;
    if (all.length === 0) return t("dashboard.health.connectors_none");
    const shown = all.slice(0, NAMES);
    return all.length > NAMES ? t("dashboard.health.connectors_more", { names: formatList(shown), count: all.length - NAMES }) : formatList(shown);
  };

  const act = () => props.counts?.total.act ?? null;
  const waiting = () => props.counts?.areas.jobs.act ?? 0;

  return (
    <section class="metric-row health-row" aria-label={t("dashboard.health.label")} data-testid="dashboard-health">
      <Show when={ipam()}>
        <Metric
          testid="dashboard-health-v4"
          label={t("dashboard.health.v4")}
          value={props.vrfs ? count(families().v4) : null}
          unit={t("dashboard.health.in_use")}
          href={paths.ipam()}
          context={
            props.vrfs
              ? t("dashboard.health.v4_context", { count: families().v4Networks, fullest: formatNumber(families().fullest, { maximumFractionDigits: 1 }) })
              : undefined
          }
        />
        <Metric
          testid="dashboard-health-v6"
          label={t("dashboard.health.v6")}
          value={props.vrfs ? count(families().v6) : null}
          unit={t("dashboard.health.in_use")}
          href={paths.ipam()}
          context={props.vrfs ? t("dashboard.health.v6_context", { count: families().v6Networks }) : undefined}
        />
      </Show>
      <Metric
        testid="dashboard-health-findings"
        label={t("dashboard.health.findings")}
        value={act()}
        unit={t("dashboard.health.to_act_on")}
        href={paths.discovery({ severity: "act" })}
        tone={(act() ?? 0) > 0 ? "act" : undefined}
        context={props.counts ? t("dashboard.health.findings_context", { review: props.counts.total.review, info: props.counts.total.info }) : undefined}
      />
      <Show when={props.operations}>
        <Metric
          testid="dashboard-health-jobs"
          label={t("dashboard.health.jobs")}
          value={props.running}
          unit={t("dashboard.health.running")}
          href={waiting() > 0 ? paths.jobs({ state: "waiting" }) : paths.jobs()}
          tone={waiting() > 0 ? "act" : undefined}
          context={t("dashboard.health.jobs_context", { count: waiting() })}
        />
        <Metric
          testid="dashboard-connectors"
          label={t("dashboard.health.connectors")}
          value={connectors.latest() ? `${health().healthy}/${health().total}` : null}
          data={connectors.latest() ? health().healthy : undefined}
          unit={t("dashboard.health.healthy")}
          href={paths.connectors()}
          context={
            <span
              data-testid="dashboard-connectors-hint"
              data-total={connectors.latest() ? health().total : undefined}
              data-failing={connectors.latest() ? health().total - health().healthy : undefined}
            >
              {connectors.latest() ? names() : ""}
            </span>
          }
        />
      </Show>
      <Show when={ipam()}>
        <Metric
          testid="dashboard-health-alarms"
          label={t("dashboard.health.alarms")}
          value={props.vrfs ? alarms().length : null}
          href={paths.ipam()}
          tone={critical() > 0 ? "act" : undefined}
          context={
            props.vrfs
              ? alarms().length === 0
                ? t("dashboard.health.alarms_none")
                : t("dashboard.health.alarms_critical", { count: critical() })
              : undefined
          }
        />
      </Show>
    </section>
  );
}
