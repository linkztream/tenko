// The fullest prefixes of the start page (U3, ui-plan section 5.1): per tenant and VRF a header
// line with the addresses in use and the network counts per family, then the fullest networks,
// one 28 px row each with the prefix, its description, a meter with the alarm line at the
// network's warning threshold and the share in use. Each row is a link to the network; the
// selector narrows the panel to one tenant and VRF, and "All N prefixes" opens IPAM. The
// threshold is said once in the panel's header when every row shares it (principle 7).
//
// Test ids: `dashboard-utilization`, `dashboard-vrf-select`, `dashboard-prefixes-all`,
// `dashboard-vrf` per VRF (`data-vrf`), `dashboard-prefix` per row (`data-key` the prefix,
// `data-level`, `data-percent`).
import { A } from "@solidjs/router";
import { createMemo, createSignal, createUniqueId, For, Show } from "solid-js";
import type { TreeNode } from "../api/types";
import { paths } from "../app/paths";
import { formatNumber, t } from "../i18n";
import { siCount } from "../ipam/words";
import type { VrfUse } from "./utilization";

/** Networks shown per VRF, the fullest first. */
export const NETWORKS_SHOWN = 6;

const ALL = "";

function vrfName(v: VrfUse): string {
  return t("dashboard.prefixes.vrf", { tenant: v.tenant?.name ?? t("dashboard.prefixes.no_tenant"), vrf: v.vrf.name });
}

function share(value: number): string {
  return formatNumber(Number.isFinite(value) ? value : 0, { maximumFractionDigits: 1 });
}

/** The warning threshold of a network, when it has an alarm. */
function threshold(node: TreeNode): number | null {
  return node.alarm?.warn_pct ?? null;
}

export function Prefixes(props: { vrfs: readonly VrfUse[] }) {
  const selectId = createUniqueId();
  const [chosen, setChosen] = createSignal(ALL);
  const shown = createMemo(() => (chosen() === ALL ? props.vrfs : props.vrfs.filter((v) => v.vrf.id === chosen())));
  const total = () => props.vrfs.reduce((n, v) => n + v.networks.length, 0);
  // The one threshold every drawn row shares, said once in the header.
  const common = createMemo(() => {
    const values = new Set(shown().flatMap((v) => v.networks.slice(0, NETWORKS_SHOWN).map(threshold)));
    return values.size === 1 ? [...values][0] : null;
  });

  return (
    <article class="dpanel dash-prefixes" aria-labelledby={`${selectId}-title`} data-testid="dashboard-utilization">
      <div class="dpanel-head">
        <h2 id={`${selectId}-title`}>{t("dashboard.prefixes.title")}</h2>
        <Show when={common() != null}>
          <span class="dpanel-note">{t("dashboard.prefixes.alarm_at", { percent: common()! })}</span>
        </Show>
        <Show when={props.vrfs.length > 1}>
          <label class="dpanel-select" for={selectId}>
            {t("dashboard.prefixes.choose")}
            <select id={selectId} data-testid="dashboard-vrf-select" value={chosen()} onChange={(e) => setChosen(e.currentTarget.value)}>
              <option value={ALL}>{t("dashboard.prefixes.all_vrfs", { count: props.vrfs.length })}</option>
              <For each={props.vrfs}>{(v) => <option value={v.vrf.id}>{vrfName(v)}</option>}</For>
            </select>
          </label>
        </Show>
        <A class="dpanel-link" href={paths.ipam()} data-testid="dashboard-prefixes-all">
          {t("dashboard.prefixes.all", { count: total() })}
        </A>
      </div>
      <For each={shown()}>
        {(v) => (
          <section class="dash-vrf" aria-label={vrfName(v)} data-testid="dashboard-vrf" data-vrf={v.vrf.id}>
            <h3 class="dash-vrf-head">
              <span class="dash-vrf-name">{vrfName(v)}</span>
              <span class="dash-vrf-totals">
                {t("dashboard.prefixes.totals", {
                  v4: siCount(String(v.families.v4.used)),
                  v4_count: v.families.v4.networks,
                  v6: siCount(String(v.families.v6.used)),
                  v6_count: v.families.v6.networks,
                })}
              </span>
            </h3>
            <Show when={v.networks.length > 0} fallback={<p class="muted dash-vrf-empty">{t("dashboard.prefixes.empty")}</p>}>
              <ul class="dash-prefix-list">
                <For each={v.networks.slice(0, NETWORKS_SHOWN)}>
                  {(n) => (
                    <li>
                      <A
                        class="dash-prefix"
                        href={paths.prefix(n.cidr, v.vrf.id)}
                        data-testid="dashboard-prefix"
                        data-key={n.cidr}
                        data-level={n.level}
                        data-percent={n.utilization.percent}
                        title={t("dashboard.prefixes.meter_title", { used: siCount(n.utilization.in_use), capacity: siCount(n.utilization.capacity) })}
                      >
                        <span class="mono dash-prefix-cidr">{n.cidr}</span>
                        <span class="dash-prefix-desc">{n.description || "—"}</span>
                        <span
                          class="dash-meter"
                          classList={{ over: n.level !== "normal" }}
                          style={{
                            "--v": `${Math.min(100, Math.max(0, n.utilization.percent))}%`,
                            "--alarm": threshold(n) != null ? `${threshold(n)}%` : undefined,
                          }}
                          aria-hidden="true"
                        >
                          <i />
                          <Show when={threshold(n) != null}>
                            <b />
                          </Show>
                        </span>
                        <span class="dash-prefix-pct">
                          {t("dashboard.prefixes.percent", { percent: share(n.utilization.percent) })}
                          <Show when={n.level !== "normal"}>
                            <span class="sr-only"> {t(n.level === "critical" ? "dashboard.prefixes.critical" : "dashboard.prefixes.warning")}</span>
                          </Show>
                        </span>
                      </A>
                    </li>
                  )}
                </For>
              </ul>
            </Show>
          </section>
        )}
      </For>
    </article>
  );
}
