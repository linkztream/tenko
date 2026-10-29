// The small panels beside a network's meter (section 5.2 of the UI plan): its DHCP scope, the
// findings inside it and its recent changes, from what the API carries today. The wireless
// networks (SSIDs) of a prefix have no route yet; the topology's SSID view (U7) is where they
// show until then. A panel is never empty: it holds data or one sentence.
import { createResource, For, Show } from "solid-js";
import type { HistoryEntry } from "../../api/types";
import { paths } from "../../app/paths";
import { PrincipalLabel } from "../../components/Principal";
import { listScopes } from "../../dhcp/api";
import { dhcpPaths } from "../../dhcp/paths";
import { TimeAgo } from "../../grid/cells";
import { t } from "../../i18n";
import { areaEnabled } from "../../updates/modules";
import { historyPage } from "../collections";
import type { MapFinding } from "../../components/addressMapCells";

/** The DHCP scope of a network, or one sentence; nothing when DHCP is off or not readable. */
export function DhcpPanel(props: { prefixId: string; revision: number | null | undefined }) {
  const [scope] = createResource(
    () => (areaEnabled("dhcp") ? ([props.prefixId, props.revision] as const) : false),
    async ([id]) => {
      try {
        const all = await listScopes();
        return { found: all.items.find((s) => s.prefix === id) ?? null };
      } catch {
        return null;
      }
    },
  );
  return (
    <Show when={scope.latest}>
      {(s) => (
        <section class="side-panel" data-testid="panel-dhcp" aria-labelledby="panel-dhcp-title">
          <h2 id="panel-dhcp-title">{t("ipam.panel.dhcp.title")}</h2>
          <Show when={s().found} fallback={<p class="muted">{t("ipam.panel.dhcp.none")}</p>}>
            {(found) => (
              <>
                <p>
                  <span>{t("ipam.panel.dhcp.pools", { count: found().pools })}</span>
                  <span>{t("ipam.panel.dhcp.leases", { count: found().leases })}</span>
                  <Show when={found().enabled === false}>
                    <span class="muted">{t("ipam.panel.dhcp.disabled")}</span>
                  </Show>
                </p>
                <a class="more" href={dhcpPaths.scope(found().cidr)}>
                  {t("ipam.panel.dhcp.open")}
                </a>
              </>
            )}
          </Show>
        </section>
      )}
    </Show>
  );
}

/** The findings inside a prefix by severity, with the way to Discovery. */
export function FindingsPanel(props: { prefixId: string; findings: readonly MapFinding[] | undefined }) {
  const count = (severity: MapFinding["severity"]) => (props.findings ?? []).filter((f) => f.severity === severity).length;
  return (
    <Show when={props.findings}>
      <section class="side-panel" data-testid="panel-findings" aria-labelledby="panel-findings-title">
        <h2 id="panel-findings-title">{t("ipam.panel.findings.title")}</h2>
        <Show when={(props.findings?.length ?? 0) > 0} fallback={<p class="muted">{t("ipam.panel.findings.none")}</p>}>
          <p>
            <Show when={count("act") > 0}>
              <span class="sev sev-act">{t("ipam.panel.findings.act", { count: count("act") })}</span>
            </Show>
            <Show when={count("review") > 0}>
              <span class="sev sev-review">{t("ipam.panel.findings.review", { count: count("review") })}</span>
            </Show>
            <Show when={count("info") > 0}>
              <span class="muted">{t("ipam.panel.findings.info", { count: count("info") })}</span>
            </Show>
          </p>
          <a class="more" href={paths.discovery({ prefix: props.prefixId })}>
            {t("ipam.panel.findings.open")}
          </a>
        </Show>
      </section>
    </Show>
  );
}

/** The newest changes of a prefix, with the way to the whole history. */
export function ChangesPanel(props: { prefixId: string; revision: number | null | undefined; onAll: () => void }) {
  const [entries] = createResource(
    () => [props.prefixId, props.revision] as const,
    async ([id]) => {
      try {
        return (await historyPage("prefixes", id)).items.slice(0, 3) as HistoryEntry[];
      } catch {
        return null;
      }
    },
  );
  return (
    <Show when={entries.latest}>
      {(list) => (
        <section class="side-panel" data-testid="panel-changes" aria-labelledby="panel-changes-title">
          <h2 id="panel-changes-title">{t("ipam.panel.changes.title")}</h2>
          <Show when={list().length > 0} fallback={<p class="muted">{t("ipam.panel.changes.none")}</p>}>
            <ul>
              <For each={list()}>
                {(entry) => (
                  <li>
                    <span>{t(`ipam.plan.change.${entry.action}`)}</span>
                    <PrincipalLabel principal={entry.by} />
                    <TimeAgo at={entry.at} />
                  </li>
                )}
              </For>
            </ul>
            <button type="button" class="btn sm ghost more" onClick={() => props.onAll()}>
              {t("ipam.panel.changes.all")}
            </button>
          </Show>
        </section>
      )}
    </Show>
  );
}
