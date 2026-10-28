// The recent changes of the start page (U3, ui-plan section 5.1): the newest audit records as
// the label of the catalog with the code below it in the data font (no raw code in the default
// view, principle 8), who made the change (a person, or "Tenko (reconciler)") and when. Records
// next to each other with the same action by the same principal are one row with a count ("×2").
// The "System activity" switch, a real checkbox, leaves out what Tenko did itself, so an
// administrator sees what people changed; its default comes from the profile (all activity under
// Lab and Home, people only under Standard and Hardened).
//
// Test ids: `dashboard-audit`, `dashboard-system-activity` (the checkbox), `dashboard-change` per row
// (`data-seq` the newest record, `data-count`, `data-system`), `dashboard-audit-all`.
import { A } from "@solidjs/router";
import { createSignal, createUniqueId, For, Show } from "solid-js";
import { api } from "../api/client";
import { createLiveQuery } from "../api/live";
import type { AuditRecord } from "../api/types";
import { paths } from "../app/paths";
import { AuditAction } from "../audit/actionLabel";
import { PrincipalLabel } from "../components/Principal";
import { TimeAgo } from "../grid/cells";
import { t } from "../i18n";
import { groupChanges, isSystem } from "./model";

/** Rows the panel shows. */
export const CHANGES_SHOWN = 8;
/** Records read: enough for eight rows after grouping and after leaving Tenko's own out. */
const READ = 100;

export function Changes(props: { systemDefault: boolean }) {
  const id = createUniqueId();
  // The profile's default is read once, when the panel mounts; the switch then holds for the page.
  // eslint-disable-next-line solid/reactivity
  const [system, setSystem] = createSignal(props.systemDefault);
  const audit = createLiveQuery<AuditRecord[]>({
    topics: ["audit"],
    fetch: async (signal) => {
      const page = await api.get("/api/v1/audit", { query: { order: "desc", limit: READ }, signal });
      return { value: page.items, revision: page.revision };
    },
  });
  const rows = () => groupChanges(audit.latest() ?? [], { system: system(), limit: CHANGES_SHOWN });

  return (
    <article class="dpanel dash-changes" aria-labelledby={`${id}-title`} data-testid="dashboard-audit">
      <div class="dpanel-head">
        <h2 id={`${id}-title`}>{t("dashboard.changes.title")}</h2>
        <label class="dpanel-switch">
          <input
            type="checkbox"
            checked={system()}
            data-testid="dashboard-system-activity"
            onChange={(e) => setSystem(e.currentTarget.checked)}
          />
          {t("dashboard.changes.system")}
        </label>
        <A class="dpanel-link" href={paths.audit()} data-testid="dashboard-audit-all">
          {t("dashboard.changes.all")}
        </A>
      </div>
      <Show
        when={rows().length > 0}
        fallback={
          <Show when={audit.latest()}>
            <p class="muted">{system() ? t("dashboard.changes.none") : t("dashboard.changes.none_people")}</p>
          </Show>
        }
      >
        <ul class="dash-change-list">
          <For each={rows()}>
            {(row) => (
              <li>
                <A
                  class="dash-change"
                  href={paths.auditRecord(row.record.seq)}
                  data-testid="dashboard-change"
                  data-seq={row.record.seq}
                  data-count={row.count}
                  data-system={isSystem(row.record.principal) ? "true" : undefined}
                >
                  <span class="dash-change-what">
                    <AuditAction draft={row.record.draft} stacked />
                    <Show when={row.count > 1}>
                      <span class="dash-change-count">{t("dashboard.changes.count", { count: row.count })}</span>
                    </Show>
                  </span>
                  <span class="dash-change-when">
                    <TimeAgo at={row.record.at} />
                  </span>
                  <span class="dash-change-who">
                    <PrincipalLabel principal={row.record.principal} />
                  </span>
                </A>
              </li>
            )}
          </For>
        </ul>
      </Show>
    </article>
  );
}
