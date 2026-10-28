// The security panel of the start page under Hardened (U3, ui-plan section 6: "Standard set +
// security events and audit summary"), both read from the audit log, the only source of either
// in the API: the security events are the records of the `auth.` actions of the last 24 hours that
// were denied or failed (sign-ins refused, access denied), the newest first; the audit summary is
// the number of records of those 24 hours, by people and by Tenko itself, with the link to the
// log. Follows the `audit` topic.
//
// Test ids: `dashboard-security` (`data-events`, `data-records`), `dashboard-security-event` per
// row (`data-seq`, `data-outcome`), `dashboard-security-audit`.
import { A } from "@solidjs/router";
import { createUniqueId, For, Show } from "solid-js";
import { api } from "../api/client";
import { createLiveQuery } from "../api/live";
import type { AuditRecord } from "../api/types";
import { paths } from "../app/paths";
import { AuditAction } from "../audit/actionLabel";
import { Metric } from "../components/Metric";
import { PrincipalLabel } from "../components/Principal";
import { TimeAgo } from "../grid/cells";
import { t } from "../i18n";
import { isSystem } from "./model";

/** The window of both figures. */
const DAY_MS = 24 * 3600 * 1000;
/** Events listed; the count covers every one read. */
const EVENTS_SHOWN = 5;
/** Records read per figure; a page that has more says so ("1K+"). */
const READ = 1000;

interface Summary {
  events: AuditRecord[];
  /** Whether more events than were read exist. */
  moreEvents: boolean;
  records: number;
  people: number;
  moreRecords: boolean;
}

export function SecurityPanel() {
  const id = createUniqueId();
  const live = createLiveQuery<Summary | null>({
    topics: ["audit"],
    debounceMs: 1000,
    fetch: async (signal) => {
      const from = new Date(Date.now() - DAY_MS).toISOString();
      try {
        const [denied, failed, all] = await Promise.all([
          api.get("/api/v1/audit", { query: { action: "auth.", outcome: "denied", from, order: "desc", limit: READ }, signal }),
          api.get("/api/v1/audit", { query: { action: "auth.", outcome: "failed", from, order: "desc", limit: READ }, signal }),
          api.get("/api/v1/audit", { query: { from, order: "desc", limit: READ }, signal }),
        ]);
        const events = [...denied.items, ...failed.items].sort((a, b) => b.seq - a.seq);
        return {
          value: {
            events,
            moreEvents: !!denied.next_cursor || !!failed.next_cursor,
            records: all.items.length,
            people: all.items.filter((r) => !isSystem(r.principal)).length,
            moreRecords: !!all.next_cursor,
          },
        };
      } catch {
        // An account that may not read the audit log sees no panel.
        return { value: null };
      }
    },
  });
  const summary = () => live.latest();

  return (
    <Show when={summary()}>
      {(s) => (
        <article class="dpanel dash-security" aria-labelledby={id} data-testid="dashboard-security" data-events={s().events.length} data-records={s().records}>
          <div class="dpanel-head">
            <h2 id={id}>{t("dashboard.security.title")}</h2>
            <span class="dpanel-note">{t("dashboard.security.window")}</span>
            <A class="dpanel-link" href={paths.audit()} data-testid="dashboard-security-audit">
              {t("dashboard.changes.all")}
            </A>
          </div>
          <div class="metric-row flat">
            <Metric
              testid="dashboard-security-events"
              label={t("dashboard.security.events")}
              value={s().moreEvents ? t("dashboard.security.more", { count: s().events.length }) : s().events.length}
              data={s().events.length}
              tone={s().events.length > 0 ? "act" : undefined}
              context={t("dashboard.security.events_context")}
              href={paths.audit({ action: "auth.", outcome: "denied" })}
            />
            <Metric
              testid="dashboard-security-records"
              label={t("dashboard.security.records")}
              value={s().moreRecords ? t("dashboard.security.more", { count: s().records }) : s().records}
              data={s().records}
              context={t("dashboard.security.records_context", { people: s().people, system: s().records - s().people })}
              href={paths.audit()}
            />
          </div>
          <Show when={s().events.length > 0} fallback={<p class="muted">{t("dashboard.security.none")}</p>}>
            <ul class="dash-change-list">
              <For each={s().events.slice(0, EVENTS_SHOWN)}>
                {(r) => (
                  <li>
                    <A class="dash-change" href={paths.auditRecord(r.seq)} data-testid="dashboard-security-event" data-seq={r.seq} data-outcome={r.draft.outcome.kind}>
                      <span class="dash-change-what">
                        <AuditAction draft={r.draft} stacked />
                      </span>
                      <span class="dash-change-when">
                        <TimeAgo at={r.at} />
                      </span>
                      <span class="dash-change-who">
                        <PrincipalLabel principal={r.principal} />
                      </span>
                    </A>
                  </li>
                )}
              </For>
            </ul>
          </Show>
        </article>
      )}
    </Show>
  );
}
