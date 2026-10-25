// The banner of a decommissioned host page (when, by whom, why, what it released and whether
// the DNS names were kept) with the way back, and the note of what a reinstatement could not
// bind again.
import { For, Show } from "solid-js";
import type { Host, PlanWarning } from "../api/types";
import { Icon } from "../components/Icon";
import { Notice } from "../components/Notice";
import { t } from "../i18n";
import { warningText } from "../ipam/plan/describe";
import { DecommissionedBy } from "./DecommissionedTag";

export function DecommissionBanner(props: { host: Host; mayReinstate: boolean; onReinstate: () => void }) {
  return (
    <Show when={props.host.decommissioned}>
      {(d) => (
        <Notice kind="warn" role="status" title={t("hosts.banner.title")} testid="host-decommissioned">
          <div class="decommission-banner">
            <dl class="kv">
              <dt>{t("hosts.banner.when")}</dt>
              <dd data-testid="decommission-when">
                <DecommissionedBy decommissioned={d()} />
              </dd>
              <dt>{t("hosts.banner.reason")}</dt>
              <dd data-testid="decommission-reason-text">{d().reason?.trim() ? d().reason : t("hosts.banner.no_reason")}</dd>
              <dt>{t("hosts.banner.released")}</dt>
              <dd data-testid="decommission-released">
                {t("hosts.banner.released_count", { count: d().released?.length ?? 0 })}{" "}
                {d().kept_dns ? t("hosts.banner.dns_kept") : t("hosts.banner.dns_removed")}
              </dd>
            </dl>
            <Show when={props.mayReinstate && !props.host.meta.deleted}>
              <div class="row-actions">
                <button type="button" class="btn primary" data-testid="host-reinstate" onClick={() => props.onReinstate()}>
                  <Icon name="undo" />
                  {t("hosts.do.reinstate")}
                </button>
              </div>
            </Show>
          </div>
        </Notice>
      )}
    </Show>
  );
}

/** The addresses a reinstatement did not bind again, each with its cause. */
export function ReinstateSkipped(props: { warnings: readonly PlanWarning[]; onDismiss: () => void }) {
  return (
    <Show when={props.warnings.length > 0}>
      <Notice kind="warn" role="status" title={t("hosts.reinstate.skipped_title", { count: props.warnings.length })} testid="host-reinstate-skipped">
        <ul class="plain-list">
          <For each={props.warnings}>
            {(w) => (
              <li data-testid="reinstate-skipped" data-cause={w.params?.cause ?? ""}>
                {warningText(w)}
              </li>
            )}
          </For>
        </ul>
        <button type="button" class="btn sm ghost" onClick={() => props.onDismiss()}>
          {t("common.action.dismiss")}
        </button>
      </Notice>
    </Show>
  );
}
