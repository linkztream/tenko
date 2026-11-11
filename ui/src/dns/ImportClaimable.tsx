// The claimable names of a Windows zone file in the import wizard (ImportWizard.tsx): the
// list a preview shows (a page at a time), the rule that limits it, the names that stay static
// and why, and the approval that an import needs to make the names claimable by the computers
// they name. The server decides what is claimable; this file only shows its answer.
import { createMemo, For, Show } from "solid-js";
import { Notice } from "../components/Notice";
import { formatNumber, t, tDynamic } from "../i18n";
import type { ClaimableName, ClaimHeldName, ImportReport } from "./api";

/** The rule of the operator as the three fields hold it. */
export interface RuleText {
  under: string;
  within: string;
  except: string;
}

/** The entries of a field: one per line or separated by commas (spaces separate too, a name has none). */
export function entriesOf(text: string): string[] {
  return text.split(/[\s,]+/).filter((entry) => entry !== "");
}

/** Why a listing is not usable: the later page came with another digest, or an import found another set. */
export type Stale = "list" | "approval";

export function ClaimableSection(props: {
  report: ImportReport;
  names: readonly ClaimableName[];
  next: string | null;
  stale: Stale | null;
  approved: boolean;
  onApprove: (approved: boolean) => void;
  rule: RuleText;
  onRule: (field: keyof RuleText, value: string) => void;
  /** The fields hold another rule than the preview was made with. */
  dirty: boolean;
  onPreview: () => void;
  onMore: () => void;
  busy: boolean;
}) {
  const count = () => props.report.claimable ?? 0;
  const overflow = () => props.report.claimable_overflow === true;
  const digest = () => props.report.claimable_digest ?? null;
  // The approval covers every name of the digest: it is offered only once the whole list is shown.
  const canApprove = () => !!digest() && count() > 0 && props.stale === null && !props.dirty && !props.next;
  return (
    <div class="dns-claim" data-testid="import-claim">
      <h3 data-testid="import-claim-count" data-count={count()}>
        {t("dns.import.claim.title", { count: count() })}
      </h3>
      <Show when={overflow()}>
        <Notice kind="warn" testid="import-claim-overflow">
          {t("dns.import.claim.overflow")}
        </Notice>
      </Show>
      <Show when={props.stale === "list"}>
        <Notice kind="warn" role="alert" testid="import-claim-stale">
          {t("dns.import.claim.stale")}
        </Notice>
      </Show>
      <Show when={props.names.length > 0}>
        <p class="muted">{t("dns.import.claim.intro")}</p>
        <div class="table-wrap dns-claim-list">
          <table class="plain" data-testid="import-claim-names">
            <thead>
              <tr>
                <th>{t("dns.col.name")}</th>
                <th>{t("dns.col.type")}</th>
                <th>{t("dns.import.claim.claimant")}</th>
                <th>{t("dns.import.claim.records")}</th>
                <th class="r">{t("dns.import.losses.line")}</th>
              </tr>
            </thead>
            <tbody>
              <For each={props.names}>
                {(row) => (
                  <tr data-testid="import-claim-row" data-key={`${row.name}/${row.rtype}`} data-claimant={row.claimant}>
                    <td class="mono">{row.name}</td>
                    <td class="mono">{row.rtype}</td>
                    <td class="mono">{row.claimant}</td>
                    <td class="mono">
                      {row.records.join(", ")}
                      <Show when={row.more > 0}>
                        {" "}
                        <span class="muted">{t("dns.import.claim.more_records", { count: row.more })}</span>
                      </Show>
                    </td>
                    <td class="r num">{row.line}</td>
                  </tr>
                )}
              </For>
            </tbody>
          </table>
        </div>
        <p class="muted dns-claim-paging" data-testid="import-claim-paging">
          {t("dns.import.claim.shown", { shown: formatNumber(props.names.length), total: formatNumber(count()) })}
          <Show when={props.next}>
            {" "}
            <button type="button" class="btn" data-testid="import-claim-more" disabled={props.busy} onClick={() => props.onMore()}>
              {t("dns.import.claim.more")}
            </button>
          </Show>
        </p>
      </Show>
      <details class="import-group dns-claim-rule" data-testid="import-rule">
        <summary>{t("dns.import.rule.title")}</summary>
        <p class="muted">{t("dns.import.rule.help")}</p>
        <div class="dns-claim-fields">
          <For each={["under", "within", "except"] as const}>
            {(field) => (
              <div class="field">
                <label for={`dns-f-claim_${field}`}>{t(`dns.import.rule.${field}`)}</label>
                <textarea
                  id={`dns-f-claim_${field}`}
                  class="input mono"
                  rows={2}
                  spellcheck={false}
                  value={props.rule[field]}
                  data-testid={`field-claim-${field}`}
                  onInput={(e) => props.onRule(field, e.currentTarget.value)}
                />
              </div>
            )}
          </For>
        </div>
      </details>
      <Show when={props.dirty || props.stale !== null}>
        <div>
          <button type="button" class="btn" data-testid="import-rule-apply" disabled={props.busy} onClick={() => props.onPreview()}>
            {t("dns.import.rule.apply")}
          </button>
          <Show when={props.dirty}>
            {" "}
            <span class="muted" data-testid="import-rule-dirty">
              {t("dns.import.rule.dirty")}
            </span>
          </Show>
        </div>
      </Show>
      <HeldBack count={props.report.held_back ?? 0} names={props.report.held_back_names ?? []} />
      <label class="ackrow">
        <input
          type="checkbox"
          class="cb"
          checked={props.approved}
          disabled={!canApprove()}
          data-testid="field-claim-approve"
          onChange={(e) => props.onApprove(e.currentTarget.checked)}
        />
        {t("dns.import.approve.label", { count: count() })}
      </label>
      <p class="muted" data-testid="import-approve-help">
        {t("dns.import.approve.help")}
        <Show when={count() === 0 && !overflow()}>
          {" "}
          {t("dns.import.approve.none")}
        </Show>
        <Show when={props.next}>
          {" "}
          <span data-testid="import-approve-whole">{t("dns.import.approve.whole")}</span>
        </Show>
      </p>
    </div>
  );
}

/** The names a Windows file brings that stay static, each with its reason in words. */
export function HeldBack(props: { count: number; names: readonly ClaimHeldName[] }) {
  const more = createMemo(() => Math.max(0, props.count - props.names.length));
  return (
    <Show when={props.count > 0}>
      <div class="dns-claim-held" data-testid="import-held">
        <h3 data-testid="import-held-count" data-count={props.count}>
          {t("dns.import.held.title", { count: props.count })}
        </h3>
        <div class="table-wrap dns-claim-list">
          <table class="plain" data-testid="import-held-names">
            <thead>
              <tr>
                <th>{t("dns.col.name")}</th>
                <th>{t("dns.col.type")}</th>
                <th>{t("dns.import.held.reason")}</th>
                <th class="r">{t("dns.import.losses.line")}</th>
              </tr>
            </thead>
            <tbody>
              <For each={props.names}>
                {(row) => (
                  <tr data-testid="import-held-row" data-key={`${row.name}/${row.rtype}`} data-reason={row.reason}>
                    <td class="mono">{row.name}</td>
                    <td class="mono">{row.rtype}</td>
                    <td>{tDynamic(`dns.import.held.${row.reason}`) ?? <code>{row.reason}</code>}</td>
                    <td class="r num">{row.line}</td>
                  </tr>
                )}
              </For>
            </tbody>
          </table>
        </div>
        <Show when={more() > 0}>
          <p class="muted" data-testid="import-held-more" data-count={more()}>
            {t("dns.import.held.more", { count: formatNumber(more()) })}
          </p>
        </Show>
      </div>
    </Show>
  );
}
