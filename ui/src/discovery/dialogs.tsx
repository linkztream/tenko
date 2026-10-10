// The dialogs of the proposal inbox: approve (the plan dialog of IPAM writes, with a dry run
// first and the acknowledgements it asks for), reject or dismiss with an optional reason, and
// the report of a reconciler run.
import { createSignal, For, Show } from "solid-js";
import { Dialog } from "../components/Dialog";
import { Icon } from "../components/Icon";
import { ErrorNotice } from "../components/Notice";
import { formatDateTime, formatNumber, t, type MessageKey } from "../i18n";
import { PlanDialog } from "../ipam/plan/PlanDialog";
import { approveProposal, MAX_REASON_BYTES, rejectProposal, type Decision, type Proposal, type ReconcileReport } from "./api";
import { ruleText } from "./model";

/** Approves a proposal: the planner's preview of its commands, then the apply at the revision seen. */
export function ApproveDialog(props: { proposal: Proposal; onDone: (decision: Decision) => void; onClose: () => void }) {
  const count = () => props.proposal.commands?.length ?? 0;
  return (
    <PlanDialog<Decision>
      title={t("discovery.approve.title")}
      confirmLabel={t("discovery.approve.confirm", { count: count() })}
      intro={<p class="muted">{ruleText(props.proposal)}</p>}
      send={(o) => approveProposal(props.proposal, o)}
      onDone={props.onDone}
      onClose={props.onClose}
      testid="dialog-approve"
    />
  );
}

function bytes(text: string): number {
  return new TextEncoder().encode(text.trim()).length;
}

/** Rejects a proposal, or dismisses a conflict once its cause is resolved; the reason is optional. */
export function RejectDialog(props: { proposal: Proposal; onDone: (decision: Decision) => void; onClose: () => void }) {
  const conflict = () => props.proposal.kind === "conflict";
  const [reason, setReason] = createSignal("");
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>(null);
  const tooLong = () => bytes(reason()) > MAX_REASON_BYTES;

  const submit = async (e: Event) => {
    e.preventDefault();
    if (tooLong() || busy()) return;
    setBusy(true);
    setError(null);
    try {
      props.onDone(await rejectProposal(props.proposal, reason()));
    } catch (err) {
      setError(err);
      setBusy(false);
    }
  };

  return (
    <Dialog label={conflict() ? t("discovery.reject.title_conflict") : t("discovery.reject.title")} onClose={props.onClose} class="dialog discovery-dialog">
      <form class="discovery-form" data-testid="dialog-reject" onSubmit={(e) => void submit(e)}>
        <h2 class="dialog-title">{conflict() ? t("discovery.reject.title_conflict") : t("discovery.reject.title")}</h2>
        <p class="muted">{ruleText(props.proposal)}</p>
        <p>{conflict() ? t("discovery.reject.body_conflict") : t("discovery.reject.body")}</p>
        <div class="field">
          <label for="reject-reason">{t("discovery.reject.reason")}</label>
          <textarea
            id="reject-reason"
            class="input"
            rows={3}
            value={reason()}
            data-testid="field-reason"
            aria-invalid={tooLong() ? "true" : undefined}
            aria-describedby="reject-reason-help"
            onInput={(e) => setReason(e.currentTarget.value)}
          />
          <small id="reject-reason-help" class={tooLong() ? "help bad" : "help"}>
            <Show when={tooLong()} fallback={t("discovery.reject.reason_hint")}>
              <Icon name="alert" size="xs" /> {t("discovery.reject.reason_too_long", { max: MAX_REASON_BYTES })}
            </Show>
          </small>
        </div>
        <ErrorNotice error={error()} />
        <div class="dialog-actions">
          <button type="button" class="btn ghost" onClick={() => props.onClose()}>
            {t("common.action.cancel")}
          </button>
          <button type="submit" class="btn primary" disabled={busy() || tooLong()} data-testid="form-submit">
            {conflict() ? t("discovery.reject.confirm_conflict") : t("discovery.reject.confirm")}
          </button>
        </div>
      </form>
    </Dialog>
  );
}

const REPORT_LINES: readonly [keyof ReconcileReport, MessageKey][] = [
  ["opened", "discovery.report.opened"],
  ["refreshed", "discovery.report.refreshed"],
  ["unchanged", "discovery.report.unchanged"],
  ["superseded", "discovery.report.superseded"],
  ["expired", "discovery.report.expired"],
  ["suppressed", "discovery.report.suppressed"],
  ["adopted", "discovery.report.adopted"],
  ["adoption_failures", "discovery.report.adoption_failures"],
  ["sightings", "discovery.report.sightings"],
  ["moves_confirmed", "discovery.report.moves_confirmed"],
];

/** What one run of the reconciler did. */
export function ReconcileReportDialog(props: { report: ReconcileReport; onClose: () => void }) {
  return (
    <Dialog label={t("discovery.report.title")} onClose={props.onClose} class="dialog discovery-dialog" testid="dialog-reconcile-report">
      <h2 class="dialog-title">{t("discovery.report.title")}</h2>
      <p class="muted">{t("discovery.report.at", { at: formatDateTime(props.report.at) })}</p>
      <dl class="kv report-kv">
        <For each={REPORT_LINES}>
          {([member, label]) => (
            <>
              <dt>{t(label)}</dt>
              <dd class="num" data-testid="report-count" data-key={member}>
                {formatNumber(Number(props.report[member] ?? 0))}
              </dd>
            </>
          )}
        </For>
      </dl>
      <Show when={props.report.revision == null}>
        <p class="muted">{t("discovery.report.nothing")}</p>
      </Show>
      <div class="dialog-actions">
        <button type="button" class="btn primary" onClick={() => props.onClose()}>
          {t("common.action.close")}
        </button>
      </div>
    </Dialog>
  );
}
