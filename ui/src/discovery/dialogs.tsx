// The dialogs of the proposal inbox: approve (the plan dialog of IPAM writes, with a dry run
// first and the acknowledgements it asks for), reject or dismiss with an optional reason, and
// the report of a reconciler run. The same decisions for many proposals at once: one confirmation
// for the approvals, the same reason dialog for the rejections, and the panel of the proposals
// the batch skipped.
import { createSignal, For, Show } from "solid-js";
import { ApiError, errorMessage } from "../api/problem";
import { Dialog } from "../components/Dialog";
import { Icon } from "../components/Icon";
import { ErrorNotice } from "../components/Notice";
import { formatDateTime, formatNumber, t, type MessageKey } from "../i18n";
import { PlanDialog } from "../ipam/plan/PlanDialog";
import { approveProposal, MAX_REASON_BYTES, type ApproveRequest, type BatchDecision, type BatchItem, type Decision, type Proposal, type ReconcileReport } from "./api";
import { kindSummary, ruleText } from "./model";

/**
 * Approves a proposal: the planner's preview of its commands, then the apply at the revision
 * seen. A `request` names the one of the proposal's names that the host takes and what to
 * remember; the preview and the apply both carry it.
 */
export function ApproveDialog(props: { proposal: Proposal; request?: ApproveRequest; onDone: (decision: Decision) => void; onClose: () => void }) {
  const count = () => props.proposal.commands?.length ?? 0;
  return (
    <PlanDialog<Decision>
      title={t("discovery.approve.title")}
      confirmLabel={t("discovery.approve.confirm", { count: count() })}
      intro={
        <>
          <p class="muted">{ruleText(props.proposal)}</p>
          <Show when={props.request?.choice}>
            {(name) => (
              <p data-testid="approve-choice">
                {t("discovery.approve.choice", { name: name() })}
                <Show when={props.request?.remember}>
                  {(remember) => <span class="muted"> {t(`discovery.approve.remember_${remember()}`)}</span>}
                </Show>
              </p>
            )}
          </Show>
        </>
      }
      send={(o) => approveProposal(props.proposal, o, props.request)}
      onDone={props.onDone}
      onClose={props.onClose}
      testid="dialog-approve"
    />
  );
}

function bytes(text: string): number {
  return new TextEncoder().encode(text.trim()).length;
}

/**
 * Rejects a proposal, or dismisses a conflict once its cause is resolved; the reason is optional.
 * With several proposals the one reason goes to all of them.
 */
export function RejectDialog<R>(props: { proposals: Proposal[]; send: (reason: string) => Promise<R>; onDone: (result: R) => void; onClose: () => void }) {
  const many = () => props.proposals.length > 1;
  const conflict = () => !many() && props.proposals[0]?.kind === "conflict";
  const title = () => (many() ? t("discovery.batch.reject_title", { count: props.proposals.length }) : conflict() ? t("discovery.reject.title_conflict") : t("discovery.reject.title"));
  const confirm = () => (many() ? title() : conflict() ? t("discovery.reject.confirm_conflict") : t("discovery.reject.confirm"));
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
      props.onDone(await props.send(reason()));
    } catch (err) {
      setError(err);
      setBusy(false);
    }
  };

  return (
    <Dialog label={title()} onClose={props.onClose} class="dialog discovery-dialog">
      <form class="discovery-form" data-testid="dialog-reject" onSubmit={(e) => void submit(e)}>
        <h2 class="dialog-title">{title()}</h2>
        <Show
          when={many()}
          fallback={
            <>
              <p class="muted">{props.proposals[0] ? ruleText(props.proposals[0]) : ""}</p>
              <p>{conflict() ? t("discovery.reject.body_conflict") : t("discovery.reject.body")}</p>
            </>
          }
        >
          <p data-testid="reject-kinds">{t("discovery.batch.reject_body", { kinds: kindSummary(props.proposals) })}</p>
        </Show>
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
            {confirm()}
          </button>
        </div>
      </form>
    </Dialog>
  );
}

/** The one confirmation of an approval of many proposals: how many, and of which kinds. */
export function ApproveManyDialog(props: { proposals: Proposal[]; send: () => Promise<BatchDecision>; onDone: (result: BatchDecision) => void; onClose: () => void }) {
  const title = () => t("discovery.batch.approve_title", { count: props.proposals.length });
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>(null);

  const submit = async (e: Event) => {
    e.preventDefault();
    if (busy()) return;
    setBusy(true);
    setError(null);
    try {
      props.onDone(await props.send());
    } catch (err) {
      setError(err);
      setBusy(false);
    }
  };

  return (
    <Dialog label={title()} onClose={props.onClose} class="dialog discovery-dialog">
      <form class="discovery-form" data-testid="dialog-approve-many" onSubmit={(e) => void submit(e)}>
        <h2 class="dialog-title">{title()}</h2>
        <p data-testid="approve-kinds">{t("discovery.batch.approve_body", { kinds: kindSummary(props.proposals) })}</p>
        <ErrorNotice error={error()} />
        <div class="dialog-actions">
          <button type="button" class="btn ghost" onClick={() => props.onClose()}>
            {t("common.action.cancel")}
          </button>
          <button type="submit" class="btn primary" disabled={busy()} data-testid="form-submit">
            {t("discovery.batch.approve_confirm", { count: props.proposals.length })}
          </button>
        </div>
      </form>
    </Dialog>
  );
}

/** The refusal of the single route for a skipped proposal, in words. */
function skipReason(item: BatchItem): string {
  return errorMessage(new ApiError({ status: item.status ?? 0, code: item.code ?? "", title: "", detail: item.message ?? "", params: item.params ?? {} }));
}

/** The proposals a batch skipped, each with the reason; the person may keep them selected. */
export function SkippedDialog(props: { result: BatchDecision; label: (id: string) => string; onKeep: (ids: string[]) => void; onClose: () => void }) {
  const skipped = () => props.result.results.filter((r) => r.outcome === "skipped");
  return (
    <Dialog label={t("discovery.batch.skipped_title", { count: skipped().length })} onClose={props.onClose} class="dialog discovery-dialog" testid="dialog-skipped">
      <h2 class="dialog-title">{t("discovery.batch.skipped_title", { count: skipped().length })}</h2>
      <p class="muted">{t("discovery.batch.skipped_body")}</p>
      <ul class="skipped-list" data-testid="skipped-list">
        <For each={skipped()}>
          {(item) => (
            <li data-testid="skipped-item" data-id={item.id} data-code={item.code ?? ""}>
              <span class="skipped-what">{props.label(item.id)}</span>
              <span class="muted">{skipReason(item)}</span>
            </li>
          )}
        </For>
      </ul>
      <div class="dialog-actions">
        <button type="button" class="btn ghost" data-testid="skipped-keep" onClick={() => props.onKeep(skipped().map((r) => r.id))}>
          {t("discovery.batch.keep")}
        </button>
        <button type="button" class="btn primary" data-testid="skipped-close" onClick={() => props.onClose()}>
          {t("common.action.close")}
        </button>
      </div>
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
