// The side panel of a finding, shared by the Discovery list and the reconciliation view (U4,
// ui-plan section 5.3): a finding of a proposal opens the proposal's panel with its decisions
// (approve, reject or dismiss, decommission a host of a conflict, keep both); any other finding of
// the reconciliation view opens its evidence (the four truths with the winner marked, the MAC
// addresses, the OS field and the vendors, the rule) and its default action. A conflict leads
// with the MAC addresses on the address, both of them, before anything else.
//
// `DecisionPanel` takes what is selected: a proposal by its id, a finding by its id (read from
// `GET /findings/{id}`), or a finding with the row of the view it stands for, as the
// reconciliation view has them. It owns the approve and reject dialogs of the proposal panel.
import { A } from "@solidjs/router";
import { createResource, createSignal, Show } from "solid-js";
import { api } from "../api/client";
import { fetchAll } from "../api/paginate";
import { Icon } from "../components/Icon";
import { ErrorNotice, Notice } from "../components/Notice";
import { TimeAgo } from "../grid/cells";
import { t } from "../i18n";
import { reconcilePath } from "../ipam/reconcile/links";
import type { ReconcileRow } from "../ipam/reconcile/model";
import { TruthList } from "../ipam/reconcile/truths";
import { useWriteToast } from "../ipam/plan/PlanDialog";
import { isDecider } from "./access";
import { rejectProposal, type ApproveRequest, type Proposal } from "./api";
import { ApproveDialog, RejectDialog } from "./dialogs";
import { FindingAction } from "./FindingAction";
import { ConflictLead } from "./ConflictLead";
import { actionOf, edgeWord, findingRule, kindGlyph, kindWord, levelWord, macsOf, viewKindOf, type Finding } from "./findings";
import type { SourceNames } from "./model";
import { ProposalPanel } from "./ProposalPanel";
import "./findings.css";

/** Every row of the reconciliation view of one kind in a prefix; at most this many are read. */
export const VIEW_MAX = 5000;

/** The row of the reconciliation view a finding stands for, or null when the view has none (a scan artifact). */
export async function readViewRow(finding: Finding): Promise<ReconcileRow | null> {
  const kind = viewKindOf(finding);
  if (!kind) return null;
  try {
    const page = await fetchAll<ReconcileRow>("/api/v1/ipam/reconcile", { query: { kind, prefix: finding.subject.prefix ?? undefined }, max: VIEW_MAX });
    return page.items.find((row) => row.key === finding.evidence.id) ?? null;
  } catch {
    return null;
  }
}

/** The panel of a finding that is not a proposal: its evidence and its default action. */
export function FindingPanel(props: { finding: Finding; row?: ReconcileRow | null | undefined; inReconcile?: boolean; onClose: () => void; onDone?: () => void }) {
  const f = () => props.finding;
  const glyph = () => kindGlyph(f().kind, f().severity);
  const title = () => t("discovery.findings.panel.title", { kind: kindWord(f().kind), subject: f().subject.label });
  const plan = () => actionOf(f());
  const macs = () => (props.row?.macs?.length ? props.row.macs : macsOf(f()));
  return (
    <aside
      class="panel proposal-panel finding-panel"
      aria-label={title()}
      data-testid="finding-panel"
      data-id={f().id}
      onKeyDown={(e) => {
        if (e.key === "Escape" && !document.querySelector("[aria-modal='true']")) {
          e.stopPropagation();
          props.onClose();
        }
      }}
    >
      <div class="panel-head">
        <span class={`fglyph ${glyph().tone}`}>
          <Icon name={glyph().icon} />
        </span>
        <div class="grow">
          <h2 data-testid="finding-title">{title()}</h2>
          <div class="meta">
            <span class={`sev-word ${f().severity}`}>{levelWord(f().severity)}</span> · {t("discovery.findings.panel.since")} <TimeAgo at={f().since} />
          </div>
        </div>
        <div class="acts">
          <button type="button" class="icon-btn" aria-label={t("common.action.close")} title={t("common.action.close")} onClick={() => props.onClose()}>
            <Icon name="x" />
          </button>
        </div>
      </div>
      <div class="panel-body">
        <Show when={f().kind === "scan_artifact"}>
          <div class="section">
            <Notice kind="warn" testid="finding-artifact">
              {t("discovery.findings.panel.artifact", { ip: f().subject.label, edge: edgeWord(f().params?.edge) })}
            </Notice>
          </div>
        </Show>
        <Show when={f().kind === "conflict" && macs().length > 0}>
          <ConflictLead macs={macs()} row={props.row} />
        </Show>
        <section class="section" aria-labelledby="finding-evidence">
          <h3 id="finding-evidence">{t("discovery.panel.evidence")}</h3>
          <Show when={findingRule(f())}>{(rule) => <p class="muted" data-testid="finding-rule">{rule()}</p>}</Show>
          <Show when={props.row} fallback={<p class="muted">{f().summary}</p>}>{(row) => <TruthList row={row()} />}</Show>
        </section>
        <section class="section finding-decide" aria-labelledby="finding-decide">
          <h3 id="finding-decide">{t("discovery.findings.panel.decide")}</h3>
          <div class="row-actions">
            <Show when={plan() && plan()!.kind !== "panel"}>
              <FindingAction finding={f()} primary onPanel={() => undefined} onDone={props.onDone} />
            </Show>
            <Show when={!props.inReconcile && viewKindOf(f())}>
              <A class="btn" href={reconcilePath({ prefix: f().subject.prefix ?? undefined, kind: viewKindOf(f()) })} data-testid="finding-reconcile-link">
                {t("discovery.findings.panel.open_reconcile")}
              </A>
            </Show>
          </div>
          <Show when={plan()?.kind === "panel" || !plan()}>
            <p class="muted">{t(plan() ? "discovery.findings.panel.decide_hint" : "discovery.findings.panel.info_hint")}</p>
          </Show>
        </section>
      </div>
    </aside>
  );
}

/** What the panel shows: a proposal, a finding by its id, or a finding with its row of the view. */
export type PanelTarget = { proposal: string } | { findingId: string } | { finding: Finding; row?: ReconcileRow | null | undefined };

/** The side panel for a selection, with the dialogs of the proposal panel. */
export function DecisionPanel(props: { target: PanelTarget; names: SourceNames; inReconcile?: boolean; onClose: () => void; onDone?: () => void }) {
  const writeToast = useWriteToast();
  const [dialog, setDialog] = createSignal<{ kind: "approve"; proposal: Proposal; request?: ApproveRequest | undefined } | { kind: "reject"; proposal: Proposal } | null>(null);
  const decided = (title: string, result: Parameters<typeof writeToast>[1]) => {
    setDialog(null);
    writeToast(title, result);
    props.onDone?.();
  };
  const byId = () => ("findingId" in props.target ? props.target.findingId : undefined);
  const [read] = createResource(byId, async (id) => {
    const finding = await api.get("/api/v1/findings/{id}", { path: { id } });
    return { finding, row: await readViewRow(finding) };
  });
  return (
    <>
      <Show when={"proposal" in props.target && props.target.proposal} keyed>
        {(id) => (
          <ProposalPanel
            id={id}
            names={props.names}
            decider={isDecider()}
            onApprove={(p, request) => setDialog({ kind: "approve", proposal: p, request })}
            onReject={(p) => setDialog({ kind: "reject", proposal: p })}
            onClose={() => props.onClose()}
          />
        )}
      </Show>
      <Show when={"finding" in props.target && props.target} keyed>
        {(target) => <FindingPanel finding={(target as { finding: Finding }).finding} row={(target as { row?: ReconcileRow | null }).row} inReconcile={props.inReconcile} onClose={props.onClose} onDone={props.onDone} />}
      </Show>
      <Show when={byId()}>
        <Show
          when={read()}
          keyed
          fallback={
            <aside class="panel proposal-panel finding-panel" aria-label={t("discovery.panel.label")} data-testid="finding-panel">
              <div class="panel-body section">
                <Show when={read.error} fallback={<p class="muted" role="status">{t("common.loading")}</p>}>
                  <ErrorNotice error={read.error} />
                </Show>
                <button type="button" class="btn" onClick={() => props.onClose()}>
                  {t("common.action.close")}
                </button>
              </div>
            </aside>
          }
        >
          {(found) => <FindingPanel finding={found.finding} row={found.row} inReconcile={props.inReconcile} onClose={props.onClose} onDone={props.onDone} />}
        </Show>
      </Show>
      <Show when={dialog()} keyed>
        {(d) =>
          d.kind === "approve" ? (
            <ApproveDialog proposal={d.proposal} request={d.request} onClose={() => setDialog(null)} onDone={(r) => decided(t("discovery.toast.approved"), r)} />
          ) : (
            <RejectDialog
              proposals={[d.proposal]}
              send={(reason) => rejectProposal(d.proposal, reason)}
              onClose={() => setDialog(null)}
              onDone={(r) => decided(d.proposal.kind === "conflict" ? t("discovery.toast.dismissed") : t("discovery.toast.rejected"), r)}
            />
          )
        }
      </Show>
    </>
  );
}
