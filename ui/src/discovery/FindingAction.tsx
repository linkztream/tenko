// The default action of a finding as one button (ui-plan section 5.3: "each finding row carries
// its action button"), for the rows of the Discovery list and of the reconciliation view and for
// the side panel. The finding names the action (findings.ts, `actionOf`); the button does what it
// says through the route the action stands for:
//
// - a link: the job's manual step, the network over its alarm, the host, the address whose PTR
//   record to fix, the page of a health condition;
// - the side panel, for a decision with several choices (resolve a conflict, decide a proposal);
// - adopt a device or delete an orphaned record: the approval of the proposal
//   (`POST /proposals/{id}/approve` through the plan dialog, a dry run first);
// - decommission the host of a ghost address (`POST /hosts/{id}/decommission` through its dialog).
//
// A person who may not decide gets the panel instead of a write; the server checks again.
import { A } from "@solidjs/router";
import { createSignal, Show } from "solid-js";
import type { Host } from "../api/types";
import { errorMessage } from "../api/problem";
import { may } from "../auth/gate";
import { toast } from "../components/toast";
import { DecommissionDialog, decommissionTitle } from "../hosts/DecommissionDialog";
import { readHost } from "../hosts/lifecycle";
import { t } from "../i18n";
import { useWriteToast } from "../ipam/plan/PlanDialog";
import { isDecider } from "./access";
import { getProposal, type Proposal } from "./api";
import { ApproveDialog } from "./dialogs";
import { actionOf, type ActionPlan, type Finding } from "./findings";

type LinkPlan = Extract<ActionPlan, { kind: "link" }>;
const linkOf = (plan: ActionPlan): LinkPlan | undefined => (plan.kind === "link" ? plan : undefined);

/** The action as this person may run it: a write they may not do opens the panel instead. */
function planFor(finding: Finding): ActionPlan | null {
  const plan = actionOf(finding);
  if (!plan) return null;
  if ((plan.kind === "approve" || plan.kind === "decommission") && !isDecider()) return { kind: "panel", label: t("discovery.findings.action.open") };
  return plan;
}

export function FindingAction(props: {
  finding: Finding;
  /** Opens the finding in the side panel. */
  onPanel: (finding: Finding) => void;
  /** Called after a write the button started, so the list reloads. */
  onDone?: () => void;
  /** The primary style, for the panel; the rows use the small one. */
  primary?: boolean;
}) {
  const writeToast = useWriteToast();
  const [proposal, setProposal] = createSignal<Proposal | null>(null);
  const [host, setHost] = createSignal<Host | null>(null);
  const [busy, setBusy] = createSignal(false);
  const plan = () => planFor(props.finding);
  const cls = () => (props.primary ? "btn primary" : "btn sm finding-action");

  const approve = async (id: string) => {
    setBusy(true);
    try {
      setProposal(await getProposal(id));
    } catch (err) {
      toast({ kind: "bad", title: t("discovery.findings.action.failed"), body: errorMessage(err) });
    } finally {
      setBusy(false);
    }
  };
  const decommission = async (id: string) => {
    setBusy(true);
    try {
      const found = await readHost(id);
      if (!found) throw new Error(t("discovery.findings.action.host_gone"));
      if (!may.host(found)) {
        props.onPanel(props.finding);
        return;
      }
      setHost(found);
    } catch (err) {
      toast({ kind: "bad", title: t("discovery.findings.action.failed"), body: errorMessage(err) });
    } finally {
      setBusy(false);
    }
  };

  return (
    <Show when={plan()}>
      {(p) => (
        <>
          <Show
            when={linkOf(p())}
            fallback={
              <button
                type="button"
                class={cls()}
                data-testid="finding-action"
                data-action={props.finding.action}
                disabled={busy()}
                onClick={(e) => {
                  e.stopPropagation();
                  const now = p();
                  if (now.kind === "approve") void approve(now.proposal);
                  else if (now.kind === "decommission") void decommission(now.host);
                  else props.onPanel(props.finding);
                }}
              >
                {p().label}
              </button>
            }
          >
            {(link) => (
              <A class={cls()} href={link().href} data-testid="finding-action" data-action={props.finding.action} onClick={(e) => e.stopPropagation()}>
                {link().label}
              </A>
            )}
          </Show>
          <Show when={proposal()} keyed>
            {(found) => (
              <ApproveDialog
                proposal={found}
                onClose={() => setProposal(null)}
                onDone={(r) => {
                  setProposal(null);
                  writeToast(t("discovery.toast.approved"), r);
                  props.onDone?.();
                }}
              />
            )}
          </Show>
          <Show when={host()} keyed>
            {(found) => (
              <DecommissionDialog
                hosts={[found]}
                onClose={() => setHost(null)}
                onDone={(r) => {
                  setHost(null);
                  writeToast(decommissionTitle([found]), r);
                  props.onDone?.();
                }}
              />
            )}
          </Show>
        </>
      )}
    </Show>
  );
}
