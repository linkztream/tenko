// The lead of a conflict in the side panel (U4, ui-plan section 5.3): the MAC addresses on the
// address, both of them (the intended one first, each once), with what saw each and when, then
// the OS field of the view's row when it is known. The proposal panel and the panel of a conflict
// row of the reconciliation view put it before anything else.
import { createResource, For, Show } from "solid-js";
import { fetchAll } from "../api/paginate";
import { Mac } from "../components/Addr";
import { TimeAgo } from "../grid/cells";
import { t } from "../i18n";
import type { ReconcileRow } from "../ipam/reconcile/model";
import type { Proposal } from "./api";
import { sourceText, type SourceNames } from "./model";

/** Rows of the view read at most, to find the one of an address. */
const VIEW_MAX = 5000;

/** The conflict row of the view about an address, for the OS field and the vendors of a conflict proposal. */
async function readConflictRow(proposal: Proposal): Promise<ReconcileRow | null> {
  const ip = proposal.subject.ip;
  if (!ip) return null;
  try {
    const page = await fetchAll<ReconcileRow>("/api/v1/ipam/reconcile", { query: { kind: "conflict", prefix: proposal.subject.prefix ?? undefined }, max: VIEW_MAX });
    const vrf = proposal.subject.vrf;
    return page.items.find((row) => row.address === ip && (!vrf || !row.vrf || row.vrf === vrf)) ?? null;
  } catch {
    return null;
  }
}

/** The MAC addresses on the address of a conflict, the intended one first, each once. */
export function conflictMacs(proposal: Pick<Proposal, "params" | "evidence" | "subject">): string[] {
  const params = proposal.params ?? {};
  const listed = [params.intended_mac, ...(params.macs ?? "").split(/,\s*/), ...proposal.evidence.map((e) => e.mac), proposal.subject.mac];
  const seen: string[] = [];
  for (const mac of listed) if (mac && !seen.includes(mac.toLowerCase())) seen.push(mac.toLowerCase());
  return seen;
}

/**
 * The lead of a conflict: the MAC addresses on the address, each with what saw it and when, then
 * the OS field and the vendors of the view's row when it is known.
 */
export function ConflictLead(props: { macs: readonly string[]; proposal?: Proposal | undefined; names?: SourceNames | undefined; row?: ReconcileRow | null | undefined }) {
  const seenBy = (mac: string) => (props.proposal?.evidence ?? []).filter((e) => e.mac?.toLowerCase() === mac);
  const intended = () => props.proposal?.params?.intended_mac?.toLowerCase();
  return (
    <section class="section conflict-lead" aria-labelledby="conflict-lead" data-testid="conflict-lead">
      <h3 id="conflict-lead">{t("discovery.findings.panel.devices", { count: props.macs.length })}</h3>
      <ul class="conflict-macs">
        <For each={props.macs}>
          {(mac) => (
            <li data-testid="conflict-mac" data-mac={mac}>
              <Mac value={mac} />
              <span class="muted">
                <Show when={mac === intended()}>{t("discovery.findings.panel.intended")} · </Show>
                <For each={seenBy(mac)}>
                  {(e, i) => (
                    <>
                      {i() > 0 ? " · " : ""}
                      {props.names ? sourceText(e.source, props.names) : e.source_key} <TimeAgo at={e.last_seen} />
                    </>
                  )}
                </For>
              </span>
            </li>
          )}
        </For>
      </ul>
      <Show when={props.row?.os}>
        {(os) => (
          <p class="muted" data-testid="conflict-os">
            {t("discovery.findings.panel.os", { guess: os().guess, confidence: os().confidence, source: os().source })}
          </p>
        )}
      </Show>
    </section>
  );
}

/** The conflict lead of a proposal panel: the MAC addresses, and the OS field read from the view. */
export function ProposalConflictLead(props: { proposal: Proposal; names: SourceNames }) {
  const [row] = createResource(() => props.proposal.id, () => readConflictRow(props.proposal));
  return <ConflictLead macs={conflictMacs(props.proposal)} proposal={props.proposal} names={props.names} row={row.latest} />;
}
