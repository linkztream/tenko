// The only module of the discovery area that talks to the API (docs/reconciliation.md): the
// proposals with their decisions, a run of the reconciler, the observed facts and the picture
// of one subject across sources, and the adoption policy of a prefix (shown on the prefix pane
// of the IPAM view, src/ipam/prefix/AdoptionPanel.tsx).
import { ANY_REVISION, api } from "../api/client";
import type { components } from "../api/generated/schema";
import { fetchAll } from "../api/paginate";
import { isApiError } from "../api/problem";
import { writeQuery } from "../ipam/plan/describe";

type S = components["schemas"];

export type Proposal = S["IntentProposal"];
export type ProposalKind = S["IntentProposalKind"];
export type ProposalState = S["IntentProposalState"];
export type ProposalSeverity = S["ProposalSeverity"];
export type ProposalEvidence = S["ProposalEvidence"];
export type Decision = S["Decision"];
export type BatchDecision = S["BatchDecision"];
export type BatchItem = S["BatchItem"];
export type ReconcileReport = S["ReconcileReport"];
export type ObservedFact = S["ObservedFact"];
export type ObservationSource = S["ObservationSource"];
export type Observed = S["Observed"];
export type SubjectView = S["SubjectView"];
export type SubjectSummary = S["SubjectSummary"];
export type AdoptionPolicy = S["AdoptionPolicy"];
export type AdoptionMode = S["AdoptionMode"];
export type PolicyView = S["PolicyView"];
export type FactType = S["FactSubject"]["type"];
export type NameChoice = S["NameChoice"];
export type NameChoiceSource = S["NameChoiceSource"];
export type NameSource = S["NameSource"];
export type ApproveRequest = S["ApproveRequest"];
export type Remember = S["Remember"];

export const PROPOSAL_KINDS: readonly ProposalKind[] = [
  "discovered_host",
  "address_mismatch",
  "conflict",
  "outside_prefixes",
  "orphaned_intent",
  "vlan_discovered",
  "prefix_vlan_mismatch",
  "host_name",
];
export const PROPOSAL_STATES: readonly ProposalState[] = ["open", "accepted", "rejected", "expired", "superseded"];
export const SEVERITIES: readonly ProposalSeverity[] = ["critical", "warning", "info"];
export const FACT_TYPES: readonly FactType[] = ["host", "address", "attachment", "services", "os", "link", "name", "vendor", "network"];
/** The kinds of source the name authority ranks, in the order of the server's list. */
export const NAME_SOURCES: readonly NameSource[] = ["proxmox", "home_assistant", "windows", "dns", "mdns", "llmnr", "unifi", "scan", "dhcp", "other"];
export const ADOPTION_MODES: readonly AdoptionMode[] = ["manual", "adopt_hosts", "adopt_all"];

/** The most bytes a rejection reason may have (docs/reconciliation.md, section 5.2). */
export const MAX_REASON_BYTES = 1024;

/** The most proposals one batch decision takes; a longer selection goes in several requests. */
export const MAX_BATCH = 500;

export function getProposal(id: string, signal?: AbortSignal): Promise<Proposal> {
  return api.get("/api/v1/proposals/{id}", { path: { id }, signal });
}

/** Every proposal of a query (the dashboard counts the open ones). */
export async function listProposals(query: { state?: ProposalState[]; prefix?: string; subject?: string }, signal?: AbortSignal): Promise<Proposal[]> {
  const page = await fetchAll<Proposal>("/api/v1/proposals", { query, signal });
  return page.items;
}

/**
 * Approves a proposal: a dry run plans its commands and writes nothing; the real run applies
 * them with the acknowledged warning codes, at the revision the person saw. A proposal that
 * offers names (`choices`) takes the one named in `request` and remembers what it asks to;
 * without a request the proposed name applies.
 */
export function approveProposal(
  proposal: Pick<Proposal, "id" | "revision">,
  options: { dryRun: boolean; acknowledge: readonly string[] },
  request?: ApproveRequest,
): Promise<Decision> {
  return api.post("/api/v1/proposals/{id}/approve", {
    path: { id: proposal.id },
    query: writeQuery(options.dryRun, options.acknowledge),
    ...(request ? { body: request } : {}),
    ifMatch: proposal.revision ?? ANY_REVISION,
  });
}

/** Rejects (for a conflict: dismisses) a proposal with an optional reason. */
export function rejectProposal(proposal: Pick<Proposal, "id" | "revision">, reason: string): Promise<Decision> {
  const trimmed = reason.trim();
  return api.post("/api/v1/proposals/{id}/reject", {
    path: { id: proposal.id },
    body: trimmed ? { reason: trimmed } : {},
    ifMatch: proposal.revision ?? ANY_REVISION,
  });
}

/**
 * Approves many proposals at once. The server applies each as the single approval does and
 * reports each: the ones it could not approve come back skipped with the reason, the others
 * are approved.
 */
export function approveProposals(ids: readonly string[]): Promise<BatchDecision> {
  return inChunks(ids, (chunk) => api.post("/api/v1/proposals/approve", { body: { ids: chunk } }));
}

/** Rejects many proposals at once with one optional reason; the answer is as for approving. */
export function rejectProposals(ids: readonly string[], reason: string): Promise<BatchDecision> {
  const trimmed = reason.trim();
  return inChunks(ids, (chunk) => api.post("/api/v1/proposals/reject", { body: trimmed ? { ids: chunk, reason: trimmed } : { ids: chunk } }));
}

/** Sends the identifiers in requests of at most MAX_BATCH and answers them as one batch. */
async function inChunks(ids: readonly string[], send: (chunk: string[]) => Promise<BatchDecision>): Promise<BatchDecision> {
  const results: BatchItem[] = [];
  for (let at = 0; at < ids.length; at += MAX_BATCH) {
    results.push(...(await send(ids.slice(at, at + MAX_BATCH))).results);
  }
  const count = (outcome: BatchItem["outcome"]) => results.filter((r) => r.outcome === outcome).length;
  return { results, approved: count("approved"), rejected: count("rejected"), skipped: count("skipped") };
}

/** Runs the reconciler once, now. */
export function reconcileNow(): Promise<ReconcileReport> {
  return api.post("/api/v1/proposals/reconcile");
}

/** The picture of one subject (a MAC address, an IP address or a name); null when no fact names it. */
export async function getSubject(subject: string, signal?: AbortSignal): Promise<SubjectView | null> {
  try {
    return await api.get("/api/v1/observations/{subject}", { path: { subject }, signal });
  } catch (err) {
    if (isApiError(err, "ipam.not_found")) return null;
    throw err;
  }
}

export function getAdoptionPolicy(prefix: string, signal?: AbortSignal): Promise<PolicyView> {
  return api.get("/api/v1/prefixes/{id}/adoption", { path: { id: prefix }, signal });
}

/** Sets the own policy of a prefix; `revision` is the one read with it (0 when it has none). */
export function setAdoptionPolicy(prefix: string, policy: AdoptionPolicy, revision: number): Promise<PolicyView> {
  return api.put("/api/v1/prefixes/{id}/adoption", { path: { id: prefix }, body: policy, ifMatch: revision });
}

/** Removes the own policy of a prefix, so that it inherits again. */
export function clearAdoptionPolicy(prefix: string, revision: number): Promise<PolicyView> {
  return api.delete("/api/v1/prefixes/{id}/adoption", { path: { id: prefix }, ifMatch: revision }) as Promise<PolicyView>;
}
