// The words, glyphs, links and default actions of the findings (docs/plans/ui-plan.md section 2.2),
// for the Discovery list and the reconciliation view (U4), as pure functions over `t`. A finding of
// a proposal reads its rule in words the way the proposal list does; a finding of the
// reconciliation view reads its kind with the values of its parameters; the server's English
// summary is the last fallback. The server names the default action (ui-plan section 2.6); the UI
// only maps it to a button or a link, and never infers an action from a kind.
import type { components } from "../api/generated/schema";
import { paths } from "../app/paths";
import type { IconName } from "../components/Icon";
import { formatDateTime, formatNumber, t } from "../i18n";
import { RULE_TEXT, type WinRule } from "../ipam/reconcile/model";
import { jobTitle } from "../jobs/words";
import { ruleText } from "./model";

type S = components["schemas"];
export type Finding = S["Finding"];
export type FindingKind = S["FindingKind"];
export type FindingLevel = S["FindingLevel"];
export type FindingSource = S["FindingSource"];
export type FindingCounts = S["FindingCounts"];

/** The severities, the most urgent first: the order of the groups. */
export const LEVELS: readonly FindingLevel[] = ["act", "review", "info"];

/** Every kind, in the order of the plan's table: the order of the filter chips. */
export const FINDING_KINDS: readonly FindingKind[] = [
  "conflict",
  "job_waiting",
  "utilization",
  "unknown_device",
  "orphaned_record",
  "orphaned_address",
  "ptr_mismatch",
  "intent_differs",
  "outside_prefixes",
  "vlan",
  "host_name",
  "dns",
  "ghost",
  "scan_artifact",
  "health",
];

/** The kinds of the reconciliation view's rows, by the tail of a finding's code. */
const VIEW_KINDS = ["conflict", "ghost", "rogue", "orphan", "ptr_mismatch"] as const;
export type ViewKind = (typeof VIEW_KINDS)[number];

export function levelWord(level: FindingLevel): string {
  return t(`discovery.findings.level.${level}`);
}

export function kindWord(kind: FindingKind): string {
  return t(`discovery.findings.kind.${kind}`);
}

/**
 * The glyph of a kind and the class of its domain color (ui-plan section 2.2): the octagon of a
 * conflict in red, the dashed plus of a proposal in magenta, the triangle of an alarm in the
 * warning color, the mark of a difference in amber, the ghost and the artifact in muted ink. The
 * severity decides where a finding is drawn and counted; the glyph keeps its domain color.
 */
export function kindGlyph(kind: FindingKind, level: FindingLevel): { icon: IconName; tone: string } {
  switch (kind) {
    case "conflict":
      return { icon: "conflict", tone: "conflict" };
    case "job_waiting":
      return { icon: "jobs", tone: "accent" };
    case "utilization":
      return { icon: "alert", tone: "warning" };
    case "ptr_mismatch":
    case "intent_differs":
      return { icon: "alert", tone: "discrepancy" };
    case "ghost":
      return { icon: "clock", tone: level === "info" ? "muted" : "proposal" };
    case "scan_artifact":
      return { icon: "info", tone: "muted" };
    case "health":
      return { icon: "alert", tone: level === "act" ? "conflict" : level === "review" ? "warning" : "muted" };
    default:
      return { icon: "proposal", tone: "proposal" };
  }
}

/** The proposal a finding stands for, or undefined for a finding of another source. */
export function proposalOf(finding: Pick<Finding, "source" | "evidence">): string | undefined {
  return finding.source === "proposal" ? finding.evidence.id : undefined;
}

/** The kind of the reconciliation view's row a finding stands for (`ipam.reconcile.view.ghost`). */
export function viewKindOf(finding: Pick<Finding, "source" | "code">): ViewKind | undefined {
  if (finding.source !== "reconcile") return undefined;
  const tail = finding.code.slice(finding.code.lastIndexOf(".") + 1);
  return (VIEW_KINDS as readonly string[]).includes(tail) ? (tail as ViewKind) : undefined;
}

/** What a finding is about, as text and where it opens; none for a health condition. */
export function subjectOf(finding: Finding): { text: string; mono: boolean; href?: string | undefined } | null {
  const s = finding.subject;
  const vrf = s.vrf ?? undefined;
  switch (s.kind) {
    case "address":
      return { text: s.label, mono: true, href: paths.address(s.ip ?? s.label, vrf) };
    case "host":
      return { text: s.label, mono: false, href: paths.host(s.label) };
    case "prefix":
      return { text: s.label, mono: true, href: s.cidr ? paths.prefix(s.cidr, vrf) : undefined };
    case "device":
      return { text: s.label, mono: true, href: paths.observation(s.mac ?? s.label) };
    case "record":
      return { text: s.label, mono: true, href: paths.search(s.label) };
    case "job":
      return {
        text: jobTitle({ title: finding.params?.title ?? finding.code, kind: finding.params?.job_kind ?? finding.code, targets: s.objects ?? [] }),
        mono: false,
        href: paths.job(finding.evidence.id),
      };
    case "node":
      return null;
  }
}

/** A share in percent as the server writes it ("15.2"), in the language of the UI. */
function percent(text: string | undefined): string {
  const value = Number(text);
  return Number.isFinite(value) ? formatNumber(value, { maximumFractionDigits: 1 }) : (text ?? "");
}

/** MAC addresses as the server lists them ("a, b"), one dot between them. */
export function macsOf(finding: Pick<Finding, "params" | "subject">): string[] {
  const list = (finding.params?.macs ?? "").split(/,\s*/).filter(Boolean);
  if (list.length === 0 && finding.subject.mac) return [finding.subject.mac];
  return list;
}

function dateOf(text: string | undefined): string {
  const at = text ? Date.parse(text) : Number.NaN;
  return Number.isNaN(at) ? (text ?? "") : formatDateTime(at);
}

/**
 * One line of evidence: the MACs of a conflict (in the data font), the proposal's rule in words,
 * the share of a network over its alarm, the step a job waits at, when a ghost was last seen, the
 * PTR record that disagrees; for anything else the server's summary.
 */
export function evidenceOf(finding: Finding): { text: string; mono: boolean } {
  const params = finding.params ?? {};
  if (finding.kind === "conflict" && macsOf(finding).length > 1) return { text: macsOf(finding).join(" · "), mono: true };
  if (finding.source === "proposal") return { text: ruleText({ rule: finding.code, params, summary: finding.summary }), mono: false };
  switch (finding.kind) {
    case "utilization":
      return {
        text: params.threshold
          ? t("discovery.findings.evidence.utilization", { percent: percent(params.percent), threshold: params.threshold })
          : t("discovery.findings.evidence.utilization_bare", { percent: percent(params.percent) }),
        mono: false,
      };
    case "job_waiting": {
      const step = Number(params.step);
      return { text: t("discovery.findings.evidence.job_step", { step: Number.isFinite(step) ? step + 1 : 1 }), mono: false };
    }
    case "ghost":
      return { text: t("discovery.findings.evidence.ghost", { since: dateOf(params.unseen_since) }), mono: false };
    case "ptr_mismatch":
      return { text: t("discovery.findings.evidence.ptr", { ptr: params.ptr ?? "" }), mono: false };
    case "orphaned_record":
      return { text: t("discovery.findings.evidence.orphan", { names: params.names ?? finding.subject.label }), mono: false };
    case "unknown_device":
      return { text: t("discovery.findings.evidence.rogue_decided", { macs: macsOf(finding).join(", ") || "none" }), mono: false };
    case "scan_artifact":
      return { text: t("discovery.findings.evidence.artifact", { edge: edgeWord(params.edge), macs: params.macs || "none" }), mono: false };
    default:
      return { text: finding.summary, mono: false };
  }
}

/** Which edge address of its network a scan artifact sits on, in words. */
export function edgeWord(edge: string | undefined): string {
  switch (edge) {
    case "network":
    case "broadcast":
    case "subnet_router_anycast":
      return t(`discovery.findings.edge.${edge}`);
    default:
      return t("discovery.findings.edge.other");
  }
}

/** The rule that decides a row of the reconciliation view, in words: the sentence a group says once. */
export function ruleSentence(rule: string | undefined): string | undefined {
  return rule && rule in RULE_TEXT ? t(RULE_TEXT[rule as WinRule]) : undefined;
}

/** The sentence of a finding's rule, when it has one (the findings of the reconciliation view). */
export function findingRule(finding: Pick<Finding, "source" | "params">): string | undefined {
  return finding.source === "reconcile" ? ruleSentence(finding.params?.rule) : undefined;
}

/**
 * What the default action does: a link to where it is done, the side panel (a decision with
 * several choices), the approval of the proposal (the plan dialog), or decommissioning the host
 * (its dialog). Null for a finding listed for information only.
 */
export type ActionPlan =
  | { kind: "link"; label: string; href: string }
  | { kind: "panel"; label: string }
  | { kind: "approve"; label: string; proposal: string }
  | { kind: "decommission"; label: string; host: string };

export function actionOf(finding: Finding): ActionPlan | null {
  const proposal = proposalOf(finding);
  const s = finding.subject;
  const address = () => paths.address(s.ip ?? s.label, s.vrf ?? undefined);
  switch (finding.action) {
    case "resolve":
      return { kind: "panel", label: t("discovery.findings.action.resolve") };
    case "open_manual_step":
      return { kind: "link", label: t("discovery.findings.action.open_job"), href: paths.job(finding.evidence.id) };
    case "open_prefix":
      return { kind: "link", label: t("discovery.findings.action.open_prefix"), href: s.cidr ? paths.prefix(s.cidr, s.vrf ?? undefined) : paths.ipam() };
    case "adopt":
      return proposal ? { kind: "approve", label: t("discovery.findings.action.adopt"), proposal } : { kind: "panel", label: t("discovery.findings.action.decide") };
    case "delete_record":
      return proposal
        ? { kind: "approve", label: t("discovery.findings.action.delete_record"), proposal }
        : { kind: "link", label: t("discovery.findings.action.open_record"), href: paths.search((finding.params?.names ?? s.label).split(/,\s*/)[0] ?? s.label) };
    case "fix_ptr":
      return { kind: "link", label: t("discovery.findings.action.fix_ptr"), href: address() };
    case "open_host": {
      const name = s.kind === "host" ? s.label : finding.params?.host;
      return name ? { kind: "link", label: t("discovery.findings.action.open_host"), href: paths.host(name) } : { kind: "panel", label: t("discovery.findings.action.decide") };
    }
    case "decide":
      return { kind: "panel", label: t("discovery.findings.action.decide") };
    case "decommission":
      return s.host
        ? { kind: "decommission", label: t("discovery.findings.action.decommission"), host: s.host }
        : { kind: "link", label: t("discovery.findings.action.open_host"), href: paths.host(s.label) };
    case "open_status":
      return statusAction(finding);
    case "none":
      return null;
  }
}

/** Where a health condition is looked at: the page of its area. */
function statusAction(finding: Finding): ActionPlan {
  switch (finding.area) {
    case "nodes":
      return { kind: "link", label: t("discovery.findings.action.open_nodes"), href: paths.nodes() };
    case "connectors":
      return { kind: "link", label: t("discovery.findings.action.open_connectors"), href: paths.connectors() };
    case "dns":
      return { kind: "link", label: t("discovery.findings.action.open_dns"), href: paths.dns() };
    case "dhcp":
      return { kind: "link", label: t("discovery.findings.action.open_dhcp"), href: paths.dhcp() };
    case "ipam":
      return { kind: "link", label: t("discovery.findings.action.open_ipam"), href: paths.ipam() };
    default:
      return { kind: "link", label: t("discovery.findings.action.open_settings"), href: paths.settings() };
  }
}

/**
 * Where selecting a finding leads: the side panel of its proposal or of its row of the
 * reconciliation view, or, for a finding of another source, its subject (the job, the network,
 * the page of a health condition's area).
 */
export function selectionOf(finding: Finding): { panel: string } | { href: string } {
  const proposal = proposalOf(finding);
  if (proposal) return { panel: proposal };
  if (finding.source === "reconcile") return { panel: finding.id };
  switch (finding.source) {
    case "job":
      return { href: paths.job(finding.evidence.id) };
    case "alarm":
      return { href: finding.subject.cidr ? paths.prefix(finding.subject.cidr, finding.subject.vrf ?? undefined) : paths.ipam() };
    default: {
      const plan = statusAction(finding);
      return { href: plan.kind === "link" ? plan.href : paths.dashboard() };
    }
  }
}

/** The design's exception class of a finding row: a red edge for a conflict, magenta for a proposal, amber for a difference. */
export function rowClassOf(finding: Pick<Finding, "kind" | "severity">): string | undefined {
  if (finding.severity === "info") return undefined;
  if (finding.kind === "conflict") return "conflict";
  if (finding.kind === "ptr_mismatch" || finding.kind === "intent_differs" || finding.kind === "orphaned_address") return "differs";
  if (finding.kind === "unknown_device" || finding.kind === "orphaned_record") return "proposal";
  return undefined;
}

/** Whether a finding stands for the address `ip` in `vrf` (a conflict proposal and its row of the view). */
export function isAbout(finding: Pick<Finding, "subject">, vrf: string | null | undefined, ip: string): boolean {
  return finding.subject.ip === ip && (!vrf || !finding.subject.vrf || finding.subject.vrf === vrf);
}
