// The words, glyphs and actions of the findings on the start page's needs-attention strip (U3):
// per finding the glyph of its kind, the kind in a word, the subject, one line of evidence (the two
// MACs of a conflict, the share of a network over its alarm, the step a job waits at) and the
// default action the finding names, as a link to where it is done. The server names the action
// (ui-plan section 2.6); the UI only maps it to a destination.
import type { components } from "../api/generated/schema";
import { paths } from "../app/paths";
import type { IconName } from "../components/Icon";
import { formatNumber, t, tDynamic } from "../i18n";
import { jobTitle } from "../jobs/words";
import { formatBytes } from "../nodes/format";

export type Finding = components["schemas"]["Finding"];
export type FindingKind = components["schemas"]["FindingKind"];

/** The reconciliation view, where a conflict of the view (not of a proposal) is resolved. */
const RECONCILE_PATH = "/ipam/reconcile";

/** The glyph of a kind (the 16-unit sprite): the octagon of a conflict, the triangle of an alarm or a health condition. */
export function findingGlyph(kind: FindingKind): IconName {
  switch (kind) {
    case "conflict":
      return "conflict";
    case "job_waiting":
      return "jobs";
    case "utilization":
    case "health":
      return "alert";
    default:
      return "proposal";
  }
}

/** The kind in a word or two ("Conflict"). */
export function findingKindWord(kind: FindingKind): string {
  return t(`dashboard.finding.kind.${kind}`);
}

/** The subject in the data font (an address, a network), or the job's title; none for a health condition. */
export function findingSubject(finding: Finding): { text: string; mono: boolean } | null {
  switch (finding.kind) {
    case "health":
      return null;
    case "job_waiting":
      return {
        text: jobTitle({ title: finding.params?.title ?? finding.code, kind: finding.params?.job_kind ?? finding.code, targets: finding.subject.objects ?? [] }),
        mono: false,
      };
    default:
      return { text: finding.subject.label, mono: finding.subject.kind === "address" || finding.subject.kind === "prefix" || finding.subject.kind === "device" };
  }
}

/** A share in percent as the server writes it ("15.2"), in the language of the UI. */
function percent(text: string | undefined): string {
  const value = Number(text);
  return Number.isFinite(value) ? formatNumber(value, { maximumFractionDigits: 1 }) : (text ?? "");
}

/**
 * One line of evidence: the MACs of a conflict (in the data font), the share and threshold of an
 * alarm, the step a job waits at, the room left on a low disk; for anything else the server's
 * summary of the finding.
 */
export function findingEvidence(finding: Finding): { text: string; mono: boolean } {
  const params = finding.params ?? {};
  switch (finding.kind) {
    case "conflict":
      if (params.macs) return { text: params.macs.split(/,\s*/).join(" · "), mono: true };
      return { text: finding.summary, mono: false };
    case "utilization":
      return {
        text: params.threshold
          ? t("dashboard.finding.evidence.utilization", { percent: percent(params.percent), threshold: params.threshold })
          : t("dashboard.finding.evidence.utilization_bare", { percent: percent(params.percent) }),
        mono: false,
      };
    case "job_waiting": {
      const step = Number(params.step);
      return { text: t("dashboard.finding.evidence.job_step", { step: Number.isFinite(step) ? step + 1 : 1 }), mono: false };
    }
    case "health":
      if (finding.code === "node.disk.low" && params.available && params.total) {
        return { text: t("dashboard.finding.evidence.disk_low", { free: formatBytes(Number(params.available)), total: formatBytes(Number(params.total)) }), mono: false };
      }
      return { text: tDynamic(`dashboard.finding.health.${finding.code}`, params) ?? finding.summary, mono: false };
    default:
      return { text: finding.summary, mono: false };
  }
}

/** The default action of a finding: its words and where it is done; null for a finding without one. */
export function findingAction(finding: Finding): { label: string; href: string } | null {
  const fromProposal = finding.source === "proposal";
  const proposal = () => (fromProposal ? paths.proposal(finding.evidence.id) : RECONCILE_PATH);
  switch (finding.action) {
    case "resolve":
      return { label: t("dashboard.finding.action.resolve"), href: proposal() };
    case "open_manual_step":
      return { label: t("dashboard.finding.action.open_job"), href: paths.job(finding.evidence.id) };
    case "open_prefix":
      return {
        label: t("dashboard.finding.action.open_prefix"),
        href: finding.subject.cidr ? paths.prefix(finding.subject.cidr, finding.subject.vrf ?? undefined) : paths.ipam(),
      };
    case "adopt":
    case "decide":
    case "delete_record":
    case "fix_ptr":
      return { label: t("dashboard.finding.action.review"), href: proposal() };
    case "open_host":
    case "decommission":
      return {
        label: t(finding.action === "decommission" ? "dashboard.finding.action.decommission" : "dashboard.finding.action.open_host"),
        href: finding.subject.kind === "host" ? paths.host(finding.subject.label) : proposal(),
      };
    case "open_status":
      return statusAction(finding);
    // U7: the root is chosen on the map, a WLAN finding is decided in the SSID view.
    case "use_root":
      return { label: t("dashboard.finding.action.open_topology"), href: paths.topology() };
    case "move_host":
      return { label: t("dashboard.finding.action.open_ssids"), href: `${paths.topology()}?view=ssids` };
    case "none":
      return null;
  }
}

/** Where a health condition is looked at: the page of its area. */
function statusAction(finding: Finding): { label: string; href: string } {
  switch (finding.area) {
    case "nodes":
      return { label: t("dashboard.finding.action.open_nodes"), href: paths.nodes() };
    case "connectors":
      return { label: t("dashboard.finding.action.open_connectors"), href: paths.connectors() };
    case "dns":
      return { label: t("dashboard.finding.action.open_dns"), href: paths.dns() };
    case "dhcp":
      return { label: t("dashboard.finding.action.open_dhcp"), href: paths.dhcp() };
    case "ipam":
      return { label: t("dashboard.finding.action.open_ipam"), href: paths.ipam() };
    default:
      return { label: t("dashboard.finding.action.open_settings"), href: paths.settings() };
  }
}
