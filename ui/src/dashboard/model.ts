// The pure parts of the start page (U3, docs/plans/ui-plan.md sections 5.1 and 6): which blocks
// a profile draws, what the Hidden line names, the families of the address counts, and the
// grouping of recent changes. No component and no request here, so the rules have tests of
// their own.
import type { AuditRecord, Principal, TreeNode } from "../api/types";
import { memoryPercent, type MetricsSample } from "./metrics";

/** The security profiles, as the session names them. */
export type Profile = "lab" | "home" | "standard" | "hardened";

/** The blocks a profile adds to the Home set (ui-plan section 6, "Dashboard"). */
export interface DashboardSet {
  /** The Jobs and Connectors blocks of the health row: Standard and Hardened. */
  operations: boolean;
  /** The controller's metrics (commit p99, replication lag, node buffers, live clients): Lab, or more than one node. */
  controller: boolean;
  /** The nodes connected of the enrolled: more than one node. */
  cluster: boolean;
  /** Hardened: the security events and the audit summary. */
  security: boolean;
  /** The default of the System activity switch: off (people only) under Standard and Hardened. */
  systemActivity: boolean;
}

/** The profile of the session, Home when it is unknown. */
export function profileOf(name: string | null | undefined): Profile {
  return name === "lab" || name === "standard" || name === "hardened" ? name : "home";
}

/**
 * The blocks of `profile`. `multiNode` is a cluster of more than one node (a second controller
 * or an enrolled node); `showAll` is "Show all metrics" of the Hidden line, which draws every
 * metric block whatever the profile (the security panel is not a metric and stays Hardened's).
 */
export function dashboardSet(profile: Profile, multiNode: boolean, showAll: boolean): DashboardSet {
  const standard = profile === "standard" || profile === "hardened";
  return {
    operations: standard || showAll,
    controller: profile === "lab" || multiNode || showAll,
    cluster: multiNode || showAll,
    security: profile === "hardened",
    systemActivity: !standard,
  };
}

/** The things the Hidden line can name, each with its reason in the words of the page. */
export type HiddenKey =
  | "host"
  | "host-cpu"
  | "host-memory"
  | "controller"
  | "operations"
  | "dns"
  | "dhcp"
  | "admin";

/**
 * What the page does not draw, in the order the line names it. `sample` is the newest sample of
 * the cluster (null before the first, and always for an account that does not read the metrics).
 */
export function hiddenKeys(input: { set: DashboardSet; admin: boolean; sample: MetricsSample | null | undefined }): HiddenKey[] {
  const out: HiddenKey[] = [];
  const { set, admin, sample } = input;
  if (admin && sample) {
    const host = sample.host;
    const cpu = host?.cpu_percent ?? null;
    const memory = host ? memoryPercent(host) : null;
    if (cpu === null && memory === null) out.push("host");
    else if (cpu === null) out.push("host-cpu");
    else if (memory === null) out.push("host-memory");
  }
  if (admin && !set.controller) out.push("controller");
  if (!set.operations) out.push("operations");
  if (admin && sample && !sample.dns) out.push("dns");
  if (admin && sample && !sample.dhcp) out.push("dhcp");
  if (!admin) out.push("admin");
  return out;
}

/** Whether a prefix of the tree is IPv6. */
export function isV6(node: Pick<TreeNode, "cidr">): boolean {
  return node.cidr.includes(":");
}

/** The addresses in use and the networks of one family, over the top-level prefixes so nothing counts twice. */
export interface FamilyUse {
  used: bigint;
  networks: number;
}

function big(text: string): bigint {
  try {
    return BigInt(text);
  } catch {
    return 0n;
  }
}

/** The in-use totals and the network counts of a VRF's tree per family. */
export function familyUse(nodes: readonly TreeNode[]): { v4: FamilyUse; v6: FamilyUse } {
  const sum = (v6: boolean): FamilyUse => ({
    used: nodes.filter((n) => n.depth === 0 && isV6(n) === v6).reduce((total, n) => total + big(n.utilization.in_use), 0n),
    networks: nodes.filter((n) => n.role === "network" && isV6(n) === v6).length,
  });
  return { v4: sum(false), v6: sum(true) };
}

/**
 * Whether a change was made by Tenko itself (a component on its own behalf, or a node) rather than
 * by a person or a token; a component that acts on behalf of a person (a job someone started) is
 * that person's change.
 */
export function isSystem(principal: Principal): boolean {
  return (principal.kind === "system" && !principal.on_behalf_of) || principal.kind === "node";
}

function principalKey(principal: Principal): string {
  switch (principal.kind) {
    case "system":
      return `system:${principal.component}`;
    case "node":
      return `node:${principal.id}`;
    default:
      return `${principal.kind}:${principal.id}`;
  }
}

/** A run of the same change by the same principal: the newest record and how many there are. */
export interface ChangeGroup {
  record: AuditRecord;
  count: number;
}

/**
 * The recent changes for the panel, newest first: records next to each other with the same
 * action by the same principal become one entry with a count ("×2"); without `system` the
 * changes Tenko made itself are left out, so an administrator sees what people changed. At most
 * `limit` entries.
 */
export function groupChanges(records: readonly AuditRecord[], options: { system: boolean; limit: number }): ChangeGroup[] {
  const out: ChangeGroup[] = [];
  for (const record of records) {
    if (!options.system && isSystem(record.principal)) continue;
    const last = out[out.length - 1];
    if (last && last.record.draft.action === record.draft.action && principalKey(last.record.principal) === principalKey(record.principal)) {
      last.count += 1;
      continue;
    }
    if (out.length === options.limit) break;
    out.push({ record, count: 1 });
  }
  return out;
}
