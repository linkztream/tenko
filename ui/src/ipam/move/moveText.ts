// Words of the move preview: the text of each step of each device, built from the item's
// own fields (host, addresses, MAC, DNS name, target), so the preview reads the same
// whatever arguments the server attaches to a step. A step kind this UI does not know falls
// back to the server's text. The L2 step (IPAM-19 step 4) has its own words: what happens
// in the table, why a person does it, the exact manual task, the notes and the diff.
import type { MoveItem, MoveL2, MoveL2Problem, MovePreview, MoveStepPreview, MoveTimeoutSource } from "../../api/moves";
import { formatDuration, t, tDynamic, type MessageKey } from "../../i18n";

/** The order of the checklist groups (IPAM-19, design decision 7). */
export const STEP_ORDER: readonly string[] = [
  "ipam.intent",
  "dhcp.manual",
  "device.manual",
  "dns.manual",
  "l2.move",
  "observe",
  "cleanup",
];

const GROUP: Record<string, MessageKey> = {
  "ipam.intent": "move.group.ipam_intent",
  "dhcp.manual": "move.group.dhcp_manual",
  "device.manual": "move.group.device_manual",
  "dns.manual": "move.group.dns_manual",
  "l2.move": "move.group.l2_move",
  observe: "move.group.observe",
  cleanup: "move.group.cleanup",
};

/** The heading of a checklist group of one step kind. */
export function groupTitle(kind: string, count: number): string {
  const key = GROUP[kind];
  return key ? t(key as "move.group.dhcp_manual", { count }) : kind;
}

/** The name a person knows the device by. */
export function deviceName(item: MoveItem): string {
  return item.host_name ?? item.dns?.name ?? item.old_ip;
}

function lengthOf(cidr: string): string {
  return cidr.split("/")[1] ?? "";
}

/** The text of one step of one device. */
export function stepText(step: MoveStepPreview, item: MoveItem, preview: MovePreview): string {
  const host = deviceName(item);
  const target = preview.target;
  switch (step.kind) {
    case "ipam.intent":
      return t("move.step.ipam_intent", { old_ip: item.old_ip, new_ip: item.new_ip });
    case "dhcp.manual":
      return item.mac
        ? t("move.step.dhcp_manual", { ip: item.new_ip, mac: item.mac, cidr: target.cidr })
        : t("move.step.dhcp_manual_no_mac", { ip: item.new_ip, host, cidr: target.cidr });
    case "device.manual":
      return t("move.step.device_manual", { host, ip: item.new_ip, length: lengthOf(target.cidr) });
    case "dns.manual":
      return t("move.step.dns_manual", { name: item.dns?.new ?? item.dns?.name ?? host, ip: item.new_ip });
    case "l2.controller": {
      const text = fill("move.step.l2_controller", ["host", "vid", "connector"], {
        host,
        vid: target.vid,
        connector: step.params.connector ?? item.l2?.connector?.name,
      });
      return text ?? tDynamic(step.text, step.params) ?? step.text;
    }
    case "l2.move":
      return l2TaskText(step, item, preview) ?? (target.vid != null ? t("move.step.l2_move", { host, vid: target.vid }) : t("move.step.l2_move_novlan", { host, cidr: target.cidr }));
    case "observe":
      return t("move.step.observe", { host, ip: item.new_ip });
    case "cleanup":
      return t("move.step.cleanup", { ip: item.old_ip });
    default:
      return tDynamic(step.text, step.params) ?? step.text;
  }
}

/** Why the new address does not keep the host part. */
export function reasonText(item: MoveItem): string | undefined {
  if (item.same_host_part || !item.reason) return undefined;
  return tDynamic(`move.reason.${item.reason.replace(/^ipam\.move\./, "")}`, { ip: item.new_ip, old_ip: item.old_ip }) ?? item.reason;
}

/** How the timeout was chosen, in words ("lease 24 h, timeout 12 h"). */
export function timeoutText(source: MoveTimeoutSource, timeoutSecs: number, leaseSecs: number | null | undefined): string {
  const timeout = formatDuration(timeoutSecs);
  if (source === "lease" && leaseSecs) return t("move.timeout.lease", { lease: formatDuration(leaseSecs), timeout });
  if (source === "request") return t("move.timeout.request", { timeout });
  return t("move.timeout.default", { timeout });
}

// ---------------------------------------------------------------------------------
// The L2 step

/** Reason codes of the L2 step (crates/tenko-ipam/src/moves/mod.rs, `codes`). */
export const L2_REASON = {
  noVlan: "ipam.move.l2.no_vlan",
  noProfile: "ipam.move.l2.no_profile",
  sharedPort: "ipam.move.l2.shared_port",
  joinSsid: "ipam.move.l2.join_ssid",
  noNetwork: "ipam.move.l2.no_network",
  readOnly: "ipam.move.l2.read_only",
  refused: "ipam.move.l2.refused",
} as const;

/** The warning of a guardrail refusal, which a person acknowledges. */
export const L2_REFUSED_WARNING = "ipam.move.l2_refused";

/** The problem code of a submit whose plan differs from the confirmed preview (409). */
export const PLAN_CHANGED = "ipam.move.plan_changed";

/**
 * Formats a message when every argument it needs is there; `undefined` otherwise, so a caller
 * can fall back to other words instead of showing a half-built sentence. Absent, null and
 * empty values count as missing; `count` is the one numeric argument (plural rules).
 */
function fill(key: string, needs: readonly string[], values: Readonly<Record<string, string | number | null | undefined>>): string | undefined {
  const args: Record<string, string | number> = {};
  for (const [name, value] of Object.entries(values)) {
    if (value === undefined || value === null || value === "") continue;
    args[name] = name === "count" ? Number(value) : value;
  }
  if (needs.some((n) => args[n] === undefined || Number.isNaN(args[n]))) return undefined;
  return tDynamic(key, args);
}

/** The message key of the manual task of an L2 step (`instruction` in crates/tenko-ipam/src/moves/l2.rs). */
export type L2TaskKey = Extract<MessageKey, `ipam.move.task.l2${string}`>;

/** The arguments each task message needs. */
const TASK_ARGS: Readonly<Record<L2TaskKey, readonly string[]>> = {
  "ipam.move.task.l2": ["cidr"],
  "ipam.move.task.l2_client": ["connector", "mac", "network", "vid"],
  "ipam.move.task.l2_network": ["connector", "vid"],
  "ipam.move.task.l2_port": ["connector", "device", "port", "profile", "vid"],
  "ipam.move.task.l2_port_vlan": ["connector", "device", "port", "vid"],
  "ipam.move.task.l2_refused": ["rule", "vid"],
  "ipam.move.task.l2_shared_port": ["count", "device", "port", "vid"],
  "ipam.move.task.l2_ssid": ["device", "ssid", "vid"],
  "ipam.move.task.l2_vlan": ["vid"],
};

/** Which task message says what a person does for an L2 step, chosen like the server chooses it. */
export function l2TaskKey(l2: MoveL2): L2TaskKey {
  switch (l2.reason ?? "") {
    case L2_REASON.noVlan:
      return "ipam.move.task.l2";
    case L2_REASON.readOnly:
      return l2.change?.type === "set_port_profile" ? "ipam.move.task.l2_port" : "ipam.move.task.l2_client";
    case L2_REASON.noProfile:
      return "ipam.move.task.l2_port_vlan";
    case L2_REASON.sharedPort:
      return "ipam.move.task.l2_shared_port";
    case L2_REASON.joinSsid:
      return "ipam.move.task.l2_ssid";
    case L2_REASON.noNetwork:
      return "ipam.move.task.l2_network";
    case L2_REASON.refused:
      return "ipam.move.task.l2_refused";
    default:
      return "ipam.move.task.l2_vlan";
  }
}

/**
 * The exact manual action of an `l2.move` step: the task message of the server with the
 * step's own arguments. The few values every item knows (VLAN, network, MAC) fill in what a
 * step did not carry. `undefined` when the item has no manual L2 step or the arguments the
 * message needs are not there; the caller then uses the general text.
 */
export function l2TaskText(step: MoveStepPreview, item: MoveItem, preview: MovePreview): string | undefined {
  const l2 = item.l2;
  if (!l2 || l2.action !== "manual") return undefined;
  const key = l2TaskKey(l2);
  return fill(key, TASK_ARGS[key], {
    cidr: preview.target.cidr,
    vid: preview.target.vid,
    mac: item.mac,
    host: deviceName(item),
    ...step.params,
  });
}

/** The translated text of a guardrail or controller problem (`errors.<code>`), else the server's detail. */
export function problemText(problem: MoveL2Problem): string {
  return tDynamic(`errors.${problem.code}`) ?? problem.detail;
}

/** The arguments each reason message needs. */
const REASON_ARGS: Readonly<Record<string, readonly string[]>> = {
  no_network: ["vid"],
  no_profile: ["vid"],
  join_ssid: ["ssid", "vid"],
  no_ssid: ["vid"],
  read_only: ["connector"],
  shared_port: ["count"],
  refused: ["rule"],
};

/** Why a person does the L2 step, or why there is none (`move.l2.reason.<tail of the code>`). */
export function l2ReasonText(l2: MoveL2, preview: MovePreview): string | undefined {
  const code = l2.reason;
  if (!code) return undefined;
  const tail = code.replace(/^ipam\.move\.l2\./, "");
  const text = fill(`move.l2.reason.${tail}`, REASON_ARGS[tail] ?? [], {
    vid: preview.target.vid,
    connector: l2.connector?.name,
    ssid: code === L2_REASON.joinSsid ? l2.ssids?.[0] : l2.attachment?.ssid,
    count: l2.others_on_port,
    rule: l2.problem ? problemText(l2.problem) : undefined,
  });
  return text ?? code;
}

/** What happens to a device, short: the first line of the L2 column. `withIp` is the old address of the item this one moves with. */
export function l2Headline(l2: MoveL2, preview: MovePreview, withIp?: string): string {
  const attachment = l2.attachment;
  switch (l2.action) {
    case "port_profile":
      return t("move.l2.action.port_profile", {
        profile: l2.profile_name ?? "?",
        device: attachment?.device_name ?? "?",
        port: attachment?.port ?? "?",
      });
    case "client_vlan": {
      const device = attachment?.device_name ?? "?";
      return attachment?.ssid ? t("move.l2.action.client_vlan_ssid", { device, ssid: attachment.ssid }) : t("move.l2.action.client_vlan", { device });
    }
    case "unchanged":
      return t("move.l2.action.unchanged", { vid: preview.target.vid ?? attachment?.vlan ?? "?" });
    case "shared":
      return withIp ? t("move.l2.action.shared", { ip: withIp }) : (l2ReasonText(l2, preview) ?? t("move.l2.action.manual"));
    default:
      return t("move.l2.action.manual");
  }
}

/** The muted second line of the L2 column: the controller of an automatic change, the reason of a manual one. */
export function l2Detail(l2: MoveL2, preview: MovePreview): string | undefined {
  switch (l2.action) {
    case "port_profile":
    case "client_vlan":
      return l2.connector ? t("move.l2.through", { connector: l2.connector.name }) : undefined;
    case "manual": {
      // A refusal is its guardrail; any other reason can carry the controller's error.
      if (l2.reason === L2_REASON.refused && l2.problem) return problemText(l2.problem);
      const reason = l2ReasonText(l2, preview);
      if (!l2.problem) return reason;
      return reason ? `${reason} ${problemText(l2.problem)}` : problemText(l2.problem);
    }
    default:
      return undefined;
  }
}

/** A note about the L2 change (`ipam.move.l2.note.<tail>`), else the code itself. */
export function l2NoteText(code: string, preview: MovePreview): string {
  const tail = code.replace(/^ipam\.move\.l2\.note\./, "");
  const needs = tail === "carry_unknown" ? ["vid"] : [];
  return fill(`move.l2.note.${tail}`, needs, { vid: preview.target.vid }) ?? code;
}

/** One line of the diff: "before → after", an absent side as "none". */
export function l2DiffText(before: string | null | undefined, after: string | null | undefined): string {
  return t("move.l2.diff", { before: before ?? t("jobs.l2.absent"), after: after ?? t("jobs.l2.absent") });
}

/** The alternative of joining an SSID that carries the VLAN, when the controller knows some. */
export function l2SsidsText(l2: MoveL2, preview: MovePreview): string | undefined {
  const ssids = l2.ssids ?? [];
  if (ssids.length === 0 || l2.reason === L2_REASON.joinSsid) return undefined;
  return fill("move.l2.ssids", ["vid", "ssids"], { vid: preview.target.vid, ssids: ssids.join(", ") });
}
