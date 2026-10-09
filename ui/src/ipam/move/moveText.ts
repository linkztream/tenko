// Words of the move preview: the text of each step of each device, built from the item's
// own fields (host, addresses, MAC, DNS name, target), so the preview reads the same
// whatever arguments the server attaches to a step. A step kind this UI does not know falls
// back to the server's text.
import type { MoveItem, MovePreview, MoveStepPreview, MoveTimeoutSource } from "../../api/moves";
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
    case "l2.move":
      return target.vid != null ? t("move.step.l2_move", { host, vid: target.vid }) : t("move.step.l2_move_novlan", { host, cidr: target.cidr });
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
