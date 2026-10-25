// The words of the router advertisement check (DHCP-10, docs/dhcp.md 19.12): the finding rows of
// GET /system/status and of the node's DHCPv6 status in sentences, and how severe each is.
import { tDynamic } from "../../i18n";

/** A finding of the check as the server sends it: a health row of the system status or an entry of the node's report. */
export interface RaFinding {
  code: string;
  detail: string;
  params?: Record<string, string> | null | undefined;
}

/** The prefix of the codes of this check. */
const RA_PREFIX = "dhcp.ra.";

/** Whether a health row is a finding of the router advertisement check. */
export function isRaCode(code: string): boolean {
  return code.startsWith(RA_PREFIX);
}

/** The kind of note of a finding: a warning where hosts get no configuration, information where the setup may be meant. */
export function raFindingKind(code: string): "warn" | "info" {
  return code === "dhcp.ra.flags_off" || code === "dhcp.ra.managed_without_scope" ? "warn" : "info";
}

/** A finding in words: `dhcp.ra.finding.<last segment of the code>`, else its English detail. */
export function raFindingText(finding: RaFinding): string {
  const name = finding.code.split(".").pop() ?? finding.code;
  const key = `dhcp.ra.finding.${name}`;
  const text = tDynamic(key, finding.params ?? {});
  // A message that cannot be formatted (a parameter is missing) comes back as its key.
  return text === undefined || text === key ? finding.detail : text;
}
