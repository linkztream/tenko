// The scans of the discovery module in the UI (SCAN-09): the wire shapes of `/scans*` and
// `/nodes/{id}/scan-config` in one place, the lists of their enumerations, and the pure rules
// the scan pages follow (terminal states, diff totals, the checks of a probe configuration
// that the UI can make before the server does). No texts here: views map codes to words.
import type { components } from "../api/generated/schema";
import { parseCidr, parseIp } from "../ipam/ip";
import { seg } from "../app/paths";

type S = components["schemas"];

/** A scan run (`GET /scans/{id}`); the list shows the same shape with the counts of its diff. */
export type ScanView = S["ScanView"];
/** Body of `POST /scans`. */
export type ScanRequest = S["ScanRequest"];
/** What a scan covers: a kind and an id, address or network. */
export type ScanTarget = S["ScanTarget"];
export type ScanTargetKind = S["ScanTargetKind"];
/** What an on-demand scan does. */
export type ScanKind = S["ScanKind"];
export type ScanState = S["ScanState"];
/** One probe's part of a scan. */
export type ProbeProgress = S["ProbeProgress"];
/** What a scan found compared with the facts before it. */
export type ScanDiff = S["ScanDiff"];
export type DiffItem = S["DiffItem"];
export type DiffCounts = S["DiffCounts"];
/** A probe's scan configuration with its state (`GET /nodes/{id}/scan-config`). */
export type ProbeConfigView = S["ProbeConfigView"];
/** The `[scan]` configuration a controller stores for a probe. */
export type ScanConfig = S["ScanConfig"];
/** The sections of the raw-socket methods (docs/scanning.md, 2.8 to 2.12). */
export type ScanArpSweepMethod = S["ScanArpSweepMethod"];
export type ScanTcpSynMethod = S["ScanTcpSynMethod"];
export type ScanOsFingerprintMethod = S["ScanOsFingerprintMethod"];
export type ScanLldpMethod = S["ScanLldpMethod"];
export type ScanDhcpSnoopMethod = S["ScanDhcpSnoopMethod"];
/** A probe as the scan pages list it. */
export type ProbeSummary = S["ProbeSummary"];
export type ProbeList = S["ProbeList"];
/** The scope a probe applies, as it last reported it. */
export type ProbeScope = S["ProbeScope"];
export type KillSwitchView = S["KillSwitchView"];
export type KillSwitchResult = S["KillSwitchResult"];
export type KillSwitchCommand = S["KillSwitchCommand"];
/** Body of the stop routes. */
export type StopRequest = S["StopRequest"];

export const SCAN_KINDS: readonly ScanKind[] = ["passive_refresh", "port_scan", "snmp_poll", "os_fingerprint"];
export const SCAN_STATES: readonly ScanState[] = ["queued", "running", "done", "partial", "failed", "cancelled"];
export const SCAN_TARGET_KINDS: readonly ScanTargetKind[] = ["prefix", "host", "address", "network"];

/** Whether a run has ended: a terminal state never changes again, so polling can stop. */
export function isTerminal(state: ScanState): boolean {
  return state === "done" || state === "partial" || state === "failed" || state === "cancelled";
}

/** The counts of a diff summed over its fact types. */
export function diffTotals(diff: ScanDiff | null | undefined): DiffCounts {
  const total: DiffCounts = { new: 0, changed: 0, unchanged: 0, gone: 0 };
  for (const counts of Object.values(diff?.counts ?? {})) {
    total.new += counts.new;
    total.changed += counts.changed;
    total.unchanged += counts.unchanged;
    total.gone += counts.gone;
  }
  return total;
}

/** A target the "scan now" actions hand to the scan dialog: what to scan and how to call it. */
export interface ScanNowTarget {
  kind: ScanTargetKind;
  value: string;
  label: string;
}

/** The method keys of a `ScanConfig` that carry a schedule. */
export type ConfigMethod =
  | "arp"
  | "nd"
  | "icmp"
  | "tcp_connect"
  | "reverse_dns"
  | "mdns"
  | "llmnr"
  | "snmp"
  | "arp_sweep"
  | "tcp_syn"
  | "os_fingerprint"
  | "lldp"
  | "dhcp_snoop";

/** The methods of a configuration in display order; `raw` ones need raw sockets (CAP_NET_RAW on Linux; unsupported on Windows). */
export const CONFIG_METHODS: readonly { readonly key: ConfigMethod; readonly raw: boolean }[] = [
  { key: "arp", raw: false },
  { key: "nd", raw: false },
  { key: "icmp", raw: false },
  { key: "tcp_connect", raw: false },
  { key: "reverse_dns", raw: false },
  { key: "mdns", raw: false },
  { key: "llmnr", raw: false },
  { key: "snmp", raw: false },
  { key: "arp_sweep", raw: true },
  { key: "tcp_syn", raw: true },
  { key: "os_fingerprint", raw: true },
  { key: "lldp", raw: true },
  { key: "dhcp_snoop", raw: true },
];

/** A configuration field the server would refuse: the field path and a stable code. */
export interface ConfigFieldError {
  /** The path in the body, such as `prefixes[2]` or `tcp_connect.ports[0]`. */
  field: string;
  /** `scans.config.cidr` (not a prefix or an address), `scans.config.min` or `scans.config.port`. */
  code: ConfigErrorCode;
}

export type ConfigErrorCode = "scans.config.cidr" | "scans.config.min" | "scans.config.port";

function isNetwork(text: string): boolean {
  return parseCidr(text, { strict: false }) !== null || parseIp(text.trim()) !== null;
}

/** The checks of a stored configuration that need no state of the controller (docs/scanning.md, 7.5 and 12). */
export function validateScanConfig(config: ScanConfig): ConfigFieldError[] {
  const errors: ConfigFieldError[] = [];
  const add = (field: string, code: ConfigErrorCode): void => {
    errors.push({ field, code });
  };
  const atLeastOne = (field: string, value: number | null | undefined): void => {
    if (value === null || value === undefined) return;
    if (!Number.isInteger(value) || value < 1) add(field, "scans.config.min");
  };
  const port = (field: string, value: number): void => {
    if (!Number.isInteger(value) || value < 1 || value > 65535) add(field, "scans.config.port");
  };

  config.prefixes.forEach((p, i) => {
    if (!isNetwork(p)) add(`prefixes[${i}]`, "scans.config.cidr");
  });
  config.exclude.forEach((p, i) => {
    if (!isNetwork(p)) add(`exclude[${i}]`, "scans.config.cidr");
  });
  atLeastOne("concurrency", config.concurrency);
  atLeastOne("max_hosts_per_prefix", config.max_hosts_per_prefix);
  atLeastOne("packets_per_second", config.packets_per_second);

  for (const { key } of CONFIG_METHODS) {
    const method = config[key];
    atLeastOne(`${key}.interval_secs`, method.interval_secs);
    atLeastOne(`${key}.ttl_secs`, method.ttl_secs);
    if ("timeout_ms" in method) atLeastOne(`${key}.timeout_ms`, method.timeout_ms);
  }
  atLeastOne("mdns.listen_secs", config.mdns.listen_secs);
  atLeastOne("lldp.listen_secs", config.lldp.listen_secs);
  atLeastOne("dhcp_snoop.listen_secs", config.dhcp_snoop.listen_secs);
  port("mdns.unicast_port", config.mdns.unicast_port);
  port("llmnr.port", config.llmnr.port);
  config.tcp_connect.ports.forEach((p, i) => port(`tcp_connect.ports[${i}]`, p));
  return errors;
}

// ---------------------------------------------------------------------------------
// Paths (the shared table src/app/paths.ts belongs to the shell; these stay here until folded in)

/** The list of scan jobs, with the probes and the installation-wide kill switch. */
export const SCANS_PATH = "/scans";

/** One scan job: its progress per probe and the diff it found. */
export function scanPath(id: string): string {
  return `${SCANS_PATH}/${seg(id)}`;
}

/** The scan configuration and the kill switch of one probe node. */
export function nodeScanPath(node: number | string): string {
  return `/nodes/${seg(node)}/scan`;
}
