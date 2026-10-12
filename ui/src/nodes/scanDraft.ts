// The draft behind the scan configuration form (docs/scanning.md, section 12): a configuration
// with its lists held as the text the person types (one prefix per line, ports separated by
// commas), the conversion in both directions, the comparison that tells whether anything was
// edited, and the checks the form can make before the controller does. No texts here.
import { parseIp } from "../ipam/ip";
import { validateScanConfig, type ConfigFieldError, type ScanConfig } from "../scans/model";

/** One SNMP device of the configuration. */
export type SnmpDevice = ScanConfig["snmp"]["devices"][number];

/** A configuration in the shape the form edits. */
export interface Draft {
  config: ScanConfig;
  /** `prefixes`, `exclude` and `blackout`, one entry per line. */
  prefixes: string;
  exclude: string;
  blackout: string;
  /** `tcp_connect.ports`, separated by commas or spaces. */
  ports: string;
  /** `reverse_dns.servers`, one per line. */
  servers: string;
}

/** The entries of a text with one entry per line; blank lines are dropped. */
export function linesOf(text: string): string[] {
  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line !== "");
}

/** The ports of a text; an entry that is not a number stays `NaN` so the port check names it. */
export function portsOf(text: string): number[] {
  return text
    .split(/[\s,;]+/)
    .filter((entry) => entry !== "")
    .map((entry) => Number(entry));
}

/** A deep copy that reads every member, so a reactive computation over a store tracks all of it. */
export function plain<T>(value: T): T {
  if (Array.isArray(value)) return value.map((item) => plain(item as unknown)) as T;
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [key, member] of Object.entries(value as Record<string, unknown>)) out[key] = plain(member);
    return out as T;
  }
  return value;
}

/** The draft of a stored configuration. */
export function draftOf(config: ScanConfig): Draft {
  const copy = plain(config);
  return {
    config: copy,
    prefixes: copy.prefixes.join("\n"),
    exclude: copy.exclude.join("\n"),
    blackout: copy.blackout.join("\n"),
    ports: copy.tcp_connect.ports.join(", "),
    servers: copy.reverse_dns.servers.join("\n"),
  };
}

/** An optional member that is empty is left out of the body rather than sent as an empty value. */
function tidyDevice(device: SnmpDevice): SnmpDevice {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(device)) {
    const required = key === "address" || key === "user";
    if (value === null || value === undefined || (value === "" && !required && key !== "context")) continue;
    out[key] = value;
  }
  return out as unknown as SnmpDevice;
}

/** The configuration the draft stands for, ready to send. */
export function configOf(draft: Draft): ScanConfig {
  const config = plain(draft.config);
  config.prefixes = linesOf(draft.prefixes);
  config.exclude = linesOf(draft.exclude);
  config.blackout = linesOf(draft.blackout);
  config.tcp_connect.ports = portsOf(draft.ports);
  config.reverse_dns.servers = linesOf(draft.servers);
  config.snmp.devices = config.snmp.devices.map(tidyDevice);
  const zone = config.timezone?.trim();
  config.timezone = zone ? zone : null;
  if (!config.vrf) config.vrf = null;
  return config;
}

/** The text of a value with its members in a fixed order, so two equal configurations compare equal. */
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const members = Object.entries(value as Record<string, unknown>)
      .filter(([, member]) => member !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${members.map(([key, member]) => `${JSON.stringify(key)}:${canonical(member)}`).join(",")}}`;
  }
  if (typeof value === "number" && Number.isNaN(value)) return '"NaN"';
  return JSON.stringify(value) ?? "null";
}

/** Whether two configurations are the same, whatever the order of their members. */
export function sameConfig(a: ScanConfig, b: ScanConfig): boolean {
  return canonical(configOf(draftOf(a))) === canonical(configOf(draftOf(b)));
}

/** A blank row for the table of SNMP devices: the default port and nothing else. */
export function blankDevice(): SnmpDevice {
  return { address: "", port: 161, name: null, user: "", auth: null, auth_secret: null, privacy: null, privacy_secret: null, context: "" };
}

/**
 * The checks of the form: those of `validateScanConfig` plus the ones for fields it leaves to
 * the controller that the form can still make (a number that is not a number, a device address).
 */
export function draftErrors(config: ScanConfig): ConfigFieldError[] {
  const errors = validateScanConfig(config);
  const wholeNumber = (field: string, value: number): void => {
    if (!Number.isInteger(value) || value < 0) errors.push({ field, code: "scans.config.min" });
  };
  wholeNumber("per_host_interval_ms", config.per_host_interval_ms);
  wholeNumber("snmp.retries", config.snmp.retries);
  config.snmp.devices.forEach((device, i) => {
    if (parseIp(device.address.trim()) === null) errors.push({ field: `snmp.devices[${i}].address`, code: "scans.config.cidr" });
    const port = device.port ?? 161;
    if (!Number.isInteger(port) || port < 1 || port > 65535) errors.push({ field: `snmp.devices[${i}].port`, code: "scans.config.port" });
  });
  return errors;
}

/** Whether `field` is `name` or a member or entry of it (`prefixes` covers `prefixes[2]`). */
export function within(field: string, name: string): boolean {
  return field === name || field.startsWith(`${name}[`) || field.startsWith(`${name}.`);
}

/** The 1-based positions of the entries of list `name` that the errors name, in order. */
export function positionsOf(errors: readonly { field: string }[], name: string): number[] {
  const found: number[] = [];
  for (const { field } of errors) {
    const match = field.startsWith(`${name}[`) ? /^\[(\d+)\]/.exec(field.slice(name.length)) : null;
    if (match?.[1] !== undefined) found.push(Number(match[1]) + 1);
  }
  return [...new Set(found)].sort((a, b) => a - b);
}
