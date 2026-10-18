// What the DNS settings page shows of a node's DNS role (`GET /nodes/{id}/dns`): its figures
// grouped as the configuration file groups them, each with the `tenko.toml` key that sets it and
// the section of the documentation that explains it. The settings are read at start and need a
// restart, so the page only reads; the file is where they change. Pure data, no text.
import type { components } from "../../api/generated/schema";

export type DnsNodeStatus = components["schemas"]["DnsNodeStatus"];

export type GroupId = "role" | "listeners" | "cache" | "tcp" | "log";

export type RowId =
  | "serving"
  | "started"
  | "zones"
  | "rrsets"
  | "lag"
  | "workers"
  | "socket_mode"
  | "cache_entries"
  | "cache_bytes"
  | "cache_hit_ratio"
  | "cache_hits"
  | "cache_misses"
  | "cache_stale"
  | "tcp_open"
  | "tcp_refused"
  | "log_state"
  | "log_format"
  | "log_client"
  | "log_sample"
  | "log_days"
  | "log_size_mb"
  | "log_written"
  | "log_dropped"
  | "log_write_errors";

/** A figure of the status: the number or word shown, and the file key and document behind it. */
export interface SettingRow {
  id: RowId;
  /** The raw value: a number, a boolean, a word of the API, or null when the status lacks it. */
  value: number | boolean | string | null;
  /** How the page writes the value. */
  format: "count" | "bytes" | "ratio" | "bool" | "word" | "time";
  /** The key in `tenko.toml` that sets it, or null for a figure no key sets (a counter). */
  key: string | null;
}

export interface SettingGroup {
  id: GroupId;
  /** The section of the configuration file. */
  section: string;
  /** The document and section that explain it. */
  doc: string;
  rows: SettingRow[];
}

const RESOLVER = "docs/dns-resolver.md";
const ROLE = "docs/dns.md";

/** The groups of the page; the query log group is absent while the log is off. */
export function settingGroups(s: DnsNodeStatus): SettingGroup[] {
  const groups: SettingGroup[] = [
    {
      id: "role",
      section: "[dns]",
      doc: `${ROLE} section 8`,
      rows: [
        { id: "serving", value: s.serving, format: "bool", key: null },
        { id: "started", value: s.started ?? null, format: "time", key: null },
        { id: "zones", value: s.zones, format: "count", key: null },
        { id: "rrsets", value: s.rrsets, format: "count", key: null },
        { id: "lag", value: s.lag, format: "count", key: null },
        { id: "workers", value: s.udp_workers?.length ?? null, format: "count", key: "[dns] workers" },
        { id: "socket_mode", value: s.socket_mode ?? null, format: "word", key: "[dns.udp] socket" },
      ],
    },
    {
      id: "cache",
      section: "[dns.cache]",
      doc: `${RESOLVER} section 3`,
      rows: [
        { id: "cache_entries", value: s.cache_entries, format: "count", key: "[dns.cache] entries" },
        { id: "cache_bytes", value: s.cache_bytes ?? null, format: "bytes", key: "[dns.cache] max_bytes" },
        { id: "cache_hit_ratio", value: s.cache_hit_ratio ?? null, format: "ratio", key: null },
        { id: "cache_hits", value: s.cache_hits ?? null, format: "count", key: null },
        { id: "cache_misses", value: s.cache_misses ?? null, format: "count", key: null },
        { id: "cache_stale", value: s.cache_stale ?? null, format: "count", key: "[dns.cache] stale_secs" },
      ],
    },
    {
      id: "tcp",
      section: "[dns.tcp]",
      doc: `${ROLE} section 8`,
      rows: [
        { id: "tcp_open", value: s.tcp_open ?? null, format: "count", key: "[dns.tcp] max_connections" },
        { id: "tcp_refused", value: s.tcp_refused ?? null, format: "count", key: "[dns.tcp] per_client" },
      ],
    },
  ];
  const log = s.query_log;
  if (log) {
    groups.push({
      id: "log",
      section: "[dns.log]",
      doc: `${RESOLVER} section 8.7`,
      rows: [
        { id: "log_state", value: log.state, format: "word", key: "[dns.log] enabled" },
        { id: "log_format", value: log.format, format: "word", key: "[dns.log] format" },
        { id: "log_client", value: log.client, format: "word", key: "[dns.log] pseudonymise" },
        { id: "log_sample", value: log.sample, format: "count", key: "[dns.log] sample" },
        { id: "log_days", value: log.days, format: "count", key: "[dns.log] days" },
        { id: "log_size_mb", value: log.size_mb, format: "count", key: "[dns.log] size_mb" },
        { id: "log_written", value: log.written, format: "count", key: null },
        { id: "log_dropped", value: log.dropped, format: "count", key: null },
        { id: "log_write_errors", value: log.write_errors, format: "count", key: null },
      ],
    });
  }
  return groups;
}

/** The key in `tenko.toml` of a listener's addresses, by transport. */
export function listenerKey(transport: string): string {
  if (transport === "dot") return "[dns.tls] dot_listen";
  if (transport === "doh") return "[dns.tls] doh_listen";
  return "[dns] listen";
}

/** The document of the listeners: the served transports for DoT and DoH, the role otherwise. */
export function listenerDoc(transport: string): string {
  return transport === "dot" || transport === "doh" ? `${RESOLVER} section 7.4` : `${ROLE} section 8`;
}

/** Whether DoT or DoH is served: a listener of that transport. */
export function serves(s: DnsNodeStatus, transport: "dot" | "doh"): boolean {
  return s.listeners.some((l) => l.transport === transport);
}
