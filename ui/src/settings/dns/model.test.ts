import { describe, expect, it } from "vitest";
import { listenerDoc, listenerKey, serves, settingGroups, type DnsNodeStatus } from "./model";

const LOG = { state: "on", format: "jsonl", client: "pseudonym", sample: 1, days: 7, size_mb: 256, written: 60, dropped: 0, write_errors: 0 } as const;

function status(extra: Partial<DnsNodeStatus> = {}): DnsNodeStatus {
  return {
    node: 1,
    serving: true,
    revision: 5,
    lag: 0,
    zones: 3,
    rrsets: 40,
    listeners: [
      { address: "192.0.2.53:53", transport: "udp", workers: 2 },
      { address: "192.0.2.53:53", transport: "tcp", workers: 0 },
    ],
    cache_entries: 1234,
    cache_bytes: 2_097_152,
    cache_hits: 8400,
    cache_misses: 1600,
    cache_stale: 12,
    cache_hit_ratio: 0.84,
    started: "2026-10-17T11:58:00Z",
    socket_mode: "shared",
    tcp_open: 1,
    tcp_refused: 0,
    udp_workers: [{ index: 0 }, { index: 1 }],
    ...extra,
  } as unknown as DnsNodeStatus;
}

function row(s: DnsNodeStatus, group: string, id: string) {
  const found = settingGroups(s)
    .find((g) => g.id === group)
    ?.rows.find((r) => r.id === id);
  if (!found) throw new Error(`no row ${group}/${id}`);
  return found;
}

describe("settingGroups", () => {
  it("lists the role, cache and TCP groups, and the query log group only while the log is on", () => {
    expect(settingGroups(status()).map((g) => g.id)).toEqual(["role", "cache", "tcp"]);
    const withLog = settingGroups(status({ query_log: LOG }));
    expect(withLog.map((g) => g.id)).toEqual(["role", "cache", "tcp", "log"]);
    expect(withLog[3]?.section).toBe("[dns.log]");
    expect(withLog[3]?.rows.map((r) => r.id)).toEqual([
      "log_state",
      "log_format",
      "log_client",
      "log_sample",
      "log_days",
      "log_size_mb",
      "log_written",
      "log_dropped",
      "log_write_errors",
    ]);
  });

  it("names the configuration section and the document of each group", () => {
    const groups = settingGroups(status({ query_log: LOG }));
    expect(groups.map((g) => g.section)).toEqual(["[dns]", "[dns.cache]", "[dns.tcp]", "[dns.log]"]);
    expect(groups.map((g) => g.doc)).toEqual([
      "docs/dns.md section 8",
      "docs/dns-resolver.md section 3",
      "docs/dns.md section 8",
      "docs/dns-resolver.md section 8.7",
    ]);
  });

  it("carries the value, the format and the file key of a figure", () => {
    const s = status({ query_log: LOG });
    expect(row(s, "cache", "cache_entries")).toEqual({ id: "cache_entries", value: 1234, format: "count", key: "[dns.cache] entries" });
    expect(row(s, "cache", "cache_hit_ratio")).toMatchObject({ value: 0.84, format: "ratio", key: null });
    expect(row(s, "cache", "cache_bytes")).toMatchObject({ format: "bytes", key: "[dns.cache] max_bytes" });
    expect(row(s, "role", "workers")).toMatchObject({ value: 2, key: "[dns] workers" });
    expect(row(s, "role", "socket_mode")).toMatchObject({ value: "shared", format: "word", key: "[dns.udp] socket" });
    expect(row(s, "role", "serving")).toMatchObject({ value: true, format: "bool", key: null });
    expect(row(s, "tcp", "tcp_open")).toMatchObject({ value: 1, key: "[dns.tcp] max_connections" });
    expect(row(s, "log", "log_state")).toMatchObject({ value: "on", key: "[dns.log] enabled" });
    expect(row(s, "log", "log_written")).toMatchObject({ value: 60, key: null });
  });

  it("gives a figure the status lacks the value null", () => {
    const s = status({ started: undefined, socket_mode: undefined, cache_bytes: undefined, cache_hit_ratio: undefined, tcp_open: undefined, udp_workers: undefined });
    expect(row(s, "role", "started").value).toBeNull();
    expect(row(s, "role", "socket_mode").value).toBeNull();
    expect(row(s, "role", "workers").value).toBeNull();
    expect(row(s, "cache", "cache_bytes").value).toBeNull();
    expect(row(s, "cache", "cache_hit_ratio").value).toBeNull();
    expect(row(s, "tcp", "tcp_open").value).toBeNull();
  });

  it("counts a node without UDP workers as zero workers", () => {
    expect(row(status({ udp_workers: [] }), "role", "workers").value).toBe(0);
  });
});

describe("listener keys and documents", () => {
  it("names the file key of each transport", () => {
    expect(listenerKey("udp")).toBe("[dns] listen");
    expect(listenerKey("tcp")).toBe("[dns] listen");
    expect(listenerKey("dot")).toBe("[dns.tls] dot_listen");
    expect(listenerKey("doh")).toBe("[dns.tls] doh_listen");
  });

  it("points DoT and DoH to the TLS section and the others to the role", () => {
    expect(listenerDoc("dot")).toBe("docs/dns-resolver.md section 7.4");
    expect(listenerDoc("doh")).toBe("docs/dns-resolver.md section 7.4");
    expect(listenerDoc("udp")).toBe("docs/dns.md section 8");
    expect(listenerDoc("tcp")).toBe("docs/dns.md section 8");
  });
});

describe("serves", () => {
  it("is true for a transport that has a listener", () => {
    const s = status({ listeners: [{ address: "192.0.2.53:53", transport: "udp", workers: 1 }, { address: "192.0.2.53:853", transport: "dot", workers: 0 }] });
    expect(serves(s, "dot")).toBe(true);
    expect(serves(s, "doh")).toBe(false);
  });

  it("is false for a node with plain listeners only", () => {
    expect(serves(status(), "dot")).toBe(false);
    expect(serves(status(), "doh")).toBe(false);
  });
});
