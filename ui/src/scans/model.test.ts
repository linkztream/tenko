import { describe, expect, it } from "vitest";
import { defaultScanConfig } from "../api/mock/scans-store";
import {
  CONFIG_METHODS,
  SCAN_KINDS,
  SCAN_STATES,
  SCAN_TARGET_KINDS,
  diffTotals,
  isTerminal,
  validateScanConfig,
  type ScanConfig,
  type ScanDiff,
} from "./model";

function config(change: (c: ScanConfig) => void): ScanConfig {
  const c = defaultScanConfig(["192.0.2.0/24", "2001:db8:0:10::/64", "198.51.100.7"]);
  change(c);
  return c;
}

describe("scan enumerations", () => {
  it("list every value of the document", () => {
    expect(SCAN_KINDS).toEqual(["passive_refresh", "port_scan", "snmp_poll", "os_fingerprint"]);
    expect(SCAN_STATES).toHaveLength(6);
    expect(SCAN_TARGET_KINDS).toEqual(["prefix", "host", "address", "network"]);
  });

  it("know the terminal states", () => {
    expect(SCAN_STATES.filter(isTerminal)).toEqual(["done", "partial", "failed", "cancelled"]);
  });
});

describe("diffTotals", () => {
  it("sums the counts over the fact types", () => {
    const diff: ScanDiff = {
      counts: {
        address: { new: 1, changed: 2, unchanged: 3, gone: 4 },
        name: { new: 10, changed: 0, unchanged: 1, gone: 0 },
      },
      items: [],
      truncated: false,
    };
    expect(diffTotals(diff)).toEqual({ new: 11, changed: 2, unchanged: 4, gone: 4 });
  });

  it("is zero without a diff", () => {
    expect(diffTotals(null)).toEqual({ new: 0, changed: 0, unchanged: 0, gone: 0 });
  });
});

describe("CONFIG_METHODS", () => {
  it("names every method key once, the raw-socket ones last", () => {
    expect(CONFIG_METHODS.map((m) => m.key)).toHaveLength(12);
    expect(new Set(CONFIG_METHODS.map((m) => m.key)).size).toBe(12);
    expect(CONFIG_METHODS.filter((m) => m.raw).map((m) => m.key)).toEqual(["arp_sweep", "tcp_syn", "os_fingerprint", "lldp"]);
    expect(CONFIG_METHODS.slice(0, 8).some((m) => m.raw)).toBe(false);
  });
});

describe("validateScanConfig", () => {
  it("accepts the defaults and a configuration with prefixes and an address", () => {
    expect(validateScanConfig(config(() => undefined))).toEqual([]);
  });

  it("names a prefix or an exclusion that is neither a CIDR nor an address", () => {
    const errors = validateScanConfig(
      config((c) => {
        c.prefixes.push("192.0.2.0/33", "not-a-prefix");
        c.exclude = ["192.0.2.1", "192.0.2.300"];
      }),
    );
    expect(errors).toEqual([
      { field: "prefixes[3]", code: "scans.config.cidr" },
      { field: "prefixes[4]", code: "scans.config.cidr" },
      { field: "exclude[1]", code: "scans.config.cidr" },
    ]);
  });

  it("wants a concurrency and intervals of at least 1", () => {
    const errors = validateScanConfig(
      config((c) => {
        c.concurrency = 0;
        c.icmp.interval_secs = 0;
        c.snmp.interval_secs = -5;
        c.tcp_connect.timeout_ms = 0;
        c.lldp.interval_secs = 0;
      }),
    );
    expect(errors.map((e) => e.field).sort()).toEqual(
      ["concurrency", "icmp.interval_secs", "lldp.interval_secs", "snmp.interval_secs", "tcp_connect.timeout_ms"].sort(),
    );
    expect(errors.every((e) => e.code === "scans.config.min")).toBe(true);
  });

  it("wants ports from 1 to 65535", () => {
    const errors = validateScanConfig(
      config((c) => {
        c.tcp_connect.ports = [22, 0, 65536, 65535];
        c.llmnr.port = 70000;
      }),
    );
    expect(errors).toEqual([
      { field: "llmnr.port", code: "scans.config.port" },
      { field: "tcp_connect.ports[1]", code: "scans.config.port" },
      { field: "tcp_connect.ports[2]", code: "scans.config.port" },
    ]);
  });

  it("lets the optional numbers stay unset", () => {
    const errors = validateScanConfig(config((c) => (c.packets_per_second = null)));
    expect(errors).toEqual([]);
    expect(validateScanConfig(config((c) => (c.packets_per_second = 0)))).toEqual([{ field: "packets_per_second", code: "scans.config.min" }]);
  });
});
