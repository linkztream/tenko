// The pure parts of the cache section: the suffix filter, the data column and the TTL left.
import { describe, expect, it } from "vitest";
import { cacheSuffix, entryData, ttlLeft, type DnsCacheEntry } from "./cache";

function entry(extra: Partial<DnsCacheEntry>): DnsCacheEntry {
  return { name: "www.example.test", type: "A", rcode: 0, ttl: 60, stale: false, hits: 0, state: "unvalidated", records: [], ...extra };
}

describe("the cache helpers", () => {
  it("takes a name as the suffix in canonical form and refuses what is not one", () => {
    expect(cacheSuffix("")).toBe("");
    expect(cacheSuffix("  ")).toBe("");
    expect(cacheSuffix("Example.TEST.")).toBe("example.test");
    expect(cacheSuffix(".")).toBe(".");
    expect(cacheSuffix("not a name")).toBeNull();
    expect(cacheSuffix("a..b")).toBeNull();
  });

  it("shows the records of an answer, a chain with its types, and negative answers", () => {
    expect(entryData(entry({ records: [{ type: "A", address: "192.0.2.1" }, { type: "A", address: "192.0.2.2" }] }))).toBe("192.0.2.1, 192.0.2.2");
    expect(entryData(entry({ records: [{ type: "CNAME", target: "cdn.example.test" }, { type: "A", address: "192.0.2.1" }] }))).toBe(
      "CNAME cdn.example.test, 192.0.2.1",
    );
    expect(entryData(entry({ type: "TXT", records: [{ type: "TXT", strings: ["v=spf1 -all"] }] }))).toBe('"v=spf1 -all"');
    expect(entryData(entry({ rcode: 3 }))).toBe("NXDOMAIN");
    expect(entryData(entry({}))).toBe("NODATA");
  });

  it("rounds the TTL left down to minutes and hours", () => {
    expect(ttlLeft(0)).toEqual({ value: 0, unit: "s" });
    expect(ttlLeft(119)).toEqual({ value: 119, unit: "s" });
    expect(ttlLeft(120)).toEqual({ value: 2, unit: "min" });
    expect(ttlLeft(7_199)).toEqual({ value: 119, unit: "min" });
    expect(ttlLeft(86_400)).toEqual({ value: 24, unit: "h" });
  });
});
