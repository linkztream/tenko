// HTTPS and SVCB data in the cache view in the presentation format of RFC 9460 (`svcbText`), the
// data column of such an entry, and the rule that says a column's state once (`uniform`,
// `sharedState`). Wire values are the hex the API carries.
import { describe, expect, it } from "vitest";
import type { DnsCacheEntry } from "./api";
import { buildCacheTree, entryData, paneRows, sharedState, svcbText, uniform, type CacheNode } from "./model";

type Svc = Extract<DnsCacheEntry["records"][number], { type: "HTTPS" | "SVCB" }>;

function svc(params: [number, string][], extra: { priority?: number; target?: string; type?: "HTTPS" | "SVCB" } = {}): Svc {
  return {
    type: extra.type ?? "HTTPS",
    priority: extra.priority ?? 1,
    target: extra.target ?? ".",
    params: params.map(([key, value]) => ({ key, value })),
  };
}

function entry(extra: Partial<DnsCacheEntry>): DnsCacheEntry {
  return { name: "example.net", type: "HTTPS", rcode: 0, ttl: 60, stale: false, hits: 0, state: "unvalidated", records: [], ...extra };
}

describe("svcbText", () => {
  it("writes the priority, the target and the parameters in key order", () => {
    // Given in the wrong order on purpose: the text is in key order.
    expect(svcbText(svc([[4, "c000020a"], [1, "026832026833"]]))).toBe("1 . alpn=h2,h3 ipv4hint=192.0.2.10");
  });

  it("writes an alias record as its priority and target", () => {
    expect(svcbText(svc([], { priority: 0, target: "svc.example.net", type: "SVCB" }))).toBe("0 svc.example.net");
  });

  it("writes alpn as a comma separated list of identifiers", () => {
    expect(svcbText(svc([[1, "026832"]]))).toBe("1 . alpn=h2");
    expect(svcbText(svc([[1, "026832026833"]]))).toBe("1 . alpn=h2,h3");
  });

  it("escapes a comma and a backslash of an alpn identifier for the list and for the zone file (RFC 9460 appendix D)", () => {
    // Identifiers `a,b` and `c\d`: `a\\,b,c\\\\d` as it is written in a zone file.
    expect(svcbText(svc([[1, "03612c6203635c64"]]))).toBe("1 . alpn=a\\\\,b,c\\\\\\\\d");
  });

  it("writes a space, a control byte and a quote of an identifier as the zone file does", () => {
    // `a`, space, 0x01, `"`.
    expect(svcbText(svc([[1, "0461200122"]]))).toBe('1 . alpn=a\\032\\001\\"');
  });

  it("writes no-default-alpn as a bare key", () => {
    expect(svcbText(svc([[2, ""]]))).toBe("1 . no-default-alpn");
  });

  it("writes the port in decimal", () => {
    expect(svcbText(svc([[3, "01bb"]]))).toBe("1 . port=443");
    expect(svcbText(svc([[3, "20fb"]]))).toBe("1 . port=8443");
  });

  it("writes the hints as comma separated addresses", () => {
    expect(svcbText(svc([[4, "c000020ac000020b"]]))).toBe("1 . ipv4hint=192.0.2.10,192.0.2.11");
    expect(svcbText(svc([[6, "20010db8000000000000000000000001"]]))).toBe("1 . ipv6hint=2001:db8::1");
    expect(svcbText(svc([[6, "00000000000000000000000000000001"]]))).toBe("1 . ipv6hint=::1");
    expect(svcbText(svc([[6, "20010db8000000000000000000000001" + "20010db8000000000000000000000002"]]))).toBe("1 . ipv6hint=2001:db8::1,2001:db8::2");
  });

  it("compresses the longest run of zero groups, the first of two equal ones, and never a single group", () => {
    expect(svcbText(svc([[6, "20010db8000000010001000100010001"]]))).toBe("1 . ipv6hint=2001:db8:0:1:1:1:1:1");
    expect(svcbText(svc([[6, "20010db8000000000001000000000001"]]))).toBe("1 . ipv6hint=2001:db8::1:0:0:1");
    expect(svcbText(svc([[6, "20010db8000000000000000100000001"]]))).toBe("1 . ipv6hint=2001:db8::1:0:1");
  });

  it("writes ech in base64 and mandatory as the names of the keys", () => {
    expect(svcbText(svc([[5, "000102"]]))).toBe("1 . ech=AAEC");
    expect(svcbText(svc([[0, "00010003"], [1, "026832"], [3, "01bb"]]))).toBe("1 . mandatory=alpn,port alpn=h2 port=443");
    expect(svcbText(svc([[0, "ff00"]]))).toBe("1 . mandatory=key65280");
  });

  it("writes several keys together", () => {
    const params: [number, string][] = [[1, "026832026833"], [3, "01bb"], [4, "c000020a"], [6, "20010db8000000000000000000000001"]];
    expect(svcbText(svc(params, { target: "svc.example.net" }))).toBe("1 svc.example.net alpn=h2,h3 port=443 ipv4hint=192.0.2.10 ipv6hint=2001:db8::1");
  });

  it("writes an unknown key as keyNNNNN with the value escaped, and bare when it has none", () => {
    expect(svcbText(svc([[65280, "0041"]]))).toBe("1 . key65280=\\000A");
    // 0x00, a backslash, a quote, a space and a comma.
    expect(svcbText(svc([[65280, "005c22202c"]]))).toBe('1 . key65280=\\000\\\\\\"\\032,');
    expect(svcbText(svc([[65281, ""]]))).toBe("1 . key65281");
    expect(svcbText(svc([[7, "2f646e73"]]))).toBe("1 . key7=/dns");
  });

  it("writes a registered key whose value does not fit it in the generic form", () => {
    expect(svcbText(svc([[3, "000102"]]))).toBe("1 . key3=\\000\\001\\002");
    expect(svcbText(svc([[2, "00"]]))).toBe("1 . key2=\\000");
    // The identifier is longer than the value.
    expect(svcbText(svc([[1, "0568"]]))).toBe("1 . key1=\\005h");
  });

  it("shows a value that is no hex as it came", () => {
    expect(svcbText(svc([[4, "c0000"]]))).toBe("1 . ipv4hint=c0000");
  });
});

describe("entryData of an HTTPS or SVCB entry", () => {
  it("reads as SvcParams, not JSON", () => {
    const data = entryData(entry({ records: [svc([[1, "026832026833"], [4, "c000020a"]])] }));
    expect(data).toBe("1 . alpn=h2,h3 ipv4hint=192.0.2.10");
    expect(data).not.toContain("{");
  });

  it("separates several records by a semicolon, since their values hold commas", () => {
    const records = [svc([[1, "026832026833"]]), svc([[1, "026832"]], { priority: 2, target: "alt.example.net" })];
    expect(entryData(entry({ records }))).toBe("1 . alpn=h2,h3; 2 alt.example.net alpn=h2");
  });

  it("names the type of a record that is not the one asked", () => {
    const records: DnsCacheEntry["records"] = [{ type: "CNAME", target: "cdn.example.test" }, svc([[3, "01bb"]])];
    expect(entryData(entry({ records }))).toBe("CNAME cdn.example.test; 1 . port=443");
  });

  it("still joins other records by a comma", () => {
    const records: DnsCacheEntry["records"] = [
      { type: "A", address: "192.0.2.1" },
      { type: "A", address: "192.0.2.2" },
    ];
    expect(entryData(entry({ type: "A", records }))).toBe("192.0.2.1, 192.0.2.2");
  });
});

describe("uniform and sharedState", () => {
  it("gives the value all share", () => {
    expect(uniform(["insecure", "insecure", "insecure"])).toBe("insecure");
  });

  it("gives null when they differ", () => {
    expect(uniform(["insecure", "secure", "insecure"])).toBeNull();
  });

  it("gives null for fewer than two values, since one row has no majority", () => {
    expect(uniform([])).toBeNull();
    expect(uniform(["insecure"])).toBeNull();
    expect(uniform(["insecure"], 1)).toBe("insecure");
  });

  it("reads the state of the entry rows of a folder, not of its folders or signatures", () => {
    const tree = buildCacheTree([
      entry({ name: "a.example.test", type: "A", state: "insecure" }),
      entry({ name: "b.example.test", type: "A", state: "insecure" }),
    ]);
    expect(sharedState(paneRows(tree, tree.byName.get("example.test") as CacheNode))).toBe("insecure");
    // The root holds a folder only: no entry row, no state to say.
    expect(sharedState(paneRows(tree, tree.root))).toBeNull();
  });

  it("is null when one entry differs, and for one entry alone", () => {
    const tree = buildCacheTree([entry({ name: "a.example.test", state: "insecure" }), entry({ name: "b.example.test", state: "secure" })]);
    expect(sharedState(paneRows(tree, tree.byName.get("example.test") as CacheNode))).toBeNull();
    const one = buildCacheTree([entry({ name: "a.example.test", state: "insecure" })]);
    expect(sharedState(paneRows(one, one.byName.get("example.test") as CacheNode))).toBeNull();
  });
});
