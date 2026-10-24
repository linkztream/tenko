// The pure parts of the cache section: the suffix filter, the reading of the pages up to the cap,
// the data column and the signatures, the TTL left, and the tree of names with its folders and
// the rows of the right pane.
import { describe, expect, it } from "vitest";
import {
  buildCacheTree,
  createCacheTree,
  cacheSuffix,
  entryData,
  folderChildren,
  nameLabels,
  paneRows,
  pathTo,
  readPages,
  rrsigTime,
  signatures,
  ttlLeft,
  utcMinute,
  visibleFolders,
  type CachePage,
  type DnsCacheEntry,
  type PaneRow,
  type Rrsig,
} from "./cache";

function entry(extra: Partial<DnsCacheEntry>): DnsCacheEntry {
  return { name: "www.example.test", type: "A", rcode: 0, ttl: 60, stale: false, hits: 0, state: "unvalidated", records: [], ...extra };
}

function rrsig(covered: Rrsig["type_covered"], expiration: number): Rrsig {
  return {
    type: "RRSIG",
    type_covered: covered,
    algorithm: 13,
    labels: 3,
    original_ttl: 300,
    expiration,
    inception: expiration - 1_814_400,
    key_tag: 4711,
    signer: "example.test",
    signature: "00ff",
  };
}

/** 2026-11-12 02:08 UTC. */
const EXPIRES = Date.UTC(2026, 10, 12, 2, 8) / 1000;

function names(rows: PaneRow[]): string[] {
  return rows.map((row) =>
    row.kind === "folder" ? `folder ${row.node.label}` : `${row.kind} ${row.label ?? "(same)"} ${row.kind === "signature" ? row.record.type_covered : row.entry.type}`,
  );
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

  it("reads the pages following the cursor and stops at the cap", async () => {
    const pages = (count: number) => {
      const asked: (string | undefined)[] = [];
      const read = (cursor: string | undefined): Promise<CachePage> => {
        asked.push(cursor);
        const n = cursor ? Number(cursor.slice(1)) : 0;
        return Promise.resolve({ items: [entry({ name: `h${n}.example.test` })], next: n + 1 < count ? `p${n + 1}` : null });
      };
      return { asked, read };
    };
    const three = pages(3);
    expect(await readPages(three.read, 10)).toMatchObject({ capped: false, items: [{ name: "h0.example.test" }, { name: "h1.example.test" }, { name: "h2.example.test" }] });
    expect(three.asked).toEqual([undefined, "p1", "p2"]);
    const exact = pages(10);
    expect((await readPages(exact.read, 10)).capped).toBe(false);
    const many = pages(25);
    const capped = await readPages(many.read, 10);
    expect(capped.capped).toBe(true);
    expect(capped.items).toHaveLength(10);
    expect(many.asked).toHaveLength(10);
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

  it("keeps the signatures out of the data column and lists them apart", () => {
    const signed = entry({ records: [{ type: "A", address: "192.0.2.1" }, rrsig("A", EXPIRES)] });
    expect(entryData(signed)).toBe("192.0.2.1");
    expect(signatures(signed).map((r) => r.type_covered)).toEqual(["A"]);
    expect(signatures(entry({ records: [{ type: "A", address: "192.0.2.1" }] }))).toEqual([]);
    expect(entryData(entry({ rcode: 3, records: [rrsig("NSEC", EXPIRES)] }))).toBe("NXDOMAIN");
  });

  it("reads an RRSIG time in serial arithmetic and shows it to the minute in UTC", () => {
    const now = Date.UTC(2026, 9, 24);
    expect(utcMinute(rrsigTime(EXPIRES, now))).toBe("2026-11-12 02:08");
    // Past 2106 the field wraps; the time nearest to now is meant.
    const wrapped = Date.UTC(2106, 1, 10) / 1000 - 2 ** 32;
    expect(rrsigTime(wrapped, Date.UTC(2106, 1, 1)).getUTCFullYear()).toBe(2106);
  });

  it("rounds the TTL left down to minutes and hours", () => {
    expect(ttlLeft(0)).toEqual({ value: 0, unit: "s" });
    expect(ttlLeft(119)).toEqual({ value: 119, unit: "s" });
    expect(ttlLeft(120)).toEqual({ value: 2, unit: "min" });
    expect(ttlLeft(7_199)).toEqual({ value: 119, unit: "min" });
    expect(ttlLeft(86_400)).toEqual({ value: 24, unit: "h" });
  });
});

describe("the tree of names", () => {
  const entries = [
    entry({ name: ".", type: "NS" }),
    entry({ name: "example.net", type: "TXT" }),
    entry({ name: "ns1.example.org", type: "AAAA" }),
    entry({ name: "example.test", type: "MX" }),
    entry({ name: "intranet.example.test", type: "A" }),
    entry({ name: "www.example.test", type: "A", records: [{ type: "A", address: "192.0.2.80" }, rrsig("A", EXPIRES)] }),
    entry({ name: "www.example.test", type: "AAAA" }),
  ];

  it("splits a name into its labels from the root inwards", () => {
    expect(nameLabels("www.example.test")).toEqual(["test", "example", "www"]);
    expect(nameLabels(".")).toEqual([]);
    expect(nameLabels("a\\.b.example.test")).toEqual(["test", "example", "a\\.b"]);
    expect(pathTo("www.example.test")).toEqual([".", "test", "example.test", "www.example.test"]);
    expect(pathTo(".")).toEqual(["."]);
  });

  it("builds one node per label from the root, each with the entries of exactly its name", () => {
    const tree = buildCacheTree(entries);
    expect(tree.root.name).toBe(".");
    expect(tree.root.label).toBe("");
    expect(tree.root.entries.map((e) => e.type)).toEqual(["NS"]);
    expect(tree.root.children.map((c) => c.label)).toEqual(["net", "org", "test"]);
    const example = tree.byName.get("example.test");
    expect(example?.label).toBe("example");
    expect(example?.depth).toBe(2);
    expect(example?.parent).toBe("test");
    expect(example?.entries.map((e) => e.type)).toEqual(["MX"]);
    expect(example?.children.map((c) => c.name)).toEqual(["intranet.example.test", "www.example.test"]);
    expect(tree.byName.get("www.example.test")?.entries.map((e) => e.type)).toEqual(["A", "AAAA"]);
    expect(tree.byName.get("test")?.entries).toEqual([]);
    expect(new Set([...tree.byName.values()].map((n) => n.id)).size).toBe(tree.byName.size);
  });

  it("makes folders of the root, of names with names under them and of the suffix", () => {
    const tree = buildCacheTree(entries);
    expect(folderChildren(tree, tree.root).map((n) => n.name)).toEqual(["net", "org", "test"]);
    expect(folderChildren(tree, tree.byName.get("test")!).map((n) => n.name)).toEqual(["example.test"]);
    expect(folderChildren(tree, tree.byName.get("example.test")!)).toEqual([]);
    const narrowed = buildCacheTree(entries.filter((e) => e.name === "www.example.test"), "www.example.test");
    expect(narrowed.suffix).toBe("www.example.test");
    expect(folderChildren(narrowed, narrowed.byName.get("example.test")!).map((n) => n.name)).toEqual(["www.example.test"]);
    expect(buildCacheTree([], "nothing.example.test").byName.has("nothing.example.test")).toBe(true);
    expect(buildCacheTree(entries, ".").suffix).toBe("");
  });

  it("shows the folders under the expanded ones in pre-order", () => {
    const tree = buildCacheTree(entries);
    const shown = (open: string[]) => visibleFolders(tree, new Set(open)).map((item) => (item.kind === "folder" ? item.node.name : "more"));
    expect(shown([])).toEqual(["."]);
    expect(shown(["."])).toEqual([".", "net", "org", "test"]);
    expect(shown([".", "test"])).toEqual([".", "net", "org", "test", "example.test"]);
    expect(shown([".", "org"])).toEqual([".", "net", "org", "example.org", "test"]);
    // An expanded folder under a collapsed one stays hidden.
    expect(shown(["test"])).toEqual(["."]);
  });

  it("shows a window of the folders under a folder, with a show more for the rest", () => {
    const many = Array.from({ length: 5 }, (_, n) => entry({ name: `h${n}.d${n}.example.test` }));
    const tree = buildCacheTree(many);
    const open = new Set([".", "test", "example.test"]);
    const items = (shown: Map<string, number>) =>
      visibleFolders(tree, open, shown, 2).map((item) => (item.kind === "folder" ? item.node.name : `more ${item.parent.name} ${item.hidden}`));
    expect(items(new Map())).toEqual([".", "test", "example.test", "d0.example.test", "d1.example.test", "more example.test 3"]);
    expect(items(new Map([["example.test", 4]])).at(-1)).toBe("more example.test 1");
    expect(items(new Map([["example.test", 5]])).at(-1)).toBe("d4.example.test");
  });

  it("builds a tree of 100,000 names under one folder in linear time, page by page", () => {
    const tree = createCacheTree("big.example.test");
    const started = performance.now();
    for (let page = 0; page < 100; page++) {
      tree.add(Array.from({ length: 1000 }, (_, n) => entry({ name: `h${page * 1000 + n}.big.example.test` })));
    }
    const elapsed = performance.now() - started;
    const big = tree.byName.get("big.example.test")!;
    expect(big.children).toHaveLength(100_000);
    expect(visibleFolders(tree, new Set(pathTo("big.example.test")))).toHaveLength(4);
    expect(paneRows(tree, big)).toHaveLength(100_000);
    expect(elapsed).toBeLessThan(1000);
  });

  it("lists a folder's folders, its own records and those of the names under it, each with its signatures", () => {
    const tree = buildCacheTree(entries);
    expect(names(paneRows(tree, tree.root))).toEqual(["folder net", "folder org", "folder test", "entry (same) NS"]);
    expect(names(paneRows(tree, tree.byName.get("test")!))).toEqual(["folder example"]);
    expect(names(paneRows(tree, tree.byName.get("example.test")!))).toEqual([
      "entry (same) MX",
      "entry intranet A",
      "entry www A",
      "signature www A",
      "entry www AAAA",
    ]);
    const net = tree.byName.get("example.net")!;
    expect(names(paneRows(tree, tree.byName.get("net")!))).toEqual(["entry example TXT"]);
    expect(paneRows(tree, net)).toEqual([{ kind: "entry", entry: net.entries[0], label: null }]);
  });
});

