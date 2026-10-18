// The pure DNS helpers: names relative to a zone, the zone of a name, reverse names, the
// presentation form and the parsing of record data (with the round trip between them), the
// rows of the record grid, the zone predicates, the diff kind, list splitting and the access
// list entries.
import { describe, expect, it } from "vitest";
import type { AclEntry, RecordData, RrSet } from "./api";
import {
  EDITABLE_TYPES,
  MAX_TTL,
  aclEntryText,
  canonical,
  diffKind,
  inZone,
  isEditableType,
  isOwned,
  isReverse,
  ownerName,
  parseAclEntries,
  parseRecord,
  parseRecords,
  parseTtl,
  recordRows,
  recordText,
  relativeName,
  reverseName,
  servedNow,
  splitList,
  targetName,
  validName,
  zoneFor,
} from "./model";

const ZONE = "example.test";

describe("canonical", () => {
  it("lowercases and drops the trailing dot", () => {
    expect(canonical("WWW.Example.Test.")).toBe("www.example.test");
    expect(canonical("  mail.example.test ")).toBe("mail.example.test");
  });
  it("keeps the root and the empty name", () => {
    expect(canonical(".")).toBe(".");
    expect(canonical("")).toBe("");
  });
});

describe("validName", () => {
  it("accepts ordinary, underscore and wildcard names", () => {
    expect(validName("www.example.test")).toBe(true);
    expect(validName("_ldap._tcp.example.test")).toBe(true);
    expect(validName("*.example.test")).toBe(true);
    expect(validName("1.2.0.192.in-addr.arpa")).toBe(true);
    expect(validName(".")).toBe(true);
  });
  it("refuses empty, malformed and over-long names", () => {
    expect(validName("")).toBe(false);
    expect(validName("a..b")).toBe(false);
    expect(validName("-a.example.test")).toBe(false);
    expect(validName("a b.example.test")).toBe(false);
    expect(validName("www.*.example.test")).toBe(false);
    expect(validName(`${"a".repeat(64)}.example.test`)).toBe(false);
    expect(validName(`${"a.".repeat(130)}test`)).toBe(false);
  });
});

describe("inZone", () => {
  it("takes the apex and the names below it", () => {
    expect(inZone("example.test", ZONE)).toBe(true);
    expect(inZone("www.example.test", ZONE)).toBe(true);
  });
  it("refuses a name that only shares the ending", () => {
    expect(inZone("badexample.test", ZONE)).toBe(false);
    expect(inZone("example.test.other", ZONE)).toBe(false);
  });
  it("takes every name in the root zone", () => {
    expect(inZone("anything.test", ".")).toBe(true);
  });
});

describe("ownerName", () => {
  it("makes @ and nothing the apex", () => {
    expect(ownerName("@", ZONE)).toBe(ZONE);
    expect(ownerName("", ZONE)).toBe(ZONE);
    expect(ownerName("  ", ZONE)).toBe(ZONE);
  });
  it("takes a trailing dot as absolute", () => {
    expect(ownerName("www.example.test.", ZONE)).toBe("www.example.test");
    expect(ownerName("other.test.", ZONE)).toBe("other.test");
  });
  it("keeps a name that already carries the zone suffix", () => {
    expect(ownerName("www.example.test", ZONE)).toBe("www.example.test");
    expect(ownerName("example.test", ZONE)).toBe(ZONE);
  });
  it("appends the zone to a relative name", () => {
    expect(ownerName("www", ZONE)).toBe("www.example.test");
    expect(ownerName("A.B", ZONE)).toBe("a.b.example.test");
    expect(ownerName("www", ".")).toBe("www");
  });
});

describe("targetName", () => {
  it("makes a single label relative to the zone", () => {
    expect(targetName("mail", ZONE)).toBe("mail.example.test");
    expect(targetName("mail", ".")).toBe("mail");
  });
  it("takes a dotted name as absolute", () => {
    expect(targetName("mail.other.test", ZONE)).toBe("mail.other.test");
    expect(targetName("Mail.Other.Test.", ZONE)).toBe("mail.other.test");
  });
  it("takes @ as the apex", () => {
    expect(targetName("@", ZONE)).toBe(ZONE);
  });
});

describe("relativeName", () => {
  it("shows the apex as @", () => {
    expect(relativeName(ZONE, ZONE)).toBe("@");
  });
  it("strips the zone suffix", () => {
    expect(relativeName("www.example.test", ZONE)).toBe("www");
    expect(relativeName("a.b.example.test", ZONE)).toBe("a.b");
  });
  it("leaves a name outside the zone", () => {
    expect(relativeName("www.other.test", ZONE)).toBe("www.other.test");
    expect(relativeName("www.test", ".")).toBe("www.test");
  });
});

describe("zoneFor", () => {
  const zones = [{ name: "example.test" }, { name: "lab.example.test" }, { name: "2.0.192.in-addr.arpa" }];
  it("picks the longest matching suffix", () => {
    expect(zoneFor("host.lab.example.test", zones)?.name).toBe("lab.example.test");
    expect(zoneFor("lab.example.test", zones)?.name).toBe("lab.example.test");
    expect(zoneFor("www.example.test", zones)?.name).toBe("example.test");
  });
  it("does not depend on the order of the zones", () => {
    expect(zoneFor("host.lab.example.test", [...zones].reverse())?.name).toBe("lab.example.test");
  });
  it("answers undefined when no zone matches", () => {
    expect(zoneFor("www.other.test", zones)).toBeUndefined();
    expect(zoneFor("www.example.test", [])).toBeUndefined();
  });
});

describe("reverseName", () => {
  it("reverses the octets of an IPv4 address", () => {
    expect(reverseName("192.0.2.11")).toBe("11.2.0.192.in-addr.arpa");
  });
  it("reverses the 32 nibbles of an IPv6 address", () => {
    const name = reverseName("2001:db8::1");
    const nibbles = "20010db8000000000000000000000001".split("").reverse().join(".");
    expect(name).toBe(`${nibbles}.ip6.arpa`);
    expect(name?.split(".").length).toBe(34);
  });
  it("answers undefined for an invalid address", () => {
    expect(reverseName("192.0.2.256")).toBeUndefined();
    expect(reverseName("not an address")).toBeUndefined();
    expect(reverseName("")).toBeUndefined();
  });
});

describe("recordText", () => {
  it("writes address and name data as they are", () => {
    expect(recordText({ type: "A", address: "192.0.2.1" })).toBe("192.0.2.1");
    expect(recordText({ type: "CNAME", target: "www.example.test" })).toBe("www.example.test");
    expect(recordText({ type: "NS", host: "ns1.example.test" })).toBe("ns1.example.test");
  });
  it("writes MX and SRV with their numbers", () => {
    expect(recordText({ type: "MX", preference: 10, exchange: "mail.example.test" })).toBe("10 mail.example.test");
    expect(recordText({ type: "SRV", priority: 0, weight: 100, port: 389, target: "nas.example.test" })).toBe(
      "0 100 389 nas.example.test",
    );
  });
  it("quotes TXT strings and escapes quotes and backslashes", () => {
    expect(recordText({ type: "TXT", strings: ["v=spf1 mx -all"] })).toBe('"v=spf1 mx -all"');
    expect(recordText({ type: "TXT", strings: ["a", "b"] })).toBe('"a" "b"');
    expect(recordText({ type: "TXT", strings: ['say "hi" \\ bye'] })).toBe('"say \\"hi\\" \\\\ bye"');
  });
  it("writes CAA with a quoted value", () => {
    expect(recordText({ type: "CAA", flags: 0, tag: "issue", value: "ca.example.test" })).toBe('0 issue "ca.example.test"');
  });
  it("writes SOA in its field order", () => {
    const soa: RecordData = {
      type: "SOA",
      mname: "ns1.example.test",
      rname: "hostmaster.example.test",
      serial: 2026101701,
      refresh: 3600,
      retry: 900,
      expire: 1209600,
      minimum: 300,
    };
    expect(recordText(soa)).toBe("ns1.example.test hostmaster.example.test 2026101701 3600 900 1209600 300");
  });
});

describe("parseRecord", () => {
  it("parses A and AAAA and lowercases the IPv6 address", () => {
    expect(parseRecord("A", " 192.0.2.1 ", ZONE)).toEqual({ ok: true, data: { type: "A", address: "192.0.2.1" } });
    expect(parseRecord("AAAA", "2001:DB8::1", ZONE)).toEqual({ ok: true, data: { type: "AAAA", address: "2001:db8::1" } });
  });
  it("answers ipv4 and ipv6 for the wrong family or garbage", () => {
    expect(parseRecord("A", "2001:db8::1", ZONE)).toEqual({ ok: false, code: "ipv4" });
    expect(parseRecord("A", "192.0.2.300", ZONE)).toEqual({ ok: false, code: "ipv4" });
    expect(parseRecord("AAAA", "192.0.2.1", ZONE)).toEqual({ ok: false, code: "ipv6" });
    expect(parseRecord("AAAA", "nope", ZONE)).toEqual({ ok: false, code: "ipv6" });
  });
  it("parses CNAME, DNAME, PTR and NS targets, relative or absolute", () => {
    expect(parseRecord("CNAME", "www", ZONE)).toEqual({ ok: true, data: { type: "CNAME", target: "www.example.test" } });
    expect(parseRecord("DNAME", "other.test.", ZONE)).toEqual({ ok: true, data: { type: "DNAME", target: "other.test" } });
    expect(parseRecord("PTR", "nas.example.test", ZONE)).toEqual({ ok: true, data: { type: "PTR", target: "nas.example.test" } });
    expect(parseRecord("NS", "ns1", ZONE)).toEqual({ ok: true, data: { type: "NS", host: "ns1.example.test" } });
  });
  it("answers target for two words or a bad name", () => {
    expect(parseRecord("CNAME", "a b", ZONE)).toEqual({ ok: false, code: "target" });
    expect(parseRecord("NS", "bad!name", ZONE)).toEqual({ ok: false, code: "target" });
    expect(parseRecord("PTR", "a..b", ZONE)).toEqual({ ok: false, code: "target" });
  });
  it("parses MX and refuses a bad preference or shape with mx", () => {
    expect(parseRecord("MX", "10 mail", ZONE)).toEqual({
      ok: true,
      data: { type: "MX", preference: 10, exchange: "mail.example.test" },
    });
    expect(parseRecord("MX", "65536 mail", ZONE)).toEqual({ ok: false, code: "mx" });
    expect(parseRecord("MX", "-1 mail", ZONE)).toEqual({ ok: false, code: "mx" });
    expect(parseRecord("MX", "mail", ZONE)).toEqual({ ok: false, code: "mx" });
    expect(parseRecord("MX", "10 mail extra", ZONE)).toEqual({ ok: false, code: "mx" });
  });
  it("parses SRV and refuses a bad count or number with srv", () => {
    expect(parseRecord("SRV", "0 100 389 nas.example.test", ZONE)).toEqual({
      ok: true,
      data: { type: "SRV", priority: 0, weight: 100, port: 389, target: "nas.example.test" },
    });
    expect(parseRecord("SRV", "0 100 389", ZONE)).toEqual({ ok: false, code: "srv" });
    expect(parseRecord("SRV", "0 100 70000 nas", ZONE)).toEqual({ ok: false, code: "srv" });
    expect(parseRecord("SRV", "a 100 389 nas", ZONE)).toEqual({ ok: false, code: "srv" });
  });
  it("parses TXT quoted, several strings and unquoted", () => {
    expect(parseRecord("TXT", '"v=spf1 mx -all"', ZONE)).toEqual({ ok: true, data: { type: "TXT", strings: ["v=spf1 mx -all"] } });
    expect(parseRecord("TXT", '"a" "b"', ZONE)).toEqual({ ok: true, data: { type: "TXT", strings: ["a", "b"] } });
    expect(parseRecord("TXT", "plain text", ZONE)).toEqual({ ok: true, data: { type: "TXT", strings: ["plain text"] } });
  });
  it("answers txt for an unterminated or garbled quote", () => {
    expect(parseRecord("TXT", '"open', ZONE)).toEqual({ ok: false, code: "txt" });
    expect(parseRecord("TXT", '"a" b', ZONE)).toEqual({ ok: false, code: "txt" });
  });
  it("parses CAA and lowercases the tag", () => {
    expect(parseRecord("CAA", '0 ISSUE "ca.example.test"', ZONE)).toEqual({
      ok: true,
      data: { type: "CAA", flags: 0, tag: "issue", value: "ca.example.test" },
    });
  });
  it("answers caa for a bad flag, tag or value", () => {
    expect(parseRecord("CAA", '256 issue "ca.example.test"', ZONE)).toEqual({ ok: false, code: "caa" });
    expect(parseRecord("CAA", '0 is-sue "x"', ZONE)).toEqual({ ok: false, code: "caa" });
    expect(parseRecord("CAA", "0 issue", ZONE)).toEqual({ ok: false, code: "caa" });
    expect(parseRecord("CAA", '0 issue "a" "b"', ZONE)).toEqual({ ok: false, code: "caa" });
  });
  it("answers empty for blank text and type for a type it does not edit", () => {
    expect(parseRecord("A", "   ", ZONE)).toEqual({ ok: false, code: "empty" });
    expect(parseRecord("SOA", "x", ZONE)).toEqual({ ok: false, code: "type" });
    expect(parseRecord("TLSA", "x", ZONE)).toEqual({ ok: false, code: "type" });
  });
});

describe("round trip of recordText and parseRecord", () => {
  const samples: RecordData[] = [
    { type: "A", address: "192.0.2.1" },
    { type: "AAAA", address: "2001:db8::1" },
    { type: "CNAME", target: "www.example.test" },
    { type: "MX", preference: 10, exchange: "mail.example.test" },
    { type: "NS", host: "ns1.example.test" },
    { type: "PTR", target: "nas.example.test" },
    { type: "SRV", priority: 1, weight: 2, port: 3, target: "nas.example.test" },
    { type: "TXT", strings: ["v=spf1 mx -all"] },
    { type: "TXT", strings: ["one", 'two "quoted"', "back\\slash"] },
    { type: "CAA", flags: 128, tag: "issuewild", value: "ca.example.test" },
    { type: "DNAME", target: "other.example.test" },
  ];
  it("covers every editable type", () => {
    expect(new Set(samples.map((s) => s.type))).toEqual(new Set(EDITABLE_TYPES));
  });
  it.each(samples.map((s, i) => [`${s.type} #${i}`, s] as const))("gives %s back", (_name, record) => {
    expect(parseRecord(record.type, recordText(record), ZONE)).toEqual({ ok: true, data: record });
  });
});

describe("isEditableType", () => {
  it("knows the editor types", () => {
    expect(isEditableType("MX")).toBe(true);
    expect(isEditableType("SOA")).toBe(false);
    expect(isEditableType("mx")).toBe(false);
  });
});

describe("parseRecords", () => {
  it("parses one record per line and skips blank lines", () => {
    const parsed = parseRecords("A", "192.0.2.1\n\n  \n192.0.2.2\n", ZONE);
    expect(parsed).toEqual({
      ok: true,
      records: [
        { type: "A", address: "192.0.2.1" },
        { type: "A", address: "192.0.2.2" },
      ],
    });
  });
  it("answers the code and line number of the first bad line", () => {
    expect(parseRecords("A", "192.0.2.1\n\nnope\n192.0.2.x", ZONE)).toEqual({ ok: false, code: "ipv4", line: 3 });
  });
  it("answers empty for no input", () => {
    expect(parseRecords("A", "", ZONE)).toEqual({ ok: false, code: "empty", line: 1 });
    expect(parseRecords("A", "\n \n", ZONE)).toEqual({ ok: false, code: "empty", line: 1 });
  });
});

describe("parseTtl", () => {
  it("accepts whole seconds within the bounds", () => {
    expect(parseTtl("0")).toBe(0);
    expect(parseTtl(" 300 ")).toBe(300);
    expect(parseTtl("2147483647")).toBe(MAX_TTL);
  });
  it("refuses out of range, negative, decimal and non-numeric text", () => {
    expect(parseTtl("2147483648")).toBeNull();
    expect(parseTtl("-1")).toBeNull();
    expect(parseTtl("1.5")).toBeNull();
    expect(parseTtl("")).toBeNull();
    expect(parseTtl("1h")).toBeNull();
  });
});

describe("recordRows", () => {
  const stamp = { at: "2026-10-17T12:00:00.000Z", by: { kind: "system", component: "api" } };
  const set = (name: string, type: string, records: RecordData[]): RrSet =>
    ({ scope: "default", name, type, ttl: 300, records, origin: "manual", key: null, updated: stamp }) as unknown as RrSet;
  const a = (address: string): RecordData => ({ type: "A", address });

  it("makes one row per record and marks only the first of a set", () => {
    const rows = recordRows([
      set("www.example.test", "A", [a("192.0.2.1"), a("192.0.2.2")]),
      set("mail.example.test", "A", [a("192.0.2.3")]),
    ]);
    expect(rows.map((r) => [r.index, r.first])).toEqual([
      [0, true],
      [1, false],
      [0, true],
    ]);
    expect(rows[1]?.record).toEqual(a("192.0.2.2"));
  });
  it("gives unique ids, also for sets with the same owner", () => {
    const rows = recordRows([
      set("www.example.test", "A", [a("192.0.2.1"), a("192.0.2.2")]),
      set("www.example.test", "AAAA", [{ type: "AAAA", address: "2001:db8::1" }]),
    ]);
    expect(new Set(rows.map((r) => r.id)).size).toBe(3);
  });
  it("gives no row for an empty set", () => {
    expect(recordRows([set("www.example.test", "A", [])])).toEqual([]);
    expect(recordRows([])).toEqual([]);
  });
});

describe("zone predicates", () => {
  it("owns only manual sets", () => {
    expect(isOwned("manual")).toBe(true);
    expect(isOwned("ipam")).toBe(false);
    expect(isOwned("dhcp")).toBe(false);
  });
  it("does not serve secondary and stub zones yet", () => {
    expect(servedNow("primary")).toBe(true);
    expect(servedNow("forward")).toBe(true);
    expect(servedNow("rpz")).toBe(true);
    expect(servedNow("secondary")).toBe(false);
    // A stub zone is answered through the forwarder since WP5.1.
    expect(servedNow("stub")).toBe(true);
  });
  it("tells a reverse zone by name or by its IPAM prefix", () => {
    expect(isReverse({ name: "2.0.192.in-addr.arpa", reverse_of: null })).toBe(true);
    expect(isReverse({ name: "8.b.d.0.1.0.0.2.ip6.arpa", reverse_of: null })).toBe(true);
    expect(isReverse({ name: "example.test", reverse_of: "0190d1c2-0000-7000-8000-0000000a0001" })).toBe(true);
    expect(isReverse({ name: "example.test", reverse_of: null })).toBe(false);
  });
});

describe("diffKind", () => {
  it("tells add, change and delete", () => {
    expect(diffKind({ before: null, after: {} })).toBe("add");
    expect(diffKind({ after: {} })).toBe("add");
    expect(diffKind({ before: {}, after: null })).toBe("delete");
    expect(diffKind({ before: {}, after: {} })).toBe("change");
  });
});

describe("splitList", () => {
  it("splits on commas, spaces and new lines and drops empties", () => {
    expect(splitList("a, b  c\nd,,\n e ")).toEqual(["a", "b", "c", "d", "e"]);
    expect(splitList("")).toEqual([]);
    expect(splitList(" , \n")).toEqual([]);
  });
});

describe("aclEntryText", () => {
  it("writes each kind and the deny mark", () => {
    expect(aclEntryText({ kind: "prefix", prefix: "192.0.2.0/24" })).toBe("192.0.2.0/24");
    expect(aclEntryText({ kind: "prefix", prefix: "198.51.100.0/24", deny: true })).toBe("!198.51.100.0/24");
    expect(aclEntryText({ kind: "key", name: "xfr.example.test" })).toBe("key xfr.example.test");
    expect(aclEntryText({ kind: "key", name: "xfr.example.test", deny: true })).toBe("!key xfr.example.test");
    expect(aclEntryText({ kind: "any" })).toBe("any");
    expect(aclEntryText({ kind: "any", deny: true })).toBe("!any");
  });
});

describe("parseAclEntries", () => {
  it("parses prefixes, denies, keys and any", () => {
    const text = "192.0.2.0/24\n! 198.51.100.0/24\nkey XFR.example.test\n!key lab.example.test\nANY\n!any\n2001:DB8::/32";
    const expected: AclEntry[] = [
      { kind: "prefix", prefix: "192.0.2.0/24" },
      { kind: "prefix", prefix: "198.51.100.0/24", deny: true },
      { kind: "key", name: "xfr.example.test" },
      { kind: "key", name: "lab.example.test", deny: true },
      { kind: "any" },
      { kind: "any", deny: true },
      { kind: "prefix", prefix: "2001:db8::/32" },
    ];
    expect(parseAclEntries(text)).toEqual({ ok: true, entries: expected });
  });
  it("round trips through aclEntryText", () => {
    const entries: AclEntry[] = [
      { kind: "prefix", prefix: "203.0.113.0/24", deny: true },
      { kind: "key", name: "xfr.example.test" },
      { kind: "any" },
    ];
    expect(parseAclEntries(entries.map(aclEntryText).join("\n"))).toEqual({ ok: true, entries });
  });
  it("skips blank lines and accepts empty input", () => {
    expect(parseAclEntries("")).toEqual({ ok: true, entries: [] });
    expect(parseAclEntries("\n\n192.0.2.1\n")).toEqual({ ok: true, entries: [{ kind: "prefix", prefix: "192.0.2.1/32" }] });
    expect(parseAclEntries("2001:DB8::1")).toEqual({ ok: true, entries: [{ kind: "prefix", prefix: "2001:db8::1/128" }] });
  });
  it("answers the number of the first bad line", () => {
    expect(parseAclEntries("192.0.2.0/24\n\nnot an entry\nalso bad")).toEqual({ ok: false, line: 3 });
    expect(parseAclEntries("key")).toEqual({ ok: false, line: 1 });
    expect(parseAclEntries("192.0.2.0/33")).toEqual({ ok: false, line: 1 });
  });
});
