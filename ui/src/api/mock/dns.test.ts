// The pure mock DNS service without msw: the seed, zones (create, update with the serial
// policies, delete), the record list filters, the batch change with its dry run and the origin
// and CNAME rules, the serial arithmetic, the zone file parser, import and export, access lists
// and TSIG keys. A fixed clock, a revision counter and a counter-based id stand in for the msw
// caller.
import { beforeEach, describe, expect, it } from "vitest";
import {
  DNS_IDS,
  DnsFailure,
  changeRecords,
  createAcl,
  createKey,
  createZone,
  deleteAcl,
  deleteKey,
  deleteZone,
  exportZoneFile,
  importZoneFile,
  listRecords,
  listZones,
  nextSerial,
  parseZoneFile,
  seedDns,
  updateAcl,
  updateZone,
  type DnsContext,
  type DnsState,
} from "./dns-model";

const NOW = Date.UTC(2026, 9, 17, 12);
const EX = DNS_IDS.zone.example;
const SECRET = "Zml4ZWRzZWNyZXRmaXhlZHNlY3JldA==";

let rev = 0;
let ids = 0;
let state: DnsState;
let ctx: DnsContext;

beforeEach(() => {
  rev = 0;
  ids = 0;
  ctx = {
    now: () => NOW,
    nextRevision: () => ++rev,
    principal: () => ({ kind: "system", component: "api" }) as ReturnType<DnsContext["principal"]>,
    newId: () => `0190d1c2-0000-7000-8000-${String(++ids).padStart(12, "0")}`,
    newSecret: () => SECRET,
  };
  state = seedDns(ctx);
});

/** Runs `fn`, expects it to fail with a DnsFailure and returns the failure. */
function failure(fn: () => unknown): DnsFailure {
  try {
    fn();
  } catch (error) {
    expect(error).toBeInstanceOf(DnsFailure);
    return error as DnsFailure;
  }
  throw new Error("expected a DnsFailure");
}

const zoneOf = (id: string) => state.zones.find((z) => z.id === id) as DnsState["zones"][number];
const a = (address: string) => ({ type: "A", address });
const sets = (id: string, query = {}) => listRecords(state, id, query);
const find = (id: string, name: string, type: string) => sets(id).find((s) => s.name === name && s.type === type);
const newSoa = (name: string) => ({ mname: `ns1.${name}`, rname: `hostmaster.${name}` });

describe("seedDns", () => {
  it("makes the four zones", () => {
    expect(state.zones.map((z) => [z.name, z.kind])).toEqual([
      ["example.test", "primary"],
      ["2.0.192.in-addr.arpa", "primary"],
      ["lab.example.test", "secondary"],
      ["corp.example.test", "stub"],
    ]);
  });
  it("counts the RRsets of each zone by origin", () => {
    const example = zoneOf(EX);
    expect(example.rrsets).toBe(13);
    expect(example.origins).toEqual([
      { origin: "ipam", rrsets: 4 },
      { origin: "manual", rrsets: 9 },
    ]);
    expect(zoneOf(DNS_IDS.zone.corp).rrsets).toBe(0);
  });
  it("fills the use of the access lists from the transfer policies", () => {
    const byId = (id: string) => state.acls.find((acl) => acl.id === id);
    expect(byId(DNS_IDS.acl.peers)?.used_by).toEqual(["example.test"]);
    expect(byId(DNS_IDS.acl.internal)?.used_by).toEqual([]);
  });
  it("starts at one revision for all seeded objects", () => {
    expect(rev).toBe(1);
    expect(zoneOf(EX).revision).toBe(1);
  });
});

describe("listZones", () => {
  it("orders by canonical DNS name, parents before children", () => {
    expect(listZones(state).map((z) => z.name)).toEqual([
      "2.0.192.in-addr.arpa",
      "example.test",
      "corp.example.test",
      "lab.example.test",
    ]);
  });
});

describe("createZone", () => {
  it("creates a primary zone with its SOA and NS sets", () => {
    const zone = createZone(state, ctx, { name: "New.Test.", kind: "primary", soa: newSoa("new.test") });
    expect(zone.name).toBe("new.test");
    expect(zone.serial).toBe("date_counter");
    expect(zone.soa_serial).toBe(2026101700);
    expect(zone.revision).toBe(rev);
    expect(zone.rrsets).toBe(2);
    expect(state.zones).toContain(zone);
  });
  it("lists the SOA and the NS set of the new zone", () => {
    const zone = createZone(state, ctx, { name: "new.test", kind: "primary", soa: newSoa("new.test") });
    const [soa, ns] = sets(zone.id);
    expect(soa?.type).toBe("SOA");
    expect(soa?.records[0]).toMatchObject({ type: "SOA", mname: "ns1.new.test", serial: 2026101700 });
    expect(ns?.type).toBe("NS");
    expect(ns?.records).toEqual([{ type: "NS", host: "ns1.new.test" }]);
  });
  it("takes the given name servers for the NS set", () => {
    const zone = createZone(state, ctx, {
      name: "new.test",
      kind: "primary",
      soa: newSoa("new.test"),
      name_servers: ["ns1.new.test", "ns2.new.test"],
    });
    expect(find(zone.id, "new.test", "NS")?.records).toHaveLength(2);
  });
  it("refuses an existing name with 409 dns.zone.exists", () => {
    const f = failure(() => createZone(state, ctx, { name: "example.test", kind: "primary", soa: newSoa("example.test") }));
    expect([f.status, f.code]).toEqual([409, "dns.zone.exists"]);
  });
  it("refuses a bad name with 400 dns.zone.invalid and the field", () => {
    const f = failure(() => createZone(state, ctx, { name: "bad name", kind: "primary", soa: newSoa("x.test") }));
    expect([f.status, f.code, f.params.field]).toEqual([400, "dns.zone.invalid", "name"]);
  });
  it("refuses an unknown kind and a missing SOA", () => {
    expect(failure(() => createZone(state, ctx, { name: "new.test", kind: "odd" })).params.field).toBe("kind");
    expect(failure(() => createZone(state, ctx, { name: "new.test", kind: "primary" })).params.field).toBe("soa");
  });
  it("refuses a secondary without primaries and accepts one with", () => {
    const f = failure(() => createZone(state, ctx, { name: "sec.test", kind: "secondary", soa: newSoa("sec.test") }));
    expect([f.status, f.code, f.params.field]).toEqual([400, "dns.zone.invalid", "source"]);
    const source = { primaries: [{ address: "198.51.100.53", port: 53, key: null, tls_name: null, xot: false }] };
    const zone = createZone(state, ctx, { name: "sec.test", kind: "secondary", soa: newSoa("sec.test"), source });
    expect(zone.rrsets).toBe(0);
  });
});

describe("updateZone", () => {
  it("refuses a stale If-Match revision with 412", () => {
    const f = failure(() => updateZone(state, ctx, EX, { description: "x" }, zoneOf(EX).revision - 1));
    expect([f.status, f.code]).toEqual([412, "sys.store.precondition_failed"]);
  });
  it("accepts the current revision and a wildcard, and raises the revision", () => {
    const before = zoneOf(EX).revision;
    updateZone(state, ctx, EX, { description: "changed" }, before);
    expect(zoneOf(EX).revision).toBe(rev);
    expect(zoneOf(EX).revision).toBeGreaterThan(before);
    expect(zoneOf(EX).description).toBe("changed");
    updateZone(state, ctx, EX, { description: "" }, "*");
    expect(zoneOf(EX).description).toBeNull();
  });
  it("moves the date_counter serial within the day", () => {
    updateZone(state, ctx, EX, { description: "x" }, null);
    expect(zoneOf(EX).soa_serial).toBe(2026101702);
  });
  it("moves the counter serial by one", () => {
    const zone = createZone(state, ctx, { name: "c.test", kind: "primary", soa: newSoa("c.test"), serial: "counter" });
    expect(zone.soa_serial).toBe(1);
    updateZone(state, ctx, zone.id, { description: "x" }, null);
    expect(zone.soa_serial).toBe(2);
  });
  it("moves the unixtime serial", () => {
    const zone = createZone(state, ctx, { name: "u.test", kind: "primary", soa: newSoa("u.test"), serial: "unixtime" });
    expect(zone.soa_serial).toBe(NOW / 1000);
    updateZone(state, ctx, zone.id, { description: "x" }, null);
    expect(zone.soa_serial).toBe(NOW / 1000 + 1);
  });
  it("changes the policy and keeps the SOA record in step", () => {
    updateZone(state, ctx, EX, { serial: "counter", soa: { ...newSoa("example.test"), ttl: 120 } }, null);
    const soa = find(EX, "example.test", "SOA");
    expect(zoneOf(EX).serial).toBe("counter");
    expect(zoneOf(EX).soa_serial).toBe(2026101702);
    expect(soa?.records[0]).toMatchObject({ serial: 2026101702 });
    expect(soa?.ttl).toBe(120);
  });
  it("refuses an unknown policy and an unknown zone", () => {
    expect(failure(() => updateZone(state, ctx, EX, { serial: "random" }, null)).code).toBe("dns.zone.invalid");
    expect(failure(() => updateZone(state, ctx, "missing", {}, null)).status).toBe(404);
  });
});

describe("deleteZone", () => {
  it("removes the zone and its records and the use of its access lists", () => {
    deleteZone(state, ctx, EX);
    expect(state.zones.map((z) => z.name)).not.toContain("example.test");
    expect(state.rrsets.has(EX)).toBe(false);
    expect(state.acls.find((acl) => acl.id === DNS_IDS.acl.peers)?.used_by).toEqual([]);
  });
  it("fails with 404 dns.zone.not_found for an unknown id", () => {
    const f = failure(() => deleteZone(state, ctx, "missing"));
    expect([f.status, f.code]).toEqual([404, "dns.zone.not_found"]);
  });
});

describe("listRecords", () => {
  it("lists in canonical order with the SOA and NS first", () => {
    const all = sets(EX);
    expect(all.slice(0, 2).map((s) => s.type)).toEqual(["SOA", "NS"]);
    expect(all).toHaveLength(13);
  });
  it("filters by a relative name prefix", () => {
    expect(sets(EX, { name: "gw" }).map((s) => `${s.name} ${s.type}`)).toEqual(["gw.example.test A", "gw.example.test AAAA"]);
  });
  it("filters by an absolute name prefix", () => {
    expect(sets(EX, { name: "nas.example.test" }).map((s) => s.name)).toEqual(["nas.example.test"]);
  });
  it("takes @ for the apex", () => {
    expect(new Set(sets(EX, { name: "@" }).map((s) => s.name))).toEqual(new Set(["example.test"]));
  });
  it("filters by type (any case) and by origin", () => {
    expect(sets(EX, { type: "a" })).toHaveLength(6);
    expect(sets(EX, { origin: "ipam" })).toHaveLength(4);
    expect(sets(EX, { type: "A", origin: "ipam" })).toHaveLength(3);
    expect(sets(EX, { origin: "dhcp" })).toEqual([]);
  });
});

describe("changeRecords", () => {
  const wwwAdd = { changes: [{ name: "www.example.test", type: "A", op: "add", records: [a("192.0.2.82")] }] };

  it("does not change anything in a dry run and returns before and after", () => {
    const serial = zoneOf(EX).soa_serial;
    const revision = zoneOf(EX).revision;
    const result = changeRecords(state, ctx, EX, wwwAdd, true);
    expect(result).toMatchObject({ dry_run: true, revision: null, serial: null });
    expect(result.changes).toHaveLength(1);
    expect(result.changes[0]?.before?.records).toHaveLength(2);
    expect(result.changes[0]?.after?.records).toHaveLength(3);
    expect(find(EX, "www.example.test", "A")?.records).toHaveLength(2);
    expect(zoneOf(EX).soa_serial).toBe(serial);
    expect(zoneOf(EX).revision).toBe(revision);
  });
  it("leaves before empty for a new set in a dry run", () => {
    const result = changeRecords(state, ctx, EX, { changes: [{ name: "new.example.test", type: "A", op: "set", records: [a("192.0.2.90")] }] }, true);
    expect(result.changes[0]?.before).toBeNull();
    expect(result.changes[0]?.after?.records).toEqual([a("192.0.2.90")]);
  });
  it("moves the serial and the revision on a write", () => {
    const result = changeRecords(state, ctx, EX, wwwAdd, false);
    expect(result).toMatchObject({ dry_run: false, revision: rev, serial: 2026101702 });
    expect(zoneOf(EX).soa_serial).toBe(2026101702);
    expect(find(EX, "example.test", "SOA")?.records[0]).toMatchObject({ serial: 2026101702 });
  });
  it("adds a record without duplicating one that exists", () => {
    changeRecords(state, ctx, EX, { changes: [{ name: "www.example.test", type: "A", op: "add", records: [a("192.0.2.80"), a("192.0.2.82")] }] }, false);
    expect(find(EX, "www.example.test", "A")?.records).toEqual([a("192.0.2.80"), a("192.0.2.81"), a("192.0.2.82")]);
  });
  it("sets a whole RRset with its TTL", () => {
    changeRecords(state, ctx, EX, { changes: [{ name: "www.example.test", type: "A", op: "set", ttl: 60, records: [a("192.0.2.99")] }] }, false);
    expect(find(EX, "www.example.test", "A")).toMatchObject({ ttl: 60, records: [a("192.0.2.99")] });
  });
  it("removes named records and keeps the rest", () => {
    changeRecords(state, ctx, EX, { changes: [{ name: "www.example.test", type: "A", op: "remove", records: [a("192.0.2.81")] }] }, false);
    expect(find(EX, "www.example.test", "A")?.records).toEqual([a("192.0.2.80")]);
  });
  it("deletes an RRset", () => {
    changeRecords(state, ctx, EX, { changes: [{ name: "mail.example.test", type: "A", op: "delete" }] }, false);
    expect(find(EX, "mail.example.test", "A")).toBeUndefined();
    expect(zoneOf(EX).rrsets).toBe(12);
  });
  it("refuses a CNAME beside other data with 409 dns.record.conflict", () => {
    const f = failure(() =>
      changeRecords(state, ctx, EX, { changes: [{ name: "mail.example.test", type: "CNAME", op: "set", records: [{ type: "CNAME", target: "www.example.test" }] }] }, false),
    );
    expect([f.status, f.code]).toEqual([409, "dns.record.conflict"]);
    expect(find(EX, "mail.example.test", "CNAME")).toBeUndefined();
  });
  it("refuses other data beside a CNAME", () => {
    const f = failure(() => changeRecords(state, ctx, EX, { changes: [{ name: "ftp.example.test", type: "A", op: "set", records: [a("192.0.2.5")] }] }, true));
    expect(f.code).toBe("dns.record.conflict");
  });
  it("refuses a change of an IPAM RRset with 409 dns.record.origin", () => {
    const f = failure(() => changeRecords(state, ctx, EX, { changes: [{ name: "gw.example.test", type: "A", op: "set", records: [a("192.0.2.9")] }] }, false));
    expect([f.status, f.code, f.params.origin]).toEqual([409, "dns.record.origin", "ipam"]);
  });
  it("takes over an IPAM RRset with take_over, which makes it manual", () => {
    changeRecords(state, ctx, EX, { changes: [{ name: "gw.example.test", type: "A", op: "set", records: [a("192.0.2.9")], take_over: true }] }, false);
    expect(find(EX, "gw.example.test", "A")).toMatchObject({ origin: "manual", records: [a("192.0.2.9")] });
    expect(zoneOf(EX).origins).toEqual([
      { origin: "ipam", rrsets: 3 },
      { origin: "manual", rrsets: 10 },
    ]);
  });
  it("cannot delete the apex NS", () => {
    const f = failure(() => changeRecords(state, ctx, EX, { changes: [{ name: "example.test", type: "NS", op: "delete" }] }, false));
    expect([f.status, f.code]).toEqual([409, "dns.record.conflict"]);
  });
  it("refuses SOA changes", () => {
    const soa = { type: "SOA", mname: "ns1.example.test", rname: "hostmaster.example.test", serial: 1, refresh: 1, retry: 1, expire: 1, minimum: 1 };
    const f = failure(() => changeRecords(state, ctx, EX, { changes: [{ name: "example.test", type: "SOA", op: "set", records: [soa] }] }, false));
    expect([f.status, f.code]).toEqual([400, "dns.record.invalid"]);
  });
  it("refuses an owner outside the zone, a bad op and an empty batch", () => {
    const out = failure(() => changeRecords(state, ctx, EX, { changes: [{ name: "www.other.test", type: "A", op: "set", records: [a("192.0.2.1")] }] }, true));
    expect(out.code).toBe("dns.record.invalid");
    const op = failure(() => changeRecords(state, ctx, EX, { changes: [{ name: "www.example.test", type: "A", op: "zap" }] }, true));
    expect(op.code).toBe("sys.invalid_value");
    expect(failure(() => changeRecords(state, ctx, EX, { changes: [] }, true)).code).toBe("sys.invalid_request");
  });
  it("applies a batch all or nothing", () => {
    const serial = zoneOf(EX).soa_serial;
    failure(() =>
      changeRecords(
        state,
        ctx,
        EX,
        {
          changes: [
            { name: "new.example.test", type: "A", op: "set", records: [a("192.0.2.90")] },
            { name: "gw.example.test", type: "A", op: "delete" },
          ],
        },
        false,
      ),
    );
    expect(find(EX, "new.example.test", "A")).toBeUndefined();
    expect(zoneOf(EX).soa_serial).toBe(serial);
  });
});

describe("nextSerial", () => {
  it("counts up and wraps at 2^32 for the counter policy", () => {
    expect(nextSerial("counter", 5, NOW)).toBe(6);
    expect(nextSerial("counter", 4_294_967_295, NOW)).toBe(0);
  });
  it("takes the clock for unixtime, or one more when the clock is behind", () => {
    expect(nextSerial("unixtime", 100, NOW)).toBe(NOW / 1000);
    expect(nextSerial("unixtime", NOW / 1000 + 10, NOW)).toBe(NOW / 1000 + 11);
  });
  it("increments within the day for date_counter", () => {
    expect(nextSerial("date_counter", 2026101700, NOW)).toBe(2026101701);
    expect(nextSerial("date_counter", 2026101741, NOW)).toBe(2026101742);
  });
  it("starts a new day at YYYYMMDD00", () => {
    expect(nextSerial("date_counter", 2026101741, Date.UTC(2026, 9, 18, 1))).toBe(2026101800);
    expect(nextSerial("date_counter", 7, NOW)).toBe(2026101700);
  });
});

describe("parseZoneFile", () => {
  const parse = (text: string) => parseZoneFile(text, "example.test");

  it("reads $ORIGIN, $TTL and relative names", () => {
    const { records, losses } = parse("$ORIGIN example.test.\n$TTL 600\nwww A 192.0.2.80\n@ 300 IN MX 10 mail\n");
    expect(losses).toEqual([]);
    expect(records.map((r) => [r.name, r.type, r.ttl])).toEqual([
      ["www.example.test", "A", 600],
      ["example.test", "MX", 300],
    ]);
    expect(records[1]?.data).toEqual({ type: "MX", preference: 10, exchange: "mail.example.test" });
  });
  it("applies a changed $ORIGIN to the names after it", () => {
    const { records } = parse("$ORIGIN lab.example.test.\nhost A 192.0.2.7\n");
    expect(records[0]?.name).toBe("host.lab.example.test");
  });
  it("joins parentheses over several lines and drops comments", () => {
    const text = "_sip._tcp SRV 0 5 5060 (\n    sip ) ; the SIP server\nwww A 192.0.2.80 ; comment\n";
    const { records } = parse(text);
    expect(records[0]).toMatchObject({ name: "_sip._tcp.example.test", data: { type: "SRV", port: 5060, target: "sip.example.test" } });
    expect(records[1]?.data).toEqual(a("192.0.2.80"));
  });
  it("keeps a semicolon inside a quoted string", () => {
    const { records } = parse('txt TXT "a; b"\n');
    expect(records[0]?.data).toEqual({ type: "TXT", strings: ["a; b"] });
  });
  it("repeats the previous owner for a blank owner", () => {
    const { records } = parse("www 300 A 192.0.2.80\n    A 192.0.2.81\n");
    expect(records.map((r) => r.name)).toEqual(["www.example.test", "www.example.test"]);
  });
  it("takes a trailing dot as an absolute owner", () => {
    expect(parse("mail.example.test. A 192.0.2.25\n").records[0]?.name).toBe("mail.example.test");
  });
  it("fails on $INCLUDE with 422 dns.zonefile.invalid and the line", () => {
    const f = failure(() => parse("www A 192.0.2.80\n\n$INCLUDE other.zone\n"));
    expect([f.status, f.code, f.params.line]).toEqual([422, "dns.zonefile.invalid", "3"]);
  });
  it("fails on bad data of a known type with the line", () => {
    const f = failure(() => parse("www A 192.0.2.80\nbad A 999.0.0.1\n"));
    expect([f.status, f.code, f.params.line]).toEqual([422, "dns.zonefile.invalid", "2"]);
  });
  it("turns an unknown type, the SOA and a foreign owner into losses", () => {
    const text = "@ IN SOA ns1 hostmaster 1 2 3 4 5\nhost LOC 52 22 23 N 4 53 32 E 0m\nother.test. A 192.0.2.1\nok A 192.0.2.2\n";
    const { records, losses } = parse(text);
    expect(records.map((r) => r.name)).toEqual(["ok.example.test"]);
    expect(losses.map((l) => [l.line, l.code])).toEqual([
      [1, "dns.import.soa"],
      [2, "dns.import.unsupported_type"],
      [3, "dns.import.outside"],
    ]);
  });
});

describe("importZoneFile", () => {
  const file = [
    "www 3600 A 192.0.2.80",
    "www 3600 A 192.0.2.81",
    "new 300 A 192.0.2.90",
    "mail 3600 A 192.0.2.26",
    "gw 300 A 192.0.2.1",
    "@ 300 MX 20 mx2",
    'txt 300 TXT "x"',
  ].join("\n");

  it("reports a dry run without changing anything", () => {
    const report = importZoneFile(state, ctx, EX, { zone_file: file }, false);
    expect(report).toMatchObject({ dry_run: true, revision: null, serial: null, added: 2, replaced: 2, removed: 0 });
    expect(report.types).toEqual([
      { rtype: "A", records: 5 },
      { rtype: "MX", records: 1 },
      { rtype: "TXT", records: 1 },
    ]);
    expect(report.losses.map((l) => l.code)).toEqual(["dns.import.origin"]);
    expect(find(EX, "new.example.test", "A")).toBeUndefined();
    expect(zoneOf(EX).soa_serial).toBe(2026101701);
  });
  it("writes the sets and moves the serial", () => {
    const report = importZoneFile(state, ctx, EX, { zone_file: file }, true);
    expect(report).toMatchObject({ dry_run: false, revision: rev, serial: 2026101702 });
    expect(find(EX, "new.example.test", "A")?.records).toEqual([a("192.0.2.90")]);
    expect(find(EX, "mail.example.test", "A")?.records).toEqual([a("192.0.2.26")]);
    expect(find(EX, "gw.example.test", "A")?.records).toEqual([a("192.0.2.1")]);
    expect(find(EX, "gw.example.test", "A")?.origin).toBe("ipam");
  });
  it("keeps what the file lacks without replace", () => {
    importZoneFile(state, ctx, EX, { zone_file: "new 300 A 192.0.2.90" }, true);
    expect(zoneOf(EX).rrsets).toBe(14);
  });
  it("removes manual sets the file lacks with replace, but keeps SOA, apex NS and ipam sets", () => {
    const report = importZoneFile(state, ctx, EX, { zone_file: "new 300 A 192.0.2.90", replace: true }, true);
    expect(report).toMatchObject({ added: 1, replaced: 0, removed: 7 });
    expect(sets(EX).map((s) => `${s.name} ${s.type}`)).toEqual([
      "example.test SOA",
      "example.test NS",
      "gw.example.test A",
      "gw.example.test AAAA",
      "nas.example.test A",
      "new.example.test A",
      "sw-core.example.test A",
    ]);
    expect(zoneOf(EX).soa_serial).toBe(2026101702);
  });
  it("fails on a broken file and on a missing file", () => {
    expect(failure(() => importZoneFile(state, ctx, EX, { zone_file: "$INCLUDE x" }, true)).code).toBe("dns.zonefile.invalid");
    expect(failure(() => importZoneFile(state, ctx, EX, {}, false)).code).toBe("sys.invalid_request");
  });
});

describe("exportZoneFile", () => {
  it("starts with $ORIGIN and $TTL and has one line per record", () => {
    const text = exportZoneFile(state, EX);
    const lines = text.trimEnd().split("\n");
    const records = sets(EX).reduce((n, s) => n + s.records.length, 0);
    expect(lines[0]).toBe("$ORIGIN example.test.");
    expect(lines[1]).toBe("$TTL 3600");
    expect(lines).toHaveLength(2 + records);
    expect(text.endsWith("\n")).toBe(true);
  });
  it("writes names with a trailing dot, in data too", () => {
    const lines = exportZoneFile(state, EX).split("\n");
    expect(lines).toContain("www.example.test.\t3600\tIN\tA\t192.0.2.80");
    expect(lines).toContain("example.test.\t3600\tIN\tMX\t10 mail.example.test.");
    expect(lines).toContain('example.test.\t3600\tIN\tTXT\t"v=spf1 mx -all"');
    expect(lines).toContain("ftp.example.test.\t3600\tIN\tCNAME\twww.example.test.");
  });
  it("gives the same text for an import of the export, apart from the SOA serial", () => {
    const first = exportZoneFile(state, EX);
    importZoneFile(state, ctx, EX, { zone_file: first, replace: true }, true);
    const second = exportZoneFile(state, EX);
    const withoutSoa = (text: string) => text.split("\n").filter((line) => !line.includes("\tSOA\t"));
    expect(withoutSoa(second)).toEqual(withoutSoa(first));
    expect(second).not.toBe(first);
  });
  it("fails for an unknown zone", () => {
    expect(failure(() => exportZoneFile(state, "missing")).status).toBe(404);
  });
});

describe("access lists", () => {
  const entries = [{ kind: "prefix", prefix: "192.0.2.0/24" }, { kind: "any", deny: true }];

  it("creates a list", () => {
    const acl = createAcl(state, ctx, { name: "lan-only", description: "The LAN", entries });
    expect(acl).toMatchObject({ name: "lan-only", description: "The LAN", entries, used_by: [], revision: rev });
    expect(state.acls).toContain(acl);
  });
  it("refuses a bad name, a duplicate and bad entries", () => {
    expect(failure(() => createAcl(state, ctx, { name: "bad name", entries })).code).toBe("sys.invalid_value");
    expect(failure(() => createAcl(state, ctx, { name: "internal", entries })).status).toBe(409);
    expect(failure(() => createAcl(state, ctx, { name: "x", entries: [{ kind: "prefix", prefix: "nope" }] })).code).toBe("sys.invalid_value");
  });
  it("updates a list and raises its revision", () => {
    const acl = createAcl(state, ctx, { name: "lan-only", entries });
    const before = acl.revision;
    updateAcl(state, ctx, acl.id, { description: "x", entries: [{ kind: "any" }] }, before);
    expect(acl).toMatchObject({ description: "x", entries: [{ kind: "any" }] });
    expect(acl.revision).toBeGreaterThan(before);
  });
  it("refuses a stale revision with 412", () => {
    const f = failure(() => updateAcl(state, ctx, DNS_IDS.acl.internal, { description: "x" }, 999));
    expect([f.status, f.code]).toEqual([412, "sys.store.precondition_failed"]);
  });
  it("refuses to delete a list a zone uses with dns.acl.in_use", () => {
    const f = failure(() => deleteAcl(state, ctx, DNS_IDS.acl.peers));
    expect([f.status, f.code, f.params.zones]).toEqual([409, "dns.acl.in_use", "example.test"]);
  });
  it("deletes a list nobody uses, also after the zone stops using it", () => {
    deleteAcl(state, ctx, DNS_IDS.acl.internal);
    expect(state.acls.map((acl) => acl.name)).toEqual(["transfer-peers"]);
    updateZone(state, ctx, EX, { transfer: { allow: [], notify: [], require_tsig: false, xot: false } }, null);
    deleteAcl(state, ctx, DNS_IDS.acl.peers);
    expect(state.acls).toEqual([]);
  });
  it("fails with 404 dns.acl.not_found for an unknown id", () => {
    expect(failure(() => deleteAcl(state, ctx, "missing")).code).toBe("dns.acl.not_found");
  });
});

describe("TSIG keys", () => {
  it("generates a secret when none is given", () => {
    const created = createKey(state, ctx, { name: "New.Example.Test." });
    expect(created.secret).toBe(SECRET);
    expect(created.key).toMatchObject({ name: "new.example.test", algorithm: "hmac-sha256", description: null });
    expect(state.keys.map((k) => k.name)).toEqual(["new.example.test", "xfr.example.test"]);
  });
  it("takes an imported base64 secret and an algorithm", () => {
    const created = createKey(state, ctx, { name: "imp.example.test", algorithm: "hmac-sha512", secret: " c2VjcmV0c2VjcmV0c2VjcmV0 " });
    expect(created.secret).toBe("c2VjcmV0c2VjcmV0c2VjcmV0");
    expect(created.key.algorithm).toBe("hmac-sha512");
  });
  it("refuses a duplicate name, a bad secret and a bad algorithm", () => {
    const dup = failure(() => createKey(state, ctx, { name: "xfr.example.test" }));
    expect([dup.status, dup.code]).toEqual([409, "dns.key.exists"]);
    expect(failure(() => createKey(state, ctx, { name: "k.example.test", secret: "!!" })).code).toBe("sys.invalid_value");
    expect(failure(() => createKey(state, ctx, { name: "k.example.test", algorithm: "md5" })).code).toBe("sys.invalid_value");
  });
  it("deletes a key by name and then reports it missing", () => {
    expect(deleteKey(state, ctx, "XFR.example.test.").name).toBe("xfr.example.test");
    expect(state.keys).toEqual([]);
    const f = failure(() => deleteKey(state, ctx, "xfr.example.test"));
    expect([f.status, f.code]).toEqual([404, "dns.key.not_found"]);
  });
});
