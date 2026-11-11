// The name owners of the mock DNS service without msw: the refusals of the assignment (a zone
// without Kerberos settings, protected names, a principal of another realm, a stale revision),
// the subtree and owner filters, the release with its claimable count, the checks of the
// Kerberos settings of an update policy, and the Windows dialect of the zone file import.
import { beforeEach, describe, expect, it } from "vitest";
import {
  assignOwner,
  checkKerberos,
  DNS_IDS,
  DnsFailure,
  importZoneFile,
  listOwners,
  ownerProtected,
  releaseOwner,
  seedDns,
  updateZone,
  type DnsContext,
  type DnsState,
} from "./dns-model";

const NOW = Date.UTC(2026, 9, 17, 12);
const EX = DNS_IDS.zone.example;
const KERBEROS = { realms: ["CORP.EXAMPLE.TEST"], ownership: "windows" as const, owner_hold_days: 14 };

let rev = 0;
let state: DnsState;
let ctx: DnsContext;

beforeEach(() => {
  rev = 0;
  ctx = {
    now: () => NOW,
    nextRevision: () => ++rev,
    principal: () => ({ kind: "system", component: "api" }) as ReturnType<DnsContext["principal"]>,
    newId: () => "0190d1c2-0000-7000-8000-000000000001",
    newSecret: () => "c2VjcmV0",
  };
  state = seedDns(ctx);
});

function refusal(run: () => unknown): DnsFailure {
  try {
    run();
  } catch (err) {
    if (err instanceof DnsFailure) return err;
    throw err;
  }
  throw new Error("expected a refusal");
}

const withKerberos = () => updateZone(state, ctx, EX, { update: { kerberos: { ...KERBEROS, privileged: [] } } }, null);

describe("assigning an owner", () => {
  it("is refused while the zone has no Kerberos settings", () => {
    const err = refusal(() => assignOwner(state, ctx, EX, "pc07.example.test", { principal: "PC07$@CORP.EXAMPLE.TEST" }, null));
    expect([err.status, err.code]).toEqual([409, "dns.owner.off"]);
  });

  it("keeps no owner for the apex, locator names and wildcards", () => {
    withKerberos();
    for (const name of ["example.test", "_ldap._tcp.example.test", "_kerberos._udp.dc.example.test", "x._msdcs.example.test", "domaindnszones.example.test", "*.example.test"]) {
      expect(ownerProtected({ name: "example.test" }, name), name).toBe(true);
      const err = refusal(() => assignOwner(state, ctx, EX, name, { principal: "DC1$@CORP.EXAMPLE.TEST" }, null));
      expect([err.status, err.code], name).toEqual([409, "dns.owner.protected"]);
    }
    expect(ownerProtected({ name: "example.test" }, "pc07.example.test")).toBe(false);
  });

  it("names the field when the name, principal or SID is wrong", () => {
    withKerberos();
    const field = (name: string, body: Record<string, unknown>) => {
      const err = refusal(() => assignOwner(state, ctx, EX, name, body, null));
      expect(err.code).toBe("dns.owner.invalid");
      return err.params.field;
    };
    expect(field("pc07.other.test", { principal: "PC07$@CORP.EXAMPLE.TEST" })).toBe("name");
    expect(field("pc07.example.test", { principal: "PC07$@OTHER.EXAMPLE.TEST" })).toBe("principal");
    expect(field("pc07.example.test", { principal: "PC07" })).toBe("principal");
    expect(field("pc07.example.test", { principal: "PC07$@CORP.EXAMPLE.TEST", sid: "pc07" })).toBe("sid");
  });

  it("holds a name without records and checks the revision of a reassignment", () => {
    withKerberos();
    const first = assignOwner(state, ctx, EX, "new-pc.example.test", { principal: "NEW-PC$@corp.example.test", sid: "S-1-5-21-1-2-3-1105" }, null);
    expect(first).toMatchObject({ how: "assigned", name: "new-pc.example.test", sid: "S-1-5-21-1-2-3-1105" });
    expect(Date.parse(first.hold_until ?? "") - NOW).toBe(14 * 86_400_000);
    const stale = refusal(() => assignOwner(state, ctx, EX, "new-pc.example.test", { principal: "OTHER$@CORP.EXAMPLE.TEST" }, first.revision + 1));
    expect(stale.status).toBe(412);
    const again = assignOwner(state, ctx, EX, "new-pc.example.test", { principal: "OTHER$@CORP.EXAMPLE.TEST" }, first.revision);
    expect(again.principal).toBe("OTHER$@CORP.EXAMPLE.TEST");
    // A name with records is not held.
    const www = assignOwner(state, ctx, EX, "www.example.test", { principal: "WWW$@CORP.EXAMPLE.TEST" }, null);
    expect(www.hold_until).toBeUndefined();
    expect(listOwners(state, EX, {}).map((o) => o.name)).toEqual(["new-pc.example.test", "www.example.test"]);
  });
});

describe("listing and releasing", () => {
  it("filters by subtree and by owner and releases with the claimable count", () => {
    withKerberos();
    assignOwner(state, ctx, EX, "a.lab.example.test", { principal: "A$@CORP.EXAMPLE.TEST", sid: "S-1-5-21-1-2-3-1" }, null);
    assignOwner(state, ctx, EX, "b.example.test", { principal: "B$@CORP.EXAMPLE.TEST" }, null);
    expect(listOwners(state, EX, { name: "lab.example.test" }).map((o) => o.name)).toEqual(["a.lab.example.test"]);
    expect(listOwners(state, EX, { owner: "b$" }).map((o) => o.name)).toEqual(["b.example.test"]);
    expect(listOwners(state, EX, { owner: "S-1-5-21-1-2-3-1" }).map((o) => o.name)).toEqual(["a.lab.example.test"]);
    const answer = releaseOwner(state, ctx, EX, "b.example.test");
    expect(answer).toMatchObject({ claimable: 0, owner: { name: "b.example.test" } });
    expect(refusal(() => releaseOwner(state, ctx, EX, "b.example.test")).code).toBe("dns.owner.not_found");
  });
});

describe("the Kerberos settings of an update policy", () => {
  const bad = (k: Parameters<typeof checkKerberos>[0]) => refusal(() => checkKerberos(k)).params.field;
  it("refuses what the server refuses, naming the field", () => {
    expect(bad({ ...KERBEROS, realms: [], privileged: [] })).toBe("update.kerberos.realms");
    expect(bad({ ...KERBEROS, realms: ["A.TEST", "A.TEST"], privileged: [] })).toBe("update.kerberos.realms");
    expect(bad({ ...KERBEROS, owner_hold_days: 4000, privileged: [] })).toBe("update.kerberos.owner_hold_days");
    expect(bad({ ...KERBEROS, privileged: ["x"] })).toBe("update.kerberos.privileged");
    expect(bad({ ...KERBEROS, privileged: ["S-1-5-21-1-2-3-512"], update_proxy: "S-1-5-21-1-2-3-512" })).toBe("update.kerberos.update_proxy");
    expect(() => checkKerberos(null)).not.toThrow();
    expect(() => checkKerberos({ ...KERBEROS, privileged: ["S-1-5-21-1-2-3-512"] })).not.toThrow();
  });
});

describe("the Windows dialect of an import", () => {
  const file = ["pc07 [AGE:36] 1200 IN A 192.0.2.77", "static 3600 IN A 192.0.2.78", "@ 0 IN WINS 192.0.2.10", ""].join("\n");
  const origin = (name: string) => (state.rrsets.get(EX) ?? []).find((s) => s.name === name)?.origin;
  const windows = (zone_file: string, claimable?: Record<string, unknown>, write = false) =>
    importZoneFile(state, ctx, EX, { zone_file, dialect: "windows", ...(claimable ? { claimable } : {}) }, write);

  it("lists the aged names with a digest in a dry run and writes nothing", () => {
    const report = windows(file);
    expect(report).toMatchObject({ added: 2, claimable: 1, dry_run: true, held_back: 0 });
    expect(report.claimable_digest).toMatch(/^[0-9a-f]{64}$/);
    expect(report.claimable_names).toEqual([{ name: "pc07.example.test", rtype: "A", line: 1, claimant: "PC07$", records: ["192.0.2.77"], more: 0 }]);
    expect(report.losses.map((l) => l.code)).toEqual(["dns.zonefile.wins"]);
    expect(origin("pc07.example.test")).toBeUndefined();
  });

  it("imports the names static without the approval and holds them back as not approved", () => {
    const report = windows(file, undefined, true);
    expect(report).toMatchObject({ added: 2, claimable: 0, held_back: 1, held_back_names: [{ name: "pc07.example.test", rtype: "A", reason: "not_approved" }] });
    expect(origin("pc07.example.test")).toBe("manual");
    expect(origin("static.example.test")).toBe("manual");
  });

  it("makes the names claimable with the digest of the preview", () => {
    const digest = windows(file).claimable_digest as string;
    const report = windows(file, { approve: digest }, true);
    expect(report).toMatchObject({ added: 2, claimable: 1, held_back: 0 });
    expect(origin("pc07.example.test")).toBe("ad");
    expect(origin("static.example.test")).toBe("manual");
  });

  it("refuses an approval of another file or rule with 409 and writes nothing", () => {
    const digest = windows(file).claimable_digest as string;
    for (const [text, rule] of [
      [`${file}pc09 [AGE:3] 1200 IN A 192.0.2.79\n`, { approve: digest }],
      [file, { approve: digest, except: ["pc07.example.test"] }],
    ] as const) {
      const err = refusal(() => windows(text, rule, true));
      expect([err.status, err.code, err.params.digest]).toEqual([409, "dns.import.claimable_changed", digest]);
    }
    expect(origin("pc07.example.test")).toBeUndefined();
  });

  it("holds back the names the server never makes claimable, each with its reason", () => {
    const text = [
      "wpad [AGE:1] 1200 IN A 192.0.2.5",
      "isatap [AGE:1] 1200 IN A 192.0.2.6",
      "@ [AGE:1] 1200 IN A 192.0.2.7",
      "_ldap [AGE:1] 1200 IN A 192.0.2.8",
      "*.lab [AGE:1] 1200 IN A 192.0.2.9",
      "a.b [AGE:1] 1200 IN A 192.0.2.10",
      "srv [AGE:1] 1200 IN A 192.0.2.11",
      "srv 3600 IN TXT \"x\"",
      "mixed [AGE:1] 1200 IN A 192.0.2.12",
      "mixed 3600 IN A 192.0.2.13",
      "ns9 [AGE:1] 1200 IN A 192.0.2.14",
      "@ 3600 IN NS ns9",
      "mail [AGE:1] 1200 IN A 192.0.2.15",
      "@ 3600 IN MX 10 mail",
      "ok [AGE:1] 1200 IN A 192.0.2.16",
      "off [AGE:0] 1200 IN A 192.0.2.17",
      "",
    ].join("\n");
    const report = windows(text);
    const held = Object.fromEntries((report.held_back_names ?? []).map((h) => [h.name, h.reason]));
    expect(held).toEqual({
      "wpad.example.test": "service_name",
      "isatap.example.test": "service_name",
      "example.test": "reserved",
      "_ldap.example.test": "reserved",
      "*.lab.example.test": "reserved",
      "a.b.example.test": "not_a_host",
      "srv.example.test": "other_data",
      "mixed.example.test": "other_data",
      "ns9.example.test": "name_server",
      "mail.example.test": "service_target",
    });
    expect(report.held_back).toBe(10);
    expect(report.claimable_names?.map((n) => n.name)).toEqual(["ok.example.test"]);
  });

  it("applies the rule: names under, addresses within, names never", () => {
    const text = [
      "ws01 [AGE:1] 1200 IN A 192.0.2.21",
      "ws02 [AGE:1] 1200 IN A 198.51.100.5",
      "ws03 [AGE:1] 1200 IN A 192.0.2.22",
      "ws04 [AGE:1] 1200 IN A 192.0.2.23",
      "",
    ].join("\n");
    const names = (r: ReturnType<typeof windows>) => r.claimable_names?.map((n) => n.name.split(".")[0]);
    expect(names(windows(text, { within: ["192.0.2.0/24"] }))).toEqual(["ws01", "ws03", "ws04"]);
    expect(names(windows(text, { except: ["ws03.example.test."] }))).toEqual(["ws01", "ws02", "ws04"]);
    expect(names(windows(text, { under: ["lab.example.test"] }))).toEqual([]);
    const ruled = windows(text, { within: ["192.0.2.0/24"], except: ["ws03.example.test"] });
    expect(names(ruled)).toEqual(["ws01", "ws04"]);
    expect(ruled.held_back_names?.map((h) => [h.name.split(".")[0], h.reason])).toEqual([
      ["ws02", "rule"],
      ["ws03", "rule"],
    ]);
    // The digest follows the rule: an approval made for another rule is refused.
    expect(ruled.claimable_digest).not.toBe(windows(text).claimable_digest);
  });

  it("pages the listing with after and limit, and keeps the digest across pages", () => {
    const text = Array.from({ length: 5 }, (_, i) => `h${i} [AGE:1] 1200 IN A 192.0.2.${100 + i}`).join("\n");
    const first = windows(text, { limit: 2 });
    expect(first.claimable).toBe(5);
    expect(first.claimable_names?.map((n) => n.name)).toEqual(["h0.example.test", "h1.example.test"]);
    expect(first.claimable_next).toBe("h1.example.test/A");
    const second = windows(text, { limit: 2, after: first.claimable_next as string });
    expect(second.claimable_names?.map((n) => n.name)).toEqual(["h2.example.test", "h3.example.test"]);
    const last = windows(text, { limit: 2, after: second.claimable_next as string });
    expect(last.claimable_names?.map((n) => n.name)).toEqual(["h4.example.test"]);
    expect(last.claimable_next).toBeUndefined();
    expect([second.claimable_digest, last.claimable_digest]).toEqual([first.claimable_digest, first.claimable_digest]);
  });

  it("treats a mark of 0 as a static record", () => {
    const report = windows("off [AGE:0] 1200 IN A 192.0.2.17\n");
    expect(report.claimable).toBe(0);
    expect(report.held_back).toBe(0);
  });

  it("refuses a malformed claimable part, or one outside the Windows dialect, naming the field", () => {
    const field = (claimable: Record<string, unknown>) => {
      const err = refusal(() => windows(file, claimable));
      expect([err.status, err.code]).toEqual([400, "dns.import.claimable_invalid"]);
      return err.params.field;
    };
    expect(field({ within: ["not-a-prefix"] })).toBe("claimable.within");
    expect(field({ under: ["bad name"] })).toBe("claimable.under");
    expect(field({ limit: 0 })).toBe("claimable.limit");
    expect(field({ limit: 5001 })).toBe("claimable.limit");
    expect(field({ approve: "abc" })).toBe("claimable.approve");
    expect(field({ after: "nothing/A" })).toBe("claimable.after");
    const plain = refusal(() => importZoneFile(state, ctx, EX, { zone_file: file, claimable: { except: [] } }, false));
    expect([plain.status, plain.code, plain.params.field]).toEqual([400, "dns.import.claimable_invalid", "claimable"]);
  });

  it("reads the same file as plain RFC 1035 and refuses an unknown dialect", () => {
    const plain = importZoneFile(state, ctx, EX, { zone_file: file }, false);
    expect(plain.claimable).toBe(0);
    expect(plain).not.toHaveProperty("claimable_digest");
    expect(plain.losses.map((l) => l.code)).not.toContain("dns.zonefile.wins");
    expect(refusal(() => importZoneFile(state, ctx, EX, { zone_file: file, dialect: "bind" }, false)).code).toBe("sys.invalid_request");
  });
});
