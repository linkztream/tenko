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
  it("imports aged records as origin ad and loses WINS records", () => {
    const report = importZoneFile(state, ctx, EX, { zone_file: file, dialect: "windows" }, true);
    expect(report).toMatchObject({ added: 2, claimable: 1 });
    expect(report.losses.map((l) => l.code)).toEqual(["dns.zonefile.wins"]);
    const sets = state.rrsets.get(EX) ?? [];
    expect(sets.find((s) => s.name === "pc07.example.test")?.origin).toBe("ad");
    expect(sets.find((s) => s.name === "static.example.test")?.origin).toBe("manual");
  });

  it("reads the same file as plain RFC 1035 and refuses an unknown dialect", () => {
    const plain = importZoneFile(state, ctx, EX, { zone_file: file }, false);
    expect(plain.claimable).toBe(0);
    expect(plain.losses.map((l) => l.code)).not.toContain("dns.zonefile.wins");
    expect(refusal(() => importZoneFile(state, ctx, EX, { zone_file: file, dialect: "bind" }, false)).code).toBe("sys.invalid_request");
  });
});
