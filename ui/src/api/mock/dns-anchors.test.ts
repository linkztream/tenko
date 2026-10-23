// The trust anchors and negative trust anchors of the mock (WP10.4): the seed, adding a key as
// a DS or a DNSKEY, the root's protection under the home and the lab profile, the removal, the
// refresh, the bounds of a negative trust anchor, the expiry the Hardened profile requires and
// the sweep. Pure model code with a fixed clock.
import { beforeEach, describe, expect, it } from "vitest";
import {
  addAnchor,
  createNta,
  deleteNta,
  expireNtas,
  getAnchor,
  keyTag,
  listAnchors,
  listNtas,
  pathOfZone,
  refreshAnchor,
  removeAnchor,
  seedAnchors,
  zoneFromPath,
  type AnchorsContext,
  type AnchorsState,
} from "./dns-anchors-model";
import { RecursionFailure } from "./dns-recursion-model";

const NOW = Date.UTC(2026, 9, 17, 12);
const DAY = 86_400_000;
const ROOT_DS = "20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D";
const DNSKEY = "257 3 15 l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=";

let rev = 0;
let ids = 0;
let clock = NOW;
let state: AnchorsState;
let ctx: AnchorsContext;

beforeEach(() => {
  rev = 0;
  ids = 0;
  clock = NOW;
  ctx = {
    now: () => clock,
    nextRevision: () => ++rev,
    newId: () => `0190d1c2-0000-7000-8000-${String(++ids).padStart(12, "0")}`,
    principal: () => ({ kind: "system", component: "api" }) as ReturnType<AnchorsContext["principal"]>,
  };
  state = seedAnchors(ctx);
});

/** Runs `fn`, expects a RecursionFailure and returns it. */
function failure(fn: () => unknown): RecursionFailure {
  try {
    fn();
  } catch (error) {
    expect(error).toBeInstanceOf(RecursionFailure);
    return error as RecursionFailure;
  }
  throw new Error("expected a RecursionFailure");
}

describe("seedAnchors", () => {
  it("makes the root with two shipped keys and a pending one, then the operator anchor", () => {
    const rows = listAnchors(state);
    expect(rows.map((r) => r.zone)).toEqual([".", "corp.example.test"]);
    const root = rows[0];
    expect(root?.keys.map((k) => [k.key_tag, k.algorithm, k.digest_type, k.state])).toEqual([
      [20326, 8, 2, "valid"],
      [38696, 8, 2, "valid"],
      [47000, 8, 2, "add_pend"],
    ]);
    expect(root?.keys[0]?.source).toEqual({ kind: "shipped", release: "0.0.4" });
    expect(root?.keys[0]?.data).toEqual({ kind: "ds", rdata: ROOT_DS });
    expect(root?.keys[2]?.source).toEqual({ kind: "rfc5011" });
    expect(root?.last_query).toBeTruthy();
    expect(root?.next_query).toBeTruthy();
    const corp = rows[1];
    expect(corp?.keys).toHaveLength(1);
    expect(corp?.keys[0]).toMatchObject({ state: "valid", source: { kind: "operator" } });
    expect(state.ntas).toEqual([]);
  });

  it("reads the root as `root` in a path and a zone named root as `root.`", () => {
    expect(getAnchor(state, "root").zone).toBe(".");
    expect(getAnchor(state, "CORP.example.test.").zone).toBe("corp.example.test");
    expect(zoneFromPath("root")).toBe(".");
    expect(zoneFromPath("root.")).toBe("root");
    expect(pathOfZone(".")).toBe("root");
    expect(pathOfZone("root")).toBe("root.");
    expect(failure(() => getAnchor(state, "root.")).code).toBe("dns.trust_anchor.not_found");
    expect(failure(() => getAnchor(state, "nope.example.test"))).toMatchObject({ status: 404, params: { zone: "nope.example.test" } });
  });
});

describe("adding a key", () => {
  it("computes the key tag of a DNSKEY the way RFC 4034 appendix B does", () => {
    const row = addAnchor(state, ctx, { zone: "new.example.test", dnskey: DNSKEY }, "home");
    expect(row.keys[0]).toMatchObject({ key_tag: 3613, algorithm: 15, state: "valid", source: { kind: "operator" } });
    expect(row.keys[0]?.data).toEqual({ kind: "dnskey", rdata: DNSKEY });
    expect(row.keys[0]?.digest_type ?? null).toBeNull();
    expect(keyTag(Uint8Array.from([1, 1, 3, 8]))).toBe(((1 << 8) + 1 + (3 << 8) + 8) & 0xffff);
  });

  it("creates the anchor of a new zone with an hour to the next query and adds a key to an existing one", () => {
    const first = addAnchor(state, ctx, { zone: "Lab.Example.Test.", ds: "3613 15 2 3aa5ab37efce57f737fc1627013fee07bdf241bd10f3b1964ab55c78e79a304b" }, "home");
    expect(first).toMatchObject({ zone: "lab.example.test", revision: rev });
    expect(first.keys[0]).toMatchObject({ key_tag: 3613, digest_type: 2 });
    expect(first.keys[0]?.data).toEqual({ kind: "ds", rdata: "3613 15 2 3AA5AB37EFCE57F737FC1627013FEE07BDF241BD10F3B1964AB55C78E79A304B" });
    expect(Date.parse(first.next_query ?? "") - NOW).toBe(3_600_000);
    const second = addAnchor(state, ctx, { zone: "lab.example.test", dnskey: DNSKEY }, "home");
    expect(second.keys).toHaveLength(2);
    expect(getAnchor(state, "lab.example.test")).toBe(second);
    expect(addAnchor(state, ctx, { zone: "corp.example.test", dnskey: DNSKEY }, "home").keys).toHaveLength(2);
  });

  it("wants exactly one of ds and dnskey, and a key that parses", () => {
    const refused = (body: Record<string, unknown>) => {
      const f = failure(() => addAnchor(state, ctx, { zone: "x.example.test", ...body }, "home"));
      expect(f).toMatchObject({ status: 400, code: "dns.trust_anchor.invalid" });
      return f.params;
    };
    expect(refused({})).toHaveProperty("field");
    expect(refused({ ds: ROOT_DS, dnskey: DNSKEY })).toHaveProperty("reason");
    expect(refused({ ds: "20326 8 2 zz" })).toMatchObject({ field: "ds" });
    expect(refused({ ds: "20326 8 2" })).toMatchObject({ field: "ds" });
    expect(refused({ dnskey: "257 3 15" })).toMatchObject({ field: "dnskey" });
    expect(refused({ dnskey: "257 2 15 l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=" })).toMatchObject({ field: "dnskey" });
    expect(refused({ dnskey: "257 3 15 !!!" })).toMatchObject({ field: "dnskey" });
    expect(failure(() => addAnchor(state, ctx, { zone: "bad name", ds: ROOT_DS }, "home")).params).toMatchObject({ field: "zone" });
    expect(state.anchors).toHaveLength(2);
  });

  it("refuses the same key twice and a seventeenth key", () => {
    addAnchor(state, ctx, { zone: "x.example.test", dnskey: DNSKEY }, "home");
    expect(failure(() => addAnchor(state, ctx, { zone: "x.example.test", dnskey: DNSKEY }, "home")).code).toBe("dns.trust_anchor.invalid");
    for (let tag = 1; tag < 16; tag++) addAnchor(state, ctx, { zone: "x.example.test", ds: `${tag} 8 2 ab${tag.toString(16).padStart(2, "0")}` }, "home");
    expect(getAnchor(state, "x.example.test").keys).toHaveLength(16);
    expect(failure(() => addAnchor(state, ctx, { zone: "x.example.test", ds: "99 8 2 abcd" }, "home")).params).toMatchObject({ field: "ds" });
  });
});

describe("the root", () => {
  it("is protected under every profile but lab", () => {
    for (const profile of ["home", "standard", "hardened"] as const) {
      for (const body of [{ zone: ".", ds: ROOT_DS }, { zone: ".", ds: ROOT_DS, replace_root: true }]) {
        const f = failure(() => addAnchor(state, ctx, body, profile));
        expect(f).toMatchObject({ status: 409, code: "dns.trust_anchor.root_protected" });
      }
      expect(failure(() => removeAnchor(state, "root", profile))).toMatchObject({ status: 409, code: "dns.trust_anchor.root_protected" });
    }
    expect(getAnchor(state, "root").keys).toHaveLength(3);
  });

  it("is replaced under lab, with one key, and only with replace_root", () => {
    expect(failure(() => addAnchor(state, ctx, { zone: ".", ds: ROOT_DS }, "lab")).code).toBe("dns.trust_anchor.root_protected");
    const replaced = addAnchor(state, ctx, { zone: ".", ds: ROOT_DS, replace_root: true }, "lab");
    expect(replaced.zone).toBe(".");
    expect(replaced.keys).toHaveLength(1);
    expect(replaced.keys[0]).toMatchObject({ key_tag: 20326, digest_type: 2, source: { kind: "operator" } });
    expect(addAnchor(state, ctx, { zone: ".", dnskey: DNSKEY, replace_root: true }, "lab").keys).toHaveLength(1);
    expect(listAnchors(state)[0]?.zone).toBe(".");
  });

  it("takes replace_root for the root only", () => {
    expect(failure(() => addAnchor(state, ctx, { zone: "example.test", ds: ROOT_DS, replace_root: true }, "lab")).params).toMatchObject({ field: "replace_root" });
  });
});

describe("removing and refreshing", () => {
  it("removes the anchor of a zone, the root's under lab, and answers 404 for an unknown zone", () => {
    expect(removeAnchor(state, "corp.example.test", "home").zone).toBe("corp.example.test");
    expect(state.anchors.map((a) => a.zone)).toEqual(["."]);
    expect(failure(() => removeAnchor(state, "corp.example.test", "home"))).toMatchObject({ status: 404, code: "dns.trust_anchor.not_found" });
    expect(removeAnchor(state, "root", "lab").zone).toBe(".");
    expect(state.anchors).toEqual([]);
  });

  it("refreshes a zone: the last query is now, the next one an hour on, a command id comes back", () => {
    clock = NOW + 5 * 3_600_000;
    const command = refreshAnchor(state, ctx, "root");
    expect(command).toMatch(/^0190d1c2-/);
    const root = getAnchor(state, "root");
    expect(root.last_query).toBe(new Date(clock).toISOString());
    expect(root.next_query).toBe(new Date(clock + 3_600_000).toISOString());
    expect(root.revision).toBe(rev);
    expect(root.keys.every((k) => k.last_seen === new Date(clock).toISOString())).toBe(true);
    expect(failure(() => refreshAnchor(state, ctx, "nope.example.test")).status).toBe(404);
  });

  it("keeps a pending key pending inside the hold-down and makes it valid after it", () => {
    clock = NOW + 10 * DAY;
    refreshAnchor(state, ctx, "root");
    expect(getAnchor(state, "root").keys.find((k) => k.key_tag === 47000)?.state).toBe("add_pend");
    clock = NOW + 25 * DAY;
    refreshAnchor(state, ctx, "root");
    expect(getAnchor(state, "root").keys.find((k) => k.key_tag === 47000)).toMatchObject({ state: "valid" });
  });
});

describe("negative trust anchors", () => {
  const body = (over: Record<string, unknown> = {}) => ({ zone: "broken.example.test", reason: "Signatures expired at the registry", ...over });
  const refused = (fn: () => unknown) => {
    const f = failure(fn);
    expect(f).toMatchObject({ status: 400, code: "dns.nta.invalid" });
    return f.params;
  };

  it("creates one that lives seven days without an expiry, outside hardened", () => {
    const nta = createNta(state, ctx, body({ zone: "Broken.Example.Test." }), "standard");
    expect(nta).toMatchObject({ zone: "broken.example.test", reason: "Signatures expired at the registry", revision: rev });
    expect(nta.expires_at).toBe(new Date(NOW + 7 * DAY).toISOString());
    expect(nta.created_at).toBe(new Date(NOW).toISOString());
    expect(nta.created_by).toEqual({ kind: "system", component: "api" });
    expect(listNtas(state)).toEqual([nta]);
  });

  it("takes an expiry up to seven days ahead", () => {
    const at = new Date(NOW + 2 * DAY).toISOString();
    expect(createNta(state, ctx, body({ expires_at: at }), "home").expires_at).toBe(at);
    const edge = new Date(NOW + 7 * DAY).toISOString();
    expect(createNta(state, ctx, body({ zone: "edge.example.test", expires_at: edge }), "home").expires_at).toBe(edge);
  });

  it("refuses the root, a bad expiry, an empty or long reason and a bad zone, naming the field", () => {
    expect(refused(() => createNta(state, ctx, body({ zone: "." }), "home"))).toEqual({ field: "zone", reason: "never the root" });
    expect(refused(() => createNta(state, ctx, body({ expires_at: new Date(NOW + 7 * DAY + 1000).toISOString() }), "home"))).toMatchObject({ field: "expires_at" });
    expect(refused(() => createNta(state, ctx, body({ expires_at: new Date(NOW - 1000).toISOString() }), "home"))).toEqual({ field: "expires_at", reason: "in the past" });
    expect(refused(() => createNta(state, ctx, body({ expires_at: "tomorrow" }), "home"))).toMatchObject({ field: "expires_at" });
    expect(refused(() => createNta(state, ctx, body({ reason: "" }), "home"))).toMatchObject({ field: "reason" });
    expect(refused(() => createNta(state, ctx, body({ reason: "   " }), "home"))).toMatchObject({ field: "reason" });
    expect(refused(() => createNta(state, ctx, body({ reason: "x".repeat(501) }), "home"))).toMatchObject({ field: "reason" });
    expect(createNta(state, ctx, body({ reason: "x".repeat(500) }), "home").reason).toHaveLength(500);
    expect(refused(() => createNta(state, ctx, body({ zone: "bad name" }), "home"))).toMatchObject({ field: "zone" });
  });

  it("requires an expiry under hardened", () => {
    expect(refused(() => createNta(state, ctx, body(), "hardened"))).toEqual({ field: "expires_at", reason: "required under the Hardened profile" });
    const at = new Date(NOW + DAY).toISOString();
    expect(createNta(state, ctx, body({ expires_at: at }), "hardened").expires_at).toBe(at);
  });

  it("lists by zone and deletes by id, 404 for an unknown one", () => {
    const b = createNta(state, ctx, body({ zone: "b.example.test" }), "home");
    const a = createNta(state, ctx, body({ zone: "a.example.test" }), "home");
    expect(listNtas(state).map((n) => n.zone)).toEqual(["a.example.test", "b.example.test"]);
    expect(deleteNta(state, b.id).id).toBe(b.id);
    expect(listNtas(state)).toEqual([a]);
    expect(failure(() => deleteNta(state, b.id))).toMatchObject({ status: 404, code: "dns.nta.not_found", params: { id: b.id } });
  });

  it("sweeps the ones whose expiry has passed and returns them", () => {
    const short = createNta(state, ctx, body({ zone: "short.example.test", expires_at: new Date(NOW + DAY).toISOString() }), "home");
    const long = createNta(state, ctx, body({ zone: "long.example.test", expires_at: new Date(NOW + 5 * DAY).toISOString() }), "home");
    expect(expireNtas(state, NOW + DAY - 1)).toEqual([]);
    expect(expireNtas(state, NOW + DAY)).toEqual([short]);
    expect(listNtas(state)).toEqual([long]);
    expect(expireNtas(state, NOW + 6 * DAY)).toEqual([long]);
    expect(state.ntas).toEqual([]);
  });
});
