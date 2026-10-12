import { describe, expect, it } from "vitest";
import {
  admits,
  ALL,
  hostAnchors,
  mergeAnchors,
  NO_ANCHORS,
  NOTHING,
  prefixAnchors,
  prefixChain,
  readFilter,
  siteChain,
  writeFilter,
  type Anchors,
  type ScopeFilter,
  type ScopeRule,
  type SessionGrant,
} from "./scope";

// Ids in the shape of the API's; the tree is 192.0.2.0/24 (P24) > 192.0.2.0/25 (P25) > 192.0.2.0/26 (P26),
// and 198.51.100.0/24 (Q24) beside it; sites HQ > LAB.
const P24 = "0190d1c2-0000-7000-8000-000000000031";
const P25 = "0190d1c2-0000-7000-8000-000000000032";
const P26 = "0190d1c2-0000-7000-8000-000000000033";
const Q24 = "0190d1c2-0000-7000-8000-000000000034";
const VRF = "0190d1c2-0000-7000-8000-000000000011";
const OTHER_VRF = "0190d1c2-0000-7000-8000-000000000012";
const TENANT = "0190d1c2-0000-7000-8000-000000000001";
const HQ = "0190d1c2-0000-7000-8000-000000000021";
const LAB = "0190d1c2-0000-7000-8000-000000000022";
const HOST = "0190d1c2-0000-7000-8000-000000000041";

const LINKS = new Map([
  [P24, { id: P24, parent: null }],
  [P25, { id: P25, parent: P24 }],
  [P26, { id: P26, parent: P25 }],
  [Q24, { id: Q24, parent: null }],
]);
const SITES = new Map([
  [HQ, { id: HQ, parent: null }],
  [LAB, { id: LAB, parent: HQ }],
]);

const prefix = (id: string, subtree: boolean): ScopeRule => ({ kind: "prefix", value: { id, subtree } });
const site = (id: string, subtree: boolean): ScopeRule => ({ kind: "site", value: { id, subtree } });
const only = (...rules: ScopeRule[]): ScopeFilter => ({ kind: "only", rules });
const of = (id: string): Anchors => prefixAnchors({ chain: prefixChain(id, LINKS), vrf: VRF, tenant: TENANT });

describe("chains", () => {
  it("walks the parent links of prefixes and sites, itself first", () => {
    expect(prefixChain(P26, LINKS)).toEqual([P26, P25, P24]);
    expect(prefixChain(Q24, LINKS)).toEqual([Q24]);
    expect(prefixChain("unknown", LINKS)).toEqual([]);
    expect(prefixChain(null, LINKS)).toEqual([]);
    expect(siteChain(LAB, SITES)).toEqual([LAB, HQ]);
    expect(siteChain(undefined, SITES)).toEqual([]);
  });

  it("stops at a loop instead of running forever", () => {
    const looped = new Map([
      ["a", { id: "a", parent: "b" }],
      ["b", { id: "b", parent: "a" }],
    ]);
    expect(prefixChain("a", looped)).toEqual(["a", "b"]);
  });

  it("takes the site of the nearest prefix that names one, with its ancestors", () => {
    const anchors = prefixAnchors({
      chain: [P26, P25, P24],
      vrf: VRF,
      siteOf: (id) => (id === P25 ? LAB : id === P24 ? HQ : null),
      sites: SITES,
    });
    expect(anchors.sites).toEqual([LAB, HQ]);
    expect(anchors.object).toEqual({ kind: "prefix", id: P26 });
  });
});

describe("admits, as ScopeFilter::admits", () => {
  it("admits everything with All and nothing with Nothing", () => {
    expect(admits(ALL, NO_ANCHORS, "all")).toBe(true);
    expect(admits(NOTHING, of(P24), "any")).toBe(false);
  });

  it("covers a prefix and its subtree, or only the prefix itself", () => {
    const subtree = only(prefix(P25, true));
    expect(admits(subtree, of(P25), "all")).toBe(true);
    expect(admits(subtree, of(P26), "all")).toBe(true);
    expect(admits(subtree, of(P24), "all")).toBe(false);
    expect(admits(subtree, of(Q24), "any")).toBe(false);
    const own = only(prefix(P25, false));
    expect(admits(own, of(P25), "all")).toBe(true);
    expect(admits(own, of(P26), "all")).toBe(false);
  });

  it("covers objects of a VRF, a tenant or a site as a whole", () => {
    expect(admits(only({ kind: "vrf", value: VRF }), of(P26), "all")).toBe(true);
    expect(admits(only({ kind: "vrf", value: OTHER_VRF }), of(P26), "all")).toBe(false);
    expect(admits(only({ kind: "tenant", value: TENANT }), of(P26), "all")).toBe(true);
    const inLab: Anchors = { sites: [LAB, HQ], prefixes: [] };
    expect(admits(only(site(HQ, true)), inLab, "all")).toBe(true);
    expect(admits(only(site(HQ, false)), inLab, "all")).toBe(false);
    expect(admits(only(site(LAB, false)), inLab, "all")).toBe(true);
  });

  it("reads a host with one chain in scope but writes it only with every chain covered", () => {
    const host = hostAnchors({
      id: HOST,
      addresses: [
        { vrf: VRF, chain: [P26, P25, P24] },
        { vrf: VRF, chain: [Q24] },
      ],
    });
    const rule = only(prefix(P25, true));
    expect(admits(rule, host, "any")).toBe(true);
    expect(admits(rule, host, "all")).toBe(false);
    expect(admits(only(prefix(P25, true), prefix(Q24, false)), host, "all")).toBe(true);
    // Both addresses are in one VRF: a VRF rule covers the host whole.
    expect(host.vrf).toBe(VRF);
    expect(admits(only({ kind: "vrf", value: VRF }), host, "all")).toBe(true);
  });

  it("never admits a write to an object without prefix chains through a prefix rule", () => {
    const bare = hostAnchors({ id: HOST, site: LAB, sites: SITES, addresses: [] });
    expect(admits(only(prefix(P24, true)), bare, "all")).toBe(false);
    expect(admits(only(prefix(P24, true)), bare, "any")).toBe(false);
    expect(admits(only(site(HQ, true)), bare, "all")).toBe(true);
  });

  it("takes no VRF for a host whose addresses are in two VRFs", () => {
    const host = hostAnchors({
      id: HOST,
      addresses: [
        { vrf: VRF, chain: [P24] },
        { vrf: OTHER_VRF, chain: [Q24] },
      ],
    });
    expect(host.vrf).toBeNull();
    expect(admits(only({ kind: "vrf", value: VRF }), host, "all")).toBe(false);
  });
});

describe("merged anchors of a job", () => {
  const job = { kind: "job", id: "0190d1c2-0000-7000-8000-000000000051" };

  it("keeps every chain and the common VRF", () => {
    const merged = mergeAnchors(job, [of(P26), of(Q24)]);
    expect(merged.prefixes).toEqual([[P26, P25, P24], [Q24]]);
    expect(merged.vrf).toBe(VRF);
    expect(admits(only(prefix(P24, true)), merged, "all")).toBe(false);
    expect(admits(only(prefix(P24, true), prefix(Q24, false)), merged, "all")).toBe(true);
  });

  it("adds an empty chain for a part outside the tree, so a prefix rule cannot write it", () => {
    const merged = mergeAnchors(job, [of(P26), { sites: [], prefixes: [] }]);
    expect(merged.prefixes).toContainEqual([]);
    expect(merged.vrf).toBeNull();
    expect(admits(only(prefix(P24, true)), merged, "all")).toBe(false);
    expect(admits(only(prefix(P24, true)), merged, "any")).toBe(true);
  });

  it("has no anchors but the job without targets", () => {
    expect(mergeAnchors(job, [])).toEqual({ object: job, sites: [], prefixes: [] });
  });
});

describe("the filters of a session", () => {
  const grant = (role: SessionGrant["role"], scope: ScopeRule): SessionGrant => ({
    id: `0190d1c2-0000-7000-8000-0000000000${role.length}${scope.kind.length}`,
    role,
    scope,
    delegable: false,
  });

  it("lets global administrators and operators write everything", () => {
    expect(writeFilter({ roles: ["admin"] })).toEqual(ALL);
    expect(writeFilter({ roles: ["operator"], grants: [grant("operator", prefix(P25, true))] })).toEqual(ALL);
  });

  it("lets a scoped operator write the rules of its operator grants only", () => {
    const filter = writeFilter({
      roles: [],
      grants: [grant("operator", prefix(P25, true)), grant("viewer", prefix(Q24, false))],
    });
    expect(filter).toEqual(only(prefix(P25, true)));
    expect(readFilter({ roles: [], grants: [grant("operator", prefix(P25, true)), grant("viewer", prefix(Q24, false))] })).toEqual(
      only(prefix(P25, true), prefix(Q24, false)),
    );
  });

  it("lets viewers, the auditor and nobody write nothing", () => {
    expect(writeFilter({ roles: ["viewer"] })).toEqual(NOTHING);
    expect(writeFilter({ roles: ["auditor"] })).toEqual(NOTHING);
    expect(writeFilter({ roles: [], grants: [grant("viewer", prefix(P25, true))] })).toEqual(NOTHING);
    expect(writeFilter(null)).toEqual(NOTHING);
    expect(readFilter({ roles: ["auditor"] })).toEqual(NOTHING);
    expect(readFilter({ roles: ["viewer"] })).toEqual(ALL);
  });
});
