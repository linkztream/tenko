import { describe, expect, it } from "vitest";
import { anchorsFrom, type AnchorIndex } from "./gate";
import { admits, type ScopeFilter } from "./scope";

// 203.0.113.0/24 (DOC) > 203.0.113.0/25 (LAB) in VRF V of tenant T; 198.51.100.0/24 (IOT) beside
// them; sites HOME > GARAGE; host H1 has addresses in LAB and IOT, H2 only in LAB.
const index: AnchorIndex = {
  prefixes: new Map([
    ["DOC", { id: "DOC", parent: null, vrf: "V", site: "HOME" }],
    ["LAB", { id: "LAB", parent: "DOC", vrf: "V", site: null }],
    ["IOT", { id: "IOT", parent: null, vrf: "V", site: "GARAGE" }],
  ]),
  sites: new Map([
    ["HOME", { id: "HOME", parent: null }],
    ["GARAGE", { id: "GARAGE", parent: "HOME" }],
  ]),
  vrfTenants: new Map([["V", "T"]]),
  hostAddresses: new Map([
    ["H1", [{ vrf: "V", prefix: "LAB" }, { vrf: "V", prefix: "IOT" }]],
    ["H2", [{ vrf: "V", prefix: "LAB" }]],
  ]),
  addressPrefix: new Map([["A1", "LAB"]]),
};
const a = anchorsFrom(index);
const doc: ScopeFilter = { kind: "only", rules: [{ kind: "prefix", value: { id: "DOC", subtree: true } }] };
const garage: ScopeFilter = { kind: "only", rules: [{ kind: "site", value: { id: "GARAGE", subtree: false } }] };

describe("the anchors of the views' objects", () => {
  it("builds a prefix's chain, VRF, tenant and the site of the nearest prefix with one", () => {
    expect(a.prefix("LAB")).toEqual({
      object: { kind: "prefix", id: "LAB" },
      tenant: "T",
      vrf: "V",
      sites: ["HOME"],
      prefixes: [["LAB", "DOC"]],
    });
    expect(admits(doc, a.prefix("LAB"), "all")).toBe(true);
    expect(admits(doc, a.prefix("IOT"), "all")).toBe(false);
  });

  it("anchors an address or range in its prefix, and a host in all of its prefixes", () => {
    expect(admits(doc, a.inPrefix("LAB"), "all")).toBe(true);
    expect(admits(doc, a.inPrefix(null), "all")).toBe(false);
    expect(admits(doc, a.host({ id: "H2" }), "all")).toBe(true);
    expect(admits(doc, a.host({ id: "H1" }), "all")).toBe(false);
    expect(admits(doc, a.host({ id: "H1" }), "any")).toBe(true);
  });

  it("anchors VLANs and sites in the site tree", () => {
    expect(admits(garage, a.vlan({ site: "GARAGE" }), "all")).toBe(true);
    expect(admits(garage, a.vlan({ site: "HOME" }), "all")).toBe(false);
    expect(admits(garage, a.site({ id: "GARAGE" }), "all")).toBe(true);
  });

  it("merges the targets of a job; a target outside the tree needs a whole rule", () => {
    const job = { kind: "job", id: "J" };
    expect(admits(doc, a.targets(job, [{ kind: "address", id: "A1" }, { kind: "prefix", id: "LAB" }]), "all")).toBe(true);
    expect(admits(doc, a.targets(job, [{ kind: "host", id: "H1" }]), "all")).toBe(false);
    expect(admits(doc, a.targets(job, [{ kind: "connector", id: "C" }]), "all")).toBe(false);
  });
});
