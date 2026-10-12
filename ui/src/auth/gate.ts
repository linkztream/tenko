// Display gating (IAM-01, WP3.11b): which inventory actions the signed-in principal sees. The
// views hide what the server would refuse with `auth.forbidden` or `auth.out_of_scope`; the
// server still decides every request.
//
// A global administrator or operator writes everything and a viewer or the auditor nothing,
// which needs no data. A scoped operator writes what its operator grants cover (scope.ts):
// for that principal alone an anchor index is read once and kept current by IPAM events: the
// sites, the VRFs, the prefix tree of every VRF (nodes and context rows) and the addresses
// with their hosts, which is what the anchors of docs/access.md section 3.2 are made of.
// Until the index is loaded a scoped principal sees no write action.
import { createMemo, createResource, createRoot, type Accessor } from "solid-js";
import { api } from "../api/client";
import { events } from "../api/events";
import { fetchAll } from "../api/paginate";
import type { components } from "../api/generated/schema";
import { session } from "./session";
import {
  admits,
  hostAnchors,
  isScoped,
  mergeAnchors,
  prefixAnchors,
  prefixChain,
  siteChain,
  writeFilter,
  type Anchors,
  type ObjectRef,
  type PrefixLink,
  type ScopeFilter,
  type SiteLink,
} from "./scope";

type S = components["schemas"];

/** What the anchors of a scoped principal's objects are computed from. */
export interface AnchorIndex {
  /** Every prefix of every VRF tree (nodes and context rows) by id. */
  prefixes: Map<string, PrefixLink & { vrf: string; site?: string | null | undefined }>;
  sites: Map<string, SiteLink>;
  /** The tenant of each VRF. */
  vrfTenants: Map<string, string>;
  /** The addresses of each host: VRF and most specific prefix. */
  hostAddresses: Map<string, { vrf: string; prefix: string }[]>;
  /** The most specific prefix of each address. */
  addressPrefix: Map<string, string>;
}

/** Reads the anchor index: what the principal may read, as the server filters it. */
export async function loadAnchorIndex(): Promise<AnchorIndex> {
  const [vrfs, sites, addresses] = await Promise.all([
    fetchAll<S["Vrf"]>("/api/v1/vrfs"),
    fetchAll<S["Site"]>("/api/v1/sites"),
    fetchAll<S["AddressRow"]>("/api/v1/addresses", { query: { expand: "host" } }),
  ]);
  const trees = await Promise.all(vrfs.items.map((vrf) => api.get("/api/v1/prefixes/tree", { query: { vrf: vrf.id } })));
  const prefixes: AnchorIndex["prefixes"] = new Map();
  trees.forEach((tree, i) => {
    const vrf = vrfs.items[i]?.id ?? "";
    for (const node of tree.context ?? []) prefixes.set(node.id, { id: node.id, parent: node.parent, vrf });
    for (const node of tree.nodes) prefixes.set(node.id, { id: node.id, parent: node.parent, vrf, site: node.site });
  });
  const hostAddresses: AnchorIndex["hostAddresses"] = new Map();
  const addressPrefix: AnchorIndex["addressPrefix"] = new Map();
  for (const address of addresses.items) {
    addressPrefix.set(address.id, address.prefix);
    const host = address.host?.id;
    if (!host) continue;
    hostAddresses.set(host, [...(hostAddresses.get(host) ?? []), { vrf: address.vrf, prefix: address.prefix }]);
  }
  return {
    prefixes,
    sites: new Map(sites.items.map((s) => [s.id, { id: s.id, parent: s.parent }])),
    vrfTenants: new Map(vrfs.items.map((v) => [v.id, v.tenant])),
    hostAddresses,
    addressPrefix,
  };
}

/** The anchors of the objects the views show, from an index. Pure, for the tests. */
export function anchorsFrom(index: AnchorIndex) {
  const siteOf = (id: string) => index.prefixes.get(id)?.site;
  const ofPrefix = (id: string | null | undefined): Anchors => {
    const chain = prefixChain(id, index.prefixes);
    const vrf = id ? index.prefixes.get(id)?.vrf : undefined;
    return prefixAnchors({ chain, vrf, tenant: vrf ? index.vrfTenants.get(vrf) : undefined, siteOf, sites: index.sites });
  };
  const ofHost = (host: { id: string; site?: string | null | undefined; tenant?: string | null | undefined }): Anchors =>
    hostAnchors({
      id: host.id,
      tenant: host.tenant,
      site: host.site,
      sites: index.sites,
      addresses: (index.hostAddresses.get(host.id) ?? []).map((a) => ({ vrf: a.vrf, chain: prefixChain(a.prefix, index.prefixes) })),
    });
  return {
    prefix: ofPrefix,
    /** An address or a range: the chain of its most specific prefix. */
    inPrefix: (prefix: string | null | undefined): Anchors => ({ ...ofPrefix(prefix), object: undefined }),
    host: ofHost,
    /** A VLAN: its site and the site's ancestors. */
    vlan: (vlan: { site?: string | null | undefined }): Anchors => ({ sites: siteChain(vlan.site, index.sites), prefixes: [] }),
    /** A site: itself and its ancestors. */
    site: (site: { id: string }): Anchors => ({ object: { kind: "site", id: site.id }, sites: siteChain(site.id, index.sites), prefixes: [] }),
    /** A job: the anchors of its targets, merged. Targets of other kinds have no anchors. */
    targets: (job: ObjectRef, targets: readonly ObjectRef[]): Anchors =>
      mergeAnchors(
        job,
        targets.map((target) => {
          switch (target.kind) {
            case "prefix":
              return ofPrefix(target.id);
            case "host":
              return ofHost({ id: target.id });
            case "address":
              return ofPrefix(index.addressPrefix.get(target.id));
            case "site":
              return { sites: siteChain(target.id, index.sites), prefixes: [] };
            default:
              return { sites: [], prefixes: [] };
          }
        }),
      ),
  };
}

interface Gate {
  filter: Accessor<ScopeFilter>;
  index: Accessor<AnchorIndex | undefined>;
}

const gate: Gate = createRoot(() => {
  const filter = createMemo(() => writeFilter(session()));
  const [index, { refetch }] = createResource(
    () => (isScoped(filter()) ? (session()?.session_id ?? false) : false),
    () => loadAnchorIndex(),
  );
  let timer: ReturnType<typeof setTimeout> | undefined;
  const reload = () => {
    if (!isScoped(filter())) return;
    clearTimeout(timer);
    timer = setTimeout(() => void refetch(), 300);
  };
  // eslint-disable-next-line solid/reactivity -- an event handler, called outside the tracked scope
  events.subscribe("ipam", reload);
  // eslint-disable-next-line solid/reactivity -- as above
  events.onReset("ipam", reload);
  return { filter, index: () => (index.error ? undefined : index.latest) };
});

/** Whether the anchor index of a scoped principal is loaded (for the tests). */
export const anchorIndexLoaded = (): boolean => gate.index() !== undefined;

/** The write filter of the session: all, nothing, or the rules of the operator grants. */
export const writes = (): ScopeFilter => gate.filter();

/** Whether the principal writes the whole inventory (a global administrator or operator). */
export const writesAll = (): boolean => gate.filter().kind === "all";

/** Whether the principal writes anything at all (globally or through an operator grant). */
export const writesAny = (): boolean => gate.filter().kind !== "nothing";

/**
 * Whether the principal may change an object, given how to find its anchors in the index. A
 * global writer may without anchors; a scoped one only once the index is loaded and every
 * anchor is covered.
 */
export function mayWrite(anchors: (a: ReturnType<typeof anchorsFrom>) => Anchors): boolean {
  const filter = gate.filter();
  if (filter.kind !== "only") return filter.kind === "all";
  const index = gate.index();
  return index !== undefined && admits(filter, anchors(anchorsFrom(index)), "all");
}

/** Shorthands for the views. */
export const may = {
  prefix: (id: string | null | undefined) => mayWrite((a) => a.prefix(id)),
  /** An address or a range by its most specific prefix; one in no prefix needs a global writer. */
  inPrefix: (prefix: string | null | undefined) => mayWrite((a) => a.inPrefix(prefix)),
  host: (host: { id: string; site?: string | null | undefined; tenant?: string | null | undefined }) => mayWrite((a) => a.host(host)),
  vlan: (vlan: { site?: string | null | undefined }) => mayWrite((a) => a.vlan(vlan)),
  site: (site: { id: string }) => mayWrite((a) => a.site(site)),
  job: (job: { id: string; targets: readonly ObjectRef[] }) => mayWrite((a) => a.targets({ kind: "job", id: job.id }, job.targets)),
  /**
   * Whether a new object of a kind could be created somewhere: always for a global writer; for a
   * scoped one when a rule could cover such an object (a prefix rule a prefix, range or address;
   * a site or VRF rule a host; a site rule a VLAN or a child site).
   */
  create: (kind: "prefix" | "range" | "address" | "host" | "vlan" | "site"): boolean => {
    const filter = gate.filter();
    if (filter.kind !== "only") return filter.kind === "all";
    return filter.rules.some((rule) => {
      switch (kind) {
        case "prefix":
        case "range":
        case "address":
          return rule.kind === "prefix" ? rule.value.subtree || kind !== "prefix" : rule.kind === "vrf";
        case "host":
          return rule.kind === "site" || rule.kind === "vrf";
        case "vlan":
          return rule.kind === "site";
        case "site":
          return rule.kind === "site" && rule.value.subtree;
      }
    });
  },
};
