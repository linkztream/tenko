// Scoped authorization on the client (IAM-01, docs/access.md, ADR 0015): what the signed-in
// principal may change, for display gating only. The server decides every request; the views
// use this to hide the actions it would refuse with `auth.out_of_scope` or `auth.forbidden`.
//
// `admits` mirrors `tenko_core::ScopeFilter::admits`: a tenant, VRF or site rule covers an
// object as a whole; a prefix rule covers one prefix chain of the object. A read needs one
// covered anchor (`any`); a create, update or delete needs the object covered as a whole, or
// every one of its prefix chains covered (`all`). The anchors of each kind follow
// docs/access.md section 3.2 and are built by the helpers below from what the views have.
//
// The write filter of a session: `all` for a global administrator or operator, the rules of
// the operator grants for a scoped operator, `nothing` for a viewer and the auditor (scoped
// viewer grants change nothing).
import type { components } from "../api/generated/schema";

type S = components["schemas"];

/** A scope rule as the API spells it: `{ kind: "prefix", value: { id, subtree } }`. */
export type ScopeRule = S["ScopeRule"];
/** One grant of the session (`SessionInfo.grants`). */
export type SessionGrant = S["SessionGrant"];
export type RoleName = S["RoleName"];

/** The set of objects a principal may see or change: `ScopeFilter` of tenko-core. */
export type ScopeFilter = { kind: "all" } | { kind: "nothing" } | { kind: "only"; rules: readonly ScopeRule[] };

export const ALL: ScopeFilter = { kind: "all" };
export const NOTHING: ScopeFilter = { kind: "nothing" };

/** Read: one anchor in scope is enough. Write (create, update, delete): all of them. */
export type AnchorMode = "any" | "all";

/** An object reference as the API spells it. */
export interface ObjectRef {
  kind: string;
  id: string;
}

/** Where an object sits among tenants, VRFs, sites and prefixes: `Anchors` of tenko-core. */
export interface Anchors {
  /** The object itself, for an object rule. */
  object?: ObjectRef | undefined;
  tenant?: string | null | undefined;
  vrf?: string | null | undefined;
  /** The object's site first, then its ancestors up to the root; empty without a site. */
  sites: readonly string[];
  /**
   * One chain per prefix the object lies in, each with the most specific prefix first and then
   * its ancestors: one for a prefix (starting with itself), an address or a range, one per
   * address prefix for a host, none for an object outside the prefix tree.
   */
  prefixes: readonly (readonly string[])[];
}

/** Anchors with nothing in them: only a rule that covers everything admits them. */
export const NO_ANCHORS: Anchors = { sites: [], prefixes: [] };

function coversWhole(rule: ScopeRule, anchors: Anchors): boolean {
  switch (rule.kind) {
    case "tenant":
      return anchors.tenant != null && anchors.tenant === rule.value;
    case "vrf":
      return anchors.vrf != null && anchors.vrf === rule.value;
    case "site":
      return rule.value.subtree ? anchors.sites.includes(rule.value.id) : anchors.sites[0] === rule.value.id;
    case "object":
      return anchors.object !== undefined && anchors.object.kind === rule.value.kind && anchors.object.id === rule.value.id;
    case "prefix":
      return false;
  }
}

function coversChain(rule: ScopeRule, chain: readonly string[]): boolean {
  if (rule.kind !== "prefix") return false;
  return rule.value.subtree ? chain.includes(rule.value.id) : chain[0] === rule.value.id;
}

/** Whether an object with these anchors is inside the filter (`ScopeFilter::admits`). */
export function admits(filter: ScopeFilter, anchors: Anchors, mode: AnchorMode): boolean {
  if (filter.kind === "all") return true;
  if (filter.kind === "nothing") return false;
  const rules = filter.rules;
  if (rules.some((rule) => coversWhole(rule, anchors))) return true;
  const covered = (chain: readonly string[]) => rules.some((rule) => coversChain(rule, chain));
  return mode === "any" ? anchors.prefixes.some(covered) : anchors.prefixes.length > 0 && anchors.prefixes.every(covered);
}

/** The roles that write the inventory: a global role or the role of a grant. */
const WRITERS: readonly RoleName[] = ["admin", "operator"];
/** The roles that read the inventory. The auditor reads the audit log and the system only. */
const READERS: readonly RoleName[] = ["admin", "operator", "viewer"];

/** What a session says about its principal: global roles and scoped grants. */
export interface Principal {
  roles: readonly RoleName[];
  grants?: readonly SessionGrant[] | undefined;
}

function filterFor(principal: Principal | null | undefined, roles: readonly RoleName[]): ScopeFilter {
  if (!principal) return NOTHING;
  if (principal.roles.some((role) => roles.includes(role))) return ALL;
  const rules = (principal.grants ?? []).filter((grant) => roles.includes(grant.role)).map((grant) => grant.scope);
  return rules.length > 0 ? { kind: "only", rules } : NOTHING;
}

/**
 * The inventory a principal may change: everything for a global administrator or operator,
 * the rules of its operator grants for a scoped operator, nothing for a viewer or the auditor.
 */
export function writeFilter(principal: Principal | null | undefined): ScopeFilter {
  return filterFor(principal, WRITERS);
}

/** The inventory a principal may read: global readers everything, a scoped one its grants. */
export function readFilter(principal: Principal | null | undefined): ScopeFilter {
  return filterFor(principal, READERS);
}

/** Whether the filter is decided without anchors: everything or nothing. */
export function isScoped(filter: ScopeFilter): filter is { kind: "only"; rules: readonly ScopeRule[] } {
  return filter.kind === "only";
}

// ---------------------------------------------------------------------------------
// Anchors from what the views hold

/** A prefix as the anchor helpers need it: the tree nodes, the context rows and the list rows have these. */
export interface PrefixLink {
  id: string;
  parent?: string | null | undefined;
}

/**
 * The chain of a prefix, itself first and then its ancestors, by the `parent` links of a tree
 * answer (nodes and context rows together). A prefix the links do not name has no chain.
 */
export function prefixChain(id: string | null | undefined, links: ReadonlyMap<string, PrefixLink>): string[] {
  const chain: string[] = [];
  let current = id ? links.get(id) : undefined;
  while (current && !chain.includes(current.id)) {
    chain.push(current.id);
    current = current.parent ? links.get(current.parent) : undefined;
  }
  return chain;
}

/** A site with its parent, as `GET /sites` lists it. */
export interface SiteLink {
  id: string;
  parent?: string | null | undefined;
}

/** The chain of a site, itself first and then its ancestors; empty without a site. */
export function siteChain(id: string | null | undefined, sites: ReadonlyMap<string, SiteLink>): string[] {
  const chain: string[] = [];
  let current: string | null | undefined = id;
  while (current && !chain.includes(current)) {
    chain.push(current);
    current = sites.get(current)?.parent;
  }
  return chain;
}

/**
 * The anchors of a prefix: its chain, its VRF and tenant, and the site of the nearest prefix of
 * the chain that names one, with that site's ancestors. `siteOf` answers the site of a prefix.
 */
export function prefixAnchors(input: {
  chain: readonly string[];
  vrf?: string | null | undefined;
  tenant?: string | null | undefined;
  siteOf?: ((prefix: string) => string | null | undefined) | undefined;
  sites?: ReadonlyMap<string, SiteLink> | undefined;
}): Anchors {
  let site: string | null | undefined;
  for (const prefix of input.chain) {
    site = input.siteOf?.(prefix);
    if (site) break;
  }
  return {
    object: input.chain[0] ? { kind: "prefix", id: input.chain[0] } : undefined,
    tenant: input.tenant,
    vrf: input.vrf,
    sites: input.sites ? siteChain(site, input.sites) : site ? [site] : [],
    prefixes: input.chain.length > 0 ? [input.chain] : [],
  };
}

/**
 * The anchors of a host: its tenant, its site with the ancestors, one chain per prefix of its
 * addresses, and its VRF when all its addresses are in one VRF.
 */
export function hostAnchors(input: {
  id: string;
  tenant?: string | null | undefined;
  site?: string | null | undefined;
  sites?: ReadonlyMap<string, SiteLink> | undefined;
  /** Each address of the host: its VRF and the chain of its most specific prefix. */
  addresses: readonly { vrf?: string | null | undefined; chain: readonly string[] }[];
}): Anchors {
  const vrfs = new Set(input.addresses.map((a) => a.vrf ?? ""));
  const vrf = vrfs.size === 1 ? [...vrfs][0] || null : null;
  return {
    object: { kind: "host", id: input.id },
    tenant: input.tenant,
    vrf,
    sites: input.sites ? siteChain(input.site, input.sites) : input.site ? [input.site] : [],
    prefixes: input.addresses.map((a) => a.chain),
  };
}

/**
 * The anchors of an object made of parts (a job and its targets), as `tenko_ipam::scope::merge`:
 * the tenant, the VRF and the sites only when every part has the same; every prefix chain of
 * the parts, and an empty chain for a part without any, so that only a rule covering the whole
 * object admits a write to it.
 */
export function mergeAnchors(object: ObjectRef, parts: readonly Anchors[]): Anchors {
  const first = parts[0];
  if (!first) return { object, sites: [], prefixes: [] };
  const same = <T>(pick: (a: Anchors) => T | null | undefined) =>
    parts.every((part) => pick(part) != null && pick(part) === pick(first)) ? pick(first) : null;
  const sites = first.sites.length > 0 && parts.every((part) => part.sites.join("/") === first.sites.join("/")) ? first.sites : [];
  const prefixes: (readonly string[])[] = [];
  const has = (chain: readonly string[]) => prefixes.some((c) => c.join("/") === chain.join("/"));
  for (const part of parts) {
    if (part.prefixes.length === 0) {
      if (!has([])) prefixes.push([]);
      continue;
    }
    for (const chain of part.prefixes) if (!has(chain)) prefixes.push(chain);
  }
  return { object, tenant: same((a) => a.tenant), vrf: same((a) => a.vrf), sites, prefixes };
}
