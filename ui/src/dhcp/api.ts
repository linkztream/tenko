// The only module of the DHCP area that talks to the API (docs/dhcp.md, section 7): settings,
// scopes with their utilization, exclusions and effective options, shared networks, pools, the
// option catalog, definitions and option sets, classes, policies and MAC filters. A change or a
// deletion sends `If-Match` with the revision of the object read; the lists are read whole.
import { api } from "../api/client";
import { fetchAll } from "../api/paginate";
import type {
  CatalogEntry,
  ClassCreate,
  ClassPatch,
  DhcpClass,
  EffectiveOptions,
  Exclusion,
  ExclusionCreate,
  FilterCreate,
  FilterPatch,
  MacFilter,
  OptionDef,
  OptionDefCreate,
  OptionDefPatch,
  OptionSet,
  OptionValueInput,
  Policy,
  PolicyCreate,
  PolicyPatch,
  Pool,
  PoolSet,
  Prefix,
  Scope,
  ScopeCreate,
  ScopePatch,
  Settings,
  SettingsUpdate,
  SharedNetwork,
  SharedNetworkCreate,
  SharedNetworkPatch,
  Utilization,
} from "./types";

export * from "./types";

interface Listed<T> {
  items: T[];
  revision: number;
}

async function all<T>(path: Parameters<typeof fetchAll>[0], options: { path?: Record<string, string>; query?: Record<string, string | number | boolean | undefined>; signal?: AbortSignal | undefined } = {}): Promise<Listed<T>> {
  const page = await fetchAll<T>(path, options);
  return { items: page.items, revision: Number(page.revision) };
}

// ---------------------------------------------------------------------------------
// Settings

export function getSettings(signal?: AbortSignal): Promise<Settings> {
  return api.get("/api/v1/dhcp/settings", { signal });
}

export function putSettings(current: Pick<Settings, "revision">, body: SettingsUpdate): Promise<Settings> {
  return api.put("/api/v1/dhcp/settings", { body, ifMatch: current.revision });
}

// ---------------------------------------------------------------------------------
// Scopes

export function listScopes(signal?: AbortSignal): Promise<Listed<Scope>> {
  return all<Scope>("/api/v1/dhcp/scopes", { signal });
}

export function getScope(prefix: string, signal?: AbortSignal): Promise<Scope> {
  return api.get("/api/v1/dhcp/scopes/{prefix}", { path: { prefix }, signal });
}

export function createScope(body: ScopeCreate): Promise<Scope> {
  return api.post("/api/v1/dhcp/scopes", { body });
}

export function updateScope(scope: Pick<Scope, "prefix" | "revision">, patch: ScopePatch): Promise<Scope> {
  return api.patch("/api/v1/dhcp/scopes/{prefix}", { path: { prefix: scope.prefix }, body: patch, ifMatch: scope.revision });
}

export async function deleteScope(scope: Pick<Scope, "prefix" | "revision">): Promise<void> {
  await api.delete("/api/v1/dhcp/scopes/{prefix}", { path: { prefix: scope.prefix }, ifMatch: scope.revision });
}

export function getUtilization(prefix: string, signal?: AbortSignal): Promise<Utilization> {
  return api.get("/api/v1/dhcp/scopes/{prefix}/utilization", { path: { prefix }, signal });
}

/** What a client sends that the matcher tests (WP8.6): the facts of "why did this client get this value". */
export interface ClientFacts {
  mac: string;
  /** The client identifier (option 61) in hexadecimal. */
  clientId?: string | undefined;
  /** The vendor class (option 60). */
  vendorClass?: string | undefined;
  /** The user class (option 77). */
  userClass?: string | undefined;
  /** The client system architecture (option 93), 0 to 65535. */
  architecture?: number | undefined;
  /** The host name (option 12). */
  hostName?: string | undefined;
}

/** The options a client gets in a scope, with the classes it is in and the policies that match it: the answer of the matcher the engine uses. */
export function getEffectiveOptions(prefix: string, client: ClientFacts, signal?: AbortSignal): Promise<EffectiveOptions> {
  return api.get("/api/v1/dhcp/scopes/{prefix}/effective-options", {
    path: { prefix },
    query: {
      mac: client.mac,
      client_id: client.clientId || undefined,
      vendor_class: client.vendorClass || undefined,
      user_class: client.userClass || undefined,
      architecture: client.architecture,
      host_name: client.hostName || undefined,
    },
    signal,
  });
}

/** The networks of IPAM a scope can serve: prefixes of role network. */
export async function listNetworks(signal?: AbortSignal): Promise<Prefix[]> {
  return (await all<Prefix>("/api/v1/prefixes", { query: { role: "network" }, signal })).items;
}

// ---------------------------------------------------------------------------------
// Exclusions and pools

export function listExclusions(prefix: string, signal?: AbortSignal): Promise<Listed<Exclusion>> {
  return all<Exclusion>("/api/v1/dhcp/scopes/{prefix}/exclusions", { path: { prefix }, signal });
}

export function createExclusion(prefix: string, body: ExclusionCreate): Promise<Exclusion> {
  return api.post("/api/v1/dhcp/scopes/{prefix}/exclusions", { path: { prefix }, body });
}

export async function deleteExclusion(exclusion: Pick<Exclusion, "scope" | "id" | "revision">): Promise<void> {
  await api.delete("/api/v1/dhcp/scopes/{prefix}/exclusions/{id}", { path: { prefix: exclusion.scope, id: exclusion.id }, ifMatch: exclusion.revision });
}

export function listPools(prefix: string, signal?: AbortSignal): Promise<Listed<Pool>> {
  return all<Pool>("/api/v1/dhcp/pools", { query: { scope: prefix }, signal });
}

export function setPool(pool: Pick<Pool, "range" | "revision">, body: PoolSet): Promise<Pool> {
  return api.put("/api/v1/dhcp/pools/{range}", { path: { range: pool.range }, body, ifMatch: pool.revision });
}

export async function clearPool(pool: Pick<Pool, "range" | "revision">): Promise<void> {
  await api.delete("/api/v1/dhcp/pools/{range}", { path: { range: pool.range }, ifMatch: pool.revision });
}

// ---------------------------------------------------------------------------------
// Shared networks

export function listSharedNetworks(signal?: AbortSignal): Promise<Listed<SharedNetwork>> {
  return all<SharedNetwork>("/api/v1/dhcp/shared-networks", { signal });
}

export function createSharedNetwork(body: SharedNetworkCreate): Promise<SharedNetwork> {
  return api.post("/api/v1/dhcp/shared-networks", { body });
}

export function updateSharedNetwork(network: Pick<SharedNetwork, "id" | "revision">, patch: SharedNetworkPatch): Promise<SharedNetwork> {
  return api.patch("/api/v1/dhcp/shared-networks/{id}", { path: { id: network.id }, body: patch, ifMatch: network.revision });
}

export async function deleteSharedNetwork(network: Pick<SharedNetwork, "id" | "revision">): Promise<void> {
  await api.delete("/api/v1/dhcp/shared-networks/{id}", { path: { id: network.id }, ifMatch: network.revision });
}

// ---------------------------------------------------------------------------------
// Options

export function listCatalog(signal?: AbortSignal): Promise<CatalogEntry[]> {
  return api.get("/api/v1/dhcp/option-catalog", { signal });
}

export function listOptionDefs(signal?: AbortSignal): Promise<Listed<OptionDef>> {
  return all<OptionDef>("/api/v1/dhcp/option-defs", { signal });
}

export function createOptionDef(body: OptionDefCreate): Promise<OptionDef> {
  return api.post("/api/v1/dhcp/option-defs", { body });
}

export function updateOptionDef(def: Pick<OptionDef, "id" | "revision">, patch: OptionDefPatch): Promise<OptionDef> {
  return api.patch("/api/v1/dhcp/option-defs/{id}", { path: { id: def.id }, body: patch, ifMatch: def.revision });
}

export async function deleteOptionDef(def: Pick<OptionDef, "id" | "revision">): Promise<void> {
  await api.delete("/api/v1/dhcp/option-defs/{id}", { path: { id: def.id }, ifMatch: def.revision });
}

/** The option set of an owner in its path form (`server`, `scope:<prefix>`); an owner without options reads as an empty set at revision 0. */
export function getOptionSet(owner: string, signal?: AbortSignal): Promise<OptionSet> {
  return api.get("/api/v1/dhcp/option-sets/{owner}", { path: { owner }, signal });
}

/** The option sets of all policies in one read, to tell the policies that set options from those that do not. */
export async function listPolicyOptionSets(signal?: AbortSignal): Promise<OptionSet[]> {
  return (await all<OptionSet>("/api/v1/dhcp/option-sets", { query: { level: "policy" }, signal })).items;
}

/** Replaces the whole set of an owner. */
export function putOptionSet(set: Pick<OptionSet, "path" | "revision">, values: readonly OptionValueInput[]): Promise<OptionSet> {
  return api.put("/api/v1/dhcp/option-sets/{owner}", { path: { owner: set.path }, body: { values: [...values] }, ifMatch: set.revision });
}

// ---------------------------------------------------------------------------------
// Classes, policies, filters

export function listClasses(signal?: AbortSignal): Promise<Listed<DhcpClass>> {
  return all<DhcpClass>("/api/v1/dhcp/classes", { signal });
}

export function createClass(body: ClassCreate): Promise<DhcpClass> {
  return api.post("/api/v1/dhcp/classes", { body });
}

export function updateClass(item: Pick<DhcpClass, "id" | "revision">, patch: ClassPatch): Promise<DhcpClass> {
  return api.patch("/api/v1/dhcp/classes/{id}", { path: { id: item.id }, body: patch, ifMatch: item.revision });
}

export async function deleteClass(item: Pick<DhcpClass, "id" | "revision">): Promise<void> {
  await api.delete("/api/v1/dhcp/classes/{id}", { path: { id: item.id }, ifMatch: item.revision });
}

export function listPolicies(signal?: AbortSignal): Promise<Listed<Policy>> {
  return all<Policy>("/api/v1/dhcp/policies", { signal });
}

export function createPolicy(body: PolicyCreate): Promise<Policy> {
  return api.post("/api/v1/dhcp/policies", { body });
}

export function updatePolicy(item: Pick<Policy, "id" | "revision">, patch: PolicyPatch): Promise<Policy> {
  return api.patch("/api/v1/dhcp/policies/{id}", { path: { id: item.id }, body: patch, ifMatch: item.revision });
}

export async function deletePolicy(item: Pick<Policy, "id" | "revision">): Promise<void> {
  await api.delete("/api/v1/dhcp/policies/{id}", { path: { id: item.id }, ifMatch: item.revision });
}

export function listFilters(signal?: AbortSignal): Promise<Listed<MacFilter>> {
  return all<MacFilter>("/api/v1/dhcp/filters", { signal });
}

export function createFilter(body: FilterCreate): Promise<MacFilter> {
  return api.post("/api/v1/dhcp/filters", { body });
}

export function updateFilter(item: Pick<MacFilter, "id" | "revision">, patch: FilterPatch): Promise<MacFilter> {
  return api.patch("/api/v1/dhcp/filters/{id}", { path: { id: item.id }, body: patch, ifMatch: item.revision });
}

export async function deleteFilter(item: Pick<MacFilter, "id" | "revision">): Promise<void> {
  await api.delete("/api/v1/dhcp/filters/{id}", { path: { id: item.id }, ifMatch: item.revision });
}
