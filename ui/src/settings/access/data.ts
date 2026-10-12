// What the access views read besides the access routes: the VRFs, sites and prefixes a scope
// rule can name, with the names a rule shows with. One live query per view, refreshed by IPAM
// events, so a renamed site or a new prefix appears in the picker without a reload.
import { createLiveQuery, type LiveQuery } from "../../api/live";
import { fetchAll } from "../../api/paginate";
import type { components } from "../../api/generated/schema";
import type { ScopeNames } from "./model";

type S = components["schemas"];

export interface ScopeCatalog {
  vrfs: S["Vrf"][];
  sites: S["Site"][];
  prefixes: S["Prefix"][];
}

/** The objects a scope rule can name. Must be called inside a component. */
export function createScopeCatalog(): LiveQuery<ScopeCatalog> {
  return createLiveQuery<ScopeCatalog>({
    topics: ["ipam"],
    fetch: async (signal) => {
      const [vrfs, sites, prefixes] = await Promise.all([
        fetchAll<S["Vrf"]>("/api/v1/vrfs", { signal }),
        fetchAll<S["Site"]>("/api/v1/sites", { signal }),
        fetchAll<S["Prefix"]>("/api/v1/prefixes", { signal }),
      ]);
      return { value: { vrfs: vrfs.items, sites: sites.items, prefixes: prefixes.items }, revision: prefixes.revision };
    },
  });
}

/** The names of a catalog: VRF and site names, the network of a prefix. */
export function catalogNames(catalog: ScopeCatalog | undefined): ScopeNames {
  const vrfs = new Map((catalog?.vrfs ?? []).map((v) => [v.id, v.name]));
  const sites = new Map((catalog?.sites ?? []).map((s) => [s.id, s.name]));
  const prefixes = new Map((catalog?.prefixes ?? []).map((p) => [p.id, p.cidr]));
  return { vrf: (id) => vrfs.get(id), site: (id) => sites.get(id), prefix: (id) => prefixes.get(id) };
}
