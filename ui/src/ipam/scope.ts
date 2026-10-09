// The tenant and VRF the IPAM views work in (IPAM-01). One choice per browser, remembered
// as `tenko-ipam-vrf`; a `vrf` query parameter (a deep link) wins over it. Without a choice
// the VRF `default` of the tenant `default` is used, like the API does.
import { createMemo, createRoot, createSignal } from "solid-js";
import { createLiveQuery } from "../api/live";
import { fetchAll } from "../api/paginate";
import type { Tenant, Vrf } from "../api/types";

const KEY = "tenko-ipam-vrf";

function read(): string | null {
  try {
    return localStorage.getItem(KEY);
  } catch {
    return null;
  }
}

const [chosen, setChosen] = createRoot(() => createSignal<string | null>(read()));

/** Remembers the VRF the IPAM views show. */
export function chooseVrf(id: string | null): void {
  setChosen(id);
  try {
    if (id) localStorage.setItem(KEY, id);
    else localStorage.removeItem(KEY);
  } catch {
    // Storage unavailable: the choice lasts for this page only.
  }
}

export interface ScopeData {
  tenants: Tenant[];
  vrfs: Vrf[];
}

/** The VRF `default` of the tenant `default`, else the first VRF. */
export function defaultVrf(data: ScopeData): Vrf | undefined {
  const tenant = data.tenants.find((t) => t.name === "default");
  return data.vrfs.find((v) => v.name === "default" && v.tenant === tenant?.id) ?? data.vrfs[0];
}

export interface Scope {
  data: () => ScopeData | undefined;
  error: () => unknown;
  /** The VRF in view, once tenants and VRFs are loaded. */
  vrf: () => Vrf | undefined;
  tenant: () => Tenant | undefined;
  tenantOf: (vrf: Vrf | undefined) => Tenant | undefined;
  vrfById: (id: string | null | undefined) => Vrf | undefined;
  choose: (id: string) => void;
  refetch: () => void;
}

/** Tenants and VRFs, kept current with the `ipam` topic (call inside a component). */
export function useScope(): Scope {
  const live = createLiveQuery<ScopeData>({
    topics: ["ipam"],
    relevant: (e) => [...e.objects, ...e.deleted].some((o) => o.kind === "tenant" || o.kind === "vrf"),
    fetch: async (signal) => {
      const [tenants, vrfs] = await Promise.all([
        fetchAll<Tenant>("/api/v1/tenants", { signal }),
        fetchAll<Vrf>("/api/v1/vrfs", { signal }),
      ]);
      return { value: { tenants: tenants.items, vrfs: vrfs.items }, revision: tenants.revision as number };
    },
  });
  const data = () => (live.value.state === "ready" || live.value.state === "refreshing" ? live.value() : undefined);
  const vrf = createMemo(() => {
    const d = data();
    if (!d) return undefined;
    const id = chosen();
    return d.vrfs.find((v) => v.id === id) ?? defaultVrf(d);
  });
  const tenantOf = (v: Vrf | undefined) => (v ? data()?.tenants.find((t) => t.id === v.tenant) : undefined);
  return {
    data,
    error: () => live.value.error,
    vrf,
    tenant: () => tenantOf(vrf()),
    tenantOf,
    vrfById: (id) => (id ? data()?.vrfs.find((v) => v.id === id) : undefined),
    choose: chooseVrf,
    refetch: live.refetch,
  };
}
