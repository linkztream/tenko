// The utilization of every VRF from its prefix tree, for the start page's health row and its
// fullest prefixes (IPAM-10): the networks of each tree, the busiest first, and the in-use totals
// and network counts per address family over the top-level prefixes, so nothing counts twice.
// Follows the `ipam` topic (prefixes, addresses, ranges) and the alarms of the `system` topic.
import { api } from "../api/client";
import { createLiveQuery } from "../api/live";
import { fetchAll } from "../api/paginate";
import type { Tenant, TreeNode, TreeResponse, Vrf } from "../api/types";
import { isAlarmEvent } from "../ipam/alarms";
import { moduleRunning } from "../updates/modules";
import { familyUse, type FamilyUse } from "./model";

export interface VrfUse {
  vrf: Vrf;
  tenant: Tenant | undefined;
  /** The networks of the tree, the fullest first. */
  networks: TreeNode[];
  families: { v4: FamilyUse; v6: FamilyUse };
}

export function useUtilization() {
  return createLiveQuery<VrfUse[]>({
    topics: ["ipam", "system"],
    relevant: (e) => isAlarmEvent(e) || e.objects.some((o) => o.kind === "prefix" || o.kind === "address" || o.kind === "range"),
    debounceMs: 500,
    fetch: async (signal) => {
      // Without the IPAM module there are no networks to count.
      if (!moduleRunning("ipam")) return { value: [] as VrfUse[] };
      const [tenants, vrfs] = await Promise.all([fetchAll<Tenant>("/api/v1/tenants", { signal }), fetchAll<Vrf>("/api/v1/vrfs", { signal })]);
      const trees: TreeResponse[] = await Promise.all(vrfs.items.map((vrf) => api.get("/api/v1/prefixes/tree", { query: { vrf: vrf.id }, signal })));
      const value = vrfs.items.map((vrf, i) => {
        const nodes = trees[i]?.nodes ?? [];
        return {
          vrf,
          tenant: tenants.items.find((tn) => tn.id === vrf.tenant),
          networks: nodes.filter((n) => n.role === "network").sort((a, b) => b.utilization.percent - a.utilization.percent),
          families: familyUse(nodes),
        };
      });
      return { value, revision: vrfs.revision as number };
    },
  });
}
