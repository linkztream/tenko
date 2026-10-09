// Utilization alarms (IPAM-10): every prefix whose level is warning or critical, over all
// VRFs. The server writes level changes as `system` events (`ipam.alarms`); there is no
// alarm list endpoint in Slice 1, so the alarms are read from the prefix tree of each VRF
// and read again when such an event arrives. Used by the status bar and the dashboard.
import { api } from "../api/client";
import { createLiveQuery } from "../api/live";
import { fetchAll } from "../api/paginate";
import type { TreeNode, Vrf } from "../api/types";

export interface PrefixAlarm {
  vrf: Vrf;
  node: TreeNode;
}

/** Critical first, then by utilization. */
function byUrgency(a: PrefixAlarm, b: PrefixAlarm): number {
  const rank = (x: PrefixAlarm) => (x.node.level === "critical" ? 0 : 1);
  return rank(a) - rank(b) || b.node.utilization.percent - a.node.utilization.percent;
}

/** Whether an event may change the alarms. */
export function isAlarmEvent(e: { topic: string; data: Record<string, unknown>; objects: { kind: string }[] }): boolean {
  if (e.topic === "system") {
    const tables = Array.isArray(e.data.tables) ? (e.data.tables as unknown[]) : [];
    return e.data.kind === "ipam.prefix.alarm" || tables.includes("ipam.alarms");
  }
  return e.objects.some((o) => o.kind === "vrf");
}

/** The active alarms, kept current (call inside a component). */
export function createAlarms() {
  const live = createLiveQuery<PrefixAlarm[]>({
    topics: ["system", "ipam"],
    relevant: isAlarmEvent,
    debounceMs: 400,
    fetch: async (signal) => {
      const vrfs = await fetchAll<Vrf>("/api/v1/vrfs", { signal });
      const trees = await Promise.all(
        vrfs.items.map((vrf) =>
          api
            .get("/api/v1/prefixes/tree", { query: { vrf: vrf.id }, signal })
            .then((tree) => tree.nodes.filter((n) => n.level !== "normal").map((node) => ({ vrf, node })))
            .catch(() => [] as PrefixAlarm[]),
        ),
      );
      return { value: trees.flat().sort(byUrgency), revision: vrfs.revision as number };
    },
  });
  const list = () => (live.value.state === "ready" || live.value.state === "refreshing" ? live.value() : []);
  return {
    list,
    loading: () => live.value.loading,
    error: () => live.value.error,
    critical: () => list().filter((a) => a.node.level === "critical").length,
    refetch: live.refetch,
  };
}
