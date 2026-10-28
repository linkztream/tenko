// What the node chip of the top bar says about the controller cluster: this controller's role,
// how many controllers there are and how many lag behind ("Leader · 1 node", "Follower · 3
// nodes, 1 behind"). A single controller (quorum `single`, or a server from before the cluster)
// is one node and needs no read; a cluster reads `GET /cluster/members`, the source of the
// cluster page, each time the status is read and when a member changes. An account that may not
// read the members sees the role alone.
import { createEffect, createSignal, on, onCleanup, type Accessor } from "solid-js";
import { api } from "../api/client";
import { events } from "../api/events";
import type { components } from "../api/generated/schema";
import type { SystemStatus } from "../api/types";
import { isBehind } from "../cluster/health";

export type MemberView = components["schemas"]["MemberView"];
export type ClusterView = components["schemas"]["ClusterView"];

export interface ClusterSummary {
  /** Controllers in the cluster; null while unknown. */
  nodes: number | null;
  /** Controllers that lag behind the leader or are out of its contact. */
  behind: number;
  /** The members, for the cluster card; null for a single controller or while unknown. */
  view: ClusterView | null;
}

/** Whether the status describes more than one controller (or one that lost its peers). */
export function isCluster(system: SystemStatus | null): boolean {
  const state = system?.store.quorum?.state;
  return state !== undefined && state !== "single";
}

/** Summarizes the members of a cluster for the chip. */
export function summarize(view: ClusterView): ClusterSummary {
  return { nodes: view.members.length, behind: view.members.filter(isBehind).length, view };
}

export function createClusterSummary(system: Accessor<SystemStatus | null>): Accessor<ClusterSummary> {
  const [view, setView] = createSignal<ClusterView | null>(null);
  let controller: AbortController | undefined;
  const load = async () => {
    controller?.abort();
    controller = new AbortController();
    try {
      setView(await api.get("/api/v1/cluster/members", { signal: controller.signal }));
    } catch {
      setView(null);
    }
  };
  createEffect(
    on(system, (s) => {
      if (isCluster(s)) void load();
      else setView(null);
    }),
  );
  // Only a cluster listens to its members' changes.
  createEffect(
    on(
      () => isCluster(system()),
      (cluster) => {
        if (cluster) onCleanup(events.subscribe("cluster", () => void load()));
      },
    ),
  );
  onCleanup(() => controller?.abort());
  return () => {
    const s = system();
    if (!s) return { nodes: null, behind: 0, view: null };
    if (!isCluster(s)) return { nodes: 1, behind: 0, view: null };
    const v = view();
    return v ? summarize(v) : { nodes: null, behind: 0, view: null };
  };
}
