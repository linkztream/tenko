// The system panel of the start page (U3, ui-plan sections 5.1 and 6): metric blocks for what
// the node and the cluster report, each drawn only while it has a source. The host's CPU and
// memory while the node reads them; the controller's metrics (commit p99, replication lag, node
// buffers, event-stream clients) under Lab or while the cluster has more than one node, otherwise
// they live on the Cluster page; the nodes connected of the enrolled while the cluster has more
// than one node. Without a block to draw the panel is not drawn.
//
// Test ids: `dashboard-system`; `dashboard-host-cpu`, `-host-memory`, `-commit`, `-replication`,
// `-buffers`, `-clients` (each with `data-value`); `dashboard-nodes` with `dashboard-nodes-hint`
// (`data-total`, `data-mismatched`).
import { A } from "@solidjs/router";
import { createUniqueId, Show } from "solid-js";
import { api } from "../api/client";
import { createLiveQuery } from "../api/live";
import type { ClusterStatus } from "../api/nodes";
import type { SystemStatus } from "../api/types";
import { paths } from "../app/paths";
import { Metric } from "../components/Metric";
import { formatNumber, t } from "../i18n";
import type { LiveMetrics } from "./liveMetrics";
import { bufferedBatches, highestLag, memoryPercent } from "./metrics";

/** The cluster page, where the controller's metrics live while the cluster is one node. */
const CLUSTER_PATH = "/cluster";

function share(value: number): string {
  return formatNumber(value, { maximumFractionDigits: 0 });
}

/**
 * The cluster summary of the status, following the `cluster` topic (nodes enrol, connect and are
 * revoked) while the page's status is only polled; until it has read, `fallback` stands in.
 */
export function useClusterSummary(fallback: () => SystemStatus | null): () => ClusterStatus | null {
  const clusterRead = createLiveQuery<ClusterStatus | null>({
    topics: ["cluster"],
    debounceMs: 500,
    fetch: async (signal) => ({ value: (await api.get("/api/v1/system/status", { signal })).cluster ?? null }),
  });
  return () => {
    const read = clusterRead.latest();
    return read !== undefined ? read : (fallback()?.cluster ?? null);
  };
}

export function SystemPanel(props: {
  live: LiveMetrics | undefined;
  /** The cluster summary (`useClusterSummary`). */
  nodes: ClusterStatus | null;
  /** The controller's metrics (Lab, more than one node, or Show all). */
  controller: boolean;
  /** The nodes connected (more than one node, or Show all). */
  cluster: boolean;
}) {
  const id = createUniqueId();
  const sample = () => props.live?.history().latest?.cluster;
  const cpu = () => sample()?.host?.cpu_percent ?? null;
  const memory = () => {
    const host = sample()?.host;
    return host ? memoryPercent(host) : null;
  };
  const controller = () => props.controller && !!sample();
  const nodes = () => props.nodes;

  const any = () => cpu() !== null || memory() !== null || controller() || props.cluster;
  return (
    <Show when={any()}>
      <article class="dpanel dash-system" aria-labelledby={id} data-testid="dashboard-system">
        <div class="dpanel-head">
          <h2 id={id}>{t("dashboard.system.title")}</h2>
          <A class="dpanel-link" href={CLUSTER_PATH} data-testid="dashboard-system-cluster">
            {t("dashboard.system.open_cluster")}
          </A>
        </div>
        <div class="metric-row flat">
          <Show when={cpu() !== null}>
            <Metric testid="dashboard-host-cpu" label={t("dashboard.system.cpu")} value={cpu()} unit="%" context={t("dashboard.system.cpu_context")} />
          </Show>
          <Show when={memory() !== null}>
            <Metric
              testid="dashboard-host-memory"
              label={t("dashboard.system.memory")}
              value={Math.round(memory()!)}
              unit="%"
              context={t("dashboard.system.memory_context", { share: share(memory()!) })}
            />
          </Show>
          <Show when={controller()}>
            <Metric
              testid="dashboard-commit"
              label={t("dashboard.system.commit")}
              value={sample()?.store.commit_p99_ms ?? null}
              unit={t("dashboard.system.ms")}
              context={t("dashboard.system.commit_context")}
            />
            <Metric
              testid="dashboard-replication"
              label={t("dashboard.system.replication")}
              value={sample() ? highestLag(sample()!) : null}
              unit={t("dashboard.system.entries")}
              href={CLUSTER_PATH}
              context={t("dashboard.system.replication_context", { term: sample()?.raft.term ?? 0 })}
            />
            <Metric
              testid="dashboard-buffers"
              label={t("dashboard.system.buffers")}
              value={sample() ? bufferedBatches(sample()!) : null}
              unit={t("dashboard.system.batches")}
              href={paths.nodes()}
              context={t("dashboard.system.buffers_context", { count: sample()?.nodes.length ?? 0 })}
            />
            <Metric
              testid="dashboard-clients"
              label={t("dashboard.system.clients")}
              value={sample()?.sse.subscribers ?? null}
              context={t("dashboard.system.clients_context")}
            />
          </Show>
          <Show when={props.cluster}>
            <Metric
              testid="dashboard-nodes"
              label={t("dashboard.system.nodes")}
              value={nodes() ? `${nodes()!.connected}/${nodes()!.nodes}` : null}
              data={nodes()?.connected}
              unit={t("dashboard.system.connected")}
              href={paths.nodes()}
              context={
                <span data-testid="dashboard-nodes-hint" data-total={nodes()?.nodes} data-mismatched={nodes() ? nodes()!.mismatched : undefined}>
                  {nodes() ? t("dashboard.system.nodes_context", { mismatched: nodes()!.mismatched }) : t("dashboard.system.nodes_none")}
                </span>
              }
            />
          </Show>
        </div>
      </article>
    </Show>
  );
}
