// The tiles of the start page for discovery, connectors and nodes (WP2.9): the open proposals
// with a link to the inbox (and how many of them are conflicts), the health of the connector
// instances, and the connected nodes from the system status. Each tile follows its topic.
import { A } from "@solidjs/router";
import { createMemo, Show } from "solid-js";
import { api } from "../api/client";
import { createLiveQuery } from "../api/live";
import type { ClusterStatus } from "../api/nodes";
import type { SystemStatus } from "../api/types";
import { paths } from "../app/paths";
import { Si } from "../components/Si";
import { listConnectors, type ConnectorView } from "../connectors/api";
import { connectorHealth } from "../connectors/model";
import { listProposals, type Proposal } from "../discovery/api";
import { isProposalEvent } from "../discovery/model";
import { t } from "../i18n";
import { moduleRunning } from "../updates/modules";

export function OperationsTiles(props: { status: SystemStatus | null | undefined }) {
  const proposals = createLiveQuery<Proposal[]>({
    topics: ["ipam"],
    relevant: isProposalEvent,
    debounceMs: 500,
    fetch: async (signal) => ({ value: moduleRunning("discovery") ? await listProposals({ state: ["open"] }, signal) : [] }),
  });
  const connectors = createLiveQuery<ConnectorView[]>({
    topics: ["connectors"],
    debounceMs: 500,
    fetch: async (signal) => {
      try {
        return { value: await listConnectors(signal) };
      } catch {
        return { value: [] };
      }
    },
  });

  // The cluster summary follows the `cluster` topic (nodes enrol, connect and are revoked); the
  // status of the page is only polled. Until this has read, the status of the page stands in.
  const clusterRead = createLiveQuery<ClusterStatus | null>({
    topics: ["cluster"],
    debounceMs: 500,
    fetch: async (signal) => ({ value: (await api.get("/api/v1/system/status", { signal })).cluster ?? null }),
  });

  // Reading a failed query throws its error at the reader (and breaks the page), so a failed
  // read reads as not read: the tile shows no number.
  const proposalsRead = () => (proposals.value.error ? undefined : proposals.value.latest);
  const open = () => proposalsRead() ?? [];
  const conflicts = () => open().filter((p) => p.kind === "conflict").length;
  const health = createMemo(() => {
    const list = (connectors.value.latest ?? []).filter((c) => c.enabled);
    return { total: list.length, healthy: list.filter((c) => connectorHealth(c) === "healthy").length };
  });
  const cluster = (): ClusterStatus | null => {
    const read = clusterRead.value.error ? undefined : clusterRead.value.latest;
    return read !== undefined ? read : (props.status?.cluster ?? null);
  };
  const mismatched = () => cluster()?.mismatched ?? 0;

  return (
    <>
      <Show when={moduleRunning("discovery")}>
        <section class="card tile" data-testid="dashboard-proposals">
          <h2>{t("dashboard.tile.proposals")}</h2>
          <div class="tile-value">
            <A href={paths.discovery()} data-testid="dashboard-proposals-link" aria-label={proposalsRead() ? undefined : t("dashboard.tile.proposals_link")}>
              <Si value={proposalsRead() ? open().length : null} />
            </A>
          </div>
          <p class="muted">{t("dashboard.tile.proposals_hint", { conflicts: conflicts() })}</p>
        </section>
      </Show>
      <section class="card tile" data-testid="dashboard-connectors">
        <h2>{t("dashboard.tile.connectors")}</h2>
        <div class="tile-value">
          <A href={paths.connectors()} data-testid="dashboard-connectors-link" aria-label={connectors.value.latest ? undefined : t("dashboard.tile.connectors_link")}>
            <Si value={connectors.value.latest ? health().healthy : null} />
          </A>
        </div>
        <p class="muted">{t("dashboard.tile.connectors_hint", { total: health().total, failing: health().total - health().healthy })}</p>
      </section>
      <section class="card tile" data-testid="dashboard-nodes">
        <h2>{t("dashboard.tile.nodes")}</h2>
        <div class="tile-value">
          <A href={paths.nodes()} data-testid="dashboard-nodes-link" aria-label={cluster() ? undefined : t("dashboard.tile.nodes_link")}>
            <Si value={cluster() ? cluster()!.connected : null} />
          </A>
        </div>
        <p class="muted">
          {cluster() ? t("dashboard.tile.nodes_hint", { total: cluster()!.nodes, mismatched: mismatched() }) : t("dashboard.tile.nodes_none")}
        </p>
      </section>
    </>
  );
}
