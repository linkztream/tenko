// The short cluster card behind the node chip of the top bar: this controller's role and store
// revision, whether it reaches a quorum, and each controller with how it is doing, from the data
// the chip already read (the status and, for a cluster, GET /cluster/members). No read of its own.
import { A } from "@solidjs/router";
import { For, Show } from "solid-js";
import type { SystemStatus } from "../api/types";
import { Popover } from "../components/Popover";
import { CLUSTER_PATH, healthWord, memberHealth, memberName, quorumWord, sortMembers } from "../cluster/model";
import { formatNumber, t } from "../i18n";
import type { ClusterSummary } from "./cluster";
import { storeRoleLabel } from "./TopBar";

export default function ClusterCard(props: {
  id: string;
  anchor: HTMLElement;
  system: SystemStatus | null;
  summary: ClusterSummary;
  onClose: () => void;
}) {
  const quorum = () => props.system?.store.quorum?.state ?? "single";
  return (
    <Popover anchor={props.anchor} id={props.id} label={t("cluster.card.title")} onClose={props.onClose} align="end" testid="cluster-card" class="top-card">
      <h2 class="popover-title">{t("cluster.card.title")}</h2>
      <Show when={props.system} fallback={<p class="muted">{t("shell.top.node_unreachable")}</p>}>
        {(s) => (
          <dl class="card-facts">
            <dt>{t("cluster.card.this_node")}</dt>
            <dd data-testid="cluster-card-role">{storeRoleLabel(s().store.role)}</dd>
            <dt>{t("cluster.card.quorum")}</dt>
            <dd data-testid="cluster-card-quorum">{quorumWord(quorum())}</dd>
            <dt>{t("cluster.card.revision")}</dt>
            <dd class="num">{formatNumber(s().store.revision)}</dd>
          </dl>
        )}
      </Show>
      <Show when={props.summary.view}>
        {(view) => (
          <ul class="card-members" aria-label={t("cluster.card.members")} data-testid="cluster-card-members">
            <For each={sortMembers(view().members)}>
              {(member) => (
                <li data-testid="cluster-card-member" data-state={memberHealth(member)}>
                  <span class="grow">{memberName(member)}</span>
                  <span class="muted">{healthWord(memberHealth(member))}</span>
                </li>
              )}
            </For>
          </ul>
        )}
      </Show>
      <A class="btn sm" href={CLUSTER_PATH} onClick={() => props.onClose()} data-testid="cluster-card-open">
        {t("cluster.card.open")}
      </A>
    </Popover>
  );
}
