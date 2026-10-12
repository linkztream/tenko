import { createEffect, lazy, on, onCleanup, onMount, Show } from "solid-js";
import type { SystemStatus } from "../api/types";
import { partition } from "../cluster/partition";
import { withPacks } from "../i18n";

// What the banner and the status bar show, and the dialog that offers to queue a refused write,
// come with the cluster pack when there is something to show: the shell only keeps the raw state.
export const PartitionStatus = lazy(withPacks(["cluster"], () => import("../cluster/PartitionStatus")));

/**
 * The partition banner (OPS-26): while this controller is isolated or electing a leader, or while
 * queued changes wait for the person's decision after a heal. Also hooks the client and the event
 * stream that feed the partition state, and hosts the dialog of a write refused with
 * `cluster.no_quorum`.
 */
export function ClusterBanner(props: { system: SystemStatus | null }) {
  onMount(() => onCleanup(partition.install()));
  // The state belongs to the session of this shell: a later sign-in starts afresh.
  onCleanup(partition.reset);
  createEffect(on(() => props.system?.store.quorum, (quorum) => quorum && partition.setQuorum(quorum)));

  return (
    <>
      <Show when={partition.active()}>
        <PartitionStatus />
      </Show>
      <Show when={partition.refused()}>
        {(refused) => <PartitionStatus refused={refused()} />}
      </Show>
    </>
  );
}
