// The partition state of the controller this tab talks to (OPS-26, WP3.9): whether it is in
// contact with a quorum, the `Tenko-Staleness` header of its last answer, the last write it
// refused for want of a quorum, and how many queued changes wait for the person after a heal.
// First-load code: it keeps raw values only; what reads and renders them (PartitionStatus.tsx)
// loads with the cluster pack once there is something to show.
//
// Three sources set the quorum: `store.quorum` of `GET /system/status`, the `cluster.quorum`
// event of the `cluster` topic, and a write refused with 503 `cluster.no_quorum`. The newest
// observation wins; a status without `store.quorum` says nothing.
import { createMemo, createRoot, createSignal } from "solid-js";
import { setNoQuorumHandler, setStalenessHandler, type SentWrite } from "../api/client";
import { events, type ApiEvent } from "../api/events";
import type { ApiError } from "../api/problem";
import type { QuorumKind, QuorumView } from "./model";

/** A write the controller refused with `cluster.no_quorum`, for the dialog that offers to queue it. */
export interface RefusedWrite {
  error: ApiError;
  write: SentWrite;
}

/** The quorum a `cluster.quorum` event announces (params `state`, `since`, `applied`; `last_contact` is not shown). */
export function quorumOfEvent(event: Pick<ApiEvent, "data">): QuorumView | null {
  const p = (event.data.params ?? {}) as Record<string, string | undefined>;
  if (event.data.kind !== "cluster.quorum" || !p.state) return null;
  return { state: p.state as QuorumKind, since: p.since, applied: p.applied ? +p.applied : null };
}

/** Whether the controller refuses writes: isolated, or electing a leader. */
export function refusesWrites(quorum: QuorumView | null | undefined): boolean {
  return quorum?.state === "isolated" || quorum?.state === "electing";
}

function createPartition() {
  const [quorum, setQuorum] = createSignal<QuorumView | null>(null);
  const [staleness, setStaleness] = createSignal<string | null>(null);
  const [refused, setRefused] = createSignal<RefusedWrite | null>(null);
  const [conflicts, setConflicts] = createSignal(0);
  // Whether the shell shows anything of it: once true, it stays so (the banner notices the heal).
  const active = createMemo((was: boolean) => was || refusesWrites(quorum()) || conflicts() > 0 || !!staleness(), false);

  /** Hooks the client and the event stream; returns the function that unhooks them. */
  const install = () => {
    setNoQuorumHandler((error, write) => {
      setRefused({ error, write });
      setQuorum((q) => (refusesWrites(q) ? q : { state: "isolated", since: error.params.since }));
    });
    setStalenessHandler(setStaleness);
    const off = events.subscribe("cluster", (event) => {
      const next = quorumOfEvent(event);
      if (next) setQuorum(next);
    });
    return () => {
      setNoQuorumHandler(undefined);
      setStalenessHandler(undefined);
      off();
    };
  };

  return {
    quorum,
    setQuorum,
    staleness,
    setStaleness,
    refused,
    setRefused,
    conflicts,
    setConflicts,
    active,
    install,
    /** Forgets everything, for sign-out and tests. */
    reset: () => {
      setQuorum(null);
      setStaleness(null);
      setRefused(null);
      setConflicts(0);
    },
  };
}

/** The partition state of this tab. */
export const partition = createRoot(createPartition);
