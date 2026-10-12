import { lazy } from "solid-js";
import type { AppRoute } from "../app/router";
import { withPacks } from "../i18n";

// The cluster area (WP3.11a): a platform area of the rail, so no product module switches it
// off, and any signed-in account may open it. The page also brings the strings of the
// enrolment dialog (the nodes pack); the queue view needs only its own.
const PAGE_PACKS = ["cluster", "nodes"] as const;
const QUEUE_PACKS = ["cluster"] as const;

export const routes: AppRoute[] = [
  { path: "/cluster", component: lazy(withPacks(PAGE_PACKS, () => import("./ClusterPage"))), title: "cluster.title" },
  { path: "/cluster/queue", component: lazy(withPacks(QUEUE_PACKS, () => import("./QueueView"))), title: "cluster.queue.title" },
];
