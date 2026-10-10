import { lazy } from "solid-js";
import type { AppRoute } from "../app/router";
import { withPacks } from "../i18n";

// The cluster area (WP3.0 placeholder, WP3.11a builds the page): a platform area of the rail,
// so no product module switches it off, and any signed-in account may open it.
const PACKS = ["cluster"] as const;

export const routes: AppRoute[] = [
  { path: "/cluster", component: lazy(withPacks(PACKS, () => import("./ClusterPage"))), title: "cluster.title" },
];
