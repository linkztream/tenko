import { lazy } from "solid-js";
import type { AppRoute } from "../app/router";
import { withPacks } from "../i18n";

// The migration views (Windows takeover plan section 3.3), stubbed by WP14.0: a mirror's page
// with its three tabs under the connectors area (WP14.1 fills the Losses and Settings tabs and
// the diff of the Scopes tab, WP14.2 the scope actions), and the two zone actions under the DNS
// area (WP14.2). The static segments `flip` and `release` outrank the zone page's `:tab?`.
const PACKS = ["migrate"] as const;

export const routes: AppRoute[] = [
  { path: "/connectors/mirrors/:id/:tab?", component: lazy(withPacks(PACKS, () => import("./MirrorPage"))), title: "migrate.mirror.title" },
  { path: "/dns/zones/:id/flip", component: lazy(withPacks(PACKS, () => import("./ZoneFlipPage"))), title: "migrate.flip.title" },
  { path: "/dns/zones/:id/release", component: lazy(withPacks(PACKS, () => import("./ZoneReleasePage"))), title: "migrate.release.title" },
];
