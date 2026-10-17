import { lazy } from "solid-js";
import type { AppRoute } from "../app/router";
import { withPacks } from "../i18n";

// The DNS area of the rail (Phase 2). WP4.0 claims every DNS path with one page that says the
// module is coming; WP4.5 replaces it with the zone list, the zone page and the records, and
// adds the routes of views, forwarders, lists and keys in later slices. `pathModule`
// (updates/modules.ts) hides the area while the DNS module is off.
const PACKS = ["dns"] as const;

export const routes: AppRoute[] = [
  { path: "/dns/*rest", component: lazy(withPacks(PACKS, () => import("./DnsPage"))), title: "dns.title" },
];
