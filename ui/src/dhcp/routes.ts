import { lazy } from "solid-js";
import type { AppRoute } from "../app/router";
import { withPacks } from "../i18n";

// The DHCP area of the rail (Phase 3). WP7.4 builds the scopes with their pools, exclusions and
// options, the shared networks, the options, the classes, the policies and the MAC filters (the
// server settings are the settings page /settings/dhcp). The leases and the history still show the
// placeholder page, which also answers any other path under /dhcp; the packages that build them
// replace those routes. `pathModule` (updates/modules.ts) hides the area while the DHCP module is
// off. The grid's words come with the `grid` pack.
const GRID = ["grid", "dhcp"] as const;
const PACKS = ["dhcp"] as const;
const placeholder = lazy(withPacks(PACKS, () => import("./DhcpPage")));

export const routes: AppRoute[] = [
  { path: "/dhcp", component: lazy(withPacks(GRID, () => import("./ScopesPage"))), title: "dhcp.scopes.title" },
  { path: "/dhcp/scopes/:prefix/:tab?", component: lazy(withPacks(GRID, () => import("./ScopePage"))), title: "dhcp.scope.title" },
  { path: "/dhcp/shared-networks", component: lazy(withPacks(GRID, () => import("./SharedNetworksPage"))), title: "dhcp.shared_networks.title" },
  { path: "/dhcp/options", component: lazy(withPacks(GRID, () => import("./options/OptionsPage"))), title: "dhcp.options.title" },
  { path: "/dhcp/classes", component: lazy(withPacks(GRID, () => import("./classes/ClassesPage"))), title: "dhcp.classes.title" },
  { path: "/dhcp/policies", component: lazy(withPacks(GRID, () => import("./policies/PoliciesPage"))), title: "dhcp.policies.title" },
  { path: "/dhcp/filters", component: lazy(withPacks(GRID, () => import("./filters/FiltersPage"))), title: "dhcp.filters.title" },
  { path: "/dhcp/leases", component: placeholder, title: "dhcp.leases.title" },
  { path: "/dhcp/history", component: placeholder, title: "dhcp.history.title" },
  { path: "/dhcp/*rest", component: placeholder, title: "dhcp.title" },
];
