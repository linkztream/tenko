import { lazy } from "solid-js";
import type { AppRoute } from "../app/router";
import { withPacks } from "../i18n";

// The DHCP area of the rail (Phase 3). WP7.0 claims every DHCP path with one page that says this
// part of the module comes with a later package; the packages that build the scopes, the shared
// networks, the options, the classes, the policies, the MAC filters, the leases and the history
// replace the page route by route. `pathModule` (updates/modules.ts) hides the area while the
// DHCP module is off.
const PACKS = ["dhcp"] as const;
const page = lazy(withPacks(PACKS, () => import("./DhcpPage")));

export const routes: AppRoute[] = [
  { path: "/dhcp", component: page, title: "dhcp.scopes.title" },
  { path: "/dhcp/scopes/:prefix/:tab?", component: page, title: "dhcp.scope.title" },
  { path: "/dhcp/shared-networks", component: page, title: "dhcp.shared_networks.title" },
  { path: "/dhcp/options", component: page, title: "dhcp.options.title" },
  { path: "/dhcp/classes", component: page, title: "dhcp.classes.title" },
  { path: "/dhcp/policies", component: page, title: "dhcp.policies.title" },
  { path: "/dhcp/filters", component: page, title: "dhcp.filters.title" },
  { path: "/dhcp/leases", component: page, title: "dhcp.leases.title" },
  { path: "/dhcp/history", component: page, title: "dhcp.history.title" },
  { path: "/dhcp/*rest", component: page, title: "dhcp.title" },
];
