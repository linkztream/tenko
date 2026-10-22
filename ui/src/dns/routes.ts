import { lazy } from "solid-js";
import type { AppRoute } from "../app/router";
import { withPacks } from "../i18n";

// The DNS area of the rail (Phase 2, WP4.5, WP5.5 and WP6.4): the zone list, a zone with its
// records, settings and history, the zone file import, the views, the forwarding rules, the block
// lists, the access lists, the TSIG keys (administrators, the scope `dns.keys`), the query log and the
// blocking view (the figures of the log and the lists, the pause, allow from the log).
// Any other path under /dns shows a page that leads back to the zones. `pathModule` (updates/modules.ts) hides the area while the
// DNS module is off. The grid's words come with the `grid` pack, a job's with `jobs`.
const GRID = ["grid", "dns"] as const;

export const routes: AppRoute[] = [
  { path: "/dns", component: lazy(withPacks(GRID, () => import("./ZonesPage"))), title: "dns.zones.title" },
  { path: "/dns/zones/:id/:tab?", component: lazy(withPacks(GRID, () => import("./ZonePage"))), title: "dns.zones.title" },
  { path: "/dns/import/:id", component: lazy(withPacks(["dns", "jobs"], () => import("./ImportWizard"))), title: "dns.import.title" },
  { path: "/dns/acls", component: lazy(withPacks(GRID, () => import("./AclsPage"))), title: "dns.acls.title" },
  { path: "/dns/keys", component: lazy(withPacks(GRID, () => import("./KeysPage"))), access: "admin", title: "dns.keys.title" },
  // WP6.4
  { path: "/dns/views", component: lazy(withPacks(GRID, () => import("./views/ViewsPage"))), title: "dns.view.title" },
  { path: "/dns/forwarders", component: lazy(withPacks(GRID, () => import("./forwarders/ForwardersPage"))), title: "dns.fwd.title" },
  { path: "/dns/lists", component: lazy(withPacks(["grid", "dns", "jobs"], () => import("./lists/ListsPage"))), title: "dns.lists.title" },
  { path: "/dns/blocking", component: lazy(withPacks(["dns", "jobs"], () => import("./blocking/BlockingPage"))), title: "dns.blocking.title" },
  { path: "/dns/log", component: lazy(withPacks(["dns"], () => import("./log/LogPage"))), title: "dns.log.title" },
  // WP10.0: the placeholder of the recursion section.
  { path: "/dns/recursion", component: lazy(withPacks(["dns"], () => import("./recursion/RecursionPage"))), title: "dns.recursion.title" },
  { path: "/dns/*rest", component: lazy(withPacks(["dns"], () => import("./DnsPage"))), title: "dns.title" },
];
