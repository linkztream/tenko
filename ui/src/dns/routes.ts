import { lazy } from "solid-js";
import type { AppRoute } from "../app/router";
import { withPacks } from "../i18n";

// The DNS area of the rail (Phase 2, WP4.5): the zone list, a zone with its records, settings
// and history, the zone file import, the access lists and the TSIG keys (administrators, the
// scope `dns.keys`). Views, forwarders and block lists come in later slices; until then their
// paths show a page that says so. `pathModule` (updates/modules.ts) hides the area while the
// DNS module is off. The grid's words come with the `grid` pack, a job's with `jobs`.
const GRID = ["grid", "dns"] as const;

export const routes: AppRoute[] = [
  { path: "/dns", component: lazy(withPacks(GRID, () => import("./ZonesPage"))), title: "dns.zones.title" },
  { path: "/dns/zones/:id/:tab?", component: lazy(withPacks(GRID, () => import("./ZonePage"))), title: "dns.zones.title" },
  { path: "/dns/import/:id", component: lazy(withPacks(["dns", "jobs"], () => import("./ImportWizard"))), title: "dns.import.title" },
  { path: "/dns/acls", component: lazy(withPacks(GRID, () => import("./AclsPage"))), title: "dns.acls.title" },
  { path: "/dns/keys", component: lazy(withPacks(GRID, () => import("./KeysPage"))), access: "admin", title: "dns.keys.title" },
  { path: "/dns/*rest", component: lazy(withPacks(["dns"], () => import("./DnsPage"))), title: "dns.title" },
];
