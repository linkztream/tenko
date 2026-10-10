import { lazy } from "solid-js";
import type { AppRoute } from "../app/router";
import { withPacks } from "../i18n";

// The topology map (WP2.7). The selected device is the path parameter, the filters (site,
// vlan, kind, q) live in the query string, so a filtered map is a link that can be shared. The
// connectors pack carries the error texts of the network controllers (errors.connect.*).
export const routes: AppRoute[] = [
  {
    path: "/topology/:id?",
    component: lazy(withPacks(["topology", "connectors"], () => import("./TopologyView"))),
    title: "shell.nav.topology",
  },
];
