import { lazy } from "solid-js";
import type { AppRoute } from "../app/router";
import { withPacks } from "../i18n";

// The nodes area: the enrolled nodes (with the node in the URL beside the list) and the
// enrolment tokens. A rail area of its own: nodes are read by every role, tokens by
// administrators.
const PACKS = ["grid", "nodes"] as const;
// The scan configuration of a probe, with its kill switch, hangs off the node (WP3.11a): its own
// page so that the long form does not crowd the panel.
const SCAN_PACKS = ["nodes", "scans"] as const;

export const routes: AppRoute[] = [
  { path: "/nodes/:id/scan", component: lazy(withPacks(SCAN_PACKS, () => import("./ScanConfigPage"))), title: "nodes.scan.title" },
  { path: "/nodes/:id?", component: lazy(withPacks(PACKS, () => import("./NodesView"))), title: "shell.nav.nodes" },
];
