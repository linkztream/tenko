import { lazy } from "solid-js";
import type { AppRoute } from "../app/router";
import { withPacks } from "../i18n";

// The connectors area: the instances and plugins, and one instance with its recent runs (job
// words from the jobs pack).
const PACKS = ["grid", "connectors", "jobs"] as const;

export const routes: AppRoute[] = [
  { path: "/connectors", component: lazy(withPacks(PACKS, () => import("./ConnectorsView"))), title: "shell.nav.connectors" },
  { path: "/connectors/:id", component: lazy(withPacks(PACKS, () => import("./ConnectorDetail"))), title: "shell.nav.connectors" },
];
