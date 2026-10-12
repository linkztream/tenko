import { lazy } from "solid-js";
import type { AppRoute } from "../app/router";
import { withPacks } from "../i18n";

// The scans of the discovery module: the list of scans with the probes, and one scan with its
// progress and diff. Not an area of the rail: it is reached from Discovery, and `pathModule`
// (updates/modules.ts) hides it while the Discovery module is off.
const PACKS = ["scans"] as const;

export const routes: AppRoute[] = [
  { path: "/scans", component: lazy(withPacks(PACKS, () => import("./ScansPage"))), title: "scans.title" },
  { path: "/scans/:id", component: lazy(withPacks(PACKS, () => import("./ScanView"))), title: "scans.view.tab" },
];
