import { lazy } from "solid-js";
import type { AppRoute } from "../app/router";
import { withPacks } from "../i18n";

// The scans of the discovery module (WP3.0 placeholder, WP3.11a builds the page): a scan, or the
// list of scans, with the scan job in the URL. Not an area of the rail: it is reached from
// Discovery, and `pathModule` (updates/modules.ts) hides it while the Discovery module is off.
const PACKS = ["scans"] as const;

export const routes: AppRoute[] = [
  { path: "/scans/:id?", component: lazy(withPacks(PACKS, () => import("./ScansPage"))), title: "scans.title" },
];
