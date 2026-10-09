import { lazy } from "solid-js";
import type { AppRoute } from "../app/router";
import { withPacks } from "../i18n";

// The start page (decision 13); it shows IPAM alarms and jobs, so it loads their packs too.
export const routes: AppRoute[] = [
  {
    path: "/",
    component: lazy(withPacks(["dashboard", "grid", "ipam", "jobs"], () => import("./Dashboard"))),
    title: "shell.nav.dashboard",
  },
];
