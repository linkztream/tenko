import { lazy } from "solid-js";
import type { AppRoute } from "../app/router";
import { withPacks } from "../i18n";

// The jobs views load the grid and jobs message packs with their chunk.
const PACKS = ["grid", "jobs"] as const;

export const routes: AppRoute[] = [
  { path: "/jobs", component: lazy(withPacks(PACKS, () => import("./JobsView"))), title: "shell.nav.jobs" },
  { path: "/jobs/:id", component: lazy(withPacks(PACKS, () => import("./JobDetail"))), title: "shell.nav.jobs" },
];
