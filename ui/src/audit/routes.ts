import { lazy } from "solid-js";
import type { AppRoute } from "../app/router";
import { withPacks } from "../i18n";

// The audit views load the grid and audit message packs with their chunks.
const PACKS = ["grid", "audit"] as const;

export const routes: AppRoute[] = [
  { path: "/audit", component: lazy(withPacks(PACKS, () => import("./AuditPage"))), title: "shell.nav.audit" },
  { path: "/audit/:seq", component: lazy(withPacks(PACKS, () => import("./RecordPage"))), title: "shell.nav.audit" },
];
