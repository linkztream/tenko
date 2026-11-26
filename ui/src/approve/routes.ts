import { lazy } from "solid-js";
import type { AppRoute } from "../app/router";
import { withPacks } from "../i18n";

// The page where an administrator approves a takeover script (ADR 0038). In the shell, so a
// signed-out visitor signs in and comes back here; administrators only.
export const routes: AppRoute[] = [
  { path: "/approve", component: lazy(withPacks(["approve"], () => import("./ApprovePage"))), access: "admin", title: "approve.title" },
];
