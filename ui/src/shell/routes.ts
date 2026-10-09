import { lazy } from "solid-js";
import type { AppRoute } from "../app/router";

export const routes: AppRoute[] = [
  { path: "/", component: lazy(() => import("./pages/Dashboard")), title: "shell.nav.dashboard" },
  { path: "/search", component: lazy(() => import("./pages/Search")), title: "shell.search.title" },
];
