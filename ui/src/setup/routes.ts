import { lazy } from "solid-js";
import type { AppRoute } from "../app/router";

export const routes: AppRoute[] = [
  { path: "/setup", component: lazy(() => import("./Wizard")), layout: "focus", access: "setup", title: "setup.title" },
];
