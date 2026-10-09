import { lazy } from "solid-js";
import type { AppRoute } from "../app/router";
import { withPacks } from "../i18n";

export const routes: AppRoute[] = [
  { path: "/setup", component: lazy(withPacks(["setup"], () => import("./Wizard"))), layout: "focus", access: "setup", title: "setup.title" },
];
