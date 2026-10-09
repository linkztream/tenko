import { lazy } from "solid-js";
import type { AppRoute } from "../app/router";
import { withPacks } from "../i18n";

export const routes: AppRoute[] = [
  {
    path: "/settings/:section?/:id?",
    component: lazy(withPacks(["settings"], () => import("./Settings"))),
    access: "admin",
    title: "settings.title",
  },
];
