import { lazy } from "solid-js";
import type { AppRoute } from "../app/router";

export const routes: AppRoute[] = [
  {
    path: "/settings/:section?/:id?",
    component: lazy(() => import("./Settings")),
    access: "admin",
    title: "settings.title",
  },
];
