import { lazy } from "solid-js";
import type { AppRoute } from "../app/router";
import { withPacks } from "../i18n";

export const routes: AppRoute[] = [
  {
    path: "/ipam/import",
    component: lazy(withPacks(["grid", "ipam", "import"], () => import("./Wizard"))),
    title: "import.title",
  },
];
