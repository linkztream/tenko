import { lazy } from "solid-js";
import type { AppRoute } from "../app/router";
import { withPacks } from "../i18n";
import { UPDATES_PATH } from "./paths";

// The updates page needs the words of the updates area and of the jobs it follows.
export const routes: AppRoute[] = [
  {
    path: UPDATES_PATH,
    component: lazy(withPacks(["settings", "updates", "jobs"], () => import("./UpdatesPage"))),
    access: "admin",
    title: "updates.title",
  },
];
