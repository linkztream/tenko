import { lazy } from "solid-js";
import type { AppRoute } from "../app/router";
import { withPacks } from "../i18n";
import { UPDATES_PATH } from "./paths";

// The updates page needs the words of the updates area, of the jobs it follows and of the backup it offers before an install.
export const routes: AppRoute[] = [
  {
    path: UPDATES_PATH,
    component: lazy(withPacks(["settings", "updates", "jobs", "backup"], () => import("./UpdatesPage"))),
    access: "admin",
    title: "updates.title",
  },
];
