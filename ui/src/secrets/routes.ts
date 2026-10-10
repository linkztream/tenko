import { lazy } from "solid-js";
import type { AppRoute } from "../app/router";
import { withPacks } from "../i18n";

// The secrets page and its dialogs have their words in the `secrets` pack (the reveal dialog
// and the errors of the vault belong to it); the host names it shows come from the API.
export const routes: AppRoute[] = [
  {
    path: "/secrets/:id?",
    component: lazy(withPacks(["secrets"], () => import("./SecretsPage"))),
    title: "secrets.title",
  },
];
