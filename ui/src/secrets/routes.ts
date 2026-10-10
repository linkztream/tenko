import { lazy } from "solid-js";
import type { AppRoute } from "../app/router";
import { withPacks } from "../i18n";
import { LEGACY_SECRETS_PATH, SECRETS_PATH } from "./paths";
import SecretsRedirect from "./SecretsRedirect";

// The secrets page is a sub-page of Settings: /settings/secrets, with one secret open at
// /settings/secrets/:id. Its route is its own, not a section of the Settings route, because
// operators see the secrets too while Settings is for administrators; the static segment
// ranks it above /settings/:section?/:id?. The page has its words in the `secrets` pack (the
// reveal dialog and the errors of the vault belong to it) and the settings navigation it
// shows to administrators in the `settings` pack; the host names it shows come from the API.
//
// The address before the move, /secrets and everything under it, redirects.
export const routes: AppRoute[] = [
  {
    path: `${SECRETS_PATH}/:id?`,
    component: lazy(withPacks(["secrets", "settings"], () => import("./SecretsPage"))),
    title: "secrets.title",
  },
  { path: `${LEGACY_SECRETS_PATH}/*rest`, component: SecretsRedirect },
];
