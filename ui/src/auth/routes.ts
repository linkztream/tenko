import { lazy } from "solid-js";
import type { AppRoute } from "../app/router";
import { withPacks } from "../i18n";

export const routes: AppRoute[] = [
  {
    path: "/signin",
    component: lazy(() => import("./SignIn")),
    layout: "focus",
    access: "public",
    title: "auth.signin.title",
  },
  { path: "/account/:section?", component: lazy(withPacks(["account"], () => import("./account/Account"))), title: "account.title" },
];
