import { lazy } from "solid-js";
import type { AppRoute } from "../app/router";

export const routes: AppRoute[] = [
  {
    path: "/signin",
    component: lazy(() => import("./SignIn")),
    layout: "focus",
    access: "public",
    title: "auth.signin.title",
  },
  { path: "/account/:section?", component: lazy(() => import("./account/Account")), title: "account.title" },
];
