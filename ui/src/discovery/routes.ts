import { lazy } from "solid-js";
import type { AppRoute } from "../app/router";
import { withPacks } from "../i18n";

// The discovery area: the proposal inbox (with the proposal in the URL beside it) and the
// observations. The approve dialog is the plan dialog of IPAM writes, so the area loads the
// IPAM pack too.
const PACKS = ["grid", "discovery", "ipam"] as const;

export const routes: AppRoute[] = [
  {
    path: "/discovery/observations",
    component: lazy(withPacks(PACKS, () => import("./ObservationsView"))),
    title: "discovery.nav.observations",
  },
  {
    path: "/discovery/observations/:subject",
    component: lazy(withPacks(PACKS, () => import("./SubjectView"))),
    title: "discovery.nav.observations",
  },
  {
    path: "/discovery/:id?",
    component: lazy(withPacks(PACKS, () => import("./ProposalsView"))),
    title: "shell.nav.discovery",
  },
];
