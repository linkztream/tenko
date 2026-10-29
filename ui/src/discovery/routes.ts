import { lazy } from "solid-js";
import type { AppRoute } from "../app/router";
import { withPacks } from "../i18n";

// The discovery area: the findings list (with the proposal or finding in the URL beside it), the
// proposals with their states and the observations. The approve dialog is the plan dialog of IPAM
// writes, so the area loads the IPAM pack too; the titles of waiting jobs come from the jobs pack.
const PACKS = ["grid", "discovery", "ipam"] as const;
const FINDINGS_PACKS = [...PACKS, "jobs"] as const;

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
    path: "/discovery/proposals/:id?",
    component: lazy(withPacks(PACKS, () => import("./ProposalList"))),
    title: "discovery.nav.proposals",
  },
  {
    path: "/discovery/:id?",
    component: lazy(withPacks(FINDINGS_PACKS, () => import("./FindingsView"))),
    title: "shell.nav.discovery",
  },
];
