import { lazy } from "solid-js";
import type { AppRoute } from "../app/router";
import { withPacks } from "../i18n";

// The host views live under /ipam (the IPAM area of the rail); they show jobs too.
const PACKS = ["grid", "ipam", "jobs"] as const;

export const routes: AppRoute[] = [
  { path: "/ipam/hosts", component: lazy(withPacks(PACKS, () => import("./HostsView"))), title: "ipam.nav.hosts" },
  { path: "/ipam/hosts/:fqdn", component: lazy(withPacks(PACKS, () => import("./HostView"))), title: "ipam.nav.hosts" },
  { path: "/ipam/macs/:mac", component: lazy(withPacks(PACKS, () => import("./MacRedirect"))), title: "ipam.nav.hosts" },
];
