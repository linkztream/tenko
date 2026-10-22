import { lazy } from "solid-js";
import type { AppRoute } from "../app/router";
import { withPacks } from "../i18n";

// Every IPAM view loads the grid and IPAM message packs with its chunk.
const PACKS = ["grid", "ipam"] as const;
const view = () => withPacks(PACKS, () => import("./IpamView"));

export const routes: AppRoute[] = [
  { path: "/ipam", component: lazy(view()), title: "shell.nav.ipam" },
  { path: "/ipam/prefixes/:network/:length", component: lazy(view()), title: "shell.nav.ipam" },
  { path: "/ipam/addresses", component: lazy(withPacks(PACKS, () => import("./address/AddressesView"))), title: "ipam.nav.addresses" },
  { path: "/ipam/addresses/:ip", component: lazy(withPacks(PACKS, () => import("./address/AddressView"))), title: "ipam.nav.addresses" },
  // The VLAN page also shows the error texts of the network controller (errors.connect.*; the
  // guardrail refusals are in the jobs pack).
  { path: "/ipam/vlans", component: lazy(withPacks([...PACKS, "connectors", "jobs"], () => import("./tenancy/VlansView"))), title: "ipam.nav.vlans" },
  { path: "/ipam/sites", component: lazy(withPacks(PACKS, () => import("./tenancy/SitesView"))), title: "ipam.nav.sites" },
  { path: "/ipam/tenants", component: lazy(withPacks(PACKS, () => import("./tenancy/TenancyView"))), title: "ipam.nav.tenancy" },
  { path: "/ipam/tags", component: lazy(withPacks(PACKS, () => import("./tenancy/TagsView"))), title: "ipam.nav.tags" },
  { path: "/ipam/custom-fields", component: lazy(withPacks(PACKS, () => import("./tenancy/CustomFieldsView"))), title: "ipam.nav.custom_fields" },
  // WP8.2: the reconciliation view.
  { path: "/ipam/reconcile", component: lazy(withPacks(PACKS, () => import("./reconcile/ReconcileView"))), title: "ipam.reconcile.title" },
  { path: "/ipam/move", component: lazy(withPacks([...PACKS, "jobs"], () => import("./move/MovePreview"))), title: "move.title" },
];
