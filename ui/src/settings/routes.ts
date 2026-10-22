import { lazy } from "solid-js";
import type { AppRoute } from "../app/router";
import { withPacks } from "../i18n";

// The settings pages Security and Users are sections of one route, /settings/:section?/:id?.
// The other sub-pages (WP3.0 placeholders; WP3.11b builds access, audit export, vault and backup,
// WP3.7 languages) have a route of their own, like the secrets page: the static segment ranks
// above the section route. Each loads its own message pack beside `settings`, which holds the
// settings navigation they show. Administrators only.
const PAGE_ROUTES: readonly AppRoute[] = [
  {
    path: "/settings/access",
    component: lazy(withPacks(["settings", "access"], () => import("./access/AccessPage"))),
    access: "admin",
    title: "access.title",
  },
  {
    path: "/settings/audit-export",
    component: lazy(withPacks(["settings", "audit_export"], () => import("./audit-export/AuditExportPage"))),
    access: "admin",
    title: "audit_export.title",
  },
  {
    path: "/settings/vault",
    component: lazy(withPacks(["settings", "vault"], () => import("./vault/VaultPage"))),
    access: "admin",
    title: "vault.title",
  },
  {
    path: "/settings/backup",
    component: lazy(withPacks(["settings", "backup"], () => import("./backup/BackupPage"))),
    access: "admin",
    title: "backup.title",
  },
  {
    path: "/settings/reconciler",
    component: lazy(withPacks(["settings", "reconciler"], () => import("./reconciler/ReconcilerPage"))),
    access: "admin",
    title: "reconciler.title",
  },
  {
    path: "/settings/guardrails",
    component: lazy(withPacks(["settings", "guardrails"], () => import("./guardrails/GuardrailsPage"))),
    access: "admin",
    title: "guardrails.title",
  },
  {
    path: "/settings/dns",
    component: lazy(withPacks(["settings", "dns"], () => import("./dns/DnsSettingsPage"))),
    access: "admin",
    title: "dns.node.title",
  },
  // WP7.4: the DHCP server settings.
  {
    path: "/settings/dhcp",
    component: lazy(withPacks(["settings", "dhcp"], () => import("../dhcp/settings/DhcpSettingsPage"))),
    access: "admin",
    title: "dhcp.settings.title",
  },
  {
    path: "/settings/languages",
    component: lazy(withPacks(["settings", "languages"], () => import("./languages/LanguagesPage"))),
    access: "admin",
    title: "languages.title",
  },
];

export const routes: AppRoute[] = [
  ...PAGE_ROUTES,
  {
    path: "/settings/:section?/:id?",
    // The user page shows the grants and tokens of an account, with the words of the access pack.
    component: lazy(withPacks(["settings", "access"], () => import("./Settings"))),
    access: "admin",
    title: "settings.title",
  },
];
