// The name authority of the mock (docs/reconciliation.md): which kind of source decides the
// name of a host when the sources disagree. The state is in memory: the global order, the
// orders of sites and the hosts that prefer a source. The routes are for administrators; the
// approval of a proposal with a choice of name (routes-reconcile.ts) uses `chooseName` and
// `rememberChoice` from here.
import type { components } from "../generated/schema";
import { principalNow } from "./audit-store";
import { requireAdmin } from "./auth";
import { commit, db, onMockReset } from "./db";
import { HOST_IDS, ipamState } from "./ipam/api";
import { notFound } from "./ipam/problems";
import { noContent, ok, Problem } from "./reply";
import { route } from "./route";
import { MOCK_USER_IDS } from "./fixtures";
import { DAY_MS, iso } from "./util";

type S = components["schemas"];
export type NameSource = S["NameSource"];
export type StoredAuthority = S["StoredAuthority"];
export type HostPreference = S["HostPreference"];
export type NameChoice = S["NameChoice"];
export type ApproveRequest = S["ApproveRequest"];

/** Every kind of source, in the order of the server's list. */
export const NAME_SOURCES: readonly NameSource[] = ["proxmox", "home_assistant", "windows", "dns", "mdns", "llmnr", "unifi", "scan", "dhcp", "other"];

/** The order in force while no rule is stored; DHCP and other connectors rank after it. */
export const DEFAULT_NAME_ORDER: readonly NameSource[] = ["proxmox", "home_assistant", "windows", "dns", "mdns", "llmnr", "unifi", "scan"];

export interface NameAuthorityState {
  global: StoredAuthority | null;
  /** The rules of sites, by site id. */
  sites: Map<string, StoredAuthority>;
  /** The hosts that prefer a source, by host id. */
  preferences: Map<string, HostPreference>;
}

let state: NameAuthorityState | null = null;

onMockReset(() => {
  state = null;
});

/** The state, built on first use after a reset: no rule, and one host that prefers a source. */
export function nameAuthorityState(): NameAuthorityState {
  if (!state) {
    const preferences = new Map<string, HostPreference>();
    const empty = db.scenario === "setup" || db.scenario === "setup-slow-disk";
    const nas = HOST_IDS["nas"];
    if (!empty && nas) {
      preferences.set(nas, {
        host: nas,
        host_name: "nas",
        source: "proxmox",
        name: "nas",
        decided: { at: iso(Date.now() - 2 * DAY_MS), by: { kind: "user", id: MOCK_USER_IDS.alex, session: "0190d1c2-0000-7000-8000-0000000e0001", strength: "passkey" } as S["Principal"] },
      });
    }
    state = { global: null, sites: new Map(), preferences };
  }
  return state;
}

function stamp(): S["Stamp"] {
  return { at: new Date().toISOString(), by: principalNow() };
}

/** The order of a body, checked as the server does: one to ten kinds, each once. */
function readOrder(body: Record<string, unknown>): NameSource[] {
  const order = body["order"];
  const valid =
    Array.isArray(order) &&
    order.length >= 1 &&
    order.length <= NAME_SOURCES.length &&
    order.every((s) => typeof s === "string" && (NAME_SOURCES as readonly string[]).includes(s)) &&
    new Set(order).size === order.length;
  if (!valid) {
    throw new Problem("ipam.name_authority.invalid", {
      status: 422,
      detail: "the order lists one to ten kinds of source, each once",
      params: { field: "order" },
    });
  }
  return order as NameSource[];
}

function changed(): void {
  commit("system", { tables: ["ipam.name_authority"] });
}

const view = route("get", "/api/v1/settings/reconciler/name-authority", () => {
  requireAdmin();
  const s = nameAuthorityState();
  const sites = ipamState().data.site;
  return ok({
    default_order: [...DEFAULT_NAME_ORDER],
    sources: [...NAME_SOURCES],
    global: s.global,
    sites: [...s.sites.entries()].map(([id, rule]) => ({ ...rule, site_name: sites.get(id)?.name ?? id })).sort((a, b) => a.site_name.localeCompare(b.site_name)),
    preferences: [...s.preferences.values()].sort((a, b) => a.host_name.localeCompare(b.host_name)),
  });
});

const setGlobal = route("put", "/api/v1/settings/reconciler/name-authority", async (ctx) => {
  requireAdmin();
  const order = readOrder(await ctx.body());
  const s = nameAuthorityState();
  s.global = { site: null, order, updated: stamp(), revision: db.revision + 1 };
  changed();
  return ok(s.global);
});

const clearGlobal = route("delete", "/api/v1/settings/reconciler/name-authority", () => {
  requireAdmin();
  nameAuthorityState().global = null;
  changed();
  return noContent();
});

function liveSite(id: string): void {
  const site = ipamState().data.site.get(id);
  if (!site || site.meta.deleted) throw notFound("site", id);
}

const setSite = route("put", "/api/v1/settings/reconciler/name-authority/sites/{site}", async (ctx) => {
  requireAdmin();
  liveSite(ctx.params.site);
  const order = readOrder(await ctx.body());
  const rule: StoredAuthority = { site: ctx.params.site, order, updated: stamp(), revision: db.revision + 1 };
  nameAuthorityState().sites.set(ctx.params.site, rule);
  changed();
  return ok(rule);
});

const clearSite = route("delete", "/api/v1/settings/reconciler/name-authority/sites/{site}", (ctx) => {
  requireAdmin();
  liveSite(ctx.params.site);
  nameAuthorityState().sites.delete(ctx.params.site);
  changed();
  return noContent();
});

const clearPreference = route("delete", "/api/v1/settings/reconciler/name-authority/hosts/{host}", (ctx) => {
  requireAdmin();
  nameAuthorityState().preferences.delete(ctx.params.host);
  changed();
  return noContent();
});

export const nameAuthorityRoutes = [view, setGlobal, clearGlobal, setSite, clearSite, clearPreference];

// ---------------------------------------------------------------------------------
// The approval of a proposal that offers names

/**
 * The name an approval takes: the one in `request.choice` (compared without case), else the
 * proposed one (the first). A name the proposal does not offer is `ipam.proposal.choice_invalid`.
 */
export function chooseName(choices: readonly NameChoice[], request: ApproveRequest): NameChoice | null {
  const wanted = request.choice;
  if (wanted === undefined || wanted === null) return null;
  const found = choices.find((c) => c.name.toLowerCase() === wanted.toLowerCase());
  if (!found) {
    throw new Problem("ipam.proposal.choice_invalid", {
      status: 422,
      detail: `${wanted} is not one of the names the proposal offers`,
      params: { choice: wanted },
    });
  }
  return found;
}

/** Refuses what only an administrator may ask to remember: a source for every host changes the name authority. */
export function checkRemember(request: ApproveRequest, isAdminRole: boolean): void {
  if (request.remember === "source" && !isAdminRole) {
    throw new Problem("auth.forbidden", { status: 403, detail: "preferring a source for every host needs the admin role" });
  }
}

/** Remembers a choice as the approval asked to: for the host, or the source for every host. */
export function rememberChoice(request: ApproveRequest, chosen: NameChoice | null, host: { id: string; name: string } | null): void {
  const remember = request.remember;
  if (!remember || !chosen) return;
  const source = chosen.sources[0]?.source;
  if (!source) return;
  const s = nameAuthorityState();
  if (remember === "host" && host) {
    s.preferences.set(host.id, { host: host.id, host_name: chosen.name, source, name: chosen.name, decided: stamp() });
    changed();
  } else if (remember === "source") {
    const current = s.global?.order ?? DEFAULT_NAME_ORDER;
    s.global = { site: null, order: [source, ...current.filter((x) => x !== source)], updated: stamp(), revision: db.revision + 1 };
    changed();
  }
}
