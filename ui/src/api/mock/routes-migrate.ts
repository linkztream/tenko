// The mirrored sources of the mock API (ADR 0033, WP14.1), after
// crates/tenko-api/src/routes/migrate.rs and crates/tenko-migrate/src/mirror. Every signed-in
// account reads; creating, changing, deleting, the token and the acknowledgment need `admin`.
//
// What the mock simplifies: there is no exporter and no push. A mirror starts without a
// snapshot (no scopes, no losses, never pushed); a test seeds the freshness, the scopes, the
// losses and the diff of a mirror with `seedMirror`. The token is a fixed text per mirror.
// Nothing is audited and no event is published: the cards read the list on a timer. A pair is
// set and taken apart on both mirrors, with the server's refusals.
import type { HttpHandler } from "msw";
import type { components } from "../generated/schema";
import { requireAdmin, requireSession } from "./auth";
import { db, onMockReset } from "./db";
import { created, noContent, ok, Problem } from "./reply";
import { route } from "./route";

type S = components["schemas"];
type MirrorItem = S["MirrorItem"];

/** What a test seeds beside a mirror: its loss report and the diffs of its scopes, by network. */
export interface MirrorSeed {
  item: MirrorItem;
  losses?: S["MirrorLossItem"][];
  diffs?: Record<string, S["ScopeDiff"]>;
}

const mirrors = new Map<string, MirrorSeed>();
onMockReset(() => mirrors.clear());

/** Adds or replaces a mirror of the mock. */
export function seedMirror(seed: MirrorSeed): void {
  mirrors.set(seed.item.id, seed);
}

const STAMP = () => ({ at: new Date().toISOString(), by: { kind: "system", component: "api" } }) as unknown as S["Stamp"];

function found(id: string): MirrorSeed {
  const seed = mirrors.get(id);
  if (!seed) throw new Problem("migrate.mirror.not_found", { status: 404, params: { id } });
  return seed;
}

function withSnapshot(id: string): MirrorSeed {
  const seed = found(id);
  if (seed.item.last_sequence === undefined || seed.item.last_sequence === null) {
    throw new Problem("migrate.mirror.no_snapshot", { status: 404, params: { id } });
  }
  return seed;
}

function minted(item: MirrorItem): S["MirrorCreated"] {
  // A token bound to source prefixes has the constrained form, as on the server.
  const form = (item.source_prefixes ?? []).length > 0 ? "tnkc_" : "tnk_";
  return { mirror: item, token: `${form}mock-mirror-${item.id.slice(-4)}`, ca_fingerprint: "ab".repeat(32) };
}

/** The source prefixes of a request body, as the server stores them (a host address as /32). */
function sourcesOf(body: Record<string, unknown>): string[] {
  const list = Array.isArray(body.source_prefixes) ? body.source_prefixes.filter((p): p is string => typeof p === "string") : [];
  return list.map((prefix) => (prefix.includes("/") ? prefix : `${prefix}/32`));
}

const list = route("get", "/api/v1/migrate/mirrors", () => {
  requireSession();
  const items = [...mirrors.values()].map((seed) => seed.item).sort((a, b) => a.name.localeCompare(b.name));
  return ok({ items, next_cursor: null, revision: db.revision });
});

const create = route("post", "/api/v1/migrate/mirrors", async (ctx) => {
  requireAdmin();
  const body = await ctx.body();
  const name = typeof body.name === "string" ? body.name : "";
  if (!name.trim() || name.trim() !== name || name.length > 64) {
    throw new Problem("migrate.mirror.invalid_settings", { status: 400, params: { field: "name", reason: "1 to 64 characters, no space at either end" } });
  }
  const id = crypto.randomUUID();
  const item: MirrorItem = {
    id,
    name,
    kind: "windows-dhcp",
    enabled: true,
    token: crypto.randomUUID(),
    account: crypto.randomUUID(),
    interval_secs: typeof body.interval_secs === "number" ? body.interval_secs : 60,
    created: STAMP(),
    updated: STAMP(),
    stale: false,
    losses_open: 0,
    changes_left: 30,
    change_reserve: 30,
    scopes: [],
    source_prefixes: sourcesOf(body),
    ca_fingerprint: "ab".repeat(32),
  };
  mirrors.set(id, { item });
  return created(minted(item));
});

const one = route("get", "/api/v1/migrate/mirrors/{id}", (ctx) => {
  requireSession();
  return ok(found(ctx.params.id).item);
});

/** Pairs two mirrors on both rows, or takes a pair apart, with the server's refusals. */
function pair(seed: MirrorSeed, partner: string | null): void {
  const refuse = (reason: string) => new Problem("migrate.mirror.partner", { status: 409, params: { id: seed.item.id, partner: partner ?? "", reason } });
  const other = partner === null ? (seed.item.partner ?? null) : partner;
  if (partner === seed.item.id) throw refuse("a mirror cannot be its own partner");
  if (partner !== null && seed.item.partner && seed.item.partner !== partner) throw refuse("the mirror is paired with another mirror");
  const theirs = other === null ? undefined : mirrors.get(other);
  if (partner !== null && !theirs) throw refuse("no mirror of that id exists");
  if (partner !== null && theirs?.item.partner && theirs.item.partner !== seed.item.id) throw refuse("the partner is paired with another mirror");
  if (theirs) theirs.item = { ...theirs.item, partner: partner === null ? null : seed.item.id };
  seed.item = { ...seed.item, partner };
}

const patch = route("patch", "/api/v1/migrate/mirrors/{id}", async (ctx) => {
  requireAdmin();
  const seed = found(ctx.params.id);
  const body = await ctx.optionalBody();
  if ("partner" in body) pair(seed, typeof body.partner === "string" ? body.partner : null);
  seed.item = {
    ...seed.item,
    name: typeof body.name === "string" ? body.name : seed.item.name,
    enabled: typeof body.enabled === "boolean" ? body.enabled : seed.item.enabled,
    interval_secs: typeof body.interval_secs === "number" ? body.interval_secs : seed.item.interval_secs,
    updated: STAMP(),
  };
  return ok(seed.item);
});

const remove = route("delete", "/api/v1/migrate/mirrors/{id}", (ctx) => {
  requireAdmin();
  pair(found(ctx.params.id), null);
  mirrors.delete(ctx.params.id);
  return noContent();
});

const token = route("post", "/api/v1/migrate/mirrors/{id}/token", async (ctx) => {
  requireAdmin();
  const seed = found(ctx.params.id);
  seed.item = { ...seed.item, source_prefixes: sourcesOf(await ctx.optionalBody()) };
  return created(minted(seed.item));
});

const losses = route("get", "/api/v1/migrate/mirrors/{id}/losses", (ctx) => {
  requireSession();
  const seed = withSnapshot(ctx.params.id);
  return ok({ mirror: seed.item.id, sequence: seed.item.last_sequence ?? 0, entries: seed.losses ?? [] });
});

const ack = route("post", "/api/v1/migrate/mirrors/{id}/losses/ack", async (ctx) => {
  const principal = requireAdmin();
  const seed = withSnapshot(ctx.params.id);
  const body = await ctx.body();
  const keys = Array.isArray(body.keys) ? body.keys.filter((key): key is string => typeof key === "string") : [];
  const entries = seed.losses ?? [];
  const latest = seed.item.last_sequence ?? 0;
  if (body.sequence !== latest) {
    throw new Problem("migrate.mirror.snapshot_moved", { status: 409, params: { sequence: String(body.sequence), latest: String(latest) } });
  }
  if (keys.length === 0 || keys.some((key) => !entries.some((item) => item.key === key))) {
    throw new Problem("sys.invalid_request", { status: 400, detail: "a key names no entry of the latest snapshot" });
  }
  const at = new Date().toISOString();
  const acks = keys.map((key) => ({ mirror: seed.item.id, key, entry_hash: "00", by: principal.user.id, at }));
  seed.losses = entries.map((item) => ({ ...item, ack: acks.find((a) => a.key === item.key) ?? item.ack }));
  seed.item = { ...seed.item, losses_open: seed.losses.filter((item) => !item.ack).length };
  return ok({ acks, revision: db.revision });
});

const diff = route("get", "/api/v1/migrate/mirrors/{id}/scopes/{cidr}/diff", (ctx) => {
  requireSession();
  const seed = withSnapshot(ctx.params.id);
  const cidr = decodeURIComponent(ctx.params.cidr);
  const answer = seed.diffs?.[cidr];
  if (!answer) throw new Problem("migrate.mirror.scope_not_found", { status: 404, params: { id: seed.item.id, scope: cidr } });
  return ok(answer);
});

export const migrateRoutes: HttpHandler[] = [list, create, one, patch, remove, token, losses, ack, diff];
