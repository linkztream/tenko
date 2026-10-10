// The state of the operator secrets mock (IAM-15, IAM-16, API-11, TGL-24): the secrets with
// their values (kept here and nowhere else), the credentials bound to hosts with the version
// of each set, and when each person revealed last. The HTTP side is routes-secrets.ts.
//
// The seed after every reset (none for the first-run setup scenarios, which have no users and
// no IPAM data):
//
// - "nas admin": kind `password`, user name `admin`, value `example-nas-pass`, tags `["ssh"]`,
//   bound with the role `admin` to the host `nas` of the IPAM seed (192.0.2.11,
//   nas.example.test; `SEED_HOST_ID`). Id `SEED_SECRET_IDS.nasAdmin`.
// - "unifi api": kind `api_key`, value `example-api-key`, tags `["api_key", "unifi"]`, bound to
//   no host. Id `SEED_SECRET_IDS.unifiApi`.
//
// The ids of the seed are fixed (UUID syntax, group d); secrets created by the API get random
// ones. Seeding records no event and no audit entry, and leaves `db.vaultHasOperatorSecrets`
// alone (it is false after a reset, which the settings tests rely on); creating a secret
// through the API sets it, like the server's vault.
//
// The test switches live in `mockSecrets`; `seedSecret`, `bindSecret`, `secretValue`,
// `revealsOf` and `ageCurrentSession` are the helpers tests use.
import type { components } from "../generated/schema";
import type { AuditRecord, FieldChange } from "../types";
import { AUDIT_SEED_IDS, audit } from "./audit-store";
import { db, onMockReset } from "./db";
import { HOST_IDS } from "./ipam/api";
import { DAY_MS, MINUTE, iso, randomId } from "./util";

type S = components["schemas"];

export type SecretKind = S["SecretKind"];
export type SecretOrigin = S["SecretOrigin"];
export type CredentialRole = S["CredentialRole"];
export type SecretView = S["OperatorSecretView"];

/** The roles in the order the server sorts credentials by. */
export const ROLE_ORDER: readonly CredentialRole[] = ["admin", "rdp", "ssh", "web", "other"];
export const SECRET_KINDS: readonly SecretKind[] = ["password", "api_key", "ssh_key", "token", "other"];

/** Seconds after which the UI clears a revealed value from the clipboard. */
export const CLEAR_AFTER_SECS = 30;
/** A sign-in counts as fresh for the reveal policy for this long. */
export const FRESH_MS = 5 * MINUTE;
/** The window of the reveal rate limit. */
export const REVEAL_WINDOW_MS = MINUTE;
/** Most credentials bound to one host. */
export const MAX_HOST_CREDENTIALS = 32;

/** The fixed ids of the two seeded secrets. */
export const SEED_SECRET_IDS = {
  nasAdmin: "0190d1c2-0000-7000-8000-0000000d0001",
  unifiApi: "0190d1c2-0000-7000-8000-0000000d0002",
} as const;

/** The values of the seeded secrets (test values that protect nothing). */
export const SEED_SECRET_VALUES = {
  nasAdmin: "example-nas-pass",
  unifiApi: "example-api-key",
} as const;

/** The host the seed binds "nas admin" to: `nas` of the IPAM seed. */
export const SEED_HOST_ID: string = HOST_IDS.nas ?? AUDIT_SEED_IDS.hostNas;

// ---------------------------------------------------------------------------------
// Test switches

export interface MockSecrets {
  /**
   * Names of enabled accounts that sign in with a PIN alone and may reveal secrets. While the
   * list is not empty, creating a secret fails with 409 `vault.pin_coupling` (IAM-07).
   */
  pinOnlyAccounts: string[];
  /** Reveals one person may make per minute before the answer is 429. */
  revealLimit: number;
}

function freshSwitches(): MockSecrets {
  return { pinOnlyAccounts: [], revealLimit: 10 };
}

/** The test switches. One object; a reset replaces its members. */
export const mockSecrets: MockSecrets = freshSwitches();

// ---------------------------------------------------------------------------------
// State

export interface StoredReveal {
  at: string;
  user: string;
  user_name: string;
  host: string | null;
}

/** A secret as the mock keeps it: the metadata of the view and the value. */
export interface StoredSecret {
  id: string;
  name: string;
  kind: SecretKind;
  tags: string[];
  username: string | null;
  notes: string | null;
  origin: SecretOrigin;
  created_at: string;
  updated_at: string;
  value_updated_at: string;
  /** The value. Only a reveal and a test helper read it. */
  value: string;
  /** The revision of the metadata (the `ETag`), stamped by `commit`. */
  revision: number;
  last_revealed: StoredReveal | null;
}

export interface StoredBinding {
  role: CredentialRole;
  bound_at: string;
}

/** The credentials of one host: the secrets bound to it and the version of the set. */
export interface HostBindings {
  version: number;
  /** By secret id. */
  items: Map<string, StoredBinding>;
}

interface State {
  secrets: Map<string, StoredSecret>;
  hosts: Map<string, HostBindings>;
  /** The times (ms) of the reveals of each person, by user id. */
  reveals: Map<string, number[]>;
}

const state: State = { secrets: new Map(), hosts: new Map(), reveals: new Map() };

function tagsOf(tags: readonly string[]): string[] {
  return [...new Set(tags.map((t) => t.trim().toLowerCase()))].sort();
}

// ---------------------------------------------------------------------------------
// Secrets

function compareText(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/** Every secret by name ignoring case, then id. */
export function secretList(): StoredSecret[] {
  return [...state.secrets.values()].sort(
    (a, b) => compareText(a.name.toLowerCase(), b.name.toLowerCase()) || compareText(a.id, b.id),
  );
}

export function findSecret(id: string): StoredSecret | undefined {
  return state.secrets.get(id);
}

export function storeSecret(secret: StoredSecret): void {
  state.secrets.set(secret.id, secret);
}

/** Forgets a secret, its reveal stamp and any binding left over. */
export function dropSecret(id: string): void {
  state.secrets.delete(id);
  for (const set of state.hosts.values()) set.items.delete(id);
}

/** The hosts a secret is bound to, by host id. */
export function secretHosts(id: string): S["SecretHostRef"][] {
  const out: S["SecretHostRef"][] = [];
  for (const [host, set] of state.hosts) {
    const binding = set.items.get(id);
    if (binding) out.push({ host, role: binding.role });
  }
  return out.sort((a, b) => compareText(a.host, b.host));
}

/** The secret as the API shows it: metadata only. Members that are null are left out. */
export function toView(secret: StoredSecret): SecretView {
  const view: SecretView = {
    id: secret.id,
    name: secret.name,
    kind: secret.kind,
    tags: [...secret.tags],
    origin: secret.origin,
    created_at: secret.created_at,
    updated_at: secret.updated_at,
    value_updated_at: secret.value_updated_at,
    hosts: secretHosts(secret.id),
    revision: secret.revision,
  };
  if (secret.username !== null) view.username = secret.username;
  if (secret.notes !== null) view.notes = secret.notes;
  if (secret.last_revealed) {
    const { at, user, user_name, host } = secret.last_revealed;
    view.last_revealed = { at, user, user_name, ...(host === null ? {} : { host }) };
  }
  return view;
}

// ---------------------------------------------------------------------------------
// Host credentials

/** The version of the credential set of a host: 0 until something was bound. */
export function credentialVersion(host: string): number {
  return state.hosts.get(host)?.version ?? 0;
}

export interface HostCredentialEntry {
  role: CredentialRole;
  bound_at: string;
  secret: StoredSecret;
}

/** The credentials of a host by role, then name ignoring case, then id. */
export function credentialsOf(host: string): HostCredentialEntry[] {
  const set = state.hosts.get(host);
  if (!set) return [];
  const out: HostCredentialEntry[] = [];
  for (const [id, binding] of set.items) {
    const secret = state.secrets.get(id);
    if (secret) out.push({ role: binding.role, bound_at: binding.bound_at, secret });
  }
  return out.sort(
    (a, b) =>
      ROLE_ORDER.indexOf(a.role) - ROLE_ORDER.indexOf(b.role) ||
      compareText(a.secret.name.toLowerCase(), b.secret.name.toLowerCase()) ||
      compareText(a.secret.id, b.secret.id),
  );
}

export interface BindingChange {
  /** What changed, one entry per secret bound, unbound or given another role. */
  changes: FieldChange[];
  /** The secrets that changed. */
  secrets: string[];
}

/**
 * Makes `wanted` (one entry per secret) the credentials of `host`: a new set raises the
 * version by one. Returns what changed; a set equal to the current one changes nothing.
 */
export function replaceCredentials(
  host: string,
  wanted: readonly { secret: string; role: CredentialRole }[],
  now: string,
): BindingChange {
  const set = state.hosts.get(host) ?? { version: 0, items: new Map<string, StoredBinding>() };
  const after = new Map(wanted.map((w) => [w.secret, w.role] as const));
  const result: BindingChange = { changes: [], secrets: [] };
  const next = new Map<string, StoredBinding>();
  for (const [secret, binding] of set.items) {
    if (after.has(secret)) continue;
    result.secrets.push(secret);
    result.changes.push({ object: { kind: "secret", id: secret }, field: "role", old: binding.role, new: null });
  }
  for (const [secret, role] of after) {
    const before = set.items.get(secret);
    if (before?.role === role) {
      next.set(secret, before);
      continue;
    }
    next.set(secret, { role, bound_at: now });
    result.secrets.push(secret);
    result.changes.push({
      object: { kind: "secret", id: secret },
      field: "role",
      old: before?.role ?? null,
      new: role,
    });
  }
  if (result.changes.length === 0) return result;
  state.hosts.set(host, { version: set.version + 1, items: next });
  return result;
}

// ---------------------------------------------------------------------------------
// Reveal rate limit

/**
 * Counts a reveal of `person` against `limit` per minute. Returns null when it may go on (it
 * is counted), else the seconds to wait.
 */
export function takeReveal(person: string, limit: number, now: number): number | null {
  const times = (state.reveals.get(person) ?? []).filter((t) => now - t < REVEAL_WINDOW_MS);
  if (times.length >= limit) {
    const first = times[0];
    state.reveals.set(person, times);
    return Math.max(1, Math.ceil(((first ?? now) + REVEAL_WINDOW_MS - now) / 1000));
  }
  times.push(now);
  state.reveals.set(person, times);
  return null;
}

// ---------------------------------------------------------------------------------
// Helpers for tests

export interface SeedSecretInput {
  /** A fixed id; random by default. */
  id?: string;
  name: string;
  kind?: SecretKind;
  /** Default `example-secret-value`. */
  value?: string;
  tags?: string[];
  username?: string | null;
  notes?: string | null;
  origin?: SecretOrigin;
}

/**
 * Adds a secret straight to the state: no validation, no event, no audit record. Returns its
 * view.
 */
export function seedSecret(input: SeedSecretInput): SecretView {
  const now = iso(Date.now());
  const secret: StoredSecret = {
    id: input.id ?? randomId(),
    name: input.name,
    kind: input.kind ?? "password",
    tags: tagsOf(input.tags ?? []),
    username: input.username ?? null,
    notes: input.notes ?? null,
    origin: input.origin ?? "manual",
    created_at: now,
    updated_at: now,
    value_updated_at: now,
    value: input.value ?? "example-secret-value",
    revision: db.revision,
    last_revealed: null,
  };
  state.secrets.set(secret.id, secret);
  return toView(secret);
}

/**
 * Binds a secret to a host with a role (replacing the role it had there), without an event or
 * an audit record. The version of the host's set rises by one.
 */
export function bindSecret(host: string, secretId: string, role: CredentialRole): void {
  if (!state.secrets.has(secretId)) throw new Error(`no secret ${secretId}`);
  const set = state.hosts.get(host) ?? { version: 0, items: new Map<string, StoredBinding>() };
  set.items.set(secretId, { role, bound_at: iso(Date.now()) });
  set.version += 1;
  state.hosts.set(host, set);
}

/** The value of a secret, the one thing the API never shows except through a reveal. */
export function secretValue(id: string): string {
  const secret = state.secrets.get(id);
  if (!secret) throw new Error(`no secret ${id}`);
  return secret.value;
}

/** The audit records of reveals of a secret (`vault.secret.reveal`), successes and refusals, oldest first. */
export function revealsOf(id: string): AuditRecord[] {
  return audit.records.filter(
    (r) => r.draft.action === "vault.secret.reveal" && (r.draft.objects ?? []).some((o) => o.kind === "secret" && o.id === id),
  );
}

/**
 * Makes the current session older by `seconds`, so a reveal policy that wants a recent sign-in
 * (`fresh`, `passkey`) refuses it. Changes `created_at` of the session only.
 */
export function ageCurrentSession(seconds: number): void {
  const session = db.sessions.find((s) => s.id === db.currentSessionId);
  if (!session) throw new Error("nobody is signed in");
  session.created_at -= seconds * 1000;
}

// ---------------------------------------------------------------------------------
// Reset and seed

function seedState(): void {
  state.secrets = new Map();
  state.hosts = new Map();
  state.reveals = new Map();
  const setup = db.scenario === "setup" || db.scenario === "setup-slow-disk";
  if (setup) return;
  const now = Date.now();
  const created = iso(now - 30 * DAY_MS);
  const base = { origin: "manual" as const, created_at: created, updated_at: created, value_updated_at: created };
  const nas: StoredSecret = {
    ...base,
    id: SEED_SECRET_IDS.nasAdmin,
    name: "nas admin",
    kind: "password",
    tags: ["ssh"],
    username: "admin",
    notes: null,
    value: SEED_SECRET_VALUES.nasAdmin,
    revision: db.revision,
    last_revealed: null,
  };
  const unifi: StoredSecret = {
    ...base,
    id: SEED_SECRET_IDS.unifiApi,
    name: "unifi api",
    kind: "api_key",
    tags: ["api_key", "unifi"],
    username: null,
    notes: null,
    value: SEED_SECRET_VALUES.unifiApi,
    revision: db.revision,
    last_revealed: null,
  };
  state.secrets.set(nas.id, nas);
  state.secrets.set(unifi.id, unifi);
  state.hosts.set(SEED_HOST_ID, {
    version: 1,
    items: new Map([[nas.id, { role: "admin", bound_at: iso(now - 29 * DAY_MS) }]]),
  });
}

onMockReset(() => {
  Object.assign(mockSecrets, freshSwitches());
  seedState();
});
seedState();
