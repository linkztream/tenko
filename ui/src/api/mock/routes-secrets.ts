// Operator secrets, host credentials, the reveal and the remote hand-off for the mock API
// (IAM-15, IAM-16, IAM-07, API-11, TGL-24), after crates/tenko-api/src/routes/secrets.rs and
// remote.rs. The state is secrets-store.ts.
//
// Who may do what: viewers see no secret and no binding (the list is empty, the rest is 403);
// operators read the metadata and the bindings and may reveal; administrators also create,
// change, delete and bind. A session of PIN strength never stores or reveals (403
// `auth.step_up_required`, `required` = `password`).
//
// What the mock simplifies: a value is a text of 1 byte to 64 KiB, and the idempotency key is
// ignored. The connector instances of connectors-store.ts are the `connectors` of the
// references of a secret, and an instance that references a secret keeps it from deletion.
// Every write is committed as an event on the `secrets` topic and audited; the audit
// records never carry a value.
import type { HttpHandler } from "msw";
import { rdpFile, rdpFileName, sshUri } from "../../hosts/handoff";
import { formatIp, parseIp, type Ip } from "../../ipam/ip";
import type { components } from "../generated/schema";
import type { Address, Host, Interface, ObjectRef } from "../types";
import { appendAudit } from "./audit-store";
import { STRENGTH_RANK, requireAdmin, requireSession, type Principal } from "./auth";
import { commit, db, isAdmin, type MockSession, type MockUser } from "./db";
import { connectorReferences } from "./connectors-store";
import { ipamState } from "./ipam/api";
import { badPathId, invalidQuery, notFound } from "./ipam/problems";
import { Problem, created, fail, fieldError, noContent, ok } from "./reply";
import { paginate, route } from "./route";
import { revealPolicy } from "./reveal-policy";
import {
  CLEAR_AFTER_SECS,
  FRESH_MS,
  MAX_HOST_CREDENTIALS,
  ROLE_ORDER,
  SECRET_KINDS,
  credentialVersion,
  credentialsOf,
  dropSecret,
  findSecret,
  mockSecrets,
  replaceCredentials,
  secretHosts,
  secretList,
  storeSecret,
  takeReveal,
  toView,
  type CredentialRole,
  type SecretKind,
  type StoredSecret,
} from "./secrets-store";
import { iso, isUuid, randomId } from "./util";
import { isRecord, type Obj } from "./validate";

type S = components["schemas"];

// ---------------------------------------------------------------------------------
// Limits (crates/tenko-vault/src/operator.rs)

const MAX_NAME_CHARS = 128;
const MAX_USERNAME_CHARS = 256;
const MAX_NOTES_CHARS = 2000;
const MAX_TAG_CHARS = 64;
const MAX_TAGS = 16;
const MAX_VALUE_BYTES = 64 * 1024;
const MAX_REASON_CHARS = 200;
const MAX_REMOTE_USER_CHARS = 256;

// ---------------------------------------------------------------------------------
// Small helpers

function etag(revision: number): Record<string, string> {
  return { ETag: `"${revision}"` };
}

const secretRef = (id: string): ObjectRef => ({ kind: "secret", id });
const hostRef = (id: string): ObjectRef => ({ kind: "host", id });

function canRead(user: MockUser): boolean {
  return isAdmin(user) || user.roles.includes("operator");
}

/** The signed-in administrator or operator; viewers fail with 403. */
function requireReader(): Principal {
  const principal = requireSession();
  if (!canRead(principal.user)) {
    return fail("auth.forbidden", { detail: "this needs the admin or operator role" });
  }
  return principal;
}

function stepUp(required: string, detail: string): never {
  return fail("auth.step_up_required", { detail, params: { required } });
}

/** A session of PIN strength never stores or reveals a secret (IAM-07). */
function requirePassword(session: MockSession): void {
  if (STRENGTH_RANK[session.strength] < STRENGTH_RANK.password) {
    stepUp("password", "revealing and storing secrets needs a sign-in with a password or stronger");
  }
}

function pathId(raw: string): string {
  if (!isUuid(raw)) throw badPathId(raw);
  return raw;
}

function secretOr404(id: string): StoredSecret {
  const secret = findSecret(id);
  if (!secret) return fail("vault.secret.not_found", { params: { secret: id } });
  return secret;
}

/** The host of the IPAM mock, deleted ones included; 404 `ipam.not_found` otherwise. */
function hostOr404(id: string): Host {
  const host = ipamState().data.host.get(id);
  if (!host) throw notFound("host", id);
  return host;
}

// ---------------------------------------------------------------------------------
// Request bodies

function badBody(detail: string): never {
  return fail("sys.invalid_request", { detail });
}

/** The request types deny unknown members, like the server's. */
function rejectUnknown(body: Obj, allowed: readonly string[]): void {
  for (const key of Object.keys(body)) {
    if (!allowed.includes(key)) badBody(`unknown field \`${key}\``);
  }
}

function needText(body: Obj, key: string): string {
  const value = body[key];
  if (typeof value !== "string") return badBody(`${key}: a text is required`);
  return value;
}

/** A text member that may be null or absent: undefined when absent, null when null. */
function nullableText(body: Obj, key: string): string | null | undefined {
  const value = body[key];
  if (value === undefined || value === null) return value;
  if (typeof value !== "string") return badBody(`${key}: a text or null is required`);
  return value;
}

function kindOf(value: unknown): SecretKind {
  if (typeof value !== "string" || !(SECRET_KINDS as readonly string[]).includes(value)) {
    return badBody(`kind: one of ${SECRET_KINDS.join(", ")} is required`);
  }
  return value as SecretKind;
}

function roleOf(value: unknown, field: string): CredentialRole {
  if (typeof value !== "string" || !(ROLE_ORDER as readonly string[]).includes(value)) {
    return badBody(`${field}: one of ${ROLE_ORDER.join(", ")} is required`);
  }
  return value as CredentialRole;
}

function tagList(value: unknown): string[] {
  if (!Array.isArray(value) || value.some((t) => typeof t !== "string")) {
    return badBody("tags: a list of texts is required");
  }
  return value as string[];
}

// ---------------------------------------------------------------------------------
// Validation (`vault.secret.invalid` with the field in the params)

function invalidSecret(field: string, reason: string): never {
  return fail("vault.secret.invalid", {
    detail: `invalid ${field}: ${reason}`,
    params: { field, reason },
    errors: [fieldError(field, "vault.secret.invalid")],
  });
}

const charCount = (text: string): number => Array.from(text).length;
const hasControl = (text: string): boolean => /\p{Cc}/u.test(text);

function validName(raw: string): string {
  const name = raw.trim();
  if (name === "" || charCount(name) > MAX_NAME_CHARS || hasControl(name)) {
    return invalidSecret("name", `a name has 1 to ${MAX_NAME_CHARS} visible characters`);
  }
  return name;
}

function validUsername(raw: string | null | undefined): string | null {
  const name = raw?.trim() ?? "";
  if (name === "") return null;
  if (charCount(name) > MAX_USERNAME_CHARS || hasControl(name)) {
    return invalidSecret("username", `a user name has at most ${MAX_USERNAME_CHARS} visible characters`);
  }
  return name;
}

function validNotes(raw: string | null | undefined): string | null {
  if (raw === null || raw === undefined || raw.trim() === "") return null;
  // Line breaks and tabs are the only control characters notes may hold.
  if (charCount(raw) > MAX_NOTES_CHARS || hasControl(raw.replace(/[\n\r\t]/g, ""))) {
    return invalidSecret("notes", `notes have at most ${MAX_NOTES_CHARS} characters`);
  }
  return raw;
}

/** Lower-cased, 1 to 64 characters of `[a-z0-9._-]`, at most 16; sorted without duplicates. */
function validTags(tags: readonly string[]): string[] {
  const out = new Set<string>();
  for (const raw of tags) {
    const tag = raw.trim().toLowerCase();
    if (tag === "" || tag.length > MAX_TAG_CHARS || !/^[a-z0-9._-]+$/.test(tag)) {
      return invalidSecret(
        "tags",
        `a tag has 1 to ${MAX_TAG_CHARS} characters of a to z, 0 to 9, dot, underscore and hyphen`,
      );
    }
    out.add(tag);
  }
  if (out.size > MAX_TAGS) return invalidSecret("tags", `at most ${MAX_TAGS} tags`);
  return [...out].sort();
}

function validValue(value: string): string {
  const bytes = new TextEncoder().encode(value).length;
  if (bytes < 1) return invalidSecret("value", "a value has at least 1 byte");
  if (bytes > MAX_VALUE_BYTES) {
    return fail("vault.secret.too_large", {
      detail: `secret of ${bytes} bytes exceeds the limit of ${MAX_VALUE_BYTES} bytes`,
      params: { size: String(bytes), limit: String(MAX_VALUE_BYTES) },
    });
  }
  return value;
}

function validReason(raw: string | null): string | null {
  const reason = raw?.trim() ?? "";
  if (reason === "") return null;
  if (charCount(reason) > MAX_REASON_CHARS || hasControl(reason)) {
    return invalidSecret("reason", `a reason has at most ${MAX_REASON_CHARS} visible characters`);
  }
  return reason;
}

// ---------------------------------------------------------------------------------
// The list

const QUERY_NAMES = ["q", "kind", "tag", "host", "limit", "cursor"] as const;

/** The server refuses a query parameter it does not know and one that is repeated. */
function checkQueryNames(url: URL, allowed: readonly string[]): void {
  for (const name of new Set(url.searchParams.keys())) {
    if (!allowed.includes(name)) {
      throw invalidQuery(name, url.searchParams.get(name) ?? "", `the query parameter ${name} is not known`);
    }
    if (url.searchParams.getAll(name).length > 1) {
      throw invalidQuery(name, url.searchParams.get(name) ?? "", `the query parameter ${name} is repeated`);
    }
  }
}

const listSecrets = route("get", "/api/v1/secrets", (ctx) => {
  const { user } = requireSession();
  checkQueryNames(ctx.url, QUERY_NAMES);
  const q = ctx.query("q")?.toLowerCase() ?? "";
  const kind = ctx.query("kind");
  if (kind !== null && !(SECRET_KINDS as readonly string[]).includes(kind)) {
    throw invalidQuery("kind", kind, `kind is one of ${SECRET_KINDS.join(", ")}`);
  }
  const tag = ctx.query("tag")?.toLowerCase() ?? "";
  const host = ctx.query("host");
  if (host !== null && !isUuid(host)) throw invalidQuery("host", host, "host is an identifier");

  const items = canRead(user)
    ? secretList().filter(
        (secret) =>
          (kind === null || secret.kind === kind) &&
          (tag === "" || secret.tags.includes(tag)) &&
          (host === null || secretHosts(secret.id).some((bound) => bound.host === host)) &&
          (q === "" ||
            secret.name.toLowerCase().includes(q) ||
            (secret.username?.toLowerCase().includes(q) ?? false) ||
            secret.tags.some((t) => t.includes(q))),
      )
    : [];
  // A viewer gets an empty page, but the paging parameters are checked all the same.
  return ok(paginate(items.map(toView), ctx.url, db.revision));
});

// ---------------------------------------------------------------------------------
// Create, read, change, delete

const createSecret = route("post", "/api/v1/secrets", async (ctx) => {
  const { session } = requireAdmin();
  requirePassword(session);
  if (mockSecrets.pinOnlyAccounts.length > 0) {
    const accounts = mockSecrets.pinOnlyAccounts.join(",");
    return fail("vault.pin_coupling", {
      detail: `the vault takes operator secrets only when every account that may reveal them has more than a PIN: ${mockSecrets.pinOnlyAccounts.join(", ")} sign in with a PIN alone`,
      params: { accounts },
    });
  }
  const body = await ctx.body();
  rejectUnknown(body, ["name", "kind", "tags", "username", "notes", "value"]);
  const rawName = needText(body, "name");
  const kind = kindOf(body.kind);
  const rawTags = body.tags === undefined ? [] : tagList(body.tags);
  const rawUsername = nullableText(body, "username");
  const rawNotes = nullableText(body, "notes");
  const rawValue = needText(body, "value");

  const name = validName(rawName);
  const tags = validTags(rawTags);
  const username = validUsername(rawUsername);
  const notes = validNotes(rawNotes);
  const value = validValue(rawValue);

  const stamp = iso(Date.now());
  const secret: StoredSecret = {
    id: randomId(),
    name,
    kind,
    tags,
    username,
    notes,
    origin: "manual",
    created_at: stamp,
    updated_at: stamp,
    value_updated_at: stamp,
    value,
    revision: db.revision,
    last_revealed: null,
  };
  storeSecret(secret);
  db.vaultHasOperatorSecrets = true;
  commit("secrets", { objects: [secretRef(secret.id)], tables: ["vault.operator_meta"] }, [secret]);
  appendAudit({ action: "vault.secret.create", objects: [secretRef(secret.id)], context: { name, kind } });
  return created(toView(secret), etag(secret.revision));
});

const getSecret = route("get", "/api/v1/secrets/{id}", (ctx) => {
  requireReader();
  const secret = secretOr404(pathId(ctx.params.id));
  return ok(toView(secret), etag(secret.revision));
});

const updateSecret = route("patch", "/api/v1/secrets/{id}", async (ctx) => {
  requireAdmin();
  const id = pathId(ctx.params.id);
  const expect = ctx.ifMatch();
  const body = await ctx.body();
  rejectUnknown(body, ["name", "kind", "tags", "username", "notes", "value"]);
  // Absent and null mean "leave it" for these; `username` and `notes` use null to clear.
  const rawName = nullableText(body, "name");
  const rawKind = body.kind === undefined || body.kind === null ? undefined : kindOf(body.kind);
  const rawTags = body.tags === undefined || body.tags === null ? undefined : tagList(body.tags);
  const rawUsername = nullableText(body, "username");
  const rawNotes = nullableText(body, "notes");
  const rawValue = nullableText(body, "value");

  // The server checks the value first, then loads the secret and the revision.
  const value = rawValue === undefined || rawValue === null ? undefined : validValue(rawValue);
  const secret = secretOr404(id);
  if (typeof expect === "number" && expect !== secret.revision) {
    return fail("vault.secret.conflict", { params: { expected: String(expect), actual: String(secret.revision) } });
  }

  const next: StoredSecret = { ...secret, tags: [...secret.tags] };
  const changes: components["schemas"]["FieldChange"][] = [];
  if (rawName !== undefined && rawName !== null) {
    next.name = validName(rawName);
    if (next.name !== secret.name) changes.push({ field: "name", old: secret.name, new: next.name });
  }
  if (rawKind !== undefined && rawKind !== secret.kind) {
    next.kind = rawKind;
    changes.push({ field: "kind", old: secret.kind, new: rawKind });
  }
  if (rawTags !== undefined) {
    next.tags = validTags(rawTags);
    if (next.tags.join(",") !== secret.tags.join(",")) {
      changes.push({ field: "tags", old: secret.tags.join(","), new: next.tags.join(",") });
    }
  }
  if (rawUsername !== undefined) {
    next.username = validUsername(rawUsername);
    if (next.username !== secret.username) {
      changes.push({ field: "username", old: secret.username, new: next.username });
    }
  }
  if (rawNotes !== undefined) {
    next.notes = validNotes(rawNotes);
    // The audit record says that the notes changed, never what they say.
    if (next.notes !== secret.notes) changes.push({ field: "notes", old: null, new: null });
  }
  if (changes.length === 0 && value === undefined) return ok(toView(secret), etag(secret.revision));

  const stamp = iso(Date.now());
  next.updated_at = stamp;
  if (value !== undefined) {
    next.value = value;
    next.value_updated_at = stamp;
  }
  storeSecret(next);
  commit("secrets", { objects: [secretRef(id)], tables: ["vault.operator_meta"] }, [next]);
  if (changes.length > 0) {
    appendAudit({ action: "vault.secret.update", objects: [secretRef(id)], changes, context: { name: next.name } });
  }
  if (value !== undefined) {
    appendAudit({ action: "vault.secret.replace", objects: [secretRef(id)], context: { name: next.name } });
  }
  return ok(toView(next), etag(next.revision));
});

const deleteSecret = route("delete", "/api/v1/secrets/{id}", (ctx) => {
  requireAdmin();
  const id = pathId(ctx.params.id);
  const expect = ctx.ifMatch();
  const secret = secretOr404(id);
  // As on the server, a secret in use is refused before the revision is compared.
  const bound = secretHosts(id);
  const used = connectorReferences(id);
  if (bound.length > 0 || used.length > 0) {
    return fail("vault.secret.in_use", {
      detail: `the secret is bound to ${bound.length} host(s) and used by ${used.length} connector(s)`,
      params: { hosts: String(bound.length), connectors: String(used.length) },
    });
  }
  if (typeof expect === "number" && expect !== secret.revision) {
    return fail("vault.secret.conflict", { params: { expected: String(expect), actual: String(secret.revision) } });
  }
  dropSecret(id);
  commit("secrets", { deleted: [secretRef(id)], tables: ["vault.operator_meta"] });
  appendAudit({ action: "vault.secret.delete", objects: [secretRef(id)], context: { name: secret.name } });
  return noContent();
});

const secretReferences = route("get", "/api/v1/secrets/{id}/references", (ctx) => {
  requireReader();
  const id = pathId(ctx.params.id);
  secretOr404(id);
  const hosts: S["SecretHostReference"][] = secretHosts(id).map((bound) => {
    const host = ipamState().data.host.get(bound.host);
    const reference: S["SecretHostReference"] = {
      host: bound.host,
      role: bound.role,
      deleted: host ? host.meta.deleted !== null : false,
    };
    if (host) reference.name = host.name;
    return reference;
  });
  hosts.sort(
    (a, b) =>
      (a.name ?? "").localeCompare(b.name ?? "") || (a.host < b.host ? -1 : a.host > b.host ? 1 : 0),
  );
  return ok({ id, hosts, connectors: connectorReferences(id) });
});

// ---------------------------------------------------------------------------------
// Reveal

interface RevealInput {
  host: string | null;
  reason: string | null;
}

function parseReveal(body: Obj): RevealInput {
  rejectUnknown(body, ["host", "reason"]);
  const host = nullableText(body, "host") ?? null;
  if (host !== null && !isUuid(host)) badBody("host: an identifier is required");
  return { host, reason: nullableText(body, "reason") ?? null };
}

/** The reveal itself; every refusal is a `Problem`, which the route audits. */
function revealNow(id: string, input: RevealInput, principal: Principal): S["RevealedSecret"] {
  const { user, session } = principal;
  if (!canRead(user)) return fail("auth.forbidden", { detail: "this needs the admin or operator role" });
  requirePassword(session);
  const policy = revealPolicy();
  const now = Date.now();
  const fresh = now - session.created_at <= FRESH_MS;
  if (policy.step_up === "fresh" && !fresh) {
    stepUp("fresh", "sign in again to reveal a secret: the reveal policy wants a sign-in within five minutes");
  }
  if (policy.step_up === "passkey" && !(fresh && STRENGTH_RANK[session.strength] >= STRENGTH_RANK.passkey)) {
    stepUp("passkey", "sign in with a passkey or a security key to reveal a secret");
  }
  const reason = validReason(input.reason);
  const secret = secretOr404(id);
  if (input.host !== null) {
    if (!secretHosts(id).some((bound) => bound.host === input.host)) {
      return fail("vault.reveal.not_bound", { params: { host: input.host } });
    }
  } else if (policy.bound_host_only) {
    return fail("vault.reveal.host_required");
  }
  const wait = takeReveal(user.id, mockSecrets.revealLimit, now);
  if (wait !== null) {
    return fail("vault.reveal.rate_limited", {
      detail: `too many reveals; retry in ${wait} seconds`,
      params: { retry_after: String(wait) },
      headers: { "Retry-After": String(wait) },
    });
  }

  const at = iso(now);
  secret.last_revealed = { at, user: user.id, user_name: user.name, host: input.host };
  const context: Record<string, string> = { kind: secret.kind, name: secret.name };
  if (input.host !== null) context.host = input.host;
  if (reason !== null) context.reason = reason;
  commit("secrets", { objects: [secretRef(id)], tables: ["vault.reveals"] });
  appendAudit({
    action: "vault.secret.reveal",
    objects: [secretRef(id), ...(input.host === null ? [] : [hostRef(input.host)])],
    context,
    at: now,
  });
  const revealed: S["RevealedSecret"] = {
    id,
    value: secret.value,
    kind: secret.kind,
    revealed_at: at,
    clear_after_secs: CLEAR_AFTER_SECS,
  };
  if (secret.username !== null) revealed.username = secret.username;
  return revealed;
}

/** Audits a refused reveal like the server: the code, the host and the reason; never the value. */
function recordRefusal(id: string, input: RevealInput, problem: Problem): void {
  const code = problem.reply.body.code;
  // The rate limit is the one refusal the server does not audit.
  if (code === "vault.reveal.rate_limited") return;
  const context: Record<string, string> = { code };
  if (input.host !== null) context.host = input.host;
  const reason = input.reason?.trim() ?? "";
  if (reason !== "" && charCount(reason) <= MAX_REASON_CHARS && !hasControl(reason) && code !== "vault.secret.invalid") {
    context.reason = reason;
  }
  appendAudit({
    action: "vault.secret.reveal",
    objects: [secretRef(id), ...(input.host === null ? [] : [hostRef(input.host)])],
    outcome: { kind: "denied" },
    context,
  });
}

const revealSecret = route("post", "/api/v1/secrets/{id}/reveal", async (ctx) => {
  const principal = requireSession();
  const id = pathId(ctx.params.id);
  const input = parseReveal(await ctx.optionalBody());
  try {
    return ok(revealNow(id, input, principal), { "Cache-Control": "no-store" });
  } catch (error) {
    if (error instanceof Problem) recordRefusal(id, input, error);
    throw error;
  }
});

// ---------------------------------------------------------------------------------
// Host credentials

function credentialsView(host: string): S["HostCredentialsView"] {
  return {
    host,
    items: credentialsOf(host).map((entry) => ({
      role: entry.role,
      bound_at: entry.bound_at,
      secret: toView(entry.secret),
    })),
    version: credentialVersion(host),
  };
}

const hostCredentials = route("get", "/api/v1/hosts/{id}/credentials", (ctx) => {
  requireReader();
  const id = pathId(ctx.params.id);
  hostOr404(id);
  return ok(credentialsView(id), etag(credentialVersion(id)));
});

const updateHostCredentials = route("put", "/api/v1/hosts/{id}/credentials", async (ctx) => {
  requireAdmin();
  const id = pathId(ctx.params.id);
  const expect = ctx.ifMatch();
  const body = await ctx.body();
  rejectUnknown(body, ["credentials"]);
  if (!Array.isArray(body.credentials)) return badBody("credentials: a list is required");
  const wanted = (body.credentials as unknown[]).map((item, index) => {
    if (!isRecord(item)) return badBody(`credentials[${index}]: an object is required`);
    rejectUnknown(item, ["secret", "role"]);
    const secret = item.secret;
    if (typeof secret !== "string" || !isUuid(secret)) {
      return badBody(`credentials[${index}].secret: an identifier is required`);
    }
    return { secret, role: roleOf(item.role, `credentials[${index}].role`) };
  });
  hostOr404(id);

  if (wanted.length > MAX_HOST_CREDENTIALS) {
    return invalidSecret("credentials", `at most ${MAX_HOST_CREDENTIALS} credentials per host`);
  }
  if (new Set(wanted.map((w) => w.secret)).size !== wanted.length) {
    return invalidSecret("credentials", "a secret is bound to a host once, with one role");
  }
  const version = credentialVersion(id);
  if (typeof expect === "number" && expect !== version) {
    return fail("vault.host_credentials.conflict", {
      params: { expected: String(expect), actual: String(version) },
    });
  }
  for (const w of wanted) {
    if (!findSecret(w.secret)) {
      return fail("vault.host_credentials.secret_missing", {
        params: { secret: w.secret },
        errors: [fieldError("credentials", "vault.host_credentials.secret_missing")],
      });
    }
  }

  const result = replaceCredentials(id, wanted, iso(Date.now()));
  if (result.changes.length > 0) {
    commit("secrets", {
      objects: [hostRef(id), ...result.secrets.map(secretRef)],
      tables: ["vault.host_bindings"],
    });
    appendAudit({
      action: "vault.host.credentials",
      objects: [hostRef(id), ...result.secrets.map(secretRef)],
      changes: result.changes,
    });
  }
  return ok(credentialsView(id), etag(credentialVersion(id)));
});

// ---------------------------------------------------------------------------------
// Remote hand-off (API-11)

const REMOTE_QUERY = ["protocol", "interface", "address", "port", "user"] as const;
const DEFAULT_PORT = { rdp: 3389, ssh: 22 } as const;

interface RemoteQuery {
  protocol: "rdp" | "ssh";
  interface: string | null;
  address: string | null;
  port: number | null;
  user: string | null;
}

function parseRemote(url: URL): RemoteQuery {
  checkQueryNames(url, REMOTE_QUERY);
  const params = url.searchParams;
  const protocol = params.get("protocol");
  if (protocol !== "rdp" && protocol !== "ssh") {
    throw invalidQuery("protocol", protocol ?? "", "`rdp` or `ssh` is required");
  }
  const iface = params.get("interface");
  if (iface !== null && !isUuid(iface)) throw invalidQuery("interface", iface, "interface is an identifier");
  const rawPort = params.get("port");
  let port: number | null = null;
  if (rawPort !== null) {
    port = /^\d{1,5}$/.test(rawPort) ? Number(rawPort) : Number.NaN;
    if (!(port >= 1 && port <= 65535)) throw invalidQuery("port", rawPort, "a port is 1 to 65535");
  }
  const user = params.get("user");
  if (user !== null && (charCount(user) > MAX_REMOTE_USER_CHARS || hasControl(user))) {
    throw invalidQuery("user", user, "a user name has at most 256 visible characters");
  }
  return { protocol, interface: iface, address: params.get("address"), port, user: user === "" ? null : user };
}

/** The live interfaces of a host, by name. */
function liveInterfaces(host: string): Interface[] {
  return [...ipamState().data.interface.values()]
    .filter((i) => i.host === host && !i.meta.deleted)
    .sort((a, b) => a.name.toLowerCase().localeCompare(b.name.toLowerCase()));
}

function liveAddresses(interfaceId: string): Address[] {
  return [...ipamState().data.address.values()].filter((a) => a.interface === interfaceId && !a.meta.deleted);
}

const sameIp = (a: Ip, b: Ip): boolean => a.version === b.version && a.value === b.value;

/** IPv4 before IPv6, then by value. */
function compareIp(a: Ip, b: Ip): number {
  if (a.version !== b.version) return a.version - b.version;
  return a.value < b.value ? -1 : a.value > b.value ? 1 : 0;
}

const dnsKey = (name: string): string => name.toLowerCase().replace(/\.$/, "");

function unknownTarget(code: "remote.address_unknown" | "remote.interface_unknown", field: string): never {
  return fail(code, { params: { field }, errors: [fieldError(field, code)] });
}

/**
 * Where to connect to. `address` is an IP address of the host (or the interface), used in its
 * canonical form, or the DNS name of one of its addresses (case and a trailing dot do not
 * matter), used as sent without the trailing dot. Without `address`: the first live address
 * (IPv4 first) by its DNS name when it has one, else as an address; the host name when the
 * host has no live address.
 */
function remoteTarget(host: Host, query: RemoteQuery): string {
  let interfaces = liveInterfaces(host.id);
  if (query.interface !== null) {
    interfaces = interfaces.filter((i) => i.id === query.interface);
    if (interfaces.length === 0) return unknownTarget("remote.interface_unknown", "interface");
  }
  const live = interfaces.flatMap((i) => liveAddresses(i.id)).map((address) => ({ address, ip: parseIp(address.ip) }));
  if (query.address !== null) {
    const given = parseIp(query.address);
    if (given) {
      if (!live.some((l) => l.ip && sameIp(l.ip, given))) return unknownTarget("remote.address_unknown", "address");
      return formatIp(given);
    }
    const wanted = dnsKey(query.address);
    if (wanted === "" || !live.some((l) => l.address.dns_name && dnsKey(l.address.dns_name) === wanted)) {
      return unknownTarget("remote.address_unknown", "address");
    }
    return query.address.replace(/\.$/, "");
  }
  const sorted = live
    .filter((l): l is { address: Address; ip: Ip } => l.ip !== null)
    .sort((a, b) => compareIp(a.ip, b.ip));
  const first = sorted[0];
  if (!first) return host.name;
  return first.address.dns_name ?? first.address.ip;
}

/** The user name of the credential bound with `role`, else the `admin` one; none for a viewer. */
function handoffUsername(user: MockUser, host: string, role: "rdp" | "ssh"): string | null {
  if (!canRead(user)) return null;
  const entries = credentialsOf(host);
  const pick = (wanted: CredentialRole): string | null =>
    entries.filter((e) => e.role === wanted).find((e) => e.secret.username !== null)?.secret.username ?? null;
  return pick(role) ?? pick("admin");
}

const hostRemote = route("get", "/api/v1/hosts/{id}/remote", (ctx) => {
  const { user } = requireSession();
  const query = parseRemote(ctx.url);
  const host = hostOr404(pathId(ctx.params.id));
  const target = remoteTarget(host, query);
  const username = query.user ?? handoffUsername(user, host.id, query.protocol);
  const port = query.port ?? DEFAULT_PORT[query.protocol];
  if (query.protocol === "rdp") {
    const text = rdpFile({ address: target, port, username });
    return new Response(text, {
      status: 200,
      headers: {
        "content-type": "application/x-rdp",
        "content-disposition": `attachment; filename="${rdpFileName(host.name)}"`,
      },
    });
  }
  const handoff: S["SshHandoff"] = { uri: sshUri({ host: target, port, user: username }), host: target, port };
  if (username !== null) handoff.username = username;
  return ok(handoff);
});

export const secretsRoutes: HttpHandler[] = [
  listSecrets,
  createSecret,
  getSecret,
  updateSecret,
  deleteSecret,
  secretReferences,
  revealSecret,
  hostCredentials,
  updateHostCredentials,
  hostRemote,
];
