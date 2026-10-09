// Users, roles and the security settings (administrators only, apart from reading settings).
import type { HttpHandler } from "msw";
import type { components } from "../generated/schema";
import type {
  BreachMode,
  LockoutMode,
  MfaRequirement,
  PasswordPolicy,
  Profile,
  RoleInfo,
  RoleName,
  SecuritySettings,
  SessionLifetime,
} from "../types";
import { PROFILES } from "../types";
import { clearThrottle, requireAdmin, requireSession, revokeUserSessions } from "./auth";
import {
  commit,
  db,
  findUser,
  findUserByName,
  isAdmin,
  otherActiveAdmins,
  settingsView,
  toUserInfo,
  userChange,
  type MockUser,
} from "./db";
import { ROLE_DESCRIPTIONS } from "./fixtures";
import { checkPassword } from "./policy";
import { profileSettings } from "./profiles";
import { created, fail, noContent, ok } from "./reply";
import { paginate, route, wholePage } from "./route";
import { iso, randomId, uuidHandle } from "./util";
import {
  failPolicy,
  invalid,
  isRecord,
  oneOf,
  optBool,
  optInt,
  optString,
  reqString,
  validDisplayName,
  validLanguage,
  validRoles,
  validUserName,
} from "./validate";

function etag(revision: number): Record<string, string> {
  return { ETag: `"${revision}"` };
}

function userOr404(id: string): MockUser {
  const user = findUser(id);
  if (!user) return fail("users.not_found", { params: { kind: "user" } });
  return user;
}

/** `If-Match` against the current revision: a different revision fails with 412. */
function checkRevision(expected: number | "*" | null, actual: number): void {
  if (typeof expected === "number" && expected !== actual) {
    fail("sys.store.precondition_failed", { params: { expected: String(expected), actual: String(actual) } });
  }
}

// ---------------------------------------------------------------------------------
// Users

const listUsers = route("get", "/api/v1/users", (ctx) => {
  requireAdmin();
  const q = ctx.query("q")?.trim().toLowerCase();
  const users = [...db.users]
    .filter((u) => !q || u.name.toLowerCase().includes(q) || u.display_name.toLowerCase().includes(q))
    .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  return ok(paginate(users.map(toUserInfo), ctx.url, db.revision));
});

const createUser = route("post", "/api/v1/users", async (ctx) => {
  requireAdmin();
  const body = await ctx.body();
  const name = validUserName(reqString(body, "name"));
  if (findUserByName(name)) return fail("users.name_taken", { params: { name } });
  const displayName = validDisplayName(optString(body, "display_name"), name);
  const roles = validRoles(body.roles);
  const language = optString(body, "language");
  if (language !== undefined && language !== "") validLanguage(language);
  const password = optString(body, "password");
  if (password !== undefined && password !== "") {
    const result = checkPassword(password, {
      policy: db.settings.password_policy,
      breach: db.settings.breach_check,
      userName: name,
      displayName,
      hostName: db.installation.host_name ?? db.node.name,
    });
    if (!result.acceptable) failPolicy("password", result.violations);
  }

  const id = randomId();
  const user: MockUser = {
    id,
    name,
    display_name: displayName,
    roles,
    disabled: false,
    break_glass: false,
    lock: null,
    password: password ? password : null,
    totp: false,
    credentials: [],
    recovery_codes: [],
    // An initial password is for the first login only.
    password_change_required: Boolean(password),
    language: language ? language : null,
    created_at: iso(Date.now()),
    last_login_at: null,
    revision: db.revision,
    handle: uuidHandle(id),
  };
  db.users.push(user);
  commit("admin", userChange(user), [user]);
  return created(toUserInfo(user), etag(user.revision));
});

const getUser = route("get", "/api/v1/users/{id}", (ctx) => {
  requireAdmin();
  const user = userOr404(ctx.params.id);
  return ok(toUserInfo(user), etag(user.revision));
});

const updateUser = route("patch", "/api/v1/users/{id}", async (ctx) => {
  const { user: caller } = requireAdmin();
  const user = userOr404(ctx.params.id);
  checkRevision(ctx.ifMatch(), user.revision);
  const body = await ctx.body();

  // Check everything first so a refused change leaves the user as it was.
  const displayName = optString(body, "display_name");
  const nextDisplay = displayName === undefined ? undefined : validDisplayName(displayName, user.name);
  const disabled = optBool(body, "disabled");
  if (disabled === true) {
    if (caller.id === user.id) invalid("disabled", "you cannot disable your own account");
    if (isAdmin(user) && !user.break_glass && otherActiveAdmins(user.id).length === 0) {
      return fail("users.last_administrator");
    }
  }
  const language = optString(body, "language");
  if (language !== undefined && language !== "") validLanguage(language);
  const password = optString(body, "password");
  if (password !== undefined) {
    if (user.break_glass) return fail("auth.break_glass.hardware_key_only");
    const result = checkPassword(password, {
      policy: db.settings.password_policy,
      breach: db.settings.breach_check,
      userName: user.name,
      displayName: nextDisplay ?? user.display_name,
      hostName: db.installation.host_name ?? db.node.name,
    });
    if (!result.acceptable) failPolicy("password", result.violations);
  }

  if (nextDisplay !== undefined) user.display_name = nextDisplay;
  if (language !== undefined) user.language = language === "" ? null : language;
  if (disabled !== undefined) user.disabled = disabled;
  if (password !== undefined) {
    // An administrator's password is temporary: the user changes it at the next login.
    user.password = password;
    user.password_change_required = true;
  }
  if (disabled === true || password !== undefined) revokeUserSessions(user.id);
  commit("admin", userChange(user), [user]);
  return ok(toUserInfo(user), etag(user.revision));
});

const deleteUser = route("delete", "/api/v1/users/{id}", (ctx) => {
  const { user: caller } = requireAdmin();
  const user = userOr404(ctx.params.id);
  checkRevision(ctx.ifMatch(), user.revision);
  if (caller.id === user.id) invalid("id", "you cannot delete your own account");
  if (isAdmin(user) && !user.break_glass && otherActiveAdmins(user.id).length === 0) {
    return fail("users.last_administrator");
  }
  revokeUserSessions(user.id);
  db.users = db.users.filter((u) => u.id !== user.id);
  db.tokens = db.tokens.filter((t) => t.user_id !== user.id);
  clearThrottle(user.name);
  commit("admin", { deleted: [{ kind: "user", id: user.id }], tables: ["auth.users"] });
  return noContent();
});

const setUserRoles = route("put", "/api/v1/users/{id}/roles", async (ctx) => {
  requireAdmin();
  const user = userOr404(ctx.params.id);
  checkRevision(ctx.ifMatch(), user.revision);
  const body = await ctx.body();
  const roles: RoleName[] = validRoles(body.roles);
  if (user.break_glass) invalid("roles", "the break-glass account is always admin");
  if (isAdmin(user) && !roles.includes("admin") && !user.disabled && otherActiveAdmins(user.id).length === 0) {
    return fail("users.last_administrator");
  }
  user.roles = roles;
  commit("admin", userChange(user), [user]);
  return ok(toUserInfo(user), etag(user.revision));
});

const unlockUser = route("post", "/api/v1/users/{id}/unlock", (ctx) => {
  requireAdmin();
  const user = userOr404(ctx.params.id);
  clearThrottle(user.name);
  if (user.lock) {
    user.lock = null;
    commit("admin", userChange(user), [user]);
  }
  return ok(toUserInfo(user), etag(user.revision));
});

const revokeSessionsOfUser = route("delete", "/api/v1/users/{id}/sessions", (ctx) => {
  requireAdmin();
  const user = userOr404(ctx.params.id);
  revokeUserSessions(user.id);
  return noContent();
});

const listRoles = route("get", "/api/v1/roles", () => {
  requireAdmin();
  const roles: RoleInfo[] = (["admin", "operator", "viewer"] as const).map((name) => ({
    name,
    description: ROLE_DESCRIPTIONS[name],
  }));
  return ok(wholePage(roles, db.revision));
});

// ---------------------------------------------------------------------------------
// Security settings

const MFA: readonly MfaRequirement[] = ["optional", "administrators", "everyone"];
const BREACH: readonly BreachMode[] = ["off", "online", "offline", "offline_preferred"];
const LOCKOUT: readonly LockoutMode[] = ["off", "progressive_delay", "delay_then_temporary_lock", "lock_until_unlock"];

function parsePolicy(value: unknown): PasswordPolicy {
  if (!isRecord(value)) return invalid("password_policy", "an object with a preset is required");
  const preset = oneOf(value.preset, ["pin", "standard", "hardened", "custom"] as const, "password_policy");
  if (preset !== "custom") return { preset };
  const min = optInt(value, "min_length", "password_policy");
  const max = optInt(value, "max_length", "password_policy");
  const pattern = value.pattern;
  if (min === undefined) return invalid("password_policy", "min_length is required");
  if (min < 4) invalid("password_policy", "min_length must be at least 4");
  if (max !== undefined && max < 64) invalid("password_policy", "max_length must be at least 64");
  if (max !== undefined && max > 1024) invalid("password_policy", "max_length must not exceed 1024");
  if (min > (max ?? 256)) invalid("password_policy", "min_length must not exceed max_length");
  const policy: PasswordPolicy = { preset: "custom", min_length: min };
  if (max !== undefined) policy.max_length = max;
  if (pattern !== undefined && pattern !== null) {
    if (typeof pattern !== "string" || pattern === "") invalid("password_policy", "pattern must not be empty");
    try {
      new RegExp(`^(?:${pattern as string})$`, "u");
    } catch {
      invalid("password_policy", "pattern is not a valid regular expression");
    }
    policy.pattern = pattern as string;
  }
  return policy;
}

function parseSession(value: unknown): SessionLifetime {
  if (!isRecord(value)) return invalid("session", "an object with absolute_secs and idle_secs is required");
  const absolute = optInt(value, "absolute_secs", "session");
  const idle = optInt(value, "idle_secs", "session");
  if (absolute === undefined || idle === undefined) return invalid("session", "absolute_secs and idle_secs are required");
  if (absolute < 1 || idle < 1 || idle > absolute) {
    return invalid("session", "lifetimes must be positive and idle must not exceed absolute");
  }
  return { absolute_secs: absolute, idle_secs: idle };
}

/** The new `token_max_days`: a number of days, or null for `unlimited`. */
function parseTokenLifetime(value: unknown): number | null {
  if (value === "unlimited") return null;
  if (isRecord(value) && typeof value.days === "number" && Number.isInteger(value.days) && value.days >= 1) {
    return value.days;
  }
  return invalid("token_max_lifetime", "unlimited or a number of days of at least 1 is required");
}

type S = components["schemas"];

/** The view as the document types it: toggle values are JSON values there. */
function wire(view: ReturnType<typeof settingsView>): S["SecuritySettingsView"] {
  return view as unknown as S["SecuritySettingsView"];
}

const getSecuritySettings = route("get", "/api/v1/settings/security", () => {
  const { user } = requireSession();
  if (!user.roles.includes("admin") && !user.roles.includes("operator")) {
    return fail("auth.forbidden", { detail: "this needs the admin or operator role" });
  }
  return ok(wire(settingsView()), etag(db.settingsRevision));
});

const updateSecuritySettings = route("patch", "/api/v1/settings/security", async (ctx) => {
  requireAdmin();
  checkRevision(ctx.ifMatch(), db.settingsRevision);
  const body = await ctx.body();

  // A profile switch resets every toggle to the profile first; explicit toggles apply on top.
  const profile = body.profile === undefined ? undefined : oneOf<Profile>(body.profile, PROFILES, "profile");
  const next: SecuritySettings = profile ? profileSettings(profile) : structuredClone(db.settings);
  if (body.password_policy !== undefined) next.password_policy = parsePolicy(body.password_policy);
  if (body.mfa !== undefined) next.mfa = oneOf(body.mfa, MFA, "mfa");
  const passkey = optBool(body, "passkey_for_admins");
  if (passkey !== undefined) next.passkey_for_admins = passkey;
  if (body.session !== undefined) next.session = parseSession(body.session);
  if (body.token_max_lifetime !== undefined) next.token_max_days = parseTokenLifetime(body.token_max_lifetime);
  if (body.breach_check !== undefined) next.breach_check = oneOf(body.breach_check, BREACH, "breach_check");
  if (body.lockout !== undefined) next.lockout = oneOf(body.lockout, LOCKOUT, "lockout");

  // The PIN coupling rule: no PIN while the vault holds operator secrets (IAM-07).
  if (next.password_policy.preset === "pin" && db.settings.password_policy.preset !== "pin" && db.vaultHasOperatorSecrets) {
    return fail("settings.pin_coupling");
  }

  db.settings = next;
  commit("admin", { tables: ["auth.settings"] });
  db.settingsRevision = db.revision;
  return ok(wire(settingsView()), etag(db.settingsRevision));
});

export const adminRoutes: HttpHandler[] = [
  listUsers,
  createUser,
  getUser,
  updateUser,
  deleteUser,
  setUserRoles,
  unlockUser,
  revokeSessionsOfUser,
  listRoles,
  getSecuritySettings,
  updateSecuritySettings,
];
