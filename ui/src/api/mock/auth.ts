// Who is signed in: the one "current session" of the mock (there is no cookie), the
// guards that handlers call, and the throttling of failed logins.
import type { AuthStrength, SecuritySettings, SessionInfo } from "../types";
import {
  commit,
  db,
  ensureOtherSessions,
  isAdmin,
  newDeviceRecord,
  newSessionRecord,
  type MockSession,
  type MockUser,
} from "./db";
import { policyFloor, sessionGrantsOf } from "./access-store";
import { isPinLike } from "./policy";
import { banner, lockPolicyOf } from "./profiles";
import { Problem, fail } from "./reply";
import { iso } from "./util";

export const STRENGTH_RANK: Readonly<Record<AuthStrength, number>> = {
  pin: 0,
  password: 1,
  password_totp: 2,
  passkey: 3,
  hardware_key: 4,
};

/**
 * The strength a password login gives: `pin` for a PIN (a digits-only secret under 12 characters),
 * `password` for any other secret. Without the secret the PIN preset decides.
 */
export function passwordStrength(settings: SecuritySettings, secret?: string | null): AuthStrength {
  if (typeof secret === "string") return isPinLike(secret.normalize("NFKC")) ? "pin" : "password";
  return settings.password_policy.preset === "pin" ? "pin" : "password";
}

/** The strength the profile asks of the account (TGL-02, TGL-03, IAM-09). */
export function requiredStrength(user: MockUser, settings: SecuritySettings): AuthStrength {
  if (user.break_glass) return "hardware_key";
  const admin = isAdmin(user);
  let required: AuthStrength;
  if (admin && settings.passkey_for_admins) required = "passkey";
  else if (settings.mfa === "everyone" || (settings.mfa === "administrators" && admin)) required = "password_totp";
  else required = passwordStrength(settings);
  // The stored policies of every role the user holds, globally or through a grant (IAM-06): the strictest wins.
  const floor = policyFloor(user);
  if (floor !== null && STRENGTH_RANK[floor] > STRENGTH_RANK[required]) required = floor;
  return required;
}

/** Fails with `auth.step_up_required` when the session is weaker than its account must be. */
export function requireStrength(session: MockSession, user: MockUser): void {
  const required = requiredStrength(user, db.settings);
  if (STRENGTH_RANK[session.strength] < STRENGTH_RANK[required]) {
    fail("auth.step_up_required", { params: { required } });
  }
}

/** Whether the profile asks the account for a second factor. */
export function needsSecondFactor(user: MockUser, settings: SecuritySettings): boolean {
  return STRENGTH_RANK[requiredStrength(user, settings)] >= STRENGTH_RANK.password_totp;
}

/** The session as `GET /auth/session` and the login answers show it. */
export function sessionInfo(session: MockSession, user: MockUser): SessionInfo {
  const settings = db.settings;
  const required = requiredStrength(user, settings);
  const info: SessionInfo = {
    session_id: session.id,
    user: { id: user.id, name: user.name, display_name: user.display_name },
    roles: [...user.roles],
    strength: session.strength,
    required_strength: required,
    created_at: iso(session.created_at),
    expires_at: iso(session.expires_at),
    absolute_expires_at: iso(session.absolute_expires_at),
    flags: {
      password_change_required: user.password_change_required,
      mfa_enrollment_required: STRENGTH_RANK[session.strength] < STRENGTH_RANK[required],
      break_glass: user.break_glass,
    },
    profile: settings.profile,
    banner: banner(settings),
    default_language: db.installation.language,
  };
  if (user.language) info.user.language = user.language;
  const grants = sessionGrantsOf(user.id);
  if (grants.length > 0) info.grants = grants;
  return info;
}

// ---------------------------------------------------------------------------------
// The current session

export interface Principal {
  session: MockSession;
  user: MockUser;
}

/**
 * The signed-in account, or null. An expired session is dropped and fails once with
 * `auth.session_expired`; activity extends the idle lifetime.
 */
export function currentPrincipal(): Principal | null {
  const session = db.sessions.find((s) => s.id === db.currentSessionId);
  if (!session) return null;
  const user = db.users.find((u) => u.id === session.user_id);
  const now = Date.now();
  if (!user) {
    dropSession(session.id);
    return null;
  }
  if (now >= session.expires_at || now >= session.absolute_expires_at) {
    dropSession(session.id);
    return fail("auth.session_expired");
  }
  session.last_seen_at = now;
  session.expires_at = Math.min(now + db.settings.session.idle_secs * 1000, session.absolute_expires_at);
  return { session, user };
}

/** The signed-in account; fails with `auth.unauthenticated` without one. */
export function requireSession(): Principal {
  const principal = currentPrincipal();
  if (!principal) return fail("auth.unauthenticated");
  return principal;
}

/** The signed-in administrator; fails with `auth.forbidden` for other roles. */
export function requireAdmin(): Principal {
  const principal = requireSession();
  if (!isAdmin(principal.user)) {
    return fail("auth.forbidden", { detail: "this needs the admin role" });
  }
  return principal;
}

function dropSession(id: string): void {
  db.sessions = db.sessions.filter((s) => s.id !== id);
  if (db.currentSessionId === id) db.currentSessionId = null;
}

/** Signs `user` in: the new session becomes the current one and replaces the previous one. */
export function startSession(user: MockUser, strength: AuthStrength): MockSession {
  if (db.currentSessionId) dropSession(db.currentSessionId);
  const session = newSessionRecord(db.settings, user, strength);
  db.sessions.push(session);
  db.currentSessionId = session.id;
  ensureOtherSessions(user);
  rememberDevice(user.id);
  user.last_login_at = iso(session.created_at);
  commit("admin", { objects: [{ kind: "session", id: session.id }], tables: ["auth.sessions"] }, [user]);
  return session;
}

/** A completed sign-in makes the browser a known device of the account, or renews it. */
function rememberDevice(userId: string): void {
  const now = Date.now();
  const held = db.knownDevices.find((d) => d.id === db.currentDeviceId && d.user_id === userId);
  if (held) {
    held.last_sign_in = now;
    commit("admin", { objects: [{ kind: "known_device", id: held.id }], tables: ["auth.known_devices"] });
    return;
  }
  const device = newDeviceRecord({ id: userId }, now, now);
  db.knownDevices.push(device);
  db.currentDeviceId = device.id;
  commit("admin", { objects: [{ kind: "known_device", id: device.id }], tables: ["auth.known_devices"] });
}

/** Forgets the known devices of a user (all, or the one `only`); returns how many went. */
export function forgetKnownDevices(userId: string, only?: string): number {
  const gone = db.knownDevices.filter((d) => d.user_id === userId && (only === undefined || d.id === only));
  if (gone.length === 0) return 0;
  db.knownDevices = db.knownDevices.filter((d) => !gone.includes(d));
  commit("admin", { deleted: gone.map((d) => ({ kind: "known_device", id: d.id })), tables: ["auth.known_devices"] });
  return gone.length;
}

/** Ends one session; the current session signs the mock out. */
export function endSession(id: string): void {
  dropSession(id);
  commit("admin", { deleted: [{ kind: "session", id }], tables: ["auth.sessions"] });
}

/** Ends every session of a user, forgets its known devices, and returns how many sessions there were. */
export function revokeUserSessions(userId: string): number {
  forgetKnownDevices(userId);
  const ended = db.sessions.filter((s) => s.user_id === userId);
  for (const s of ended) dropSession(s.id);
  // The sessions are gone for good: do not seed the user's other sessions again.
  db.seededSessionUsers.add(userId);
  if (ended.length > 0) {
    commit("admin", { deleted: ended.map((s) => ({ kind: "session", id: s.id })), tables: ["auth.sessions"] });
  }
  return ended.length;
}

// ---------------------------------------------------------------------------------
// Throttling of failed logins (IAM-05)

// The wait after a failure follows the lock policy of the settings: `attempts` tries, then the waits in
// order, then (in the modes that lock) a lock of `lock_secs`; in progressive delay the last wait
// repeats. The mock counts per name; the server counts per network and per account.

function throttleKey(name: string): string {
  return name.trim().toLowerCase();
}

function throttled(seconds: number): Problem {
  return new Problem("auth.throttled", {
    params: { retry_after: String(seconds) },
    headers: { "Retry-After": String(seconds) },
  });
}

/** Fails with `auth.throttled` while the delay of a name runs. */
export function checkThrottle(name: string): void {
  if (db.settings.lockout === "off") return;
  const key = throttleKey(name);
  const entry = db.throttle.get(key);
  if (!entry) return;
  const now = Date.now();
  if (entry.locked_until > now) throw throttled(Math.ceil((entry.locked_until - now) / 1000));
}

/** The seconds the next failure waits after `failures` failures, or 0 while attempts are left. */
function waitAfter(failures: number): number {
  const policy = lockPolicyOf(db.settings);
  const step = failures - policy.attempts;
  if (step < 0) return 0;
  const waits = policy.waits_secs;
  if (step < waits.length) return waits[step] ?? 0;
  if (db.settings.lockout === "progressive_delay") return waits[waits.length - 1] ?? 0;
  return policy.lock_secs;
}

/**
 * Records a failed attempt for a name and fails: with `code` (401) while the account has attempts
 * left, then with `auth.throttled` (429, `Retry-After` the wait of the lock policy).
 */
export function failAttempt(
  name: string,
  code: "auth.invalid_credentials" | "auth.totp.code_mismatch" = "auth.invalid_credentials",
): never {
  if (db.settings.lockout !== "off") {
    const key = throttleKey(name);
    const entry = db.throttle.get(key) ?? { failures: 0, locked_until: 0 };
    entry.failures += 1;
    db.throttle.set(key, entry);
    const wait = waitAfter(entry.failures);
    if (wait > 0) {
      entry.locked_until = Date.now() + wait * 1000;
      throw throttled(wait);
    }
  }
  return fail(code);
}

export function clearThrottle(name: string): void {
  db.throttle.delete(throttleKey(name));
}
