// Who is signed in: the one "current session" of the mock (there is no cookie), the
// guards that handlers call, and the throttling of failed logins.
import type { AuthStrength, SecuritySettings, SessionInfo } from "../types";
import {
  commit,
  db,
  ensureOtherSessions,
  isAdmin,
  newSessionRecord,
  type MockSession,
  type MockUser,
} from "./db";
import { banner } from "./profiles";
import { Problem, fail } from "./reply";
import { iso } from "./util";

export const STRENGTH_RANK: Readonly<Record<AuthStrength, number>> = {
  pin: 0,
  password: 1,
  password_totp: 2,
  passkey: 3,
  hardware_key: 4,
};

/** The strength a password login gives under the settings: `pin` for the PIN preset. */
export function passwordStrength(settings: SecuritySettings): AuthStrength {
  return settings.password_policy.preset === "pin" ? "pin" : "password";
}

/** The strength the profile asks of the account (TGL-02, TGL-03, IAM-09). */
export function requiredStrength(user: MockUser, settings: SecuritySettings): AuthStrength {
  if (user.break_glass) return "hardware_key";
  const admin = isAdmin(user);
  if (admin && settings.passkey_for_admins) return "passkey";
  if (settings.mfa === "everyone" || (settings.mfa === "administrators" && admin)) return "password_totp";
  return passwordStrength(settings);
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
      mfa_enrolment_required: STRENGTH_RANK[session.strength] < STRENGTH_RANK[required],
      break_glass: user.break_glass,
    },
    profile: settings.profile,
    banner: banner(settings),
    default_language: db.installation.language,
  };
  if (user.language) info.user.language = user.language;
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
  user.last_login_at = iso(session.created_at);
  commit("admin", { objects: [{ kind: "session", id: session.id }], tables: ["auth.sessions"] }, [user]);
  return session;
}

/** Ends one session; the current session signs the mock out. */
export function endSession(id: string): void {
  dropSession(id);
  commit("admin", { deleted: [{ kind: "session", id }], tables: ["auth.sessions"] });
}

/** Ends every session of a user and returns how many there were. */
export function revokeUserSessions(userId: string): number {
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

/** Consecutive failures for one name that start the delay, and the delay in seconds. */
export const THROTTLE_FAILURES = 3;
export const THROTTLE_SECONDS = 20;

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
  // The delay is over: the count starts again.
  if (entry.locked_until !== 0) db.throttle.delete(key);
}

/**
 * Records a failed attempt for a name and fails: with `code` (401) until the third
 * consecutive failure, then with `auth.throttled` (429, `Retry-After: 20`).
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
    if (entry.failures >= THROTTLE_FAILURES) {
      entry.locked_until = Date.now() + THROTTLE_SECONDS * 1000;
      throw throttled(THROTTLE_SECONDS);
    }
  }
  return fail(code);
}

export function clearThrottle(name: string): void {
  db.throttle.delete(throttleKey(name));
}
