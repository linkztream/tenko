// Sign-in, sessions, password, second factors and personal tokens (/api/v1/auth/*).
import type { HttpHandler } from "msw";
import type {
  CreationOptionsJSON,
  CredentialInfo,
  FactorEnrolled,
  LoginResponse,
  Profile,
  RequestOptionsJSON,
  SecondFactorMethod,
  TokenInfo,
} from "../types";
import { PROFILES } from "../types";
import { forgetToken, isScopedRequest, issueScopedToken, parseTokenRequest } from "./access-store";
import {
  clearThrottle,
  checkThrottle,
  currentPrincipal,
  endSession,
  failAttempt,
  needsSecondFactor,
  passwordStrength,
  requireSession,
  requireStrength,
  sessionInfo,
  startSession,
} from "./auth";
import {
  commit,
  db,
  findUser,
  findUserByName,
  toSessionSummary,
  toTokenInfo,
  userChange,
  type MockChallenge,
  type MockCeremony,
  type MockUser,
} from "./db";
import { MOCK_KEY_ATTESTATION, MOCK_TOTP_CODE } from "./fixtures";
import { checkPassword } from "./policy";
import { profileSettings } from "./profiles";
import { created, fail, noContent, ok } from "./reply";
import { route, wholePage } from "./route";
import { base32, iso, normalizeCode, randomBytes, randomId, randomToken, recoveryCodes, DAY_MS, MINUTE } from "./util";
import { failPolicy, invalid, isRecord, optBool, optInt, optString, reqString } from "./validate";

const CHALLENGE_TTL_MS = 5 * MINUTE;
const CEREMONY_TTL_MS = 60_000;
const ENROLMENT_TTL_MS = 10 * MINUTE;
const KEY_AAGUID = "0123456789abcdef0123456789abcdef";
const PASSKEY_AAGUID = "00000000000000000000000000000000";
const ISSUER = "Tenko DDI";

// ---------------------------------------------------------------------------------
// Helpers

function stringsOf(body: Record<string, unknown>, ...keys: string[]): string[] {
  return keys.map((key) => {
    const value = body[key];
    if (typeof value !== "string") return fail("sys.invalid_request", { detail: `${key} must be a text` });
    return value;
  });
}

function secondFactorMethods(user: MockUser): SecondFactorMethod[] {
  const methods: SecondFactorMethod[] = [];
  if (user.totp) methods.push("totp");
  if ((user.totp || user.credentials.length > 0) && user.recovery_codes.length > 0) methods.push("recovery");
  if (user.credentials.length > 0) methods.push("webauthn");
  return methods;
}

function liveChallenge(id: string): MockChallenge {
  const challenge = db.challenges.get(id);
  if (!challenge || challenge.expires_at <= Date.now()) {
    db.challenges.delete(id);
    return fail("auth.challenge_invalid");
  }
  return challenge;
}

function liveCeremony(id: string, kind: MockCeremony["kind"]): MockCeremony {
  const ceremony = db.ceremonies.get(id);
  if (!ceremony || ceremony.kind !== kind || ceremony.expires_at <= Date.now()) {
    db.ceremonies.delete(id);
    return fail("auth.challenge_invalid");
  }
  return ceremony;
}

/** A completed login: resets the throttle and answers with the new session. */
function authenticated(user: MockUser, strength: Parameters<typeof startSession>[1]): LoginResponse {
  clearThrottle(user.name);
  const session = startSession(user, strength);
  return { status: "authenticated", session: sessionInfo(session, user) };
}

function descriptors(credentials: readonly CredentialInfo[]): NonNullable<RequestOptionsJSON["allowCredentials"]> {
  return credentials.map((c) => ({ type: "public-key", id: c.id }));
}

function wellFormedAssertion(value: unknown): boolean {
  if (!isRecord(value) || !isRecord(value.response)) return false;
  const r = value.response;
  return (
    typeof value.id === "string" &&
    value.id !== "" &&
    typeof value.rawId === "string" &&
    value.type === "public-key" &&
    typeof r.clientDataJSON === "string" &&
    typeof r.authenticatorData === "string" &&
    typeof r.signature === "string"
  );
}

function wellFormedAttestation(value: unknown): value is { id: string } {
  if (!isRecord(value) || !isRecord(value.response)) return false;
  const r = value.response;
  return (
    typeof value.id === "string" &&
    value.id !== "" &&
    typeof value.rawId === "string" &&
    value.type === "public-key" &&
    typeof r.clientDataJSON === "string" &&
    typeof r.attestationObject === "string"
  );
}

function newRecoveryCodes(user: MockUser): string[] {
  const codes = recoveryCodes(10);
  user.recovery_codes = codes;
  return codes;
}

// ---------------------------------------------------------------------------------
// Login

const loginPassword = route("post", "/api/v1/auth/login/password", async (ctx) => {
  const [name, password] = stringsOf(await ctx.body(), "user_name", "password") as [string, string];
  checkThrottle(name);
  const user = findUserByName(name);
  // A disabled account, a break-glass account and an unknown name fail like a wrong password.
  const accepted =
    user !== undefined && !user.disabled && !user.break_glass && user.password !== null && user.password === password;
  if (!accepted) failAttempt(name);
  const methods = secondFactorMethods(user);
  if (methods.length > 0) {
    const challenge: MockChallenge = { id: randomId(), user_id: user.id, expires_at: Date.now() + CHALLENGE_TTL_MS };
    db.challenges.set(challenge.id, challenge);
    return ok<LoginResponse>({
      status: "second_factor",
      challenge_id: challenge.id,
      methods,
      expires_in: CHALLENGE_TTL_MS / 1000,
    });
  }
  return ok(authenticated(user, passwordStrength(db.settings)));
});

const loginTotp = route("post", "/api/v1/auth/login/totp", async (ctx) => {
  const [challengeId, code] = stringsOf(await ctx.body(), "challenge_id", "code") as [string, string];
  const challenge = liveChallenge(challengeId);
  const user = findUser(challenge.user_id);
  if (!user) return fail("auth.challenge_invalid");
  checkThrottle(user.name);
  if (!user.totp || code.trim() !== MOCK_TOTP_CODE) failAttempt(user.name, "auth.totp.code_mismatch");
  db.challenges.delete(challenge.id);
  return ok(authenticated(user, "password_totp"));
});

const loginRecovery = route("post", "/api/v1/auth/login/recovery", async (ctx) => {
  const [challengeId, code] = stringsOf(await ctx.body(), "challenge_id", "code") as [string, string];
  const challenge = liveChallenge(challengeId);
  const user = findUser(challenge.user_id);
  if (!user) return fail("auth.challenge_invalid");
  checkThrottle(user.name);
  const wanted = normalizeCode(code);
  const index = user.recovery_codes.findIndex((c) => normalizeCode(c) === wanted);
  if (wanted === "" || index < 0) failAttempt(user.name);
  // A recovery code works once.
  user.recovery_codes.splice(index, 1);
  commit("admin", userChange(user), [user]);
  db.challenges.delete(challenge.id);
  return ok(authenticated(user, "password_totp"));
});

const logout = route("post", "/api/v1/auth/logout", () => {
  if (db.currentSessionId) endSession(db.currentSessionId);
  return noContent();
});

const getSession = route("get", "/api/v1/auth/session", () => {
  const { session, user } = requireSession();
  return ok(sessionInfo(session, user));
});

// ---------------------------------------------------------------------------------
// WebAuthn

const webauthnLoginStart = route("post", "/api/v1/auth/webauthn/login/start", async (ctx) => {
  const body = await ctx.optionalBody();
  const challengeId = optString(body, "challenge_id");
  const userName = optString(body, "user_name");
  const breakGlass = optBool(body, "break_glass") === true;

  let user: MockUser | undefined;
  let unknownUser = false;
  if (challengeId) {
    user = findUser(liveChallenge(challengeId).user_id);
  } else if (userName !== undefined && userName.trim() !== "") {
    user = findUserByName(userName);
    unknownUser = user === undefined;
  }
  if (breakGlass) {
    user = db.users.find((u) => u.break_glass);
    unknownUser = user === undefined;
  }

  const publicKey: RequestOptionsJSON = {
    challenge: randomToken(43),
    timeout: 60_000,
    rpId: ctx.url.hostname,
    allowCredentials: user ? descriptors(user.credentials) : [],
    userVerification: "preferred",
  };
  if (breakGlass) publicKey.hints = ["security-key"];

  const ceremony: MockCeremony = {
    id: randomId(),
    kind: "login",
    challenge: publicKey.challenge,
    expires_at: Date.now() + CEREMONY_TTL_MS,
    user_id: user?.id ?? null,
    challenge_id: challengeId ?? null,
    break_glass: breakGlass,
    unknown_user: unknownUser,
    label: null,
    security_key: false,
  };
  db.ceremonies.set(ceremony.id, ceremony);
  return ok({ ceremony_id: ceremony.id, public_key: publicKey });
});

const webauthnLoginFinish = route("post", "/api/v1/auth/webauthn/login/finish", async (ctx) => {
  const body = await ctx.body();
  const ceremony = liveCeremony(reqStringLoose(body, "ceremony_id"), "login");
  if (!wellFormedAssertion(body.credential)) {
    return fail("sys.invalid_request", { detail: "the credential is not a well-formed assertion" });
  }
  // A ceremony finishes once.
  db.ceremonies.delete(ceremony.id);

  let user: MockUser | undefined;
  if (ceremony.break_glass || ceremony.user_id) {
    user = ceremony.user_id ? findUser(ceremony.user_id) : undefined;
  } else if (!ceremony.unknown_user) {
    // A discoverable login: the mock lets alex in.
    user = findUserByName("alex") ?? db.users.find((u) => !u.disabled && u.credentials.length > 0);
  }
  if (!user || user.disabled || user.credentials.length === 0) return fail("auth.invalid_credentials");

  const first = user.credentials[0];
  if (first) first.last_used_at = iso(Date.now());
  if (ceremony.challenge_id) db.challenges.delete(ceremony.challenge_id);
  return ok(authenticated(user, user.break_glass ? "hardware_key" : "passkey"));
});

function reqStringLoose(body: Record<string, unknown>, key: string): string {
  const value = body[key];
  if (typeof value !== "string") return fail("sys.invalid_request", { detail: `${key} must be a text` });
  return value;
}

const webauthnRegisterStart = route("post", "/api/v1/auth/webauthn/register/start", async (ctx) => {
  const { user } = requireSession();
  const body = await ctx.optionalBody();
  const label = optString(body, "label");
  if (label !== undefined && (label.trim() === "" || Array.from(label).length > 64)) {
    invalid("label", "1 to 64 characters");
  }
  const securityKey = optBool(body, "security_key") === true;

  const publicKey: CreationOptionsJSON = {
    rp: { id: ctx.url.hostname, name: ISSUER },
    user: { id: user.handle, name: user.name, displayName: user.display_name },
    challenge: randomToken(43),
    pubKeyCredParams: [
      { type: "public-key", alg: -7 },
      { type: "public-key", alg: -8 },
      { type: "public-key", alg: -257 },
    ],
    timeout: 60_000,
    excludeCredentials: descriptors(user.credentials),
    authenticatorSelection: { residentKey: "required", requireResidentKey: true, userVerification: "preferred" },
    attestation: securityKey ? "direct" : "none",
  };
  if (securityKey) publicKey.hints = ["security-key"];

  const ceremony: MockCeremony = {
    id: randomId(),
    kind: "register",
    challenge: publicKey.challenge,
    expires_at: Date.now() + CEREMONY_TTL_MS,
    user_id: user.id,
    challenge_id: null,
    break_glass: false,
    unknown_user: false,
    label: label?.trim() ?? null,
    security_key: securityKey,
  };
  db.ceremonies.set(ceremony.id, ceremony);
  return ok({ ceremony_id: ceremony.id, public_key: publicKey });
});

const webauthnRegisterFinish = route("post", "/api/v1/auth/webauthn/register/finish", async (ctx) => {
  const { user } = requireSession();
  const body = await ctx.body();
  const ceremony = liveCeremony(reqStringLoose(body, "ceremony_id"), "register");
  if (ceremony.user_id !== user.id) return fail("auth.challenge_invalid");
  const credential = body.credential;
  if (!wellFormedAttestation(credential)) {
    return fail("sys.invalid_request", { detail: "the credential is not a well-formed attestation" });
  }
  if (db.users.some((u) => u.credentials.some((c) => c.id === credential.id))) {
    return fail("auth.webauthn.credential_exists");
  }
  db.ceremonies.delete(ceremony.id);

  const securityKey = ceremony.security_key;
  const info: CredentialInfo = {
    id: credential.id,
    label: ceremony.label ?? `${securityKey ? "Security key" : "Passkey"} ${user.credentials.length + 1}`,
    alg: -7,
    aaguid: securityKey ? KEY_AAGUID : PASSKEY_AAGUID,
    created_at: iso(Date.now()),
    backup_eligible: !securityKey,
    backup_state: false,
    hardware_key: securityKey,
    attestation: securityKey
      ? { kind: "certificate", anchored: true, ...MOCK_KEY_ATTESTATION }
      : { kind: "none" },
  };
  user.credentials.push(info);
  const hadCodes = user.recovery_codes.length > 0;
  const codes = hadCodes ? null : newRecoveryCodes(user);
  commit("admin", { ...userChange(user), tables: ["auth.users", "auth.credentials"] }, [user]);
  const enrolled: FactorEnrolled = { credential: info, reauthenticate: false };
  if (codes) enrolled.recovery_codes = codes;
  return ok(enrolled);
});

const listCredentials = route("get", "/api/v1/auth/webauthn/credentials", () => {
  const { user } = requireSession();
  return ok(wholePage(user.credentials.map((c) => structuredClone(c)), db.revision));
});

const deleteCredential = route("delete", "/api/v1/auth/webauthn/credentials/{id}", (ctx) => {
  const { user } = requireSession();
  const index = user.credentials.findIndex((c) => c.id === ctx.params.id);
  if (index < 0) return fail("auth.webauthn.credential_not_found");
  // Keep it simple: the only way to sign in, or the only second factor an account must
  // have, cannot be removed.
  const secondFactorsLeft = (user.totp ? 1 : 0) + user.credentials.length - 1;
  const onlyLogin = user.password === null && user.credentials.length === 1;
  if (onlyLogin || (needsSecondFactor(user, db.settings) && secondFactorsLeft === 0)) return fail("auth.conflict");
  user.credentials.splice(index, 1);
  if (!user.totp && user.credentials.length === 0) user.recovery_codes = [];
  commit("admin", { ...userChange(user), tables: ["auth.users", "auth.credentials"] }, [user]);
  return noContent();
});

// ---------------------------------------------------------------------------------
// Passwords

const checkPasswordRoute = route("post", "/api/v1/auth/password/check", async (ctx) => {
  const body = await ctx.body();
  const password = reqStringLoose(body, "password");
  const principal = currentPrincipal();
  if (principal) {
    const given = optString(body, "user_name");
    const named = given === undefined ? undefined : findUserByName(given);
    const subject = given === undefined ? principal.user : named;
    return ok(
      checkPassword(password, {
        policy: db.settings.password_policy,
        breach: db.settings.breach_check,
        userName: given ?? principal.user.name,
        displayName: subject?.display_name ?? null,
        hostName: db.installation.host_name ?? db.node.name,
      }),
    );
  }
  if (!db.setupOpen) return fail("auth.unauthenticated");
  // During first-run setup nobody is signed in: the chosen profile's preset applies.
  const asked = body.profile;
  const profile: Profile = PROFILES.includes(asked as Profile) ? (asked as Profile) : db.settings.profile;
  const settings = profileSettings(profile);
  return ok(
    checkPassword(password, {
      policy: settings.password_policy,
      breach: settings.breach_check,
      userName: optString(body, "user_name"),
      hostName: db.node.name,
    }),
  );
});

const changePassword = route("post", "/api/v1/auth/password", async (ctx) => {
  const { session, user } = requireSession();
  if (user.break_glass) return fail("auth.break_glass.hardware_key_only");
  const body = await ctx.body();
  const next = reqString(body, "new_password");
  const current = optString(body, "current_password");
  if (user.password !== null && current !== user.password) return fail("auth.password.incorrect");
  const result = checkPassword(next, {
    policy: db.settings.password_policy,
    breach: db.settings.breach_check,
    userName: user.name,
    displayName: user.display_name,
    hostName: db.installation.host_name ?? db.node.name,
  });
  if (!result.acceptable) failPolicy("new_password", result.violations);

  user.password = next;
  user.password_change_required = false;
  // The other sessions of the account end.
  const others = db.sessions.filter((s) => s.user_id === user.id && s.id !== session.id);
  db.sessions = db.sessions.filter((s) => !others.includes(s));
  commit(
    "admin",
    { ...userChange(user), deleted: others.map((s) => ({ kind: "session", id: s.id })) },
    [user],
  );
  return ok({ breach_check: result.breach_check, sessions_revoked: others.length });
});

// ---------------------------------------------------------------------------------
// TOTP and recovery codes

const totpEnrollStart = route("post", "/api/v1/auth/totp/enroll/start", () => {
  const { user } = requireSession();
  if (user.totp) return fail("auth.totp.already_enrolled");
  const secret = base32(randomBytes(20));
  const enrolmentId = randomId();
  db.enrolments.set(enrolmentId, {
    id: enrolmentId,
    user_id: user.id,
    secret,
    expires_at: Date.now() + ENROLMENT_TTL_MS,
  });
  const issuer = encodeURIComponent(ISSUER);
  return ok({
    enrolment_id: enrolmentId,
    secret,
    otpauth_uri: `otpauth://totp/${issuer}:${encodeURIComponent(user.name)}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30`,
    params: { algorithm: "sha1", digits: 6, period: 30, skew: 1 },
  });
});

const totpEnrollFinish = route("post", "/api/v1/auth/totp/enroll/finish", async (ctx) => {
  const { user } = requireSession();
  const body = await ctx.body();
  const [enrolmentId, code] = stringsOf(body, "enrolment_id", "code") as [string, string];
  const enrolment = db.enrolments.get(enrolmentId);
  if (!enrolment || enrolment.user_id !== user.id || enrolment.expires_at <= Date.now()) {
    db.enrolments.delete(enrolmentId);
    return fail("auth.challenge_invalid");
  }
  if (user.totp) return fail("auth.totp.already_enrolled");
  if (code.trim() !== MOCK_TOTP_CODE) return fail("auth.totp.code_mismatch", { status: 400 });
  db.enrolments.delete(enrolmentId);
  user.totp = true;
  const codes = user.recovery_codes.length > 0 ? null : newRecoveryCodes(user);
  commit("admin", userChange(user), [user]);
  const enrolled: FactorEnrolled = { reauthenticate: false };
  if (codes) enrolled.recovery_codes = codes;
  return ok(enrolled);
});

const removeTotp = route("delete", "/api/v1/auth/totp", () => {
  const { user } = requireSession();
  if (!user.totp) return fail("auth.totp.not_enrolled");
  if (needsSecondFactor(user, db.settings) && user.credentials.length === 0) return fail("auth.conflict");
  user.totp = false;
  if (user.credentials.length === 0) user.recovery_codes = [];
  commit("admin", userChange(user), [user]);
  return noContent();
});

const regenerateRecoveryCodes = route("post", "/api/v1/auth/recovery-codes", () => {
  const { user } = requireSession();
  if (!user.totp && user.credentials.length === 0) {
    return invalid("recovery_codes", "enrol TOTP or a passkey first");
  }
  const codes = newRecoveryCodes(user);
  commit("admin", userChange(user), [user]);
  return ok({ codes });
});

// ---------------------------------------------------------------------------------
// Sessions of the account

const listSessions = route("get", "/api/v1/auth/sessions", () => {
  const { user } = requireSession();
  const mine = db.sessions
    .filter((s) => s.user_id === user.id)
    .sort((a, b) => Number(b.id === db.currentSessionId) - Number(a.id === db.currentSessionId) || b.last_seen_at - a.last_seen_at);
  return ok(wholePage(mine.map(toSessionSummary), db.revision));
});

const revokeSession = route("delete", "/api/v1/auth/sessions/{id}", (ctx) => {
  const { user } = requireSession();
  const session = db.sessions.find((s) => s.id === ctx.params.id && s.user_id === user.id);
  if (!session) return fail("auth.session.not_found");
  endSession(session.id);
  return noContent();
});

// ---------------------------------------------------------------------------------
// Personal tokens

const listTokens = route("get", "/api/v1/auth/tokens", () => {
  const { user } = requireSession();
  const mine = db.tokens.filter((t) => t.user_id === user.id).map(toTokenInfo);
  mine.sort((a, b) => b.created_at.localeCompare(a.created_at));
  return ok(wholePage(mine, db.revision));
});

const createToken = route("post", "/api/v1/auth/tokens", async (ctx) => {
  const { session, user } = requireSession();
  const body = await ctx.body();
  // With grants or scopes the token is a scoped token of the caller (IAM-10, docs/access.md section 7).
  const request = parseTokenRequest(body);
  if (isScopedRequest(request)) {
    if (user.break_glass) return fail("auth.break_glass.hardware_key_only");
    requireStrength(session, user);
    const issued = issueScopedToken(user, request);
    commit("admin", { objects: [{ kind: "token", id: issued.info.id }], tables: ["auth.tokens", "auth.scoped_tokens"] });
    return created({ token: issued.token, info: issued.info });
  }
  const name = reqString(body, "name").trim();
  if (name === "" || Array.from(name).length > 100) invalid("name", "1 to 100 characters");
  const days = optInt(body, "expires_in_days");
  if (days !== undefined && days < 1) invalid("expires_in_days", "at least one day");
  const max = db.settings.token_max_days ?? null;
  if (days !== undefined && max !== null && days > max) {
    return fail("auth.token.lifetime_exceeded", { params: { max_days: String(max) } });
  }
  const lifetime = days ?? max;

  const token = `tko_${randomToken(32)}`;
  const now = Date.now();
  const info: TokenInfo = {
    id: randomId(),
    name,
    prefix: token.slice(0, 8),
    created_at: iso(now),
  };
  if (lifetime !== null) info.expires_at = iso(now + lifetime * DAY_MS);
  db.tokens.push({ user_id: user.id, info });
  commit("admin", { objects: [{ kind: "token", id: info.id }], tables: ["auth.tokens"] });
  return created({ token, info: { ...info } });
});

const revokeToken = route("delete", "/api/v1/auth/tokens/{id}", (ctx) => {
  const { user } = requireSession();
  const index = db.tokens.findIndex((t) => t.info.id === ctx.params.id && t.user_id === user.id);
  if (index < 0) return fail("auth.token.not_found");
  db.tokens.splice(index, 1);
  forgetToken(ctx.params.id);
  commit("admin", { deleted: [{ kind: "token", id: ctx.params.id }], tables: ["auth.tokens"] });
  return noContent();
});

export const authRoutes: HttpHandler[] = [
  loginPassword,
  loginTotp,
  loginRecovery,
  logout,
  getSession,
  listSessions,
  revokeSession,
  changePassword,
  checkPasswordRoute,
  totpEnrollStart,
  totpEnrollFinish,
  removeTotp,
  webauthnLoginStart,
  webauthnLoginFinish,
  webauthnRegisterStart,
  webauthnRegisterFinish,
  listCredentials,
  deleteCredential,
  regenerateRecoveryCodes,
  listTokens,
  createToken,
  revokeToken,
];
