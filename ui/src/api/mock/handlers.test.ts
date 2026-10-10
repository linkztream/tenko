// The mock API through `fetch`, against the msw server that src/app/testing/setup.ts starts.
// In jsdom the base URL is http://localhost:3000; the fetch interceptor resolves relative
// URLs against it, and the handlers' relative paths match the same way.
import { afterEach, describe, expect, it, vi } from "vitest";
import { apiOperations } from "../generated/operations";
import type {
  CreatedToken,
  CredentialInfo,
  LoginResponse,
  Page,
  PasswordCheckResult,
  SecuritySettingsView,
  SessionInfo,
  SessionSummary,
  SetupResult,
  SetupState,
  SystemStatus,
  TokenInfo,
  TotpEnrolment,
  UserInfo,
  WebAuthnLoginOptions,
  WebAuthnRegisterOptions,
} from "../types";
import {
  BREACHED_PASSWORDS,
  MOCK_PASSWORDS,
  MOCK_RECOVERY_CODES,
  MOCK_SETUP_TOKEN,
  MOCK_TOTP_CODE,
  MOCK_USER_IDS,
} from "./fixtures";
import {
  INITIAL_REVISION,
  MOCK_SCENARIOS,
  JOURNAL_CAPACITY,
  db,
  resetMockDb,
  type MockScenario,
} from "./db";
import { handlers, ok, route } from "./handlers";
import { checkPassword, isTrivial } from "./policy";
import { PROFILE_MATRIX, banner, profileSettings, toggleStates } from "./profiles";
import { FetchEventSource } from "./event-source";
import { advanceMockJobs } from "./job-store";
import { emitMockEvent, openStreamCount } from "./sse";

// ---------------------------------------------------------------------------------
// Helpers

interface Answer<T> {
  res: Response;
  status: number;
  body: T;
}

interface CallInit {
  json?: unknown;
  headers?: Record<string, string>;
}

async function call<T = unknown>(method: string, path: string, init: CallInit = {}): Promise<Answer<T>> {
  const headers: Record<string, string> = { accept: "application/json", ...init.headers };
  if (init.json !== undefined) headers["content-type"] = "application/json";
  const res = await fetch(path, {
    method,
    headers,
    body: init.json === undefined ? null : JSON.stringify(init.json),
  });
  const text = await res.text();
  const json = (res.headers.get("content-type") ?? "").includes("json");
  return { res, status: res.status, body: (text && json ? JSON.parse(text) : text || undefined) as T };
}

const get = <T>(path: string, init?: CallInit) => call<T>("GET", path, init);
const post = <T>(path: string, json?: unknown, init: CallInit = {}) => call<T>("POST", path, { ...init, json });
const patch = <T>(path: string, json: unknown, init: CallInit = {}) => call<T>("PATCH", path, { ...init, json });
const put = <T>(path: string, json: unknown, init: CallInit = {}) => call<T>("PUT", path, { ...init, json });
const del = <T>(path: string, init?: CallInit) => call<T>("DELETE", path, init);

interface Problem {
  type: string;
  status: number;
  code: string;
  title: string;
  detail: string;
  params: Record<string, string>;
  errors?: { field: string; code: string; params?: Record<string, string> }[];
}

function expectProblem(answer: Answer<unknown>, status: number, code: string): Problem {
  expect(answer.status).toBe(status);
  expect(answer.res.headers.get("content-type")).toContain("application/problem+json");
  const body = answer.body as Problem;
  expect(body.type).toBe("about:blank");
  expect(body.status).toBe(status);
  expect(body.code).toBe(code);
  expect(typeof body.title).toBe("string");
  expect(typeof body.detail).toBe("string");
  expect(body.params).toBeTypeOf("object");
  return body;
}

async function loginAs(name: keyof typeof MOCK_PASSWORDS): Promise<SessionInfo> {
  const answer = await post<LoginResponse>("/api/v1/auth/login/password", {
    user_name: name,
    password: MOCK_PASSWORDS[name],
  });
  expect(answer.status).toBe(200);
  if (answer.body.status !== "authenticated") throw new Error("a second factor is required");
  return answer.body.session;
}

interface SseMessage {
  id: string | null;
  event: string;
  data: { topic?: string; revision?: number; reason?: string; objects?: { kind: string; id: string }[]; [k: string]: unknown };
}

/** Opens the event stream and reads its messages one by one. */
async function openStream(query = "") {
  const res = await fetch(`/api/v1/events${query}`, { headers: { accept: "text/event-stream" } });
  expect(res.status).toBe(200);
  expect(res.headers.get("content-type")).toContain("text/event-stream");
  const reader = res.body!.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

  function parse(raw: string): SseMessage {
    let id: string | null = null;
    let event = "message";
    let data = "";
    for (const line of raw.split("\n")) {
      if (line.startsWith("id: ")) id = line.slice(4);
      else if (line.startsWith("event: ")) event = line.slice(7);
      else if (line.startsWith("data: ")) data += line.slice(6);
    }
    return { id, event, data: JSON.parse(data) as SseMessage["data"] };
  }

  let pending: Promise<void> | null = null;
  let ended = false;

  /** Reads one chunk into the buffer; concurrent callers share the read. */
  function pump(): Promise<void> {
    pending ??= reader.read().then(({ value, done }) => {
      pending = null;
      if (done) ended = true;
      else buffer += decoder.decode(value, { stream: true });
    });
    return pending;
  }

  function take(): SseMessage | null {
    for (;;) {
      const end = buffer.indexOf("\n\n");
      if (end < 0) return null;
      const raw = buffer.slice(0, end);
      buffer = buffer.slice(end + 2);
      // Comments and the retry hint carry no data and are no events.
      if (raw.split("\n").some((line) => line.startsWith("data: "))) return parse(raw);
    }
  }

  async function read(abandoned: { value: boolean }): Promise<SseMessage | null> {
    for (;;) {
      if (abandoned.value) return null;
      const message = take();
      if (message) return message;
      if (ended) throw new Error("the stream ended");
      await pump();
    }
  }

  async function next(): Promise<SseMessage> {
    const message = await read({ value: false });
    if (!message) throw new Error("no message");
    return message;
  }

  /** The next message, or null when none arrives within `ms` (nothing is lost then). */
  async function nextWithin(ms: number): Promise<SseMessage | null> {
    const abandoned = { value: false };
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<null>((resolve) => {
      timer = setTimeout(() => {
        abandoned.value = true;
        resolve(null);
      }, ms);
    });
    try {
      return await Promise.race([read(abandoned), timeout]);
    } finally {
      clearTimeout(timer);
    }
  }

  return { next, nextWithin, close: () => reader.cancel() };
}

afterEach(() => {
  vi.useRealTimers();
});

// ---------------------------------------------------------------------------------
// Every operation has a handler

describe("operations", () => {
  it("answers every operation of the document instead of leaving it unhandled", async () => {
    // The server runs with onUnhandledFrame "error", so an unhandled request would reject.
    for (const operation of apiOperations) {
      const path = operation.path.replace(/\{index\}/g, "0").replace(/\{[^}]+\}/g, "dummy");
      const answer = await call(operation.method.toUpperCase(), path, {
        json: operation.method === "get" || operation.method === "delete" ? undefined : {},
      });
      expect(answer.status, `${operation.method} ${operation.path}`).toBeGreaterThanOrEqual(200);
      expect(answer.status, `${operation.method} ${operation.path}`).toBeLessThan(600);
    }
  });

  it("registers a stub for every operation after the happy paths", () => {
    expect(handlers.length).toBeGreaterThanOrEqual(apiOperations.length);
  });

  it("answers an operation without a mock with a 501 problem", async () => {
    const answer = await get("/api/v1/metrics");
    const problem = expectProblem(answer, 501, "sys.not_implemented");
    expect(problem.title).toBe("Not implemented");
    expect(problem.detail).toBe("GET /api/v1/metrics is not implemented yet");
    expect(problem.params).toEqual({ method: "GET", path: "/api/v1/metrics" });
  });

  it("tries a static path before a parameterised one", async () => {
    resetMockDb("signed-in");
    const tree = await get<{ nodes: unknown[] }>("/api/v1/prefixes/tree");
    expect(tree.status).toBe(200);
    expect(Array.isArray(tree.body.nodes)).toBe(true);
    // "abc" reaches the parameterised route, which refuses an id that is not a UUID.
    expect((await get("/api/v1/prefixes/abc")).status).toBe(400);
    resetMockDb();
    // A static path that no mock answers yet still reaches its stub.
    const stub = expectProblem(await get("/api/v1/openapi.json"), 501, "sys.not_implemented");
    expect(stub.params.path).toBe("/api/v1/openapi.json");
  });

  it("does not compile a handler for a path that is not in the document", () => {
    // Compile-time check only: the function is never called.
    void function typeChecks() {
      // @ts-expect-error /api/v1/nope is not an operation
      route("get", "/api/v1/nope", () => ok({}));
      // @ts-expect-error /api/v1/users has no DELETE
      route("delete", "/api/v1/users", () => ok({}));
      // @ts-expect-error the reply must match the operation's response type
      route("get", "/api/v1/auth/session", () => ok({ not: "a session" }));
    };
  });

  it("starts in every scenario", () => {
    for (const scenario of MOCK_SCENARIOS) {
      resetMockDb(scenario);
      expect(db.scenario).toBe(scenario);
      expect(db.revision).toBe(INITIAL_REVISION);
    }
  });
});

// ---------------------------------------------------------------------------------
// Sign-in

describe("session", () => {
  it("answers 401 without a session", async () => {
    const problem = expectProblem(await get("/api/v1/auth/session"), 401, "auth.unauthenticated");
    expect(problem.title).toBeTruthy();
  });

  it("signs sam in directly", async () => {
    const session = await loginAs("sam");
    expect(session.user).toMatchObject({ name: "sam", display_name: "Sam Example", language: "sv" });
    expect(session.roles).toEqual(["operator"]);
    expect(session.strength).toBe("password");
    expect(session.required_strength).toBe("password");
    expect(session.profile).toBe("standard");
    expect(session.flags).toEqual({ password_change_required: false, mfa_enrolment_required: false, break_glass: false });
    expect(session.banner).toEqual({ lab: false, weaker_than_home: false, deviations: [] });
    expect(session.default_language).toBeNull();
    expect(Date.parse(session.expires_at)).toBeLessThanOrEqual(Date.parse(session.absolute_expires_at));

    const current = await get<SessionInfo>("/api/v1/auth/session");
    expect(current.status).toBe(200);
    // Activity extends the idle lifetime; everything else is the same.
    expect(current.body).toEqual({ ...session, expires_at: expect.any(String) });
  });

  it("logs out with 204 and the session is gone", async () => {
    await loginAs("sam");
    const out = await post("/api/v1/auth/logout");
    expect(out.status).toBe(204);
    expectProblem(await get("/api/v1/auth/session"), 401, "auth.unauthenticated");
  });

  it("does not tell a wrong password from an unknown, disabled or password-less account", async () => {
    const wrong = expectProblem(
      await post("/api/v1/auth/login/password", { user_name: "sam", password: "not-the-password" }),
      401,
      "auth.invalid_credentials",
    );
    const unknown = expectProblem(
      await post("/api/v1/auth/login/password", { user_name: "nobody", password: "whatever" }),
      401,
      "auth.invalid_credentials",
    );
    expect(unknown.title).toBe(wrong.title);
    expect(unknown.detail).toBe(wrong.detail);
    expectProblem(
      await post("/api/v1/auth/login/password", { user_name: "robin", password: MOCK_PASSWORDS.robin }),
      401,
      "auth.invalid_credentials",
    );
    expectProblem(
      await post("/api/v1/auth/login/password", { user_name: "breakglass", password: MOCK_PASSWORDS.breakglass }),
      401,
      "auth.invalid_credentials",
    );
  });

  it("asks alex for a second factor and accepts the TOTP code", async () => {
    const start = await post<LoginResponse>("/api/v1/auth/login/password", {
      user_name: "alex",
      password: MOCK_PASSWORDS.alex,
    });
    expect(start.status).toBe(200);
    expect(start.body).toMatchObject({ status: "second_factor", methods: ["totp", "recovery", "webauthn"], expires_in: 300 });
    if (start.body.status !== "second_factor") throw new Error("expected a challenge");
    const challenge = start.body.challenge_id;

    expectProblem(await get("/api/v1/auth/session"), 401, "auth.unauthenticated");
    expectProblem(
      await post("/api/v1/auth/login/totp", { challenge_id: challenge, code: "000000" }),
      401,
      "auth.totp.code_mismatch",
    );
    expectProblem(
      await post("/api/v1/auth/login/totp", { challenge_id: "unknown", code: MOCK_TOTP_CODE }),
      401,
      "auth.challenge_invalid",
    );
    const done = await post<LoginResponse>("/api/v1/auth/login/totp", { challenge_id: challenge, code: MOCK_TOTP_CODE });
    expect(done.status).toBe(200);
    if (done.body.status !== "authenticated") throw new Error("expected a session");
    expect(done.body.session.user.name).toBe("alex");
    expect(done.body.session.strength).toBe("password_totp");
    expect(done.body.session.roles).toEqual(["admin"]);

    // The challenge is used up.
    expectProblem(
      await post("/api/v1/auth/login/totp", { challenge_id: challenge, code: MOCK_TOTP_CODE }),
      401,
      "auth.challenge_invalid",
    );
  });

  it("accepts a recovery code once", async () => {
    const challengeOf = async (): Promise<string> => {
      const start = await post<LoginResponse>("/api/v1/auth/login/password", {
        user_name: "alex",
        password: MOCK_PASSWORDS.alex,
      });
      if (start.body.status !== "second_factor") throw new Error("expected a challenge");
      return start.body.challenge_id;
    };
    const code = MOCK_RECOVERY_CODES[0] as string;

    const first = await post<LoginResponse>("/api/v1/auth/login/recovery", { challenge_id: await challengeOf(), code });
    expect(first.status).toBe(200);
    expect(first.body.status).toBe("authenticated");
    const me = await get<UserInfo[]>("/api/v1/auth/session");
    expect(me.status).toBe(200);

    const second = await post("/api/v1/auth/login/recovery", { challenge_id: await challengeOf(), code });
    expectProblem(second, 401, "auth.invalid_credentials");
    // The other nine still work, with or without the dash.
    const other = await post<LoginResponse>("/api/v1/auth/login/recovery", {
      challenge_id: await challengeOf(),
      code: (MOCK_RECOVERY_CODES[1] as string).toLowerCase().replace("-", ""),
    });
    expect(other.body.status).toBe("authenticated");
  });

  it("throttles after three failures and lifts after 20 seconds", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date("2026-10-09T12:00:00Z"));
    const wrong = () => post("/api/v1/auth/login/password", { user_name: "sam", password: "wrong-password" });

    expectProblem(await wrong(), 401, "auth.invalid_credentials");
    expectProblem(await wrong(), 401, "auth.invalid_credentials");
    const third = await wrong();
    const problem = expectProblem(third, 429, "auth.throttled");
    expect(problem.params).toEqual({ retry_after: "20" });
    expect(third.res.headers.get("retry-after")).toBe("20");

    // Even the right password waits, and the wait counts down.
    const early = await post("/api/v1/auth/login/password", { user_name: "sam", password: MOCK_PASSWORDS.sam });
    expect(expectProblem(early, 429, "auth.throttled").params.retry_after).toBe("20");
    vi.advanceTimersByTime(19_000);
    const late = await post("/api/v1/auth/login/password", { user_name: "SAM", password: MOCK_PASSWORDS.sam });
    expect(expectProblem(late, 429, "auth.throttled").params.retry_after).toBe("1");
    expect(late.res.headers.get("retry-after")).toBe("1");

    vi.advanceTimersByTime(1_000);
    const ok = await post<LoginResponse>("/api/v1/auth/login/password", { user_name: "sam", password: MOCK_PASSWORDS.sam });
    expect(ok.status).toBe(200);
    expect(ok.body.status).toBe("authenticated");

    // The count starts again: two more failures are plain 401s.
    await post("/api/v1/auth/logout");
    expectProblem(await wrong(), 401, "auth.invalid_credentials");
    expectProblem(await wrong(), 401, "auth.invalid_credentials");
    expectProblem(await wrong(), 429, "auth.throttled");
  });

  it("does not throttle a profile whose lockout is off", async () => {
    resetMockDb("lab");
    await post("/api/v1/auth/logout");
    for (let i = 0; i < 5; i += 1) {
      expectProblem(
        await post("/api/v1/auth/login/password", { user_name: "sam", password: "wrong-password" }),
        401,
        "auth.invalid_credentials",
      );
    }
  });

  it("rejects a malformed login body", async () => {
    expectProblem(await post("/api/v1/auth/login/password", { user_name: "sam" }), 400, "sys.invalid_request");
    const res = await fetch("/api/v1/auth/login/password", { method: "POST", body: "{not json" });
    expect(res.status).toBe(400);
  });

  it("expires an idle session", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date("2026-10-09T12:00:00Z"));
    await loginAs("sam");
    vi.advanceTimersByTime(30 * 60_000);
    expect((await get("/api/v1/auth/session")).status).toBe(200);
    // One hour idle under the Standard profile.
    vi.advanceTimersByTime(61 * 60_000);
    expectProblem(await get("/api/v1/auth/session"), 401, "auth.session_expired");
    expectProblem(await get("/api/v1/auth/session"), 401, "auth.unauthenticated");
  });
});

// ---------------------------------------------------------------------------------
// WebAuthn

describe("webauthn", () => {
  it("logs in with a discoverable passkey as alex, once per ceremony", async () => {
    const start = await post<WebAuthnLoginOptions>("/api/v1/auth/webauthn/login/start", {});
    expect(start.status).toBe(200);
    const { ceremony_id, public_key } = start.body;
    expect(public_key).toMatchObject({
      rpId: "localhost",
      timeout: 60000,
      userVerification: "preferred",
      allowCredentials: [],
    });
    expect(public_key.challenge).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(public_key.hints).toBeUndefined();
    // A new ceremony has a new challenge.
    const again = await post<WebAuthnLoginOptions>("/api/v1/auth/webauthn/login/start");
    expect(again.body.public_key.challenge).not.toBe(public_key.challenge);

    const credential = assertion();
    const finish = await post<LoginResponse>("/api/v1/auth/webauthn/login/finish", { ceremony_id, credential });
    expect(finish.status).toBe(200);
    if (finish.body.status !== "authenticated") throw new Error("expected a session");
    expect(finish.body.session.user.name).toBe("alex");
    expect(finish.body.session.strength).toBe("passkey");
    expect(finish.body.session.flags.break_glass).toBe(false);

    expectProblem(
      await post("/api/v1/auth/webauthn/login/finish", { ceremony_id, credential }),
      401,
      "auth.challenge_invalid",
    );
    expectProblem(
      await post("/api/v1/auth/webauthn/login/finish", { ceremony_id: "unknown", credential }),
      401,
      "auth.challenge_invalid",
    );
  });

  it("refuses a credential that is not well formed", async () => {
    const start = await post<WebAuthnLoginOptions>("/api/v1/auth/webauthn/login/start", {});
    expectProblem(
      await post("/api/v1/auth/webauthn/login/finish", {
        ceremony_id: start.body.ceremony_id,
        credential: { id: "x", type: "public-key" },
      }),
      400,
      "sys.invalid_request",
    );
    // The ceremony was not used up by the bad attempt.
    const retry = await post("/api/v1/auth/webauthn/login/finish", {
      ceremony_id: start.body.ceremony_id,
      credential: assertion(),
    });
    expect(retry.status).toBe(200);
  });

  it("names the account's credentials for a user name or a password challenge", async () => {
    const byName = await post<WebAuthnLoginOptions>("/api/v1/auth/webauthn/login/start", { user_name: "alex" });
    expect(byName.body.public_key.allowCredentials).toHaveLength(1);

    const password = await post<LoginResponse>("/api/v1/auth/login/password", {
      user_name: "alex",
      password: MOCK_PASSWORDS.alex,
    });
    if (password.body.status !== "second_factor") throw new Error("expected a challenge");
    const start = await post<WebAuthnLoginOptions>("/api/v1/auth/webauthn/login/start", {
      challenge_id: password.body.challenge_id,
    });
    expect(start.body.public_key.allowCredentials).toEqual(byName.body.public_key.allowCredentials);
    const finish = await post<LoginResponse>("/api/v1/auth/webauthn/login/finish", {
      ceremony_id: start.body.ceremony_id,
      credential: assertion(),
    });
    expect(finish.body.status).toBe("authenticated");
    // The password challenge is used up as well.
    expectProblem(
      await post("/api/v1/auth/login/totp", { challenge_id: password.body.challenge_id, code: MOCK_TOTP_CODE }),
      401,
      "auth.challenge_invalid",
    );
    expectProblem(
      await post("/api/v1/auth/webauthn/login/start", { challenge_id: "unknown" }),
      401,
      "auth.challenge_invalid",
    );
  });

  it("logs the break-glass account in with its hardware key", async () => {
    const start = await post<WebAuthnLoginOptions>("/api/v1/auth/webauthn/login/start", { break_glass: true });
    expect(start.body.public_key.hints).toEqual(["security-key"]);
    const finish = await post<LoginResponse>("/api/v1/auth/webauthn/login/finish", {
      ceremony_id: start.body.ceremony_id,
      credential: assertion(),
    });
    if (finish.body.status !== "authenticated") throw new Error("expected a session");
    expect(finish.body.session.user.name).toBe("breakglass");
    expect(finish.body.session.strength).toBe("hardware_key");
    expect(finish.body.session.flags.break_glass).toBe(true);
    expect(finish.body.session.roles).toEqual(["admin"]);
  });

  it("registers a passkey and a security key", async () => {
    resetMockDb("signed-in");
    const before = await get<Page<CredentialInfo>>("/api/v1/auth/webauthn/credentials");
    expect(before.body.items).toHaveLength(1);
    const existing = before.body.items[0] as CredentialInfo;

    const start = await post<WebAuthnRegisterOptions>("/api/v1/auth/webauthn/register/start", { label: "Phone" });
    const options = start.body.public_key;
    expect(options.rp).toEqual({ id: "localhost", name: "Tenko DDI" });
    expect(options.user).toMatchObject({ name: "alex", displayName: "Alex Example" });
    expect(atob(options.user.id.replace(/-/g, "+").replace(/_/g, "/")).length).toBe(16);
    expect(options.pubKeyCredParams.map((p) => p.alg)).toEqual([-7, -8, -257]);
    expect(options.excludeCredentials).toEqual([{ type: "public-key", id: existing.id }]);
    expect(options.authenticatorSelection).toEqual({ residentKey: "required", requireResidentKey: true, userVerification: "preferred" });
    expect(options.attestation).toBe("none");
    expect(options.hints).toBeUndefined();

    const finish = await post<{ recovery_codes?: string[]; credential?: { label: string }; reauthenticate: boolean }>(
      "/api/v1/auth/webauthn/register/finish",
      {
      ceremony_id: start.body.ceremony_id,
      credential: attestation("new-passkey-id"),
    });
    expect(finish.status).toBe(200);
    // alex has recovery codes already: no new ones.
    expect(finish.body.recovery_codes).toBeUndefined();
    expect(finish.body.reauthenticate).toBe(false);
    expect(finish.body.credential).toBeDefined();

    const key = await post<WebAuthnRegisterOptions>("/api/v1/auth/webauthn/register/start", {
      label: "Safe key",
      security_key: true,
    });
    expect(key.body.public_key.attestation).toBe("direct");
    expect(key.body.public_key.hints).toEqual(["security-key"]);
    expect(key.body.public_key.excludeCredentials).toHaveLength(2);
    await post("/api/v1/auth/webauthn/register/finish", {
      ceremony_id: key.body.ceremony_id,
      credential: attestation("new-key-id"),
    });

    const after = await get<Page<CredentialInfo>>("/api/v1/auth/webauthn/credentials");
    expect(after.body.items.map((c) => [c.label, c.hardware_key])).toEqual([
      ["Laptop passkey", false],
      ["Phone", false],
      ["Safe key", true],
    ]);
    expect(after.body.items[2]?.attestation).toMatchObject({ kind: "certificate" });

    // The same credential id cannot be registered twice.
    const dup = await post<WebAuthnRegisterOptions>("/api/v1/auth/webauthn/register/start");
    expectProblem(
      await post("/api/v1/auth/webauthn/register/finish", {
        ceremony_id: dup.body.ceremony_id,
        credential: attestation("new-key-id"),
      }),
      409,
      "auth.webauthn.credential_exists",
    );
  });

  it("gives recovery codes with the first factor of an account that had none", async () => {
    await loginAs("sam");
    const start = await post<WebAuthnRegisterOptions>("/api/v1/auth/webauthn/register/start");
    const finish = await post<{ recovery_codes?: string[] }>("/api/v1/auth/webauthn/register/finish", {
      ceremony_id: start.body.ceremony_id,
      credential: attestation("sam-passkey"),
    });
    expect(finish.body.recovery_codes).toHaveLength(10);
    const users = await get("/api/v1/users");
    expectProblem(users, 403, "auth.forbidden");
  });

  it("needs a session to register and refuses to remove the last way in", async () => {
    expectProblem(await post("/api/v1/auth/webauthn/register/start"), 401, "auth.unauthenticated");

    resetMockDb("signed-in");
    const list = await get<Page<CredentialInfo>>("/api/v1/auth/webauthn/credentials");
    const passkey = list.body.items[0] as CredentialInfo;
    expectProblem(await del("/api/v1/auth/webauthn/credentials/unknown"), 404, "auth.webauthn.credential_not_found");

    // Standard asks administrators for a second factor: TOTP is left, so the passkey can go,
    // but then TOTP is the last one.
    expect((await del(`/api/v1/auth/webauthn/credentials/${passkey.id}`)).status).toBe(204);
    expectProblem(await del("/api/v1/auth/totp"), 409, "auth.conflict");

    // The break-glass account has no password: its only key stays.
    const start = await post<WebAuthnLoginOptions>("/api/v1/auth/webauthn/login/start", { break_glass: true });
    await post("/api/v1/auth/webauthn/login/finish", { ceremony_id: start.body.ceremony_id, credential: assertion() });
    const keys = await get<Page<CredentialInfo>>("/api/v1/auth/webauthn/credentials");
    const key = keys.body.items[0] as CredentialInfo;
    expectProblem(await del(`/api/v1/auth/webauthn/credentials/${key.id}`), 409, "auth.conflict");
  });
});

function assertion() {
  return {
    id: "credential-id",
    rawId: "credential-id",
    type: "public-key",
    response: { clientDataJSON: "e30", authenticatorData: "AAAA", signature: "AAAA" },
    clientExtensionResults: {},
  };
}

function attestation(id: string) {
  return {
    id,
    rawId: id,
    type: "public-key",
    response: { clientDataJSON: "e30", attestationObject: "AAAA", transports: ["internal"] },
    clientExtensionResults: {},
  };
}

// ---------------------------------------------------------------------------------
// TOTP, recovery codes, password

describe("factors", () => {
  it("enrols TOTP and hands out recovery codes", async () => {
    await loginAs("sam");
    const start = await post<TotpEnrolment>("/api/v1/auth/totp/enroll/start");
    expect(start.status).toBe(200);
    expect(start.body.secret).toMatch(/^[A-Z2-7]{32}$/);
    expect(start.body.otpauth_uri).toBe(
      `otpauth://totp/Tenko%20DDI:sam?secret=${start.body.secret}&issuer=Tenko%20DDI&algorithm=SHA1&digits=6&period=30`,
    );
    expect(start.body.params).toEqual({ algorithm: "sha1", digits: 6, period: 30, skew: 1 });

    expectProblem(
      await post("/api/v1/auth/totp/enroll/finish", { enrolment_id: start.body.enrolment_id, code: "999999" }),
      400,
      "auth.totp.code_mismatch",
    );
    expectProblem(
      await post("/api/v1/auth/totp/enroll/finish", { enrolment_id: "unknown", code: MOCK_TOTP_CODE }),
      401,
      "auth.challenge_invalid",
    );
    const finish = await post<{ recovery_codes?: string[]; reauthenticate: boolean }>("/api/v1/auth/totp/enroll/finish", {
      enrolment_id: start.body.enrolment_id,
      code: MOCK_TOTP_CODE,
    });
    expect(finish.status).toBe(200);
    expect(finish.body.recovery_codes).toHaveLength(10);
    expect(finish.body.reauthenticate).toBe(false);

    expectProblem(await post("/api/v1/auth/totp/enroll/start"), 409, "auth.totp.already_enrolled");
    expect((await del("/api/v1/auth/totp")).status).toBe(204);
    expectProblem(await del("/api/v1/auth/totp"), 409, "auth.totp.not_enrolled");
  });

  it("replaces the recovery codes", async () => {
    resetMockDb("signed-in");
    const fresh = await post<{ codes: string[] }>("/api/v1/auth/recovery-codes");
    expect(fresh.status).toBe(200);
    expect(fresh.body.codes).toHaveLength(10);
    expect(new Set(fresh.body.codes).size).toBe(10);
    for (const code of fresh.body.codes) expect(code).toMatch(/^[A-Z2-9]{4}-[A-Z2-9]{4}$/);

    await post("/api/v1/auth/logout");
    const start = await post<LoginResponse>("/api/v1/auth/login/password", {
      user_name: "alex",
      password: MOCK_PASSWORDS.alex,
    });
    if (start.body.status !== "second_factor") throw new Error("expected a challenge");
    expectProblem(
      await post("/api/v1/auth/login/recovery", {
        challenge_id: start.body.challenge_id,
        code: MOCK_RECOVERY_CODES[2],
      }),
      401,
      "auth.invalid_credentials",
    );
    const good = await post<LoginResponse>("/api/v1/auth/login/recovery", {
      challenge_id: start.body.challenge_id,
      code: fresh.body.codes[0],
    });
    expect(good.body.status).toBe("authenticated");
  });

  it("needs a factor before recovery codes", async () => {
    await loginAs("sam");
    expectProblem(await post("/api/v1/auth/recovery-codes"), 400, "auth.invalid_request");
  });

  it("needs a session for every factor endpoint", async () => {
    for (const [method, path] of [
      ["POST", "/api/v1/auth/totp/enroll/start"],
      ["POST", "/api/v1/auth/totp/enroll/finish"],
      ["DELETE", "/api/v1/auth/totp"],
      ["POST", "/api/v1/auth/recovery-codes"],
      ["GET", "/api/v1/auth/webauthn/credentials"],
      ["GET", "/api/v1/auth/sessions"],
      ["GET", "/api/v1/auth/tokens"],
      ["POST", "/api/v1/auth/tokens"],
      ["POST", "/api/v1/auth/password"],
    ] as const) {
      expectProblem(await call(method, path, { json: method === "POST" ? {} : undefined }), 401, "auth.unauthenticated");
    }
  });
});

describe("password", () => {
  it("checks a password during setup with the chosen profile", async () => {
    resetMockDb("setup");
    const check = (password: string, profile?: string) =>
      post<PasswordCheckResult>("/api/v1/auth/password/check", { password, profile, user_name: "admin" });

    const pin = await check("4821", "home");
    expect(pin.status).toBe(200);
    expect(pin.body).toMatchObject({ acceptable: true, violations: [], breach_check: "clean", policy: { preset: "pin" } });

    expect((await check("0000", "home")).body.violations).toEqual([{ kind: "trivial" }, { kind: "breached" }]);
    expect((await check("12ab", "home")).body.violations).toEqual([{ kind: "pin_digits_only" }]);
    expect((await check("12", "home")).body.violations).toEqual([{ kind: "too_short", min: 4 }, { kind: "trivial" }]);

    const standard = await check("short", "standard");
    expect(standard.body.violations).toEqual([{ kind: "too_short", min: 12 }]);
    expect(standard.body.policy).toEqual({ preset: "standard" });
    expect((await check("sixteen-chars-ok", "hardened")).body.acceptable).toBe(true);
    expect((await check("fifteen-chars-x", "hardened")).body.violations).toEqual([{ kind: "too_short", min: 16 }]);

    // The Lab profile does not check for breaches.
    const lab = await check("0000", "lab");
    expect(lab.body.breach_check).toBe("off");
    expect(lab.body.violations).toEqual([{ kind: "trivial" }]);
  });

  it("needs a session once setup is closed", async () => {
    expectProblem(await post("/api/v1/auth/password/check", { password: "x" }), 401, "auth.unauthenticated");
    await loginAs("sam");
    const answer = await post<PasswordCheckResult>("/api/v1/auth/password/check", { password: "sam-and-tenko-1" });
    expect(answer.body.violations).toEqual([
      { kind: "context_specific", context: "user_name" },
      { kind: "context_specific", context: "product" },
    ]);
  });

  it("changes a password and ends the other sessions", async () => {
    await loginAs("sam");
    const change = (current: string | null, next: string) =>
      post<{ breach_check: string; sessions_revoked: number }>("/api/v1/auth/password", {
        current_password: current,
        new_password: next,
      });

    expectProblem(await change("wrong", "a-long-enough-new-one"), 400, "auth.password.incorrect");
    const weak = expectProblem(await change(MOCK_PASSWORDS.sam, "short"), 400, "auth.password.policy");
    expect(weak.errors).toEqual([{ field: "new_password", code: "auth.password.too_short", params: { min: "12" } }]);

    const sessions = await get<Page<SessionSummary>>("/api/v1/auth/sessions");
    expect(sessions.body.items).toHaveLength(3);
    const done = await change(MOCK_PASSWORDS.sam, "a-long-enough-new-one");
    expect(done.status).toBe(200);
    expect(done.body).toEqual({ breach_check: "clean", sessions_revoked: 2 });
    expect((await get<Page<SessionSummary>>("/api/v1/auth/sessions")).body.items).toHaveLength(1);

    // The new password signs in, the old one does not.
    await post("/api/v1/auth/logout");
    expectProblem(
      await post("/api/v1/auth/login/password", { user_name: "sam", password: MOCK_PASSWORDS.sam }),
      401,
      "auth.invalid_credentials",
    );
    const again = await post<LoginResponse>("/api/v1/auth/login/password", {
      user_name: "sam",
      password: "a-long-enough-new-one",
    });
    expect(again.body.status).toBe("authenticated");
  });
});

// ---------------------------------------------------------------------------------
// Sessions and tokens

describe("sessions", () => {
  it("lists three sessions, one of them current, and revokes another", async () => {
    resetMockDb("signed-in");
    const list = await get<Page<SessionSummary>>("/api/v1/auth/sessions");
    expect(list.status).toBe(200);
    expect(list.body.items).toHaveLength(3);
    expect(list.body.items.filter((s) => s.current)).toHaveLength(1);
    expect(list.body.items[0]?.current).toBe(true);
    expect(list.body.items[0]?.strength).toBe("passkey");
    expect(list.body.items.map((s) => s.source_ip)).toEqual(["192.0.2.41", "198.51.100.7", "192.0.2.41"]);
    expect(list.body.items.some((s) => /Firefox/.test(s.user_agent ?? "") && /Windows/.test(s.user_agent ?? ""))).toBe(true);
    expect(list.body.items.some((s) => /Mobile/.test(s.user_agent ?? ""))).toBe(true);
    expect(list.body.next_cursor).toBeNull();
    expect(list.body.revision).toBe(db.revision);

    const other = list.body.items[1] as SessionSummary;
    expect((await del(`/api/v1/auth/sessions/${other.id}`)).status).toBe(204);
    expectProblem(await del(`/api/v1/auth/sessions/${other.id}`), 404, "auth.session.not_found");
    expect((await get<Page<SessionSummary>>("/api/v1/auth/sessions")).body.items).toHaveLength(2);
  });
});

describe("tokens", () => {
  it("creates a token that is shown once", async () => {
    resetMockDb("signed-in");
    const before = await get<Page<TokenInfo>>("/api/v1/auth/tokens");
    expect(before.body.items).toHaveLength(1);

    const create = await post<CreatedToken>("/api/v1/auth/tokens", { name: "backup job", expires_in_days: 30 });
    expect(create.status).toBe(201);
    expect(create.body.token).toMatch(/^tko_[A-Za-z0-9_-]{32}$/);
    expect(create.body.info.name).toBe("backup job");
    expect(create.body.info.prefix).toBe(create.body.token.slice(0, 8));
    const days = (Date.parse(create.body.info.expires_at as string) - Date.parse(create.body.info.created_at)) / 86_400_000;
    expect(Math.round(days)).toBe(30);

    const list = await get<Page<TokenInfo>>("/api/v1/auth/tokens");
    expect(list.body.items).toHaveLength(2);
    expect(JSON.stringify(list.body)).not.toContain(create.body.token);

    expect((await del(`/api/v1/auth/tokens/${create.body.info.id}`)).status).toBe(204);
    expectProblem(await del(`/api/v1/auth/tokens/${create.body.info.id}`), 404, "auth.token.not_found");
    expect((await get<Page<TokenInfo>>("/api/v1/auth/tokens")).body.items).toHaveLength(1);
  });

  it("holds the lifetime to the TGL-05 maximum", async () => {
    resetMockDb("signed-in");
    const long = expectProblem(
      await post("/api/v1/auth/tokens", { name: "too long", expires_in_days: 91 }),
      400,
      "auth.token.lifetime_exceeded",
    );
    expect(long.params).toEqual({ max_days: "90" });

    const absent = await post<CreatedToken>("/api/v1/auth/tokens", { name: "default" });
    const days = (Date.parse(absent.body.info.expires_at as string) - Date.parse(absent.body.info.created_at)) / 86_400_000;
    expect(Math.round(days)).toBe(90);
    expectProblem(await post("/api/v1/auth/tokens", { name: "" }), 400, "auth.invalid_request");
  });

  it("lets a profile without a maximum issue tokens that never expire", async () => {
    resetMockDb("lab");
    const created = await post<CreatedToken>("/api/v1/auth/tokens", { name: "forever" });
    expect(created.status).toBe(201);
    expect(created.body.info.expires_at ?? null).toBeNull();
    const long = await post<CreatedToken>("/api/v1/auth/tokens", { name: "long", expires_in_days: 5000 });
    expect(long.status).toBe(201);
  });
});

// ---------------------------------------------------------------------------------
// Setup

describe("setup", () => {
  const request = (overrides: Record<string, unknown> = {}) => ({
    setup_token: MOCK_SETUP_TOKEN,
    profile: "standard",
    admin: { name: "pat", display_name: "Pat Example", password: "a-long-passphrase-42" },
    host_name: "tenko1.example.test",
    language: "en",
    ...overrides,
  });

  it("is closed after setup", async () => {
    const state = await get<SetupState>("/api/v1/setup");
    expect(state.body).toEqual({ open: false });
    expectProblem(await post("/api/v1/setup", request()), 409, "auth.setup.closed");
  });

  it("describes the four profiles and the node while open", async () => {
    resetMockDb("setup");
    const state = await get<SetupState>("/api/v1/setup");
    expect(state.body.open).toBe(true);
    expect(state.body.profiles?.map((p) => p.profile)).toEqual(["home", "standard", "hardened", "lab"]);
    const lab = state.body.profiles?.find((p) => p.profile === "lab");
    expect(lab?.settings).toEqual(PROFILE_MATRIX.lab);
    expect(lab?.banner).toEqual({ lab: true, weaker_than_home: true, deviations: [] });
    expect(state.body.profiles?.find((p) => p.profile === "standard")?.banner.weaker_than_home).toBe(false);

    const node = state.body.node;
    expect(node).toMatchObject({
      name: "tenko1",
      os: "Linux",
      cores: 4,
      memory_bytes: 8 * 1024 ** 3,
      addresses: ["192.0.2.13"],
      roles: ["controller", "dns", "dhcp", "probe"],
      data_dir: {
        path: "/var/lib/tenko",
        device: "/dev/nvme0n1p2",
        media: "nvme",
        free_bytes: 412_000_000_000,
        fsync_p50_micros: 900,
      },
    });
    expect(node?.networks?.map((n) => [n.id, n.prefix, n.vlan])).toEqual([
      ["lan", "192.0.2.0/24", 10],
      ["iot", "198.51.100.0/24", 30],
      ["lab", "203.0.113.0/25", 20],
      ["dmz", "203.0.113.128/26", 40],
    ]);
    expect(node?.networks?.[0]).toMatchObject({ interface: "eth0", address: "192.0.2.13" });
  });

  it("reports a slow data disk in the slow-disk scenario", async () => {
    resetMockDb("setup-slow-disk");
    const state = await get<SetupState>("/api/v1/setup");
    expect(state.body.open).toBe(true);
    expect(state.body.node?.data_dir).toMatchObject({
      path: "/srv/tenko",
      device: "/dev/sdb1",
      media: "smr",
      fsync_p50_micros: 44_500,
    });
  });

  it("has nobody signed in and nobody to sign in while open", async () => {
    resetMockDb("setup");
    expectProblem(await get("/api/v1/auth/session"), 401, "auth.unauthenticated");
    expectProblem(
      await post("/api/v1/auth/login/password", { user_name: "alex", password: MOCK_PASSWORDS.alex }),
      401,
      "auth.invalid_credentials",
    );
  });

  it("refuses a wrong token, a host name that is an address and a weak password", async () => {
    resetMockDb("setup");
    expectProblem(await post("/api/v1/setup", request({ setup_token: "AAAA-AAAA-AAAA-AAAA" })), 401, "auth.setup.token_invalid");

    for (const host of ["192.0.2.13", "[2001:db8::1]", "2001:db8::1", "", "  ", "bad_name.example.test", "-bad.example.test", "1234"]) {
      const problem = expectProblem(
        await post("/api/v1/setup", request({ host_name: host })),
        400,
        "auth.setup.invalid_host_name",
      );
      expect(problem.params).toEqual({ host_name: host.trim() });
    }

    const weak = expectProblem(
      await post("/api/v1/setup", request({ admin: { name: "pat", password: "short" } })),
      400,
      "auth.password.policy",
    );
    expect(weak.errors).toEqual([{ field: "admin.password", code: "auth.password.too_short", params: { min: "12" } }]);

    // Setup is still open after every refusal.
    expect((await get<SetupState>("/api/v1/setup")).body.open).toBe(true);
  });

  it("completes setup, closes it and starts a session", async () => {
    resetMockDb("setup");
    const done = await post<SetupResult>("/api/v1/setup", request({ language: "sv" }));
    expect(done.status).toBe(200);
    const { ca_fingerprint, ...session } = done.body;
    expect(ca_fingerprint).toMatch(/^[0-9a-f]{64}$/);
    expect(session.user).toMatchObject({ name: "pat", display_name: "Pat Example" });
    expect(session.roles).toEqual(["admin"]);
    expect(session.strength).toBe("password");
    expect(session.profile).toBe("standard");
    // Standard asks administrators for a second factor.
    expect(session.required_strength).toBe("password_totp");
    expect(session.flags.mfa_enrolment_required).toBe(true);
    expect(session.default_language).toBe("sv");

    expect((await get<SetupState>("/api/v1/setup")).body).toEqual({ open: false });
    expect((await get<SessionInfo>("/api/v1/auth/session")).body.user.name).toBe("pat");
    expectProblem(await post("/api/v1/setup", request()), 409, "auth.setup.closed");
    const status = await get<SystemStatus>("/api/v1/system/status");
    expect(status.body.tls?.mode).toBe("internal_ca");

    // The new administrator signs in with the password they chose.
    await post("/api/v1/auth/logout");
    const again = await post<LoginResponse>("/api/v1/auth/login/password", {
      user_name: "pat",
      password: "a-long-passphrase-42",
    });
    expect(again.body.status).toBe("authenticated");
  });

  it("applies the PIN preset and the TLS choice", async () => {
    resetMockDb("setup");
    const done = await post<SetupResult>(
      "/api/v1/setup",
      request({
        profile: "home",
        admin: { name: "pat", password: "4821" },
        tls: { mode: "reverse_proxy", trusted_proxies: ["192.0.2.0/24"] },
      }),
    );
    expect(done.status).toBe(200);
    expect(done.body.strength).toBe("pin");
    expect(done.body.profile).toBe("home");
    expect(done.body.banner.lab).toBe(false);
    expect(done.body.ca_fingerprint ?? null).toBeNull();
    const status = await get<SystemStatus>("/api/v1/system/status");
    expect(status.body.tls).toMatchObject({ mode: "reverse_proxy", trusted_proxies: ["192.0.2.0/24"], hsts: false });
  });

  it("accepts the setup token without its dashes", async () => {
    resetMockDb("setup");
    const done = await post("/api/v1/setup", request({ setup_token: MOCK_SETUP_TOKEN.replace(/-/g, "").toLowerCase() }));
    expect(done.status).toBe(200);
  });

  it("does not check a Lab password for breaches", async () => {
    resetMockDb("setup");
    const done = await post<SetupResult>(
      "/api/v1/setup",
      request({ profile: "lab", admin: { name: "pat", password: "1357" } }),
    );
    expect(done.status).toBe(200);
    expect(done.body.banner).toMatchObject({ lab: true, weaker_than_home: true });
  });
});

// ---------------------------------------------------------------------------------
// Settings

describe("settings", () => {
  it("shows the profile, toggles and banner to an administrator", async () => {
    resetMockDb("signed-in");
    const view = await get<SecuritySettingsView>("/api/v1/settings/security");
    expect(view.status).toBe(200);
    expect(view.body.settings).toEqual(PROFILE_MATRIX.standard);
    expect(view.body.toggles.map((t) => t.id)).toEqual(["TGL-01", "TGL-02", "TGL-03", "TGL-04", "TGL-05", "TGL-06", "TGL-07", "TGL-23", "TGL-24"]);
    expect(view.body.toggles.every((t) => !t.deviates && !t.weaker_than_home)).toBe(true);
    expect(view.body.banner).toEqual({ lab: false, weaker_than_home: false, deviations: [] });
    expect(view.body.vault_has_operator_secrets).toBe(false);
    expect(view.body.revision).toBe(INITIAL_REVISION);
    expect(view.res.headers.get("etag")).toBe(`"${INITIAL_REVISION}"`);
  });

  it("refuses a stale revision and applies a matching one", async () => {
    resetMockDb("signed-in");
    const stale = await patch("/api/v1/settings/security", { lockout: "lock_until_unlock" }, { headers: { "if-match": '"1"' } });
    const problem = expectProblem(stale, 412, "sys.store.precondition_failed");
    expect(problem.params).toEqual({ expected: "1", actual: String(INITIAL_REVISION) });

    const fresh = await patch<SecuritySettingsView>(
      "/api/v1/settings/security",
      { lockout: "lock_until_unlock", session: { absolute_secs: 3600, idle_secs: 600 } },
      { headers: { "if-match": `"${INITIAL_REVISION}"` } },
    );
    expect(fresh.status).toBe(200);
    expect(fresh.body.settings.lockout).toBe("lock_until_unlock");
    expect(fresh.body.settings.session).toEqual({ absolute_secs: 3600, idle_secs: 600 });
    expect(fresh.body.revision).toBeGreaterThan(INITIAL_REVISION);
    expect(fresh.res.headers.get("etag")).toBe(`"${fresh.body.revision}"`);
    expect(fresh.body.toggles.filter((t) => t.deviates).map((t) => t.id)).toEqual(["TGL-04", "TGL-07"]);
    expect(fresh.body.banner.deviations).toEqual(["TGL-04", "TGL-07"]);
    expect(fresh.body.banner.weaker_than_home).toBe(false);

    // The old revision is stale now; `*` always applies.
    expectProblem(
      await patch("/api/v1/settings/security", { mfa: "everyone" }, { headers: { "if-match": `"${INITIAL_REVISION}"` } }),
      412,
      "sys.store.precondition_failed",
    );
    const star = await patch<SecuritySettingsView>("/api/v1/settings/security", { mfa: "everyone" }, { headers: { "if-match": "*" } });
    expect(star.status).toBe(200);
    expect(star.body.settings.mfa).toBe("everyone");
    expectProblem(
      await patch("/api/v1/settings/security", { mfa: "everyone" }, { headers: { "if-match": "abc" } }),
      400,
      "sys.invalid_value",
    );
  });

  it("resets the toggles on a profile switch, then applies explicit toggles", async () => {
    resetMockDb("signed-in");
    await patch("/api/v1/settings/security", { lockout: "off", mfa: "optional" });

    const switched = await patch<SecuritySettingsView>("/api/v1/settings/security", {
      profile: "hardened",
      token_max_lifetime: { days: 7 },
    });
    expect(switched.body.settings).toEqual({ ...PROFILE_MATRIX.hardened, token_max_days: 7 });
    expect(switched.body.settings.lockout).toBe("lock_until_unlock");
    expect(switched.body.settings.mfa).toBe("everyone");
    expect(switched.body.banner.deviations).toEqual(["TGL-05"]);
    const token = switched.body.toggles.find((t) => t.id === "TGL-05");
    expect(token).toMatchObject({ value: 7, profile_default: 30, deviates: true, weaker_than_home: false });

    // The session sees the new profile and banner at once.
    const session = await get<SessionInfo>("/api/v1/auth/session");
    expect(session.body.profile).toBe("hardened");
    expect(session.body.required_strength).toBe("passkey");
    expect(session.body.banner.deviations).toEqual(["TGL-05"]);

    const lab = await patch<SecuritySettingsView>("/api/v1/settings/security", { profile: "lab" });
    expect(lab.body.banner).toEqual({ lab: true, weaker_than_home: true, deviations: [] });
    expect((await get<SessionInfo>("/api/v1/auth/session")).body.banner.lab).toBe(true);

    const unlimited = await patch<SecuritySettingsView>("/api/v1/settings/security", { token_max_lifetime: "unlimited" });
    expect(unlimited.body.settings.token_max_days).toBeNull();
    expect(unlimited.body.toggles.find((t) => t.id === "TGL-05")).toMatchObject({ value: null, deviates: false });
  });

  it("refuses values that are not valid", async () => {
    resetMockDb("signed-in");
    for (const body of [
      { profile: "paranoid" },
      { mfa: "sometimes" },
      { lockout: 3 },
      { session: { absolute_secs: 60, idle_secs: 600 } },
      { token_max_lifetime: { days: 0 } },
      { password_policy: { preset: "custom", min_length: 2 } },
      { password_policy: { preset: "custom", min_length: 8, pattern: "(" } },
    ]) {
      expectProblem(await patch("/api/v1/settings/security", body), 400, "auth.invalid_request");
    }
    const custom = await patch<SecuritySettingsView>("/api/v1/settings/security", {
      password_policy: { preset: "custom", min_length: 10, max_length: 128, pattern: "[a-z0-9-]+" },
    });
    expect(custom.status).toBe(200);
    expect(custom.body.settings.password_policy).toEqual({ preset: "custom", min_length: 10, max_length: 128, pattern: "[a-z0-9-]+" });
  });

  const SETTINGS = "/api/v1/settings/security";
  const refused = async (body: unknown) => expectProblem(await patch(SETTINGS, body), 409, "settings.pin_coupling");
  const passes = async (body: unknown) => (await patch<SecuritySettingsView>(SETTINGS, body)).status;

  it("refuses a PIN while the vault holds operator secrets", async () => {
    // Standard: a password preset and MFA for administrators, so a PIN would not stand alone yet.
    resetMockDb("signed-in");
    db.vaultHasOperatorSecrets = true;
    await refused({ password_policy: { preset: "pin" }, mfa: "optional" });
    await refused({ profile: "home" });
    await refused({ profile: "lab" });
    expect(await passes({ password_policy: { preset: "hardened" } })).toBe(200);

    // With MFA optional, the PIN preset and every Custom preset that accepts a short number would.
    resetMockDb("signed-in");
    expect(await passes({ mfa: "optional" })).toBe(200);
    db.vaultHasOperatorSecrets = true;
    await refused({ password_policy: { preset: "pin" } });
    await refused({ password_policy: { preset: "custom", min_length: 8 } });
    await refused({ password_policy: { preset: "custom", min_length: 4, max_length: 64, pattern: "[0-9]+" } });
    expect(db.settings.password_policy).toEqual({ preset: "standard" });
    // A policy that no short number meets leaves the PIN out: 12 characters or more, or a pattern with letters.
    expect(await passes({ password_policy: { preset: "custom", min_length: 12 } })).toBe(200);
    expect(await passes({ password_policy: { preset: "custom", min_length: 8, pattern: "[a-z]+" } })).toBe(200);
    expect(await passes({ password_policy: { preset: "hardened" } })).toBe(200);
  });

  it("lets a PIN stand alone only through a change of the password policy or MFA", async () => {
    // Home: the PIN preset with MFA optional is the profile itself. Set it up before the secret exists.
    resetMockDb("signed-in");
    expect(await passes({ profile: "home" })).toBe(200);
    db.vaultHasOperatorSecrets = true;

    // Other toggles pass, and so does saying again what is already set.
    expect(await passes({ secret_reveal: { step_up: "passkey", bound_host_only: true } })).toBe(200);
    expect(db.settings.secret_reveal).toEqual({ step_up: "passkey", bound_host_only: true });
    expect(await passes({ lockout: "off" })).toBe(200);
    expect(db.settings.lockout).toBe("off");
    expect(await passes({ session: { absolute_secs: 3600, idle_secs: 600 } })).toBe(200);
    expect(await passes({ mfa: "optional", password_policy: { preset: "pin" } })).toBe(200);
    expect(await passes({ profile: "home" })).toBe(200);
    expect(db.settings.lockout).toBe("progressive_delay");

    // MFA for everyone passes; so does the PIN preset next to it, but optional again is the PIN alone.
    expect(await passes({ mfa: "everyone" })).toBe(200);
    expect(db.settings.mfa).toBe("everyone");
    expect(await passes({ password_policy: { preset: "pin" } })).toBe(200);
    await refused({ mfa: "optional" });
    await refused({ mfa: "optional", lockout: "off" });
    expect(db.settings.mfa).toBe("everyone");

    // A profile switch resets the toggles first: Home sets MFA optional, unless the same request says more.
    await refused({ profile: "home" });
    expect(await passes({ profile: "home", mfa: "administrators" })).toBe(200);
    expect(db.settings.mfa).toBe("administrators");
    expect(db.settings.password_policy).toEqual({ preset: "pin" });
  });

  it("compares a Custom policy the way the server does: an absent maximum is 256", async () => {
    resetMockDb("signed-in");
    expect(await passes({ mfa: "optional", password_policy: { preset: "custom", min_length: 8 } })).toBe(200);
    db.vaultHasOperatorSecrets = true;
    // The same policy again, written with the default maximum: nothing changes, so it passes.
    expect(await passes({ password_policy: { preset: "custom", min_length: 8, max_length: 256 } })).toBe(200);
    // A policy that differs and still admits a PIN is refused.
    await refused({ password_policy: { preset: "custom", min_length: 8, max_length: 128 } });
    await refused({ password_policy: { preset: "custom", min_length: 6 } });
  });

  it("is for administrators to change and administrators and operators to read", async () => {
    expectProblem(await get("/api/v1/settings/security"), 401, "auth.unauthenticated");
    expectProblem(await patch("/api/v1/settings/security", { lockout: "off" }), 401, "auth.unauthenticated");
    await loginAs("sam");
    expect((await get("/api/v1/settings/security")).status).toBe(200);
    expectProblem(await patch("/api/v1/settings/security", { lockout: "off" }), 403, "auth.forbidden");
  });
});

// ---------------------------------------------------------------------------------
// Users

describe("users", () => {
  it("is for administrators only", async () => {
    expectProblem(await get("/api/v1/users"), 401, "auth.unauthenticated");
    await loginAs("sam");
    for (const [method, path] of [
      ["GET", "/api/v1/users"],
      ["POST", "/api/v1/users"],
      ["GET", `/api/v1/users/${MOCK_USER_IDS.alex}`],
      ["PATCH", `/api/v1/users/${MOCK_USER_IDS.alex}`],
      ["DELETE", `/api/v1/users/${MOCK_USER_IDS.alex}`],
      ["PUT", `/api/v1/users/${MOCK_USER_IDS.alex}/roles`],
      ["POST", `/api/v1/users/${MOCK_USER_IDS.alex}/unlock`],
      ["DELETE", `/api/v1/users/${MOCK_USER_IDS.alex}/sessions`],
      ["GET", "/api/v1/roles"],
    ] as const) {
      expectProblem(await call(method, path, { json: method === "GET" || method === "DELETE" ? undefined : {} }), 403, "auth.forbidden");
    }
  });

  it("lists the users with their revision, factors and lock", async () => {
    resetMockDb("signed-in");
    const list = await get<Page<UserInfo>>("/api/v1/users");
    expect(list.status).toBe(200);
    expect(list.body.items.map((u) => u.name)).toEqual(["alex", "breakglass", "robin", "sam"]);
    expect(list.body.revision).toBe(db.revision);
    expect(list.body.next_cursor).toBeNull();
    const byName = Object.fromEntries(list.body.items.map((u) => [u.name, u]));

    expect(byName.alex).toMatchObject({
      id: MOCK_USER_IDS.alex,
      roles: ["admin"],
      disabled: false,
      break_glass: false,
      factors: { password: true, totp: true, webauthn: 1, hardware_keys: 0, recovery_codes: 10 },
      revision: INITIAL_REVISION,
    });
    expect(byName.sam).toMatchObject({ roles: ["operator"], factors: { password: true, totp: false, webauthn: 0 } });
    expect(byName.sam?.lock?.until_unlock).toBe(false);
    const minutes = (Date.parse(byName.sam?.lock?.until as string) - Date.now()) / 60_000;
    expect(minutes).toBeGreaterThan(9);
    expect(minutes).toBeLessThanOrEqual(10);
    expect(byName.robin).toMatchObject({ roles: ["viewer"], disabled: true });
    expect(byName.breakglass).toMatchObject({
      roles: ["admin"],
      break_glass: true,
      factors: { password: false, webauthn: 1, hardware_keys: 1 },
    });

    const one = await get<UserInfo>(`/api/v1/users/${MOCK_USER_IDS.sam}`);
    expect(one.body).toEqual(byName.sam);
    expect(one.res.headers.get("etag")).toBe(`"${INITIAL_REVISION}"`);
    expectProblem(await get("/api/v1/users/0190d1c2-0000-7000-8000-0000000000ff"), 404, "users.not_found");

    const page = await get<Page<UserInfo>>("/api/v1/users?limit=3");
    expect(page.body.items).toHaveLength(3);
    expect(page.body.next_cursor).toBeTruthy();
    const rest = await get<Page<UserInfo>>(`/api/v1/users?limit=3&cursor=${page.body.next_cursor}`);
    expect(rest.body.items.map((u) => u.name)).toEqual(["sam"]);
    expect(rest.body.next_cursor).toBeNull();
    expect((await get<Page<UserInfo>>("/api/v1/users?q=ROB")).body.items.map((u) => u.name)).toEqual(["robin"]);
  });

  it("creates a user, with a revision, and refuses a taken name", async () => {
    resetMockDb("signed-in");
    const before = db.revision;
    const made = await post<UserInfo>("/api/v1/users", {
      name: "kim",
      display_name: "Kim Example",
      roles: ["viewer", "operator"],
      password: "a-long-passphrase-42",
      language: "en",
    });
    expect(made.status).toBe(201);
    expect(made.body).toMatchObject({
      name: "kim",
      display_name: "Kim Example",
      roles: ["operator", "viewer"],
      disabled: false,
      password_change_required: true,
      language: "en",
      factors: { password: true, totp: false, webauthn: 0, recovery_codes: 0 },
    });
    expect(made.body.revision).toBeGreaterThan(before);
    expect(made.body.revision).toBe(db.revision);

    expectProblem(await post("/api/v1/users", { name: "Kim", roles: ["viewer"] }), 409, "users.name_taken");
    expectProblem(await post("/api/v1/users", { name: "has space", roles: ["viewer"] }), 400, "auth.invalid_request");
    expectProblem(await post("/api/v1/users", { name: "lee", roles: [] }), 400, "auth.invalid_request");
    expectProblem(await post("/api/v1/users", { name: "lee", roles: ["root"] }), 400, "auth.invalid_request");
    const weak = expectProblem(await post("/api/v1/users", { name: "lee", roles: ["viewer"], password: "short" }), 400, "auth.password.policy");
    expect(weak.errors?.[0]?.field).toBe("password");

    // The new user signs in with the initial password.
    await post("/api/v1/auth/logout");
    const login = await post<LoginResponse>("/api/v1/auth/login/password", { user_name: "kim", password: "a-long-passphrase-42" });
    if (login.body.status !== "authenticated") throw new Error("expected a session");
    expect(login.body.session.flags.password_change_required).toBe(true);
  });

  it("refuses a change made on a stale revision", async () => {
    resetMockDb("signed-in");
    const id = MOCK_USER_IDS.sam;
    expectProblem(
      await patch(`/api/v1/users/${id}`, { display_name: "Sam E." }, { headers: { "if-match": '"1"' } }),
      412,
      "sys.store.precondition_failed",
    );
    const done = await patch<UserInfo>(`/api/v1/users/${id}`, { display_name: "Sam E.", language: "" }, { headers: { "if-match": `"${INITIAL_REVISION}"` } });
    expect(done.status).toBe(200);
    expect(done.body.display_name).toBe("Sam E.");
    expect(done.body.language ?? null).toBeNull();
    expect(done.body.revision).toBe(db.revision);
    expect(done.res.headers.get("etag")).toBe(`"${done.body.revision}"`);
    expectProblem(
      await patch(`/api/v1/users/${id}`, { display_name: "Again" }, { headers: { "if-match": `"${INITIAL_REVISION}"` } }),
      412,
      "sys.store.precondition_failed",
    );
  });

  it("disables a user, ends their sessions and resets a password", async () => {
    resetMockDb("signed-in");
    const id = MOCK_USER_IDS.alex;
    expectProblem(await patch(`/api/v1/users/${id}`, { disabled: true }), 400, "auth.invalid_request");

    const disabled = await patch<UserInfo>(`/api/v1/users/${MOCK_USER_IDS.sam}`, { disabled: true });
    expect(disabled.body.disabled).toBe(true);
    const reset = await patch<UserInfo>(`/api/v1/users/${MOCK_USER_IDS.sam}`, { disabled: false, password: "another-long-one-77" });
    expect(reset.body.password_change_required).toBe(true);
    expectProblem(
      await patch(`/api/v1/users/${MOCK_USER_IDS.sam}`, { password: "short" }),
      400,
      "auth.password.policy",
    );
    expectProblem(
      await patch(`/api/v1/users/${MOCK_USER_IDS.breakglass}`, { password: "another-long-one-77" }),
      403,
      "auth.break_glass.hardware_key_only",
    );
  });

  it("keeps the last administrator", async () => {
    resetMockDb("signed-in");
    const alex = MOCK_USER_IDS.alex;
    // alex is the only administrator besides the break-glass account, which does not count.
    const demote = expectProblem(await put(`/api/v1/users/${alex}/roles`, { roles: ["viewer"] }), 409, "users.last_administrator");
    expect(demote.title).toBeTruthy();
    expect((await get<UserInfo>(`/api/v1/users/${alex}`)).body.roles).toEqual(["admin"]);

    // Another administrator makes demoting alex fine.
    const made = await post<UserInfo>("/api/v1/users", { name: "pat", roles: ["admin"] });
    const demoted = await put<UserInfo>(`/api/v1/users/${alex}/roles`, { roles: ["operator", "viewer"] });
    expect(demoted.status).toBe(200);
    expect(demoted.body.roles).toEqual(["operator", "viewer"]);
    expect(made.body.roles).toEqual(["admin"]);
  });

  it("keeps the last administrator from being deleted or disabled", async () => {
    // Sign in as the break-glass account: it is an admin, but not one that counts.
    const start = await post<WebAuthnLoginOptions>("/api/v1/auth/webauthn/login/start", { break_glass: true });
    await post("/api/v1/auth/webauthn/login/finish", { ceremony_id: start.body.ceremony_id, credential: assertion() });
    expectProblem(await del(`/api/v1/users/${MOCK_USER_IDS.alex}`), 409, "users.last_administrator");
    expectProblem(await patch(`/api/v1/users/${MOCK_USER_IDS.alex}`, { disabled: true }), 409, "users.last_administrator");
    expectProblem(await put(`/api/v1/users/${MOCK_USER_IDS.breakglass}/roles`, { roles: ["viewer"] }), 400, "auth.invalid_request");

    const other = await post<UserInfo>("/api/v1/users", { name: "pat", roles: ["admin"] });
    expect((await del(`/api/v1/users/${MOCK_USER_IDS.alex}`)).status).toBe(204);
    expectProblem(await get(`/api/v1/users/${MOCK_USER_IDS.alex}`), 404, "users.not_found");
    // pat is the last one now.
    expectProblem(await del(`/api/v1/users/${other.body.id}`), 409, "users.last_administrator");
  });

  it("deletes a user, but not the signed-in one", async () => {
    resetMockDb("signed-in");
    expectProblem(await del(`/api/v1/users/${MOCK_USER_IDS.alex}`), 400, "auth.invalid_request");
    expect((await del(`/api/v1/users/${MOCK_USER_IDS.robin}`)).status).toBe(204);
    expect((await get<Page<UserInfo>>("/api/v1/users")).body.items.map((u) => u.name)).toEqual(["alex", "breakglass", "sam"]);
    expectProblem(await del(`/api/v1/users/${MOCK_USER_IDS.robin}`), 404, "users.not_found");
  });

  it("unlocks a locked user", async () => {
    resetMockDb("signed-in");
    const id = MOCK_USER_IDS.sam;
    expect((await get<UserInfo>(`/api/v1/users/${id}`)).body.lock).toBeTruthy();
    const unlocked = await post<UserInfo>(`/api/v1/users/${id}/unlock`);
    expect(unlocked.status).toBe(200);
    expect(unlocked.body.lock ?? null).toBeNull();
    expect(unlocked.body.revision).toBe(db.revision);
    // Unlocking again changes nothing.
    const again = await post<UserInfo>(`/api/v1/users/${id}/unlock`);
    expect(again.body.revision).toBe(unlocked.body.revision);
  });

  it("clears the throttle of a user who is unlocked", async () => {
    resetMockDb("signed-in");
    await post("/api/v1/auth/logout");
    const wrong = () => post("/api/v1/auth/login/password", { user_name: "sam", password: "wrong-password" });
    await wrong();
    await wrong();
    expectProblem(await wrong(), 429, "auth.throttled");
    await loginAs("alex").catch(() => undefined);
  });

  it("revokes every session of a user", async () => {
    resetMockDb("signed-in");
    expect((await del(`/api/v1/users/${MOCK_USER_IDS.sam}/sessions`)).status).toBe(204);
    expect((await get<Page<SessionSummary>>("/api/v1/auth/sessions")).body.items).toHaveLength(3);
    // Revoking your own sessions signs you out.
    expect((await del(`/api/v1/users/${MOCK_USER_IDS.alex}/sessions`)).status).toBe(204);
    expectProblem(await get("/api/v1/auth/session"), 401, "auth.unauthenticated");
  });

  it("lists the three roles", async () => {
    resetMockDb("signed-in");
    const roles = await get<Page<{ name: string; description: string }>>("/api/v1/roles");
    expect(roles.body.items.map((r) => r.name)).toEqual(["admin", "operator", "viewer"]);
    for (const role of roles.body.items) expect(role.description).toMatch(/^[A-Z]/);
  });
});

// ---------------------------------------------------------------------------------
// Status, jobs, search

describe("system", () => {
  it("needs a session for the status, jobs and search", async () => {
    for (const path of ["/api/v1/system/status", "/api/v1/jobs", "/api/v1/search?q=nas"]) {
      expectProblem(await get(path), 401, "auth.unauthenticated");
    }
    expect((await get("/api/v1/health")).status).toBe(200);
    expect((await get<{ status: string; revision: number }>("/api/v1/health/ready")).body.status).toBe("ready");
  });

  it("reports the status of the installation", async () => {
    resetMockDb("signed-in");
    const status = await get<SystemStatus>("/api/v1/system/status");
    expect(status.status).toBe(200);
    expect(status.body).toMatchObject({
      version: "0.1.0-dev",
      node: { roles: ["controller", "dns", "dhcp", "probe"] },
      store: { role: "leader", revision: db.revision, lag: 0 },
      tls: { mode: "internal_ca", trusted_proxies: [], hsts: false },
      ui: { stub: false, from_directory: false },
      cluster: { nodes: 2, connected: 1, mismatched: 1 },
    });
    // The only warning of the seed: the enrolled probe that shares no protocol major (WP2.9).
    expect(status.body.warnings.map((w) => w.code)).toEqual(["cluster.protocol.mismatch"]);
    expect(status.body.uptime_seconds).toBeGreaterThan(0);
    expect(Date.parse(status.body.started_at)).toBeLessThan(Date.now());
  });

  it("warns about plain HTTP in the lab scenario", async () => {
    resetMockDb("lab");
    const status = await get<SystemStatus>("/api/v1/system/status");
    expect(status.body.tls?.mode).toBe("plain");
    expect(status.body.warnings.map((w) => w.code)).toEqual(["sys.tls.plain_http", "cluster.protocol.mismatch"]);
  });

  it("lists the seed jobs with their derived summary", async () => {
    resetMockDb("signed-in");
    type Row = { id: string; state: string; steps_done: number; step_count: number; kind: string; title: string };
    const jobs = await get<Page<Row>>("/api/v1/jobs");
    expect(jobs.status).toBe(200);
    expect(jobs.body.items.map((j) => j.state).sort()).toEqual([
      "cancelled",
      "queued",
      "rolled_back",
      "running",
      "succeeded",
      "waiting",
    ]);
    const running = jobs.body.items.find((j) => j.state === "running");
    expect(running).toMatchObject({ kind: "import.apply", title: "jobs.title.import_apply", steps_done: 2, step_count: 3 });
    expect(jobs.body.revision).toBe(db.revision);

    const onlyRunning = await get<Page<Row>>("/api/v1/jobs?state=running");
    expect(onlyRunning.body.items.map((j) => j.state)).toEqual(["running"]);
    const two = await get<Page<Row>>("/api/v1/jobs?state=waiting,succeeded");
    expect(two.body.items.map((j) => j.state).sort()).toEqual(["succeeded", "waiting"]);
    expect((await get<Page<unknown>>("/api/v1/jobs?state=failed")).body.items).toEqual([]);
    const bad = expectProblem(await get("/api/v1/jobs?state=sleeping"), 400, "jobs.query.invalid");
    expect(bad.params).toEqual({ param: "state", value: "sleeping" });
    expectProblem(await get("/api/v1/jobs?colour=red"), 400, "sys.invalid_query");
  });

  it("advances the running import with the job ticker and starts the next one", async () => {
    resetMockDb("signed-in");
    const stateOf = async () => {
      const page = await get<Page<{ kind: string; state: string; steps_done: number }>>("/api/v1/jobs?kind=import.apply");
      return page.body.items.map((j) => `${j.state}:${j.steps_done}`);
    };
    expect(await stateOf()).toEqual(["running:2"]);
    const before = db.revision;
    advanceMockJobs();
    expect(db.revision).toBe(before + 1);
    expect(await stateOf()).toEqual(["succeeded:3"]);
    advanceMockJobs();
    expect((await stateOf()).sort()).toEqual(["running:0", "succeeded:3"]);
  });

  it("searches addresses, prefixes, hosts and MACs without regard to case", async () => {
    resetMockDb("signed-in");
    type Hit = { label: string; item: { kind: string; data: { ip?: string; cidr?: string; name?: string; mac?: string } } };
    const key = (h: Hit) => h.item.data.ip ?? h.item.data.cidr ?? (h.item.kind === "interface" ? h.item.data.mac : h.item.data.name);
    const titles = async (q: string) =>
      (await get<{ items: Hit[] }>(`/api/v1/search?q=${encodeURIComponent(q)}`)).body.items.map(key);

    expect(await titles("NAS")).toEqual(expect.arrayContaining(["192.0.2.11", "nas"]));
    expect(await titles("198.51.100.0/24")).toContain("198.51.100.0/24");
    const camDoor = await titles("cam-door");
    expect(camDoor).toEqual(expect.arrayContaining(["192.0.2.43", "cam-door"]));
    const byMac = await titles("00-00-5e-00-53-2b");
    expect(byMac).toHaveLength(1);
    expect(byMac[0]).toMatch(/^00:00:5e:00:53:2b$/);
    expect(await titles("2001:db8")).toContain("2001:db8:0:10::1");
    expect(await titles("IoT")).toContain("198.51.100.0/24");
    expect(await titles("nothing like this")).toEqual([]);
    expect(await titles("")).toEqual([]);
    expect(await titles("   ")).toEqual([]);
    const all = await get<Page<unknown>>("/api/v1/search?q=example.test");
    expect(all.body.items.length).toBeGreaterThanOrEqual(5);
    expect(all.body.revision).toBe(db.revision);
    expect((await get<Page<unknown>>("/api/v1/search?q=example.test&limit=2")).body.items).toHaveLength(2);
  });
});

// ---------------------------------------------------------------------------------
// The event stream

describe("events", () => {
  it("needs a session and a known topic", async () => {
    expectProblem(await get("/api/v1/events"), 401, "auth.unauthenticated");
    resetMockDb("signed-in");
    const problem = expectProblem(await get("/api/v1/events?topics=ipam,dns"), 400, "sys.events.unknown_topic");
    expect(problem.params).toEqual({ topic: "dns" });
    expectProblem(await get("/api/v1/events?from=abc"), 400, "sys.invalid_query");
  });

  it("delivers an event emitted with emitMockEvent", async () => {
    resetMockDb("signed-in");
    const stream = await openStream("?topics=jobs,admin");
    expect(openStreamCount()).toBe(1);
    expect(await stream.nextWithin(30)).toBeNull();

    const before = db.revision;
    const sent = emitMockEvent("jobs", { objects: [{ kind: "job", id: "job-1" }] });
    expect(sent.id).toBe(before + 1);
    const message = await stream.next();
    expect(message.event).toBe("jobs");
    expect(message.id).toBe(String(before + 1));
    expect(message.data).toEqual({
      topic: "jobs",
      revision: before + 1,
      objects: [{ kind: "job", id: "job-1" }],
      deleted: [],
      audit: [],
      tables: [],
      params: {},
    });

    // A topic the stream does not follow does not reach it.
    emitMockEvent("ipam", { objects: [{ kind: "prefix", id: "p1" }] });
    expect(await stream.nextWithin(30)).toBeNull();
    await stream.close();
  });

  it("sends the writes of the mock as admin events with the revision as id", async () => {
    resetMockDb("signed-in");
    const stream = await openStream("?topics=admin");
    const made = await post<UserInfo>("/api/v1/users", { name: "kim", roles: ["viewer"] });
    const message = await stream.next();
    expect(message.event).toBe("admin");
    expect(message.id).toBe(String(made.body.revision));
    expect(message.data.objects).toEqual([{ kind: "user", id: made.body.id }]);

    const token = await post<CreatedToken>("/api/v1/auth/tokens", { name: "t" });
    const tokenEvent = await stream.next();
    expect(tokenEvent.data.objects).toEqual([{ kind: "token", id: token.body.info.id }]);
    expect(Number(tokenEvent.id)).toBeGreaterThan(Number(message.id));
    await stream.close();
  });

  it("replays the journal after `from`", async () => {
    resetMockDb("signed-in");
    const start = db.revision;
    emitMockEvent("jobs", { objects: [{ kind: "job", id: "a" }] });
    emitMockEvent("admin", { tables: ["auth.users"] });
    emitMockEvent("jobs", { objects: [{ kind: "job", id: "b" }] });

    const stream = await openStream(`?topics=jobs&from=${start}`);
    const first = await stream.next();
    const second = await stream.next();
    expect([first.id, second.id]).toEqual([String(start + 1), String(start + 3)]);
    expect(first.data.objects).toEqual([{ kind: "job", id: "a" }]);
    expect(second.data.objects).toEqual([{ kind: "job", id: "b" }]);
    expect(await stream.nextWithin(30)).toBeNull();
    // ... and goes on live.
    emitMockEvent("jobs", { objects: [{ kind: "job", id: "c" }] });
    expect((await stream.next()).data.objects).toEqual([{ kind: "job", id: "c" }]);
    await stream.close();

    // Nothing to replay from the current revision; Last-Event-ID works like `from`.
    const current = await openStream(`?from=${db.revision}`);
    expect(await current.nextWithin(30)).toBeNull();
    await current.close();
    const res = await fetch(`/api/v1/events?topics=jobs`, {
      headers: { accept: "text/event-stream", "last-event-id": String(start + 2) },
    });
    const reader = res.body!.getReader();
    const chunk = new TextDecoder().decode((await reader.read()).value);
    expect(chunk).toContain(`id: ${start + 3}\nevent: jobs`);
    await reader.cancel();
  });

  it("sends a reset with reason gap when `from` is in the future or fell out of the journal", async () => {
    resetMockDb("signed-in");
    const future = await openStream(`?from=${db.revision + 50}`);
    const reset = await future.next();
    expect(reset.event).toBe("reset");
    expect(reset.data).toEqual({ reason: "gap", revision: db.revision });
    expect(reset.id).toBe(String(db.revision));
    // The stream stays open after a reset.
    emitMockEvent("admin", { tables: ["auth.users"] });
    expect((await future.next()).event).toBe("admin");
    await future.close();

    const oldest = db.revision;
    for (let i = 0; i < JOURNAL_CAPACITY + 10; i += 1) emitMockEvent("jobs");
    expect(db.journal).toHaveLength(JOURNAL_CAPACITY);
    const old = await openStream(`?from=${oldest}`);
    expect((await old.next()).data).toEqual({ reason: "gap", revision: db.revision });
    await old.close();

    // The edge: the oldest retained event is the first one after `from`.
    const edge = await openStream(`?from=${(db.journal[0]?.id as number) - 1}&topics=jobs`);
    expect((await edge.next()).event).toBe("jobs");
    await edge.close();

    const malformed = await fetch("/api/v1/events", { headers: { accept: "text/event-stream", "last-event-id": "garbage" } });
    const malformedReader = malformed.body!.getReader();
    const chunk = new TextDecoder().decode((await malformedReader.read()).value);
    expect(chunk).toContain("event: reset");
    await malformedReader.cancel();
  });

  it("tells open streams to reload when the db is reset", async () => {
    resetMockDb("signed-in");
    const stream = await openStream();
    resetMockDb("lab");
    const reset = await stream.next();
    expect(reset.event).toBe("reset");
    expect(reset.data).toEqual({ reason: "journal", revision: INITIAL_REVISION });
    await stream.close();
  });
});

describe("event source over fetch", () => {
  /** Resolves with the first event of `type`, after `trigger` ran. */
  function once(source: EventTarget, type: string): Promise<MessageEvent> {
    return new Promise((resolve) => source.addEventListener(type, (event) => resolve(event as MessageEvent), { once: true }));
  }

  it("opens, delivers named events with their id and closes", async () => {
    resetMockDb("signed-in");
    const source = new FetchEventSource("/api/v1/events?topics=jobs");
    const opened = new Promise<void>((resolve) => {
      source.onopen = () => resolve();
    });
    await opened;
    expect(source.readyState).toBe(FetchEventSource.OPEN);
    expect(source.url).toBe("http://localhost:3000/api/v1/events?topics=jobs");

    const arrived = once(source, "jobs");
    const sent = emitMockEvent("jobs", { objects: [{ kind: "job", id: "job-1" }] });
    const event = await arrived;
    expect(event.lastEventId).toBe(String(sent.id));
    expect(JSON.parse(event.data as string)).toMatchObject({ topic: "jobs", objects: [{ kind: "job", id: "job-1" }] });

    source.close();
    expect(source.readyState).toBe(FetchEventSource.CLOSED);
  });

  it("reports an error when the stream is refused", async () => {
    // Nobody is signed in: the server answers 401.
    const source = new FetchEventSource("/api/v1/events");
    const failed = new Promise<void>((resolve) => {
      source.onerror = () => resolve();
    });
    await failed;
    expect(source.readyState).toBe(FetchEventSource.CLOSED);
  });
});

// ---------------------------------------------------------------------------------
// Profiles and policy (no network)

describe("profiles", () => {
  const weaker = (settings: ReturnType<typeof profileSettings>) =>
    toggleStates(settings)
      .filter((t) => t.weaker_than_home)
      .map((t) => t.id);

  it("holds the toggle matrix", () => {
    expect(PROFILE_MATRIX.home).toMatchObject({
      password_policy: { preset: "pin" },
      mfa: "optional",
      passkey_for_admins: false,
      session: { absolute_secs: 30 * 86_400, idle_secs: 7 * 86_400 },
      token_max_days: 365,
      breach_check: "online",
      lockout: "progressive_delay",
    });
    expect(PROFILE_MATRIX.standard).toMatchObject({
      password_policy: { preset: "standard" },
      mfa: "administrators",
      session: { absolute_secs: 12 * 3600, idle_secs: 3600 },
      token_max_days: 90,
      lockout: "delay_then_temporary_lock",
    });
    expect(PROFILE_MATRIX.hardened).toMatchObject({
      password_policy: { preset: "hardened" },
      mfa: "everyone",
      passkey_for_admins: true,
      session: { absolute_secs: 8 * 3600, idle_secs: 900 },
      token_max_days: 30,
      breach_check: "offline_preferred",
      lockout: "lock_until_unlock",
    });
    expect(PROFILE_MATRIX.lab).toMatchObject({ token_max_days: null, breach_check: "off", lockout: "off" });
    // profileSettings hands out a copy.
    const copy = profileSettings("home");
    copy.session.idle_secs = 1;
    expect(PROFILE_MATRIX.home.session.idle_secs).toBe(7 * 86_400);
  });

  it("finds Lab's lockout, breach check and token maximum weaker than Home", () => {
    const toggles = toggleStates(profileSettings("lab"));
    expect(toggles.find((t) => t.id === "TGL-07")).toMatchObject({ value: "off", deviates: false, weaker_than_home: true });
    expect(weaker(profileSettings("lab"))).toEqual(["TGL-05", "TGL-06", "TGL-07"]);
    expect(banner(profileSettings("lab"))).toEqual({ lab: true, weaker_than_home: true, deviations: [] });
  });

  it("finds no toggle of Home, Standard or Hardened weaker than Home", () => {
    for (const profile of ["home", "standard", "hardened"] as const) {
      expect(weaker(profileSettings(profile)), profile).toEqual([]);
      expect(banner(profileSettings(profile)), profile).toEqual({ lab: false, weaker_than_home: false, deviations: [] });
    }
  });

  it("judges each toggle by its own order", () => {
    const home = profileSettings("home");
    const check = (change: Partial<typeof home>) => weaker({ ...home, ...change });

    expect(check({ lockout: "off" })).toEqual(["TGL-07"]);
    expect(check({ lockout: "lock_until_unlock" })).toEqual([]);
    expect(check({ breach_check: "off" })).toEqual(["TGL-06"]);
    expect(check({ breach_check: "offline" })).toEqual([]);
    expect(check({ token_max_days: null })).toEqual(["TGL-05"]);
    expect(check({ token_max_days: 366 })).toEqual(["TGL-05"]);
    expect(check({ token_max_days: 7 })).toEqual([]);
    expect(check({ session: { ...home.session, absolute_secs: home.session.absolute_secs + 1 } })).toEqual(["TGL-04"]);
    expect(check({ session: { ...home.session, idle_secs: home.session.idle_secs + 1 } })).toEqual(["TGL-04"]);
    expect(check({ session: { absolute_secs: 3600, idle_secs: 60 } })).toEqual([]);
    expect(check({ mfa: "everyone" })).toEqual([]);
    expect(check({ passkey_for_admins: true })).toEqual([]);
    expect(check({ password_policy: { preset: "custom", min_length: 8 } })).toEqual([]);
    // Against a stronger baseline the orders show.
    const hardened = profileSettings("hardened");
    expect(weaker({ ...hardened, mfa: "optional", passkey_for_admins: false })).toEqual([]);
  });

  it("marks a toggle that differs from its profile as deviating", () => {
    const settings = { ...profileSettings("standard"), lockout: "off" as const, token_max_days: 365 };
    const toggles = toggleStates(settings);
    expect(toggles.filter((t) => t.deviates).map((t) => t.id)).toEqual(["TGL-05", "TGL-07"]);
    expect(toggles.find((t) => t.id === "TGL-05")).toMatchObject({ value: 365, profile_default: 90, weaker_than_home: false });
    expect(banner(settings)).toEqual({ lab: false, weaker_than_home: true, deviations: ["TGL-05", "TGL-07"] });
  });

  it("starts the weak scenario with one toggle weaker than Home", async () => {
    resetMockDb("weak");
    const view = await get<SecuritySettingsView>("/api/v1/settings/security");
    expect(view.body.settings.profile).toBe("home");
    expect(view.body.toggles.filter((t) => t.weaker_than_home).map((t) => t.id)).toEqual(["TGL-07"]);
    expect(view.body.banner).toEqual({ lab: false, weaker_than_home: true, deviations: ["TGL-07"] });
    expect((await get<SessionInfo>("/api/v1/auth/session")).body.banner.weaker_than_home).toBe(true);
  });

  it("starts the lab scenario signed in with the banner on", async () => {
    resetMockDb("lab");
    const session = await get<SessionInfo>("/api/v1/auth/session");
    expect(session.body.user.name).toBe("alex");
    expect(session.body.strength).toBe("passkey");
    expect(session.body.profile).toBe("lab");
    expect(session.body.banner).toEqual({ lab: true, weaker_than_home: true, deviations: [] });
  });
});

describe("password policy", () => {
  const check = (password: string, policy = profileSettings("standard").password_policy, extra = {}) =>
    checkPassword(password, { policy, breach: "online", ...extra }).violations;

  it("applies the length of each preset", () => {
    expect(check("123", { preset: "pin" })).toEqual([{ kind: "too_short", min: 4 }, { kind: "trivial" }]);
    expect(check("8".repeat(65), { preset: "pin" })).toContainEqual({ kind: "too_long", max: 64 });
    expect(check("eleven-char", { preset: "standard" })).toEqual([{ kind: "too_short", min: 12 }]);
    expect(check("twelve-chars", { preset: "standard" })).toEqual([]);
    expect(check("a-fine-passphrase".repeat(20), { preset: "standard" })).toEqual([{ kind: "too_long", max: 256 }]);
    expect(check("fifteen-chars-x", { preset: "hardened" })).toEqual([{ kind: "too_short", min: 16 }]);
    expect(check("short", { preset: "custom", min_length: 5 })).toEqual([]);
    expect(check("tiny", { preset: "custom", min_length: 5, pattern: "[a-z]+" })).toEqual([{ kind: "too_short", min: 5 }]);
    expect(check("abc-12", { preset: "custom", min_length: 5, pattern: "[a-z]+" })).toEqual([{ kind: "pattern_mismatch" }]);
    expect(check("whole", { preset: "custom", min_length: 5, pattern: "wh|ole" })).toEqual([{ kind: "pattern_mismatch" }]);
  });

  it("counts characters, not bytes, after normalization", () => {
    // Accented letters and full-width digits written as code points.
    const accented = String.fromCodePoint(0xe5, 0xe4, 0xf6);
    const fullWidth = String.fromCodePoint(0xff11, 0xff12, 0xff13, 0xff14);
    expect(check(`${accented}-${accented}-${accented}!`, { preset: "standard" })).toEqual([]);
    expect(check(`${accented}-${accented}-${accented}`, { preset: "standard" })).toEqual([{ kind: "too_short", min: 12 }]);
    expect(check(fullWidth, { preset: "pin" })).toEqual([{ kind: "trivial" }, { kind: "breached" }]);
    expect(check("ab\ncdefghijkl", { preset: "standard" })).toContainEqual({ kind: "invalid_characters" });
  });

  it("requires digits for a PIN", () => {
    expect(check("48a1", { preset: "pin" })).toEqual([{ kind: "pin_digits_only" }]);
    expect(check("4821", { preset: "pin" })).toEqual([]);
  });

  it("finds trivial passwords", () => {
    for (const trivial of ["12", "ab", "0000", "1212", "abab", "abcabc", "1234", "4321", "abcdefghijkl", "aaaaaaaaaaaa", "AbCdEfGhIjKl", "QqQqQq"]) {
      expect(isTrivial(trivial), trivial).toBe(true);
    }
    for (const fine of ["", "a", "abba", "1235", "abcd1234", "correct horse", "a1b2c3"]) {
      expect(isTrivial(fine), fine).toBe(false);
    }
  });

  it("finds context-specific words", () => {
    const context = { userName: "alex", displayName: "Alex Example", hostName: "tenko1.example.test" };
    const contexts = (password: string) =>
      check(password, { preset: "standard" }, context)
        .filter((v) => v.kind === "context_specific")
        .map((v) => (v.kind === "context_specific" ? v.context : null));
    expect(contexts("my-ALEX-passphrase")).toEqual(["user_name", "display_name"]);
    expect(contexts("example-and-more")).toEqual(["display_name"]);
    expect(contexts("tenko1-is-the-name")).toEqual(["host_name", "product"]);
    expect(contexts("TENKO-in-capitals-1")).toEqual(["product"]);
    expect(contexts("harbor-lantern-42")).toEqual([]);
    // Short parts do not count: "Al" is no context word.
    expect(check("al-is-fine-here-1", { preset: "standard" }, { userName: "al", displayName: "Al B" })).toEqual([]);
  });

  it("looks the password up in the breach corpus unless the check is off", () => {
    for (const breached of BREACHED_PASSWORDS.filter((p) => p.length >= 12)) {
      const online = checkPassword(breached, { policy: { preset: "standard" }, breach: "online" });
      expect(online.violations, breached).toContainEqual({ kind: "breached" });
      expect(online.breach_check).toBe("breached");
      expect(online.acceptable).toBe(false);
    }
    const off = checkPassword("password1234", { policy: { preset: "standard" }, breach: "off" });
    expect(off).toMatchObject({ acceptable: true, violations: [], breach_check: "off" });
    const clean = checkPassword("harbor-lantern-42", { policy: { preset: "standard" }, breach: "offline_preferred" });
    expect(clean).toMatchObject({ acceptable: true, breach_check: "clean", policy: { preset: "standard" } });
  });

  it("gives every fixture password a pass", () => {
    for (const [name, password] of Object.entries(MOCK_PASSWORDS)) {
      const result = checkPassword(password, { policy: { preset: "hardened" }, breach: "online", userName: name });
      expect(result.violations, name).toEqual([]);
    }
  });
});

// Keep the types the tests import in use even if an assertion is removed.
export type { MockScenario };
