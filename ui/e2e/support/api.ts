// The public API from the tests, over Playwright's request context of the browser context
// under test (`page.request`), so a session cookie set here signs the browser in as well.
// Used to arrange what a scenario does not test through the UI (setup for the scenarios
// after the wizard, seed data) and to check results the UI does not show in full.
//
// Mutations carry the server's own `Origin`, as a browser would: the CSRF guard refuses a
// request with the session cookie and no `Origin`.

import { randomUUID } from "node:crypto";
import type { APIRequestContext, APIResponse } from "@playwright/test";
import type { components } from "../../src/api/generated/schema";
import { Authenticator } from "./totp";

export type Schemas = components["schemas"];
export type SessionInfo = Schemas["SessionInfo"];
export type LoginResponse = Schemas["LoginResponse"];
export type TotpEnrolment = Schemas["TotpEnrolment"];
export type FactorEnrolled = Schemas["FactorEnrolled"];
export type JobDetail = Schemas["JobDetail"];

/** The first administrator of every test instance. */
export const ADMIN = {
  name: "admin",
  displayName: "Ada Admin",
  /** Digits only: the PIN preset of the Home and Lab profiles; not a common password. */
  password: "739153",
} as const;

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly body: string,
    what: string,
  ) {
    super(`${what}: HTTP ${status} ${body}`);
  }

  /** The stable problem code, when the body is problem details. */
  get code(): string | undefined {
    try {
      return (JSON.parse(this.body) as { code?: string }).code;
    } catch {
      return undefined;
    }
  }
}

interface PostOptions {
  /** `null` sends no `Idempotency-Key` (uploads); otherwise a fresh key per call. */
  idempotencyKey?: string | null;
  query?: Record<string, string | number | boolean>;
}

export class Api {
  constructor(
    readonly request: APIRequestContext,
    /** The server's origin, for example `http://localhost:41234`. */
    readonly origin: string,
  ) {}

  private url(path: string, query?: PostOptions["query"]): string {
    const url = new URL(`/api/v1${path}`, this.origin);
    for (const [key, value] of Object.entries(query ?? {})) url.searchParams.set(key, String(value));
    return url.toString();
  }

  private async json<T>(response: APIResponse, what: string): Promise<T> {
    if (!response.ok()) throw new ApiError(response.status(), await response.text(), what);
    if (response.status() === 204) return undefined as T;
    return (await response.json()) as T;
  }

  async get<T>(path: string, query?: PostOptions["query"]): Promise<T> {
    return this.json<T>(await this.request.get(this.url(path, query)), `GET ${path}`);
  }

  async text(path: string): Promise<string> {
    const response = await this.request.get(this.url(path));
    if (!response.ok()) throw new ApiError(response.status(), await response.text(), `GET ${path}`);
    return response.text();
  }

  async post<T>(path: string, body?: unknown, options: PostOptions = {}): Promise<T> {
    const headers: Record<string, string> = { Origin: this.origin };
    if (options.idempotencyKey !== null) headers["Idempotency-Key"] = options.idempotencyKey ?? randomUUID();
    const response = await this.request.post(this.url(path, options.query), {
      headers,
      ...(body === undefined ? {} : { data: body }),
    });
    return this.json<T>(response, `POST ${path}`);
  }

  async put<T>(path: string, body: unknown): Promise<T> {
    const response = await this.request.put(this.url(path), { headers: { Origin: this.origin }, data: body });
    return this.json<T>(response, `PUT ${path}`);
  }

  async patch<T>(path: string, body: unknown, revision: number | string = "*"): Promise<T> {
    const response = await this.request.patch(this.url(path), {
      headers: { Origin: this.origin, "If-Match": revision === "*" ? "*" : `"${revision}"` },
      data: body,
    });
    return this.json<T>(response, `PATCH ${path}`);
  }

  async delete(path: string, revision: number | string = "*"): Promise<void> {
    const response = await this.request.delete(this.url(path), {
      headers: { Origin: this.origin, "If-Match": revision === "*" ? "*" : `"${revision}"` },
    });
    await this.json<void>(response, `DELETE ${path}`);
  }

  /** First-run setup through the API; the answer signs the browser context in. */
  async setup(token: string, profile: Schemas["Profile"], language = "en"): Promise<SessionInfo> {
    return this.post<SessionInfo>(
      "/setup",
      {
        setup_token: token,
        profile,
        admin: { name: ADMIN.name, display_name: ADMIN.displayName, password: ADMIN.password },
        host_name: "localhost",
        language,
      },
      { idempotencyKey: null },
    );
  }

  async session(): Promise<SessionInfo> {
    return this.get<SessionInfo>("/auth/session");
  }

  async loginPassword(user: string = ADMIN.name, password: string = ADMIN.password): Promise<LoginResponse> {
    return this.post<LoginResponse>("/auth/login/password", { user_name: user, password }, { idempotencyKey: null });
  }

  /** Password and, when the server asks for it, the TOTP code of `authenticator`. */
  async signIn(authenticator?: Authenticator): Promise<SessionInfo> {
    const first = await this.loginPassword();
    if (first.status === "authenticated") return first.session;
    if (!authenticator) throw new Error(`a second factor is required: ${first.methods.join(", ")}`);
    const second = await this.post<LoginResponse>(
      "/auth/login/totp",
      { challenge_id: first.challenge_id, code: authenticator.code() },
      { idempotencyKey: null },
    );
    if (second.status !== "authenticated") throw new Error("the TOTP step did not complete the login");
    return second.session;
  }

  async logout(): Promise<void> {
    await this.post<void>("/auth/logout", undefined, { idempotencyKey: null });
  }

  /**
   * Enrols an authenticator app for the signed-in account and returns the authenticator
   * (its first code is spent on the enrolment) and the recovery codes, if any.
   */
  async enrolTotp(): Promise<{ authenticator: Authenticator; enrolled: FactorEnrolled }> {
    const start = await this.post<TotpEnrolment>("/auth/totp/enroll/start", undefined, { idempotencyKey: null });
    const authenticator = new Authenticator(start.secret);
    const enrolled = await this.post<FactorEnrolled>(
      "/auth/totp/enroll/finish",
      { enrolment_id: start.enrolment_id, code: authenticator.code() },
      { idempotencyKey: null },
    );
    return { authenticator, enrolled };
  }

  /** A job, read until it is final or `timeoutMs` has passed. */
  async waitForJob(id: string, timeoutMs = 60_000): Promise<JobDetail> {
    const final = new Set(["succeeded", "failed", "rolled_back", "cancelled"]);
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const detail = await this.get<JobDetail>(`/jobs/${id}`);
      if (final.has(detail.job.state) || Date.now() > deadline) return detail;
      await new Promise((done) => setTimeout(done, 200));
    }
  }
}
