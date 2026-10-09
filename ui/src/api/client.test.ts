import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ANY_REVISION, api, buildPath, queryString, setUnauthorizedHandler } from "./client";
import { fetchAll, fetchPage, pages } from "./paginate";
import { ApiError, CLIENT_CODES, errorMessage, fieldErrorMessage, isApiError, toProblem } from "./problem";

type Call = { url: string; init: RequestInit };

function stubFetch(respond: (call: Call) => Response | Promise<Response>) {
  const calls: Call[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init: RequestInit) => {
      const call = { url, init };
      calls.push(call);
      return respond(call);
    }),
  );
  return calls;
}

function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });
}

function problem(status: number, code: string, params: Record<string, string> = {}, extra: object = {}): Response {
  return new Response(JSON.stringify({ type: "about:blank", status, code, title: "English title", detail: "English detail", params, ...extra }), {
    status,
    headers: { "content-type": "application/problem+json" },
  });
}

function header(call: Call | undefined, name: string): string | undefined {
  return (call?.init.headers as Record<string, string> | undefined)?.[name];
}

beforeEach(() => {
  setUnauthorizedHandler(undefined);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("paths and queries", () => {
  it("fills path parameters as single segments", () => {
    expect(buildPath("/api/v1/users/{id}", { id: "a/b c" })).toBe("/api/v1/users/a%2Fb%20c");
    expect(buildPath("/api/v1/jobs/{id}/steps/{index}/complete", { id: "j1", index: 3 })).toBe("/api/v1/jobs/j1/steps/3/complete");
    expect(() => buildPath("/api/v1/users/{id}", {})).toThrow(/missing path parameter id/);
  });

  it("skips empty query values and joins lists with commas", () => {
    expect(queryString({ q: "192.0.2.41", limit: 10, cursor: undefined, none: null, state: ["running", "waiting"], empty: [] })).toBe(
      "q=192.0.2.41&limit=10&state=running%2Cwaiting",
    );
  });
});

describe("requests", () => {
  it("sends JSON with an Idempotency-Key on POST and reads the JSON answer", async () => {
    const calls = stubFetch(() => json({ status: "authenticated", session: { session_id: "s1" } }, 200));
    const res = await api.post("/api/v1/auth/login/password", { body: { user_name: "sam", password: "x" } });
    expect(res.status).toBe("authenticated");
    const call = calls[0];
    expect(call?.url).toBe("/api/v1/auth/login/password");
    expect(call?.init.method).toBe("POST");
    expect(call?.init.credentials).toBe("same-origin");
    expect(header(call, "Content-Type")).toBe("application/json");
    expect(header(call, "Idempotency-Key")).toMatch(/^[0-9a-f-]{32,36}$/);
    expect(JSON.parse(String(call?.init.body))).toEqual({ user_name: "sam", password: "x" });
  });

  it("reuses a given Idempotency-Key and makes a new one otherwise", async () => {
    const calls = stubFetch(() => new Response(null, { status: 204 }));
    await api.post("/api/v1/auth/logout", { idempotencyKey: "retry-1" });
    await api.post("/api/v1/auth/logout", { idempotencyKey: "retry-1" });
    await api.post("/api/v1/auth/logout");
    expect(header(calls[0], "Idempotency-Key")).toBe("retry-1");
    expect(header(calls[1], "Idempotency-Key")).toBe("retry-1");
    expect(header(calls[2], "Idempotency-Key")).not.toBe("retry-1");
  });

  it("sends no Idempotency-Key when the caller passes null (large uploads)", async () => {
    const calls = stubFetch(() => new Response(null, { status: 204 }));
    const form = new FormData();
    form.append("files", new Blob(["address\n192.0.2.10\n"]), "plan.csv");
    await api.post("/api/v1/imports", { body: form, idempotencyKey: null });
    expect(header(calls[0], "Idempotency-Key")).toBeUndefined();
    expect(calls[0]?.init.body).toBe(form);
    expect(header(calls[0], "Content-Type")).toBeUndefined();
  });

  it("sends If-Match with the quoted revision on PATCH and DELETE, and no Idempotency-Key", async () => {
    const calls = stubFetch(() => new Response(null, { status: 204 }));
    await api.patch("/api/v1/users/{id}", { path: { id: "u1" }, body: { display_name: "Sam" }, ifMatch: 4712 });
    await api.delete("/api/v1/users/{id}", { path: { id: "u1" }, ifMatch: ANY_REVISION });
    expect(header(calls[0], "If-Match")).toBe('"4712"');
    expect(header(calls[0], "Idempotency-Key")).toBeUndefined();
    expect(header(calls[1], "If-Match")).toBe("*");
    expect(calls[1]?.url).toBe("/api/v1/users/u1");
  });

  it("returns undefined for 204", async () => {
    stubFetch(() => new Response(null, { status: 204 }));
    expect(await api.delete("/api/v1/auth/sessions/{id}", { path: { id: "s2" } })).toBeUndefined();
  });
});

describe("problem details", () => {
  it("throws an ApiError with the stable code, params and field errors", async () => {
    stubFetch(() =>
      problem(400, "auth.password.policy", {}, { errors: [{ field: "admin.password", code: "auth.password.too_short", params: { min: "12" } }] }),
    );
    const err = await api.post("/api/v1/setup", { body: {} as never }).catch((e: unknown) => e);
    expect(isApiError(err)).toBe(true);
    const e = err as ApiError;
    expect(e.status).toBe(400);
    expect(e.code).toBe("auth.password.policy");
    expect(e.is("auth.password")).toBe(true);
    expect(e.is("auth.pass")).toBe(false);
    expect(e.field("admin.password")?.code).toBe("auth.password.too_short");
    expect(errorMessage(e)).toBe("The password does not meet the policy.");
    expect(fieldErrorMessage(e.fieldErrors[0]!)).toBe("Use at least 12 characters.");
  });

  it("translates through the code with numeric params and reads Retry-After", async () => {
    stubFetch(() => {
      const r = problem(429, "auth.throttled", { retry_after: "20" });
      r.headers.set("retry-after", "20");
      return r;
    });
    const e = (await api.post("/api/v1/auth/login/password", { body: { user_name: "alex", password: "x" } }).catch((x: unknown) => x)) as ApiError;
    expect(e.retryAfter).toBe(20);
    expect(errorMessage(e)).toBe("Too many attempts. Try again in 20 s.");
  });

  it("falls back to the English title for codes without a translation, and to generic words", async () => {
    expect(errorMessage(new ApiError({ status: 409, code: "ipam.some.new_code", title: "Server title", detail: "" }))).toBe("Server title");
    expect(errorMessage(new ApiError({ status: 503, code: "x.y", title: "", detail: "" }))).toBe(
      "The server could not complete the request. Try again in a moment.",
    );
    expect(errorMessage(new ApiError({ status: 501, code: "x.y", title: "", detail: "" }))).toBe("This function is not available on the server yet.");
    expect(errorMessage(new Error("boom"))).toBe("Something unexpected happened. Try again.");
  });

  it("makes a synthetic problem from a body that is not one", () => {
    expect(toProblem(502, "<html>")).toMatchObject({ status: 502, code: CLIENT_CODES.badResponse, params: { status: "502" } });
    expect(errorMessage(new ApiError(toProblem(502, null)))).toBe("The server answered with status 502 and no explanation.");
  });

  it("reports an unreachable server as client.network", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => Promise.reject(new TypeError("Failed to fetch"))));
    const e = (await api.get("/api/v1/health").catch((x: unknown) => x)) as ApiError;
    expect(e.code).toBe(CLIENT_CODES.network);
    expect(errorMessage(e)).toBe("The server cannot be reached. Check the connection and try again.");
  });

  it("tells the session store about a missing session, not about a failed sign-in", async () => {
    const handler = vi.fn();
    setUnauthorizedHandler(handler);
    stubFetch((call) =>
      call.url.endsWith("/auth/session") ? problem(401, "auth.unauthenticated") : problem(401, "auth.invalid_credentials"),
    );
    await api.get("/api/v1/auth/session").catch(() => undefined);
    await api.post("/api/v1/auth/login/password", { body: { user_name: "a", password: "b" } }).catch(() => undefined);
    expect(handler).toHaveBeenCalledTimes(1);
  });
});

describe("pagination", () => {
  const items = Array.from({ length: 5 }, (_, i) => ({ id: `u${i}` }));
  function pagedServer() {
    return stubFetch((call) => {
      const u = new URL(call.url, "http://localhost");
      const cursor = Number(u.searchParams.get("cursor") ?? "0");
      const limit = Number(u.searchParams.get("limit") ?? "2");
      const slice = items.slice(cursor, cursor + limit);
      const next = cursor + limit < items.length ? String(cursor + limit) : null;
      return json({ items: slice, next_cursor: next, revision: 100 + cursor });
    });
  }

  it("fetches one page with limit, cursor and at_least, capping the limit at 1000", async () => {
    const calls = pagedServer();
    const page = await fetchPage("/api/v1/users", { limit: 5000, cursor: "2", atLeast: 7 });
    expect(page.items).toHaveLength(3);
    expect(calls[0]?.url).toBe("/api/v1/users?limit=1000&cursor=2&at_least=7");
  });

  it("walks every page and keeps the first page's revision", async () => {
    pagedServer();
    const all = await fetchAll<{ id: string }>("/api/v1/users", { limit: 2 });
    expect(all.items.map((x) => x.id)).toEqual(["u0", "u1", "u2", "u3", "u4"]);
    expect(all.revision).toBe(100);
    expect(all.truncated).toBe(false);
  });

  it("stops at max and says so", async () => {
    pagedServer();
    const all = await fetchAll<{ id: string }>("/api/v1/users", { limit: 2, max: 3 });
    expect(all.items).toHaveLength(3);
    expect(all.truncated).toBe(true);
  });

  it("yields pages lazily", async () => {
    const calls = pagedServer();
    const it = pages<{ id: string }>("/api/v1/users", { limit: 2 });
    const first = await it.next();
    expect(first.value?.items).toHaveLength(2);
    expect(calls).toHaveLength(1);
    await it.return(undefined);
  });
});
