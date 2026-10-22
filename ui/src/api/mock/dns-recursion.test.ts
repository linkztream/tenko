// The recursive resolver of the mock node (WP10.1): the status of a resolver that runs and of one
// that is off, the priming, and the infrastructure cache's pages in canonical name order with
// their cursor, the suffix, the refusals and the flush. Pure model code, no msw.
import { describe, expect, it } from "vitest";
import { flushInfra, listInfra, primeNow, RecursionFailure, recursionStatus, seedRecursion } from "./dns-recursion-model";

const zones = (page: { items: { zone: string }[] }) => page.items.map((item) => item.zone);

describe("the status", () => {
  it("reports a running resolver with its figures against their bounds", () => {
    const status = recursionStatus(seedRecursion());
    expect(status.enabled).toBe(true);
    expect(status.infra).toMatchObject({ zones: 4, max_zones: 10_000, max_servers: 50_000 });
    expect(status.last_priming).toEqual({ at: "2026-10-17T11:58:02Z", outcome: "ok", duration_ms: 42.5 });
    expect(status.root_servers).toHaveLength(3);
    expect(status.problems).toEqual([]);
    expect(status.counters.secure).toBe(0);
  });

  it("reports a resolver that is off with empty and zero fields", () => {
    const state = seedRecursion();
    state.enabled = false;
    const status = recursionStatus(state);
    expect(status).toMatchObject({ enabled: false, hints_source: "", root_servers: [], problems: [] });
    expect(status.last_priming).toBeUndefined();
    expect(status.infra.max_zones).toBe(0);
    expect(status.counters.answered).toBe(0);
  });

  it("reports priming_failed after a priming that failed", () => {
    const state = seedRecursion();
    state.primingOk = false;
    expect(recursionStatus(state).problems).toEqual(["priming_failed"]);
    expect(recursionStatus(state).last_priming?.outcome).toBe("failed");
  });
});

describe("the priming", () => {
  it("ends now and succeeds", () => {
    const state = seedRecursion();
    state.primingOk = false;
    primeNow(state, Date.parse("2026-10-18T09:00:00Z"));
    expect(state).toMatchObject({ primedAt: "2026-10-18T09:00:00.000Z", primingOk: true, primings: 2 });
  });

  it("is refused while the resolver is off", () => {
    const state = seedRecursion();
    state.enabled = false;
    expect(() => primeNow(state, 0)).toThrow(RecursionFailure);
    expect(() => primeNow(state, 0)).toThrow(/is off/);
  });
});

describe("the infrastructure cache", () => {
  it("lists the cuts in canonical order and pages by the last zone", () => {
    const state = seedRecursion();
    const first = listInfra(state, { limit: "2" }, 7);
    // Label by label from the root: org before test, and a zone before the zones below it.
    expect(zones(first)).toEqual(["example.org", "test"]);
    expect(first.next_cursor).toBe("test");
    const second = listInfra(state, { limit: "2", cursor: first.next_cursor }, 7);
    expect(zones(second)).toEqual(["example.test", "sub.example.test"]);
    expect(second.next_cursor).toBe("sub.example.test");
    const last = listInfra(state, { limit: "2", cursor: second.next_cursor }, 7);
    expect(zones(last)).toEqual([]);
    expect(last.next_cursor).toBeNull();
  });

  it("keeps the cuts at or below a suffix", () => {
    const state = seedRecursion();
    expect(zones(listInfra(state, { suffix: "example.test" }, 1))).toEqual(["example.test", "sub.example.test"]);
    expect(zones(listInfra(state, { suffix: "example.test." }, 1))).toEqual(["example.test", "sub.example.test"]);
    expect(zones(listInfra(state, { suffix: "ample.test" }, 1))).toEqual([]);
  });

  it("refuses a limit, a suffix or a cursor that is not valid, with the field", () => {
    const state = seedRecursion();
    for (const [query, field] of [
      [{ limit: "0" }, "limit"],
      [{ limit: "1001" }, "limit"],
      [{ suffix: "a..b" }, "suffix"],
      [{ cursor: "bad name" }, "cursor"],
    ] as const) {
      try {
        listInfra(state, query, 1);
        throw new Error("not refused");
      } catch (err) {
        expect(err).toBeInstanceOf(RecursionFailure);
        expect((err as RecursionFailure).code).toBe("sys.invalid_value");
        expect((err as RecursionFailure).params).toEqual({ field });
      }
    }
  });

  it("flushes a suffix or everything and says how many cuts went", () => {
    const state = seedRecursion();
    expect(flushInfra(state, "example.test")).toBe(2);
    expect(zones(listInfra(state, {}, 1))).toEqual(["example.org", "test"]);
    expect(flushInfra(state, undefined)).toBe(2);
    expect(state.cuts).toEqual([]);
  });

  it("answers 409 while the resolver is off", () => {
    const state = seedRecursion();
    state.enabled = false;
    for (const run of [() => listInfra(state, {}, 1), () => flushInfra(state, null)]) {
      expect(run).toThrow(RecursionFailure);
      try {
        run();
      } catch (err) {
        expect((err as RecursionFailure).code).toBe("dns.recursion.disabled");
        expect((err as RecursionFailure).status).toBe(409);
      }
    }
  });
});
