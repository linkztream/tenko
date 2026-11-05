// The layout store against the mock API: read after sign-in, the debounce, one request in flight
// per table, the one-time import of the older browser values, the fallback to the browser while
// the API is out of reach with the reconciliation after it, and the reset.
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mockPreferences } from "../api/mock/routes-preferences";
import { server } from "../api/mock/node";
import { signInAlex } from "../auth/account/testkit";
import { session } from "../auth/session";
import {
  LEGACY_COLUMNS,
  LEGACY_WIDTHS,
  applyPatch,
  patchLayout,
  resetLayout,
  sanitizeLayout,
  setLayoutTimingForTest,
  syncLayoutsForTest,
  syncState,
  tableLayout,
} from "./layoutStore";

const PATH = "*/api/v1/auth/preferences/:key";
const user = () => session()?.user.id ?? "missing";

/** The debounce and the retry of the store in these tests, in milliseconds. */
const DEBOUNCE = 30;
const RETRY = 50;

/**
 * Lets the test's own clock run: only the store's timers (setTimeout, clearTimeout) are faked, so
 * the debounce and the retry fire when the test says and never because the machine was slow. The
 * requests of the mock API still run on real turns of the event loop; `until` waits for them.
 */
function fakeClock() {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
}

/** Moves the fake clock by `ms` and lets the promises that wake up settle. */
const tick = (ms: number) => vi.advanceTimersByTimeAsync(ms);

/**
 * Waits for `check` to stop throwing, on real turns of the event loop. `vi.waitFor` is no use
 * here: with fake timers it also moves the clock on every poll, which would fire the debounce.
 */
async function until(check: () => void, timeout = 5000): Promise<void> {
  const end = Date.now() + timeout;
  for (;;) {
    try {
      check();
      return;
    } catch (err) {
      if (Date.now() > end) throw err;
    }
    await new Promise<void>((resolve) => setImmediate(resolve));
  }
}

/** Counts the writes of the store and lets a test hold their answers. */
function watchWrites(options: { hold?: boolean; fail?: boolean } = {}) {
  const writes: { method: string; key: string; body: unknown }[] = [];
  let release: () => void = () => {};
  let gate = Promise.resolve();
  if (options.hold) gate = new Promise((resolve) => (release = resolve));
  let inFlight = 0;
  let maxInFlight = 0;
  server.use(
    http.put(PATH, async ({ request, params }) => {
      inFlight++;
      maxInFlight = Math.max(maxInFlight, inFlight);
      writes.push({ method: "PUT", key: String(params.key), body: await request.clone().json() });
      await gate;
      inFlight--;
      if (options.fail) return HttpResponse.json({ code: "client.network" }, { status: 503 });
      return undefined as never; // fall through to the mock handler
    }),
    http.delete(PATH, async ({ params }) => {
      writes.push({ method: "DELETE", key: String(params.key), body: null });
      await gate;
      if (options.fail) return HttpResponse.json({ code: "client.network" }, { status: 503 });
      return undefined as never;
    }),
  );
  return { writes, release: () => release(), maxInFlight: () => maxInFlight };
}

beforeEach(async () => {
  localStorage.clear();
  await signInAlex();
  setLayoutTimingForTest({ debounce: DEBOUNCE, retry: RETRY });
  await syncLayoutsForTest(user());
  fakeClock();
});

afterEach(() => {
  vi.useRealTimers();
  localStorage.clear();
});

describe("the document", () => {
  it("keeps the fields of version 1 with their shapes and drops the rest", () => {
    expect(
      sanitizeLayout({
        version: 1,
        order: ["ip", 3, "ip", "<b>"],
        hidden: "mac",
        widths: { ip: 140.4, name: "wide", "a b": 90 },
        sort: { column: "ip", desc: true, extra: 1 },
        script: "x",
      }),
    ).toEqual({ version: 1, order: ["ip"], widths: { ip: 140 }, sort: { column: "ip", desc: true } });
    expect(sanitizeLayout({ version: 1 })).toBeNull();
    expect(sanitizeLayout("x")).toBeNull();
    expect(applyPatch({ version: 1, order: ["a"] }, { order: undefined })).toBeNull();
    expect(applyPatch(null, { hidden: ["a"] })).toEqual({ version: 1, hidden: ["a"] });
  });
});

describe("the layout store", () => {
  it("reads the person's layouts after sign-in", async () => {
    // Another browser saved one.
    const other = await fetch(`${location.origin}/api/v1/auth/preferences/table:jobs`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ version: 1, hidden: ["owner"] }),
    });
    expect(other.status).toBe(200);
    await syncLayoutsForTest(user());
    expect(syncState()).toBe("ready");
    expect(tableLayout(user(), "jobs")()).toEqual({ version: 1, hidden: ["owner"] });
    expect(tableLayout(user(), "zones")()).toBeNull();
  });

  it("writes once after a quiet second, never twice at the same time for one table", async () => {
    const watch = watchWrites({ hold: true });
    patchLayout(user(), "addresses", { hidden: ["mac"] });
    patchLayout(user(), "addresses", { hidden: ["mac", "mode"] });
    expect(tableLayout(user(), "addresses")()?.hidden).toEqual(["mac", "mode"]);
    expect(watch.writes).toHaveLength(0);
    // Not before the debounce has run out ...
    await tick(DEBOUNCE - 1);
    expect(watch.writes).toHaveLength(0);
    // ... and once it has, in one request for both changes.
    await tick(1);
    await until(() => expect(watch.writes).toHaveLength(1));
    // A change while the first write is in flight waits for it: its debounce runs out, no
    // second request starts.
    patchLayout(user(), "addresses", { order: ["ip", "mac"] });
    await tick(DEBOUNCE);
    expect(watch.writes).toHaveLength(1);
    watch.release();
    await until(() => expect(watch.writes).toHaveLength(2));
    expect(watch.maxInFlight()).toBe(1);
    expect(watch.writes[1]?.body).toEqual({ version: 1, hidden: ["mac", "mode"], order: ["ip", "mac"] });
    await until(() =>
      expect(mockPreferences()["table:addresses"]).toEqual({ version: 1, order: ["ip", "mac"], hidden: ["mac", "mode"] }),
    );
  });

  it("imports the browser's older values once per table, then forgets them", async () => {
    localStorage.setItem(`${LEGACY_COLUMNS}dns-zones`, JSON.stringify({ order: ["name", "kind"], hidden: ["serial"] }));
    localStorage.setItem(`${LEGACY_WIDTHS}${user()}:dns-zones`, JSON.stringify({ name: 260 }));
    localStorage.setItem(`${LEGACY_COLUMNS}dhcp-leases`, JSON.stringify({ hidden: ["mac"] }));
    // The server already has a layout for the leases: it wins and the older value is dropped.
    await fetch(`${location.origin}/api/v1/auth/preferences/table:dhcp-leases`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ version: 1, hidden: ["hostname"] }),
    });
    await syncLayoutsForTest(user());
    expect(tableLayout(user(), "dns-zones")()).toEqual({ version: 1, order: ["name", "kind"], hidden: ["serial"], widths: { name: 260 } });
    expect(tableLayout(user(), "dhcp-leases")()?.hidden).toEqual(["hostname"]);
    expect(localStorage.getItem(`${LEGACY_COLUMNS}dns-zones`)).toBeNull();
    expect(localStorage.getItem(`${LEGACY_WIDTHS}${user()}:dns-zones`)).toBeNull();
    expect(localStorage.getItem(`${LEGACY_COLUMNS}dhcp-leases`)).toBeNull();
    // The import writes at once, without the debounce.
    await until(() =>
      expect(mockPreferences()["table:dns-zones"]).toEqual({ version: 1, order: ["name", "kind"], hidden: ["serial"], widths: { name: 260 } }),
    );
    // A second sign-in finds nothing more to import: no write, not even after the debounce.
    const watch = watchWrites();
    await syncLayoutsForTest(user());
    await tick(DEBOUNCE * 2);
    expect(watch.writes).toHaveLength(0);
  });

  it("falls back to the browser while the API is out of reach and reconciles when it returns", async () => {
    let reachable = false;
    let refusedWrites = 0;
    server.use(
      http.get("*/api/v1/auth/preferences", () => (reachable ? undefined : HttpResponse.error())) as never,
      http.put(PATH, () => {
        if (reachable) return undefined;
        refusedWrites++;
        return HttpResponse.error();
      }) as never,
    );
    patchLayout(user(), "findings", { hidden: ["since"] });
    await syncLayoutsForTest(user());
    expect(syncState()).toBe("offline");
    // The change applies and survives a reload of the page in this browser.
    expect(tableLayout(user(), "findings")()?.hidden).toEqual(["since"]);
    expect(JSON.parse(localStorage.getItem(`tenko-layout:${user()}:findings`) ?? "{}")).toMatchObject({ pending: true });
    // The debounce runs out and the write fails; the layout stays on the server's side unwritten.
    await tick(DEBOUNCE);
    await until(() => expect(refusedWrites).toBe(1));
    expect(mockPreferences()["table:findings"]).toBeUndefined();
    // The API comes back: when the retry delay is over the store reads it again, and writes what
    // is pending.
    reachable = true;
    await tick(RETRY);
    await until(() => expect(syncState()).toBe("ready"));
    await until(() => expect(mockPreferences()["table:findings"]).toEqual({ version: 1, hidden: ["since"] }));
    await until(() =>
      expect(JSON.parse(localStorage.getItem(`tenko-layout:${user()}:findings`) ?? "{}")).toMatchObject({ pending: false }),
    );
  });

  it("takes the server's value for what did not change here, and drops a layout reset elsewhere", async () => {
    patchLayout(user(), "jobs", { hidden: ["owner"] });
    await tick(DEBOUNCE);
    await until(() => expect(mockPreferences()["table:jobs"]).toEqual({ version: 1, hidden: ["owner"] }));
    // Another browser resets the table.
    await fetch(`${location.origin}/api/v1/auth/preferences/table:jobs`, { method: "DELETE" });
    await syncLayoutsForTest(user());
    expect(tableLayout(user(), "jobs")()).toBeNull();
  });

  it("deletes the key on reset, at once", async () => {
    patchLayout(user(), "addresses", { hidden: ["mac"], widths: { ip: 140 } });
    await tick(DEBOUNCE);
    await until(() => expect(mockPreferences()["table:addresses"]).toBeDefined());
    const watch = watchWrites();
    resetLayout(user(), "addresses");
    expect(tableLayout(user(), "addresses")()).toBeNull();
    // At once: the clock has not moved since the reset, so no debounce is behind this request.
    await until(() => expect(watch.writes).toEqual([{ method: "DELETE", key: "table:addresses", body: null }]));
    await until(() => expect(mockPreferences()["table:addresses"]).toBeUndefined());
  });

  it("keeps a table whose id cannot be a key in the browser only", async () => {
    const watch = watchWrites();
    patchLayout(user(), "Not a key", { hidden: ["a"] });
    // No debounce is started for it, so there is nothing to wait for; run the clock past one
    // anyway to show that nothing is sent.
    await tick(DEBOUNCE * 2);
    expect(watch.writes).toHaveLength(0);
    expect(tableLayout(user(), "Not a key")()?.hidden).toEqual(["a"]);
  });

  it("keeps a layout the server refuses in this browser without retrying it", async () => {
    const watch = watchWrites();
    const ids = Array.from({ length: 128 }, (_, i) => `${"c".repeat(60)}${String(i).padStart(4, "0")}`);
    patchLayout(user(), "big", { order: ids, hidden: ids });
    await tick(DEBOUNCE);
    await until(() => expect(watch.writes).toHaveLength(1));
    // The refusal is final: the layout is marked as written, and the retry delay passing sends
    // nothing more.
    await until(() =>
      expect(JSON.parse(localStorage.getItem(`tenko-layout:${user()}:big`) ?? "{}")).toMatchObject({ pending: false }),
    );
    await tick(RETRY * 2);
    expect(watch.writes).toHaveLength(1);
    expect(tableLayout(user(), "big")()?.order).toHaveLength(128);
    expect(syncState()).toBe("ready");
  });
});
