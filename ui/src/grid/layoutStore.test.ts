// The layout store against the mock API: read after sign-in, the debounce, one request in flight
// per table, the one-time import of the older browser values, the fallback to the browser while
// the API is out of reach with the reconciliation after it, and the reset.
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
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
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

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
  setLayoutTimingForTest({ debounce: 30, retry: 50 });
  await syncLayoutsForTest(user());
});

afterEach(() => {
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
    await sleep(60);
    expect(watch.writes).toHaveLength(1);
    // A change while the first write is in flight waits for it.
    patchLayout(user(), "addresses", { order: ["ip", "mac"] });
    await sleep(60);
    expect(watch.writes).toHaveLength(1);
    watch.release();
    await sleep(60);
    expect(watch.writes).toHaveLength(2);
    expect(watch.maxInFlight()).toBe(1);
    expect(watch.writes[1]?.body).toEqual({ version: 1, hidden: ["mac", "mode"], order: ["ip", "mac"] });
    expect(mockPreferences()["table:addresses"]).toEqual({ version: 1, order: ["ip", "mac"], hidden: ["mac", "mode"] });
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
    await sleep(60);
    expect(mockPreferences()["table:dns-zones"]).toEqual({ version: 1, order: ["name", "kind"], hidden: ["serial"], widths: { name: 260 } });
    // A second sign-in finds nothing more to import.
    const watch = watchWrites();
    await syncLayoutsForTest(user());
    await sleep(60);
    expect(watch.writes).toHaveLength(0);
  });

  it("falls back to the browser while the API is out of reach and reconciles when it returns", async () => {
    let reachable = false;
    server.use(
      http.get("*/api/v1/auth/preferences", () => (reachable ? undefined : HttpResponse.error())) as never,
      http.put(PATH, () => (reachable ? undefined : HttpResponse.error())) as never,
    );
    patchLayout(user(), "findings", { hidden: ["since"] });
    await syncLayoutsForTest(user());
    expect(syncState()).toBe("offline");
    // The change applies and survives a reload of the page in this browser.
    expect(tableLayout(user(), "findings")()?.hidden).toEqual(["since"]);
    expect(JSON.parse(localStorage.getItem(`tenko-layout:${user()}:findings`) ?? "{}")).toMatchObject({ pending: true });
    await sleep(60);
    expect(mockPreferences()["table:findings"]).toBeUndefined();
    // The API comes back: the store reads it again and writes what is pending.
    reachable = true;
    await sleep(150);
    expect(syncState()).toBe("ready");
    await sleep(60);
    expect(mockPreferences()["table:findings"]).toEqual({ version: 1, hidden: ["since"] });
    expect(JSON.parse(localStorage.getItem(`tenko-layout:${user()}:findings`) ?? "{}")).toMatchObject({ pending: false });
  });

  it("takes the server's value for what did not change here, and drops a layout reset elsewhere", async () => {
    patchLayout(user(), "jobs", { hidden: ["owner"] });
    await sleep(60);
    expect(mockPreferences()["table:jobs"]).toEqual({ version: 1, hidden: ["owner"] });
    // Another browser resets the table.
    await fetch(`${location.origin}/api/v1/auth/preferences/table:jobs`, { method: "DELETE" });
    await syncLayoutsForTest(user());
    expect(tableLayout(user(), "jobs")()).toBeNull();
  });

  it("deletes the key on reset, at once", async () => {
    patchLayout(user(), "addresses", { hidden: ["mac"], widths: { ip: 140 } });
    await sleep(60);
    expect(mockPreferences()["table:addresses"]).toBeDefined();
    const watch = watchWrites();
    resetLayout(user(), "addresses");
    expect(tableLayout(user(), "addresses")()).toBeNull();
    await sleep(10);
    expect(watch.writes).toEqual([{ method: "DELETE", key: "table:addresses", body: null }]);
    expect(mockPreferences()["table:addresses"]).toBeUndefined();
  });

  it("keeps a table whose id cannot be a key in the browser only", async () => {
    const watch = watchWrites();
    patchLayout(user(), "Not a key", { hidden: ["a"] });
    await sleep(60);
    expect(watch.writes).toHaveLength(0);
    expect(tableLayout(user(), "Not a key")()?.hidden).toEqual(["a"]);
  });

  it("keeps a layout the server refuses in this browser without retrying it", async () => {
    const watch = watchWrites();
    const ids = Array.from({ length: 128 }, (_, i) => `${"c".repeat(60)}${String(i).padStart(4, "0")}`);
    patchLayout(user(), "big", { order: ids, hidden: ids });
    await sleep(200);
    expect(watch.writes).toHaveLength(1);
    expect(tableLayout(user(), "big")()?.order).toHaveLength(128);
    expect(syncState()).toBe("ready");
  });
});
