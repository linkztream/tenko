import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { backoffDelay, EventStream, type ApiEvent } from "./events";

/** A scriptable stand-in for EventSource. */
class FakeSource {
  static all: FakeSource[] = [];
  readonly url: string;
  readyState = 0;
  onopen: ((e: Event) => void) | null = null;
  onerror: ((e: Event) => void) | null = null;
  closed = false;
  private listeners = new Map<string, ((e: Event) => void)[]>();

  constructor(url: string) {
    this.url = url;
    FakeSource.all.push(this);
  }
  addEventListener(type: string, fn: (e: Event) => void) {
    this.listeners.set(type, [...(this.listeners.get(type) ?? []), fn]);
  }
  close() {
    this.closed = true;
    this.readyState = 2;
  }
  open() {
    this.readyState = 1;
    this.onopen?.(new Event("open"));
  }
  fail() {
    this.onerror?.(new Event("error"));
  }
  emit(type: string, data: unknown, id = "") {
    const ev = new MessageEvent(type, { data: typeof data === "string" ? data : JSON.stringify(data), lastEventId: id });
    for (const fn of this.listeners.get(type) ?? []) fn(ev);
  }
  get query(): URLSearchParams {
    return new URL(this.url, "http://localhost").searchParams;
  }
  static last(): FakeSource {
    const s = FakeSource.all[FakeSource.all.length - 1];
    if (!s) throw new Error("no source");
    return s;
  }
}

function stream(random = () => 0.5) {
  return new EventStream({
    createEventSource: (url) => new FakeSource(url) as unknown as EventSource,
    random,
    backoff: { baseMs: 1000, maxMs: 30_000 },
  });
}

beforeEach(() => {
  FakeSource.all = [];
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
});

describe("backoff", () => {
  it("doubles the cap up to the maximum and jitters within [cap/2, cap]", () => {
    const opts = { baseMs: 1000, maxMs: 30_000 };
    expect(backoffDelay(0, opts, () => 0)).toBe(500);
    expect(backoffDelay(0, opts, () => 1)).toBe(1000);
    expect(backoffDelay(3, opts, () => 0.5)).toBe(6000);
    expect(backoffDelay(10, opts, () => 1)).toBe(30_000);
    expect(backoffDelay(50, opts, () => 0)).toBe(15_000);
  });
});

describe("EventStream", () => {
  it("connects with the subscribed topics and reports live", async () => {
    const s = stream();
    s.subscribe("jobs", () => undefined);
    s.start();
    const src = FakeSource.last();
    expect(src.query.get("topics")).toBe("jobs,system");
    expect(src.query.has("from")).toBe(false);
    expect(s.state()).toBe("connecting");
    src.open();
    expect(s.state()).toBe("live");
    s.stop();
    expect(src.closed).toBe(true);
    expect(s.state()).toBe("idle");
  });

  it("names only its subscribed topics without base topics, and delivers metrics snapshots without a revision", () => {
    const s = new EventStream({ baseTopics: [], createEventSource: (url) => new FakeSource(url) as unknown as EventSource });
    const got: ApiEvent[] = [];
    s.subscribe("metrics", (e) => got.push(e));
    s.start();
    const src = FakeSource.last();
    expect(src.query.get("topics")).toBe("metrics");
    src.emit("metrics", { topic: "metrics", kind: "metrics.snapshot", metrics: { nodes: [], cluster: {} } }, "12");
    expect(got).toHaveLength(1);
    expect(got[0]?.revision).toBeUndefined();
    expect(got[0]?.data.kind).toBe("metrics.snapshot");
    s.stop();
  });

  it("delivers topic events with revision and object references, and tracks the last id", () => {
    const s = stream();
    const seen: ApiEvent[] = [];
    s.subscribe("ipam", (e) => seen.push(e));
    s.start();
    const src = FakeSource.last();
    src.open();
    src.emit("ipam", { topic: "ipam", revision: 4712, objects: [{ kind: "address", id: "a1" }], deleted: [{ kind: "host", id: "h9" }] }, "4712");
    src.emit("jobs", { topic: "jobs", revision: 4713 }, "4713");
    src.emit("system", { topic: "system", revision: 4714, kind: "ipam.utilization" }, "4714");
    expect(seen).toHaveLength(1);
    expect(seen[0]).toMatchObject({ topic: "ipam", revision: 4712, objects: [{ kind: "address", id: "a1" }], deleted: [{ kind: "host", id: "h9" }] });
    // Not subscribed to jobs: that event never arrives; the system one does.
    expect(s.lastEventId).toBe("4714");
    expect(s.lastEventAt()).not.toBeNull();
    s.stop();
  });

  it("gives a system event no revision, although EventSource repeats the id of the store event before it", () => {
    const s = stream();
    const seen: ApiEvent[] = [];
    s.subscribe("connectors", (e) => seen.push(e));
    s.start();
    const src = FakeSource.last();
    src.open();
    src.emit("connectors", { topic: "connectors", revision: 120, objects: [{ kind: "connector", id: "c1" }] }, "120");
    // No `id:` line: the browser still reports the last id it saw.
    src.emit("connectors", { topic: "connectors", objects: [{ kind: "connector", id: "c1" }], kind: "connect.health" }, "120");
    expect(seen.map((e) => e.revision)).toEqual([120, undefined]);
    expect(seen[1]).toMatchObject({ topic: "connectors", objects: [{ kind: "connector", id: "c1" }] });
    // The resume position stays at the store event.
    expect(s.lastEventId).toBe("120");
    s.stop();
  });

  it("reconnects after an error with jittered exponential backoff and resumes from the last id", () => {
    const s = stream(() => 0.5);
    s.subscribe("jobs", () => undefined);
    s.start();
    const first = FakeSource.last();
    first.open();
    first.emit("jobs", { topic: "jobs", revision: 10 }, "10");
    first.fail();
    expect(first.closed).toBe(true);
    expect(s.state()).toBe("reconnecting");

    vi.advanceTimersByTime(749);
    expect(FakeSource.all).toHaveLength(1);
    vi.advanceTimersByTime(1);
    const second = FakeSource.last();
    expect(FakeSource.all).toHaveLength(2);
    expect(second.query.get("from")).toBe("10");

    second.fail();
    vi.advanceTimersByTime(1499);
    expect(FakeSource.all).toHaveLength(2);
    vi.advanceTimersByTime(1);
    expect(FakeSource.all).toHaveLength(3);

    const third = FakeSource.last();
    third.open();
    expect(s.state()).toBe("live");
    third.fail();
    vi.advanceTimersByTime(750);
    expect(FakeSource.all).toHaveLength(4);
    s.stop();
  });

  it("starts from a list revision unless the stream is already past it", () => {
    const s = stream();
    s.resumeFrom(500);
    s.subscribe("ipam", () => undefined);
    s.start();
    expect(FakeSource.last().query.get("from")).toBe("500");
    FakeSource.last().emit("ipam", { topic: "ipam", revision: 600 }, "600");
    s.resumeFrom(550);
    expect(s.lastEventId).toBe("600");
    s.stop();
  });

  it("asks every subscriber to reload on reset", () => {
    const s = stream();
    const ipam = vi.fn();
    const jobs = vi.fn();
    s.onReset("ipam", ipam);
    s.onReset("jobs", jobs);
    s.start();
    FakeSource.last().open();
    FakeSource.last().emit("reset", { reason: "gap", revision: 900 }, "900");
    expect(ipam).toHaveBeenCalledTimes(1);
    expect(jobs).toHaveBeenCalledTimes(1);
    expect(s.lastEventId).toBe("900");
    s.stop();
  });

  it("reconnects with backoff when the server shuts down", () => {
    const s = stream(() => 0);
    s.start();
    const src = FakeSource.last();
    src.open();
    src.emit("shutdown", "");
    expect(src.closed).toBe(true);
    vi.advanceTimersByTime(500);
    expect(FakeSource.all).toHaveLength(2);
    s.stop();
  });

  it("reconnects once with the new topic set when subscriptions change", () => {
    const s = stream();
    s.start();
    expect(FakeSource.last().query.get("topics")).toBe("system");
    const off = s.subscribe("ipam", () => undefined);
    s.subscribe("jobs", () => undefined);
    vi.advanceTimersByTime(0);
    expect(FakeSource.all).toHaveLength(2);
    expect(FakeSource.last().query.get("topics")).toBe("ipam,jobs,system");
    off();
    vi.advanceTimersByTime(0);
    expect(FakeSource.last().query.get("topics")).toBe("jobs,system");
    s.stop();
  });

  it("waits while the browser is offline and reconnects when it is back", () => {
    const s = stream();
    s.start();
    window.dispatchEvent(new Event("offline"));
    expect(s.state()).toBe("offline");
    window.dispatchEvent(new Event("online"));
    expect(s.state()).toBe("connecting");
    expect(FakeSource.all).toHaveLength(2);
    s.stop();
  });
});
