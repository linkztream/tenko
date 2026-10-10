import { createRoot } from "solid-js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { EventStream } from "./events";
import { createResource } from "solid-js";
import { createLiveQuery, latest, type LiveQuery } from "./live";

class FakeSource {
  static last: FakeSource | undefined;
  onopen: ((e: Event) => void) | null = null;
  onerror: ((e: Event) => void) | null = null;
  private listeners = new Map<string, ((e: Event) => void)[]>();
  constructor(readonly url: string) {
    FakeSource.last = this;
  }
  addEventListener(type: string, fn: (e: Event) => void) {
    this.listeners.set(type, [...(this.listeners.get(type) ?? []), fn]);
  }
  close() {}
  emit(type: string, data: unknown, id = "") {
    const ev = new MessageEvent(type, { data: JSON.stringify(data), lastEventId: id });
    for (const fn of this.listeners.get(type) ?? []) fn(ev);
  }
}

let stream: EventStream;

beforeEach(() => {
  vi.useFakeTimers();
  stream = new EventStream({ createEventSource: (u) => new FakeSource(u) as unknown as EventSource });
  stream.start();
});

afterEach(() => {
  stream.stop();
  vi.useRealTimers();
});

async function settle() {
  await vi.advanceTimersByTimeAsync(0);
}

describe("createLiveQuery", () => {
  it("loads, resumes the stream from the list revision, and refetches on newer relevant events", async () => {
    let n = 0;
    const fetch = vi.fn(async () => ({ value: ++n, revision: 100 * n }));
    let q!: LiveQuery<number>;
    const dispose = createRoot((d) => {
      q = createLiveQuery({ topics: ["admin"], fetch, stream, relevant: (e) => e.objects.some((o) => o.kind === "user") });
      return d;
    });
    await settle();
    expect(q.value()).toBe(1);
    expect(q.revision()).toBe(100);
    expect(stream.lastEventId).toBe("100");

    await vi.advanceTimersByTimeAsync(1);
    const src = FakeSource.last!;
    // Older than what was read: ignored.
    src.emit("admin", { topic: "admin", revision: 90, objects: [{ kind: "user", id: "u1" }] }, "90");
    // Newer but not relevant: ignored.
    src.emit("admin", { topic: "admin", revision: 101, objects: [{ kind: "token", id: "t1" }] }, "101");
    await vi.advanceTimersByTimeAsync(200);
    expect(fetch).toHaveBeenCalledTimes(1);

    // A burst of relevant events: one refetch after the debounce.
    src.emit("admin", { topic: "admin", revision: 102, objects: [{ kind: "user", id: "u1" }] }, "102");
    src.emit("admin", { topic: "admin", revision: 103, objects: [{ kind: "user", id: "u2" }] }, "103");
    await vi.advanceTimersByTimeAsync(149);
    expect(fetch).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(1);
    await settle();
    expect(fetch).toHaveBeenCalledTimes(2);
    expect(q.value()).toBe(2);

    // A reset reloads at once.
    src.emit("reset", { reason: "lagged", revision: 900 }, "900");
    await settle();
    expect(fetch).toHaveBeenCalledTimes(3);

    dispose();
    src.emit("admin", { topic: "admin", revision: 1000, objects: [{ kind: "user", id: "u1" }] }, "1000");
    await vi.advanceTimersByTimeAsync(500);
    expect(fetch).toHaveBeenCalledTimes(3);
  });
});

describe("latest", () => {
  it("is undefined before the first read, the value after it, and undefined again while the last read failed", async () => {
    let call = 0;
    const fetch = vi.fn(async () => {
      call += 1;
      if (call === 2) throw new Error("read failed");
      return { value: call * 10, revision: call };
    });
    let q!: LiveQuery<number>;
    const dispose = createRoot((d) => {
      q = createLiveQuery({ topics: ["admin"], fetch, stream });
      return d;
    });
    expect(q.latest()).toBeUndefined();
    expect(latest(q)).toBeUndefined();

    await settle();
    expect(q.latest()).toBe(10);
    expect(latest(q)).toBe(10);
    expect(latest(q.value)).toBe(10);

    // The second read fails: `value.latest` throws that error, the guard does not.
    q.refetch();
    await settle();
    expect(q.value.error).toBeInstanceOf(Error);
    expect(() => q.value.latest).toThrow("read failed");
    expect(q.latest()).toBeUndefined();
    expect(latest(q)).toBeUndefined();
    expect(latest(q.value)).toBeUndefined();

    // The next read succeeds again and the value is back.
    q.refetch();
    await settle();
    expect(q.value.error).toBeUndefined();
    expect(q.latest()).toBe(30);
    expect(latest(q)).toBe(30);
    dispose();
  });

  it("guards any resource, not only live queries", async () => {
    const handle = createRoot((dispose) => {
      let n = 0;
      const [resource, { refetch }] = createResource<string>(async () => {
        n += 1;
        if (n === 2) throw new Error("nope");
        return `read ${n}`;
      });
      return { resource, refetch, dispose };
    });
    expect(latest(handle.resource)).toBeUndefined();
    await settle();
    expect(latest(handle.resource)).toBe("read 1");
    void handle.refetch();
    await settle();
    expect(() => handle.resource.latest).toThrow("nope");
    expect(latest(handle.resource)).toBeUndefined();
    handle.dispose();
  });
});
