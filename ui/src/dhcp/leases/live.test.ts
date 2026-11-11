// The live view of the DHCP lists against a page that states the revision its rows are complete
// at: an event newer than the page means read again, also when the read that the event caused
// comes back older than it (the role's table takes a commit after the store announced it).
import { createRoot, createSignal } from "solid-js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ApiEvent, EventStream } from "../../api/events";
import { createLiveRefresh, LEASE_TABLE } from "./live";

function fakeStream() {
  const handlers: ((event: ApiEvent) => void)[] = [];
  const stream = {
    subscribe: (_topic: string, handler: (event: ApiEvent) => void) => {
      handlers.push(handler);
      return () => undefined;
    },
    onReset: () => () => undefined,
  } as unknown as EventStream;
  const send = (revision: number) => {
    for (const handler of handlers) handler({ topic: "dhcp", type: "dhcp", objects: [], deleted: [], revision, data: { tables: [LEASE_TABLE] } });
  };
  return { stream, send };
}

/** A view over a page at `start` whose reads answer the revisions of `answers`, then the last one again. */
function view(start: number, answers: number[]) {
  const { stream, send } = fakeStream();
  const [revision, setRevision] = createSignal(start);
  let reads = 0;
  const refresh = () => {
    const next = answers[Math.min(reads, answers.length - 1)] ?? start;
    reads += 1;
    return Promise.resolve().then(() => {
      setRevision(next);
    });
  };
  let dispose = () => undefined as void;
  createRoot((done) => {
    dispose = done;
    createLiveRefresh({ table: LEASE_TABLE, revision, refresh, stream });
  });
  return { send, reads: () => reads, dispose };
}

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
});

describe("the live view of a DHCP list", () => {
  it("reads again while the page is older than the change it saw, and stops once it holds it", async () => {
    // The event of revision 10 arrives; the first two reads still answer 8, the third 10.
    const live = view(5, [8, 8, 10]);
    live.send(10);
    await vi.advanceTimersByTimeAsync(5_000);
    expect(live.reads()).toBe(3);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(live.reads()).toBe(3);
    live.dispose();
  });

  it("takes an event at or below the page's revision as seen", async () => {
    const live = view(10, [10]);
    live.send(9);
    live.send(10);
    await vi.advanceTimersByTimeAsync(5_000);
    expect(live.reads()).toBe(0);
    live.dispose();
  });

  it("reads once for a change the first read already holds", async () => {
    const live = view(5, [12]);
    live.send(11);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(live.reads()).toBe(1);
    live.dispose();
  });

  it("pauses longer each time a read is still behind, up to five seconds", async () => {
    // Never catches up: the reads come at 0, 0.2, 0.6, 1.4, 3.0, 6.2, 11.2, 16.2 s and so on.
    const live = view(5, [8]);
    live.send(10);
    await vi.advanceTimersByTimeAsync(16_300);
    expect(live.reads()).toBe(8);
    live.dispose();
    await vi.advanceTimersByTimeAsync(60_000);
    expect(live.reads()).toBe(8);
  });
});
