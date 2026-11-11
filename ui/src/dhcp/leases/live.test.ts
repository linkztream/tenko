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

  it("pauses longer each time a read is still behind, up to five seconds, and stops after eight", async () => {
    // Never catches up: the reads come at 0, 0.2, 0.6, 1.4, 3.0, 6.2, 11.2, 16.2 and 21.2 s.
    const live = view(5, [8]);
    live.send(10);
    await vi.advanceTimersByTimeAsync(16_300);
    expect(live.reads()).toBe(8);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(live.reads()).toBe(9);
    // The next change starts the reads again.
    live.send(11);
    await vi.advanceTimersByTimeAsync(300);
    expect(live.reads()).toBe(11);
    live.dispose();
    await vi.advanceTimersByTimeAsync(60_000);
    expect(live.reads()).toBe(11);
  });

  it("checks only the page of the last read, when a newer read replaced an older one", async () => {
    const { stream, send } = fakeStream();
    const [revision, setRevision] = createSignal(5);
    const pending: (() => void)[] = [];
    let reads = 0;
    const answers = [undefined, 12];
    const refresh = () => {
      const answer = answers[reads];
      reads += 1;
      return new Promise<void>((done) => {
        pending.push(() => {
          // A replaced read sets nothing, as the list source drops it.
          if (answer !== undefined) setRevision(answer);
          done();
        });
      });
    };
    let dispose = () => undefined as void;
    createRoot((done) => {
      dispose = done;
      createLiveRefresh({ table: LEASE_TABLE, revision, refresh, stream });
    });
    send(10);
    await vi.advanceTimersByTimeAsync(0);
    send(12);
    await vi.advanceTimersByTimeAsync(200);
    expect(reads).toBe(2);
    // The replaced read comes back first, still at 5; then the last one, at 12.
    pending[0]!();
    await vi.advanceTimersByTimeAsync(0);
    pending[1]!();
    await vi.advanceTimersByTimeAsync(60_000);
    expect(reads).toBe(2);
    dispose();
  });

  it("reads nothing while it is paused, and checks the read of the resume", async () => {
    const { stream, send } = fakeStream();
    const [revision] = createSignal(5);
    let reads = 0;
    const refresh = () => {
      reads += 1;
      return Promise.resolve();
    };
    let control: ReturnType<typeof createLiveRefresh> | undefined;
    let dispose = () => undefined as void;
    createRoot((done) => {
      dispose = done;
      control = createLiveRefresh({ table: LEASE_TABLE, revision, refresh, stream });
    });
    control!.setLive(false);
    send(10);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(reads).toBe(0);
    control!.setLive(true);
    await vi.advanceTimersByTimeAsync(60_000);
    // One read on resume; the change of the pause is not followed, the resume's read shows it.
    expect(reads).toBe(1);
    dispose();
  });
});
