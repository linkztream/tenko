import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { GRACE_SECS, PROBE_INTERVAL_MS, restartTimeoutMs, watchRestart } from "./restart";

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
});

describe("restartTimeoutMs", () => {
  it("is the ready time of the server plus a minute", () => {
    expect(GRACE_SECS).toBe(60);
    expect(restartTimeoutMs(120)).toBe(180_000);
    expect(restartTimeoutMs(0)).toBe(60_000);
    expect(restartTimeoutMs(-5)).toBe(60_000);
  });
});

describe("watchRestart", () => {
  it("asks every two seconds and calls back when the target version answers", async () => {
    const answers = ["0.1.0", "0.1.0", "0.2.0"];
    const probe = vi.fn(async () => answers.shift() ?? "0.2.0");
    const onReady = vi.fn();
    const onTimeout = vi.fn();
    watchRestart({ target: "0.2.0", probe, timeoutMs: 180_000, onReady, onTimeout });

    expect(PROBE_INTERVAL_MS).toBe(2000);
    await vi.advanceTimersByTimeAsync(1999);
    expect(probe).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);
    expect(probe).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(2000);
    expect(probe).toHaveBeenCalledTimes(2);
    expect(onReady).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(2000);
    expect(probe).toHaveBeenCalledTimes(3);
    expect(onReady).toHaveBeenCalledTimes(1);

    // It stops asking once the version answered.
    await vi.advanceTimersByTimeAsync(20_000);
    expect(probe).toHaveBeenCalledTimes(3);
    expect(onTimeout).not.toHaveBeenCalled();
  });

  it("treats a probe that fails as no answer, and keeps asking", async () => {
    let calls = 0;
    const probe = vi.fn(async () => {
      calls += 1;
      if (calls < 3) throw new Error("connection refused");
      return "0.2.0";
    });
    const onReady = vi.fn();
    watchRestart({ target: "0.2.0", probe, timeoutMs: 180_000, onReady, onTimeout: vi.fn() });
    await vi.advanceTimersByTimeAsync(6000);
    expect(onReady).toHaveBeenCalledTimes(1);
  });

  it("gives up when the time is over", async () => {
    const probe = vi.fn(async () => "0.1.0");
    const onReady = vi.fn();
    const onTimeout = vi.fn();
    watchRestart({ target: "0.2.0", probe, timeoutMs: 10_000, onReady, onTimeout });
    await vi.advanceTimersByTimeAsync(8000);
    expect(onTimeout).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(2000);
    expect(onTimeout).toHaveBeenCalledTimes(1);
    expect(onReady).not.toHaveBeenCalled();
    const asked = probe.mock.calls.length;
    await vi.advanceTimersByTimeAsync(20_000);
    expect(probe.mock.calls.length).toBe(asked);
  });

  it("can be stopped", async () => {
    const probe = vi.fn(async () => "0.2.0");
    const onReady = vi.fn();
    const stop = watchRestart({ target: "0.2.0", probe, timeoutMs: 180_000, onReady, onTimeout: vi.fn() });
    stop();
    await vi.advanceTimersByTimeAsync(10_000);
    expect(probe).not.toHaveBeenCalled();
    expect(onReady).not.toHaveBeenCalled();
  });
});
