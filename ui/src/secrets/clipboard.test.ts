import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { clearNow, clearPending, copyValue, scheduleClear } from "./clipboard";

/** A clipboard the page may read and write, or not. */
function fakeClipboard(options: { readable?: boolean; writable?: boolean } = {}) {
  const state = { text: "" };
  const clipboard = {
    writeText: vi.fn((text: string) => {
      if (options.writable === false) return Promise.reject(new DOMException("denied", "NotAllowedError"));
      state.text = text;
      return Promise.resolve();
    }),
    readText: vi.fn(() =>
      options.readable === false ? Promise.reject(new DOMException("denied", "NotAllowedError")) : Promise.resolve(state.text),
    ),
  };
  Object.defineProperty(navigator, "clipboard", { configurable: true, value: clipboard });
  return state;
}

describe("the clipboard path of a revealed secret", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(async () => {
    await clearNow();
    vi.useRealTimers();
    Reflect.deleteProperty(navigator, "clipboard");
  });

  it("copies the value and clears it after the given time", async () => {
    const state = fakeClipboard();
    expect(await copyValue("example-secret")).toBe("copied");
    expect(state.text).toBe("example-secret");
    const done = vi.fn();
    scheduleClear("example-secret", 30, done);
    expect(clearPending()).toBe(true);
    await vi.advanceTimersByTimeAsync(29_000);
    expect(state.text).toBe("example-secret");
    await vi.advanceTimersByTimeAsync(1_000);
    expect(state.text).toBe("");
    expect(done).toHaveBeenCalledWith("cleared");
    expect(clearPending()).toBe(false);
  });

  it("leaves the clipboard alone when it holds something else by then", async () => {
    const state = fakeClipboard();
    await copyValue("example-secret");
    const done = vi.fn();
    scheduleClear("example-secret", 30, done);
    state.text = "something the person copied since";
    await vi.advanceTimersByTimeAsync(30_000);
    expect(state.text).toBe("something the person copied since");
    expect(done).toHaveBeenCalledWith("left");
  });

  it("clears regardless when the page may not read the clipboard", async () => {
    const state = fakeClipboard({ readable: false });
    await copyValue("example-secret");
    state.text = "unknown to the page";
    const done = vi.fn();
    scheduleClear("example-secret", 5, done);
    await vi.advanceTimersByTimeAsync(5_000);
    expect(state.text).toBe("");
    expect(done).toHaveBeenCalledWith("cleared");
  });

  it("reports a blocked copy and a failed clearing", async () => {
    fakeClipboard({ writable: false, readable: false });
    expect(await copyValue("example-secret")).toBe("blocked");
    const done = vi.fn();
    scheduleClear("example-secret", 1, done);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(done).toHaveBeenCalledWith("failed");
  });

  it("reports a blocked copy without a clipboard at all", async () => {
    Reflect.deleteProperty(navigator, "clipboard");
    expect(await copyValue("example-secret")).toBe("blocked");
  });

  it("keeps one clearing: a later reveal replaces the earlier one", async () => {
    const state = fakeClipboard();
    const first = vi.fn();
    await copyValue("example-one");
    scheduleClear("example-one", 30, first);
    await copyValue("example-two");
    const second = vi.fn();
    scheduleClear("example-two", 30, second);
    await vi.advanceTimersByTimeAsync(30_000);
    expect(first).not.toHaveBeenCalled();
    expect(second).toHaveBeenCalledWith("cleared");
    expect(state.text).toBe("");
  });

  it("clears at once on request", async () => {
    const state = fakeClipboard();
    await copyValue("example-secret");
    scheduleClear("example-secret", 30);
    expect(await clearNow()).toBe("cleared");
    expect(state.text).toBe("");
    expect(await clearNow()).toBeUndefined();
  });
});
