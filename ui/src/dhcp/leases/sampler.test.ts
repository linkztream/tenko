// The rules of the live sampling: one refresh per interval however many events arrive, the first
// event of a quiet period is served at once, the events beyond the rate are counted as folded, and
// a window that is over forgets them.
import { describe, expect, it } from "vitest";
import { arrive, initialSampler, refreshed, SAMPLER, settle, type SamplerState } from "./sampler";

/** Feeds `n` events at `at` and returns the state and the delays the steps asked for. */
function burst(state: SamplerState, at: number, n: number): { state: SamplerState; delays: (number | null)[] } {
  const delays: (number | null)[] = [];
  let s = state;
  for (let i = 0; i < n; i += 1) {
    const step = arrive(s, at);
    s = step.state;
    delays.push(step.delay);
  }
  return { state: s, delays };
}

describe("the live sampler", () => {
  it("serves the first event of a quiet period at once", () => {
    const step = arrive(initialSampler(), 5000);
    expect(step.delay).toBe(0);
    expect(step.state.due).toBe(true);
    expect(step.state.folded).toBe(0);
  });

  it("schedules one refresh for a burst of a thousand events", () => {
    const { state, delays } = burst(initialSampler(), 1000, 1000);
    expect(delays.filter((d) => d !== null)).toEqual([0]);
    expect(state.inWindow).toBe(1000);
    expect(state.folded).toBe(1000 - SAMPLER.perSecond);
  });

  it("waits out the interval after a refresh and then refreshes once more", () => {
    let state = refreshed(burst(initialSampler(), 1000, 3).state, 1000);
    const step = arrive(state, 1050);
    expect(step.delay).toBe(150);
    state = step.state;
    expect(arrive(state, 1060).delay).toBeNull();
    // After the interval the next event is served at once again.
    state = refreshed(state, 1200);
    expect(arrive(state, 1500).delay).toBe(0);
  });

  it("applies at most one refresh per interval in a second of steady events", () => {
    let state = initialSampler();
    let runs = 0;
    let pendingAt: number | null = null;
    for (let now = 0; now < 1000; now += 2) {
      if (pendingAt !== null && now >= pendingAt) {
        state = refreshed(state, now);
        pendingAt = null;
        runs += 1;
      }
      const step = arrive(state, now);
      state = step.state;
      if (step.delay !== null) pendingAt = now + step.delay;
    }
    expect(runs).toBeLessThanOrEqual(1000 / SAMPLER.intervalMs + 1);
    expect(runs).toBeGreaterThan(1);
    expect(state.folded).toBe(500 - SAMPLER.perSecond);
  });

  it("does not fold events up to the rate", () => {
    const { state } = burst(initialSampler(), 0, SAMPLER.perSecond);
    expect(state.folded).toBe(0);
    expect(arrive(state, 10).state.folded).toBe(1);
  });

  it("starts a new window after a second and forgets the folded changes", () => {
    const { state } = burst(initialSampler(), 0, 200);
    expect(state.folded).toBe(150);
    expect(settle(state, 999).folded).toBe(150);
    expect(settle(state, 1000).folded).toBe(0);
    const next = arrive(refreshed(state, 100), 1200);
    expect(next.state.inWindow).toBe(1);
    expect(next.state.folded).toBe(0);
  });

  it("counts events delivered together", () => {
    const step = arrive(initialSampler(), 0, 120);
    expect(step.state.inWindow).toBe(120);
    expect(step.state.folded).toBe(70);
    expect(step.delay).toBe(0);
  });
});
