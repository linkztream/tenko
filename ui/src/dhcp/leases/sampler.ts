// The sampling of live lease events (WP7.5). A busy server changes leases hundreds of times a
// second; the view does not read the list for each change. Every event counts, a refresh of the
// visible page runs at most once per `intervalMs`, and the events beyond `perSecond` in one second
// are folded: the view says how many changes it folded instead of showing each. The state is a
// plain value and the functions are pure, so the rules are tested without a clock or a timer.

export interface SamplerConfig {
  /** The least time between two refreshes. */
  intervalMs: number;
  /** Events one second applies; the rest are folded. */
  perSecond: number;
  /** The length of the counting window. */
  windowMs: number;
}

export const SAMPLER: SamplerConfig = { intervalMs: 200, perSecond: 50, windowMs: 1000 };

export interface SamplerState {
  /** When the counting window started. */
  windowStart: number;
  /** Events counted in the window. */
  inWindow: number;
  /** Events of the window beyond the rate: the changes the view folded. */
  folded: number;
  /** When the last refresh ran. */
  lastRefresh: number;
  /** A refresh is scheduled and has not run yet. */
  due: boolean;
}

export function initialSampler(): SamplerState {
  return { windowStart: Number.NEGATIVE_INFINITY, inWindow: 0, folded: 0, lastRefresh: Number.NEGATIVE_INFINITY, due: false };
}

export interface Step {
  state: SamplerState;
  /** Milliseconds until the refresh runs; null when one is scheduled already. */
  delay: number | null;
}

function rolled(state: SamplerState, now: number, config: SamplerConfig): SamplerState {
  return now - state.windowStart >= config.windowMs ? { ...state, windowStart: now, inWindow: 0, folded: 0 } : state;
}

/** `count` events arrive at `now`: they are counted, and the refresh is scheduled when none is. */
export function arrive(state: SamplerState, now: number, count = 1, config: SamplerConfig = SAMPLER): Step {
  const counted = rolled(state, now, config);
  const inWindow = counted.inWindow + count;
  const next: SamplerState = { ...counted, inWindow, folded: Math.max(0, inWindow - config.perSecond) };
  if (next.due) return { state: next, delay: null };
  return { state: { ...next, due: true }, delay: Math.max(0, next.lastRefresh + config.intervalMs - now) };
}

/** The scheduled refresh runs at `now`. */
export function refreshed(state: SamplerState, now: number): SamplerState {
  return { ...state, due: false, lastRefresh: now };
}

/** Time has passed without events: a window that is over no longer reports folded changes. */
export function settle(state: SamplerState, now: number, config: SamplerConfig = SAMPLER): SamplerState {
  return rolled(state, now, config);
}
