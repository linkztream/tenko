// The history chart's frame loop (OPS-20; docs/plans/dashboard-history-plan.md, section 1): it runs
// while a chart glides on a visible page and stops by itself when the tab is hidden, under "Pause
// motion", under reduced motion and when the last chart goes; and the marks that carry data reach
// 3:1 against the surface in both themes (section 6, the pattern of AddressMap.contrast.test.ts).
/// <reference types="node" />
import { readFileSync } from "node:fs";
import { render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { setMotionPaused } from "../app/prefs";
import { contrastRatio } from "../app/color/vlan";
import { emptyHistory } from "./metrics";
import { frameLoopRunning, HistoryChart } from "./HistoryChart";
import { heldOf } from "./history";
import { testHistory } from "./historyTestData";
import type { LiveMetrics } from "./liveMetrics";

let frames: FrameRequestCallback[] = [];
let hidden = false;
let reduced = false;

/** Runs the frame the loop asked for, as the browser would at time `ms`. */
function nextFrame(ms: number): void {
  const pending = frames;
  frames = [];
  for (const callback of pending) callback(ms);
}

function mountChart() {
  const at = Date.now() / 1000;
  const held = heldOf(testHistory({ at, figures: ["dns-queries"] }));
  const live: LiveMetrics = { history: () => emptyHistory(), state: () => "live", tiers: () => held, clock: () => Date.now() / 1000 };
  return render(() => <HistoryChart name="dns-queries" title="DNS queries" unit="/s" value={1} live={live} />);
}

beforeEach(() => {
  frames = [];
  hidden = false;
  reduced = false;
  let id = 0;
  vi.stubGlobal("requestAnimationFrame", (callback: FrameRequestCallback) => {
    frames.push(callback);
    return ++id;
  });
  vi.stubGlobal("cancelAnimationFrame", () => {
    frames = [];
  });
  vi.stubGlobal("matchMedia", (query: string) => ({ matches: reduced && query.includes("reduced-motion"), addEventListener() {}, removeEventListener() {} }));
  Object.defineProperty(document, "hidden", { configurable: true, get: () => hidden });
});

afterEach(() => {
  setMotionPaused(false);
  vi.unstubAllGlobals();
  Reflect.deleteProperty(document, "hidden");
});

describe("the frame loop", () => {
  it("runs while a chart glides on a visible page and stops when the last chart goes", () => {
    const { unmount } = mountChart();
    expect(frameLoopRunning()).toBe(true);
    nextFrame(1000);
    nextFrame(1100);
    expect(frameLoopRunning()).toBe(true);
    unmount();
    expect(frameLoopRunning()).toBe(false);
    expect(frames).toHaveLength(0);
  });

  it("stops while the tab is hidden and starts again when it is shown", () => {
    const { unmount } = mountChart();
    hidden = true;
    nextFrame(1000);
    expect(frameLoopRunning()).toBe(false);
    expect(frames).toHaveLength(0);
    hidden = false;
    document.dispatchEvent(new Event("visibilitychange"));
    expect(frameLoopRunning()).toBe(true);
    unmount();
  });

  it("stops while no chart is on screen and starts again when one comes into view; the text alternative is there off screen", () => {
    let report: ((entries: { target: Element; isIntersecting: boolean }[]) => void) | undefined;
    vi.stubGlobal(
      "IntersectionObserver",
      class {
        constructor(callback: typeof report) {
          report = callback;
        }
        observe() {}
        unobserve() {}
        disconnect() {}
      },
    );
    const { unmount, getByRole, getByTestId } = mountChart();
    nextFrame(1000);
    expect(frameLoopRunning()).toBe(false);
    expect(getByTestId("metrics-history-alt").textContent).toMatch(/^DNS queries/);
    report!([{ target: getByRole("slider"), isIntersecting: true }]);
    expect(frameLoopRunning()).toBe(true);
    unmount();
  });

  it("stops under Pause motion and under reduced motion", () => {
    const { unmount } = mountChart();
    setMotionPaused(true);
    nextFrame(1000);
    expect(frameLoopRunning()).toBe(false);
    unmount();
    setMotionPaused(false);
    reduced = true;
    const again = mountChart();
    expect(frameLoopRunning()).toBe(false);
    again.unmount();
  });
});

/** `a` over `b` at `share`, as a hex color. */
function mix(a: string, b: string, share: number): string {
  const channel = (hex: string, i: number) => parseInt(hex.slice(1 + 2 * i, 3 + 2 * i), 16);
  return `#${[0, 1, 2].map((i) => Math.round(share * channel(a, i) + (1 - share) * channel(b, i)).toString(16).padStart(2, "0")).join("")}`;
}

describe("the chart's colors", () => {
  /** The custom properties of the light `:root` blocks with the dark block over them. */
  function tokens(dark: boolean): Map<string, string> {
    // Stylesheets are empty modules under test: the file is read as it ships (the tests run in ui/).
    const css = readFileSync("src/app/styles/tokens.css", "utf8").replace(/\/\*[\s\S]*?\*\//g, "");
    const out = new Map<string, string>();
    const blocks = [...css.matchAll(/(^|\n):root \{([^}]*)\}/g)].map((m) => m[2]!);
    if (dark) blocks.push(/:root\[data-theme="dark"\] \{([^}]*)\}/.exec(css)![1]!);
    for (const body of blocks) for (const m of body.matchAll(/(--[a-z0-9-]+)\s*:\s*([^;]+);/g)) out.set(m[1]!, m[2]!.trim());
    return out;
  }

  it.each([false, true])("draw every mark that carries data at 3:1 or more against the surface (dark %s)", (dark) => {
    const t = tokens(dark);
    // The mean and the band's upper edge, the hatch of no data and the bar of partial coverage, the restart.
    for (const mark of ["--series-1", "--chart-ink", "--ink-3"]) {
      expect(contrastRatio(t.get(mark)!, t.get("--surface")!), mark).toBeGreaterThanOrEqual(3);
    }
    // The mean over the band, a wash of 18 % of its own color.
    const wash = mix(t.get("--series-1")!, t.get("--surface")!, 0.18);
    expect(contrastRatio(t.get("--series-1")!, wash)).toBeGreaterThanOrEqual(3);
  });
});
