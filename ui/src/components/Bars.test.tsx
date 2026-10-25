import { render } from "@solidjs/testing-library";
import { describe, expect, it } from "vitest";
import { Bars, barRects } from "./Bars";

describe("bar rectangles", () => {
  it("draws nothing without values", () => {
    expect(barRects([], 12)).toEqual([]);
    expect(barRects([null, undefined, Number.NaN], 3)).toEqual([]);
  });

  it("scales a fraction to the height of 20 and puts the newest bar in the last slot", () => {
    expect(barRects([null, 0.5, 1], 3)).toEqual([
      { x: 11.5, y: 10, width: 7, height: 10 },
      { x: 21.5, y: 0, width: 7, height: 20 },
    ]);
  });

  it("draws a zero as a hairline and keeps the last buckets only", () => {
    expect(barRects([0], 2)).toEqual([{ x: 11.5, y: 19, width: 7, height: 1 }]);
    expect(barRects([1, 1, 1], 2)).toHaveLength(2);
  });
});

describe("the bucket in progress", () => {
  it("marks only the newest bar as partial, and only when asked", () => {
    expect(barRects([0.5, 1], 3, true).map((r) => r.partial)).toEqual([undefined, true]);
    expect(barRects([0.5, 1], 3).map((r) => r.partial)).toEqual([undefined, undefined]);
    // A newest bucket without a value leaves the older bars solid.
    expect(barRects([0.5, null], 3, true).map((r) => r.partial)).toEqual([undefined]);
  });

  it("draws the partial bar with the class that makes it lighter", () => {
    const { container } = render(() => <Bars values={[0.2, 1]} buckets={3} partialLast title="t" />);
    expect([...container.querySelectorAll("rect")].map((r) => r.classList.contains("partial"))).toEqual([false, true]);
  });
});

describe("Bars", () => {
  it("is hidden from assistive technology, has a fixed viewBox and a bar per present bucket", () => {
    const { container } = render(() => <Bars values={[0.2, null, 1]} buckets={12} title="Hit ratio" testId="metrics-bars" />);
    const svg = container.querySelector("svg")!;
    expect(svg.getAttribute("aria-hidden")).toBe("true");
    expect(svg.getAttribute("viewBox")).toBe("0 0 120 20");
    expect(svg.getAttribute("data-buckets")).toBe("12");
    expect(svg.getAttribute("data-testid")).toBe("metrics-bars");
    expect(svg.querySelectorAll("rect")).toHaveLength(2);
    expect(svg.querySelector("title")?.textContent).toBe("Hit ratio");
  });
});
