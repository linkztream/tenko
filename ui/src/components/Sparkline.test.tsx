import { render } from "@solidjs/testing-library";
import { describe, expect, it } from "vitest";
import { Sparkline, sparklinePaths } from "./Sparkline";

describe("sparkline paths", () => {
  it("draws nothing without values", () => {
    expect(sparklinePaths([])).toEqual([]);
    expect(sparklinePaths([null, undefined, Number.NaN])).toEqual([]);
  });

  it("puts the newest value at the end and scales from zero to the highest value", () => {
    // Three values of 60: x 57, 58, 59; 10 is the top (y 0), 5 the middle, 0 the baseline.
    expect(sparklinePaths([0, 5, 10])).toEqual(["57,20 58,10 59,0"]);
  });

  it("draws zeros on the baseline, a flat series at the top and a lone point as a short line", () => {
    expect(sparklinePaths([0, 0])).toEqual(["58,20 59,20"]);
    expect(sparklinePaths([3, 3])).toEqual(["58,0 59,0"]);
    expect(sparklinePaths([7])).toEqual(["58.5,0 59,0"]);
  });

  it("breaks the line where a value is missing", () => {
    expect(sparklinePaths([1, null, 2, 4], 4)).toEqual(["-0.5,15 0,15", "2,10 3,0"]);
  });

  it("keeps the last points only and scales negative values from their lowest", () => {
    const values = Array.from({ length: 70 }, (_, i) => i);
    const [line] = sparklinePaths(values);
    expect(line?.split(" ")).toHaveLength(60);
    expect(line?.startsWith("0,")).toBe(true);
    expect(line?.endsWith(" 59,0")).toBe(true);
    expect(sparklinePaths([-2, 2], 2)).toEqual(["0,20 1,0"]);
  });
});

describe("sparkline", () => {
  it("is hidden from assistive technology and describes its series in a title", () => {
    const { container } = render(() => <Sparkline values={[1, 2, 3]} title="Requests over the last minute: 1, 2, 3" testId="spark" />);
    const svg = container.querySelector("svg") as SVGSVGElement;
    expect(svg.getAttribute("aria-hidden")).toBe("true");
    expect(svg.dataset.testid).toBe("spark");
    expect(svg.dataset.points).toBe("3");
    expect(svg.querySelector("title")?.textContent).toBe("Requests over the last minute: 1, 2, 3");
    expect(svg.querySelectorAll("polyline")).toHaveLength(1);
    expect(svg.getAttribute("style")).toBeNull();
  });
});
