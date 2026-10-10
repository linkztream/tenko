import { describe, expect, it } from "vitest";
import {
  MAX_SCALE,
  MIN_SCALE,
  centreOn,
  clampScale,
  fit,
  nearestInDirection,
  pan,
  transformOf,
  zoomAt,
  type View,
} from "./viewport";

/** The drawing point shown at a screen point. */
function toDrawing(view: View, sx: number, sy: number): [number, number] {
  return [view.x + sx / view.scale, view.y + sy / view.scale];
}

/** The screen point at which a drawing point is shown. */
function toScreen(view: View, px: number, py: number): [number, number] {
  return [(px - view.x) * view.scale, (py - view.y) * view.scale];
}

function expectClose(actual: readonly number[], expected: readonly number[]): void {
  expect(actual).toHaveLength(expected.length);
  expected.forEach((value, i) => expect(actual[i]).toBeCloseTo(value, 9));
}

describe("clampScale", () => {
  it("keeps a scale inside the limits", () => {
    expect(clampScale(1)).toBe(1);
    expect(clampScale(MIN_SCALE)).toBe(MIN_SCALE);
    expect(clampScale(MAX_SCALE)).toBe(MAX_SCALE);
  });

  it("limits a scale outside them", () => {
    expect(clampScale(0.001)).toBe(MIN_SCALE);
    expect(clampScale(-3)).toBe(MIN_SCALE);
    expect(clampScale(100)).toBe(MAX_SCALE);
    expect(clampScale(Infinity)).toBe(MAX_SCALE);
    expect(clampScale(-Infinity)).toBe(MIN_SCALE);
  });

  it("turns NaN into 1", () => {
    expect(clampScale(Number.NaN)).toBe(1);
  });

  it("has the documented limits", () => {
    expect(MIN_SCALE).toBe(0.05);
    expect(MAX_SCALE).toBe(4);
  });
});

describe("fit", () => {
  it("fits a wide drawing by its width, centred, with a 5 percent margin", () => {
    const view = fit(2000, 500, 1000, 800);
    expect(view.scale).toBeCloseTo(0.475, 12);
    // The drawing fills 95 percent of the screen width, centred on both axes.
    expectClose(toScreen(view, 0, 0), [25, (800 - 500 * 0.475) / 2]);
    expectClose(toScreen(view, 2000, 500), [975, (800 + 500 * 0.475) / 2]);
    expectClose(toScreen(view, 1000, 250), [500, 400]);
  });

  it("fits a tall drawing by its height", () => {
    const view = fit(500, 2000, 1000, 800);
    expect(view.scale).toBeCloseTo(0.38, 12);
    expectClose(toScreen(view, 250, 1000), [500, 400]);
    expectClose(toScreen(view, 0, 0), [(1000 - 500 * 0.38) / 2, 20]);
    expectClose(toScreen(view, 500, 2000), [(1000 + 500 * 0.38) / 2, 780]);
  });

  it("does not magnify a tiny drawing beyond 1.5", () => {
    const view = fit(100, 80, 1000, 800);
    expect(view.scale).toBe(1.5);
    expectClose(toScreen(view, 50, 40), [500, 400]);
  });

  it("caps an empty drawing at 1.5 and centres its origin", () => {
    const view = fit(0, 0, 1000, 800);
    expect(view.scale).toBe(1.5);
    expectClose(toScreen(view, 0, 0), [500, 400]);
  });

  it("does not go below the minimum scale for a huge drawing", () => {
    expect(fit(1_000_000, 1_000_000, 1000, 800).scale).toBe(MIN_SCALE);
  });

  it("returns the neutral view for an empty or zero-size screen", () => {
    const neutral = { x: 0, y: 0, scale: 1 };
    expect(fit(500, 500, 0, 0)).toEqual(neutral);
    expect(fit(500, 500, 0, 800)).toEqual(neutral);
    expect(fit(500, 500, 1000, 0)).toEqual(neutral);
    expect(fit(500, 500, -1, 800)).toEqual(neutral);
    expect(fit(500, 500, Number.NaN, 800)).toEqual(neutral);
  });
});

describe("zoomAt", () => {
  const view: View = { x: 120, y: -40, scale: 0.8 };

  it("keeps the drawing point under the screen point", () => {
    for (const [factor, sx, sy] of [
      [1.25, 300, 200],
      [0.5, 0, 0],
      [2, 799, 599],
      [1.1, 400, 50],
    ] as const) {
      const before = toDrawing(view, sx, sy);
      const zoomed = zoomAt(view, factor, sx, sy);
      expect(zoomed.scale).toBeCloseTo(view.scale * factor, 12);
      expectClose(toDrawing(zoomed, sx, sy), before);
      expectClose(toScreen(zoomed, before[0], before[1]), [sx, sy]);
    }
  });

  it("keeps the view when the point is the top left corner and the factor is 1", () => {
    expect(zoomAt(view, 1, 0, 0)).toEqual(view);
  });

  it("clamps the scale and still keeps the point under the cursor", () => {
    const sx = 250;
    const sy = 130;
    const before = toDrawing(view, sx, sy);
    const big = zoomAt(view, 1000, sx, sy);
    expect(big.scale).toBe(MAX_SCALE);
    expectClose(toDrawing(big, sx, sy), before);
    const small = zoomAt(view, 0.0001, sx, sy);
    expect(small.scale).toBe(MIN_SCALE);
    expectClose(toDrawing(small, sx, sy), before);
  });

  it("ignores a factor that is not a positive number", () => {
    expect(zoomAt(view, 0, 10, 10)).toBe(view);
    expect(zoomAt(view, -2, 10, 10)).toBe(view);
    expect(zoomAt(view, Number.NaN, 10, 10)).toBe(view);
    expect(zoomAt(view, Infinity, 10, 10)).toBe(view);
  });

  it("does not modify the view it gets", () => {
    const copy = { ...view };
    zoomAt(view, 2, 5, 5);
    expect(view).toEqual(copy);
  });
});

describe("pan", () => {
  it("makes the drawing follow the pointer", () => {
    const view: View = { x: 100, y: 50, scale: 2 };
    const moved = pan(view, 40, -20);
    expect(moved).toEqual({ x: 80, y: 60, scale: 2 });
    // A drawing point moved with the pointer: 40 px right and 20 px up on the screen.
    const before = toScreen(view, 150, 100);
    const after = toScreen(moved, 150, 100);
    expectClose(after, [before[0] + 40, before[1] - 20]);
  });

  it("keeps the scale and leaves the view alone for a zero move", () => {
    const view: View = { x: 1, y: 2, scale: 0.5 };
    expect(pan(view, 0, 0)).toEqual(view);
    expect(pan(view, 10, 10).scale).toBe(0.5);
  });
});

describe("centreOn", () => {
  it("puts the drawing point at the centre of the screen and keeps the scale", () => {
    const view = centreOn({ x: 5, y: 5, scale: 0.5 }, 300, 200, 800, 600);
    expect(view.scale).toBe(0.5);
    expectClose(toScreen(view, 300, 200), [400, 300]);
    expect(view).toEqual({ x: 300 - 800, y: 200 - 600, scale: 0.5 });
  });

  it("works at scale 1", () => {
    expect(centreOn({ x: 0, y: 0, scale: 1 }, 0, 0, 1000, 800)).toEqual({ x: -500, y: -400, scale: 1 });
  });
});

describe("transformOf", () => {
  it("translates by minus the view origin times the scale", () => {
    expect(transformOf({ x: 100, y: 50, scale: 2 })).toBe("translate(-200 -100) scale(2)");
    expect(transformOf({ x: -30, y: 12.5, scale: 1 })).toBe("translate(30 -12.5) scale(1)");
  });

  it("rounds to 3 decimals", () => {
    expect(transformOf({ x: 1 / 3, y: 2 / 3, scale: 0.12345 })).toBe("translate(-0.041 -0.082) scale(0.123)");
    expect(transformOf({ x: 10.123456, y: 0.0004, scale: 1.0004 })).toBe("translate(-10.128 0) scale(1)");
  });

  it("never writes a negative zero", () => {
    expect(transformOf({ x: 0, y: 0, scale: 1 })).toBe("translate(0 0) scale(1)");
    expect(transformOf({ x: 0.00001, y: -0.00001, scale: 1 })).toBe("translate(0 0) scale(1)");
  });

  it("scales the translation with the zoom factor", () => {
    const view: View = { x: 75, y: 25, scale: 1.5 };
    expect(transformOf(view)).toBe("translate(-112.5 -37.5) scale(1.5)");
  });
});

describe("nearestInDirection", () => {
  const points = [
    { id: "centre", x: 100, y: 100 },
    { id: "up", x: 100, y: 40 },
    { id: "down", x: 100, y: 170 },
    { id: "left", x: 30, y: 100 },
    { id: "right", x: 180, y: 100 },
  ];

  it("finds the nearest point in each direction", () => {
    expect(nearestInDirection(points, "centre", "up")).toBe("up");
    expect(nearestInDirection(points, "centre", "down")).toBe("down");
    expect(nearestInDirection(points, "centre", "left")).toBe("left");
    expect(nearestInDirection(points, "centre", "right")).toBe("right");
  });

  it("goes back where it came from", () => {
    expect(nearestInDirection(points, "up", "down")).toBe("centre");
    expect(nearestInDirection(points, "right", "left")).toBe("centre");
  });

  it("returns null when nothing is in the direction", () => {
    expect(nearestInDirection(points, "up", "up")).toBeNull();
    expect(nearestInDirection(points, "down", "down")).toBeNull();
    expect(nearestInDirection(points, "left", "left")).toBeNull();
    expect(nearestInDirection(points, "right", "right")).toBeNull();
  });

  it("ignores points outside the 60 degree cone", () => {
    const flank = [
      { id: "from", x: 0, y: 0 },
      // 71.6 degrees off the right axis: outside.
      { id: "steep", x: 10, y: 30 },
      // 45 degrees: inside.
      { id: "diagonal", x: 100, y: 100 },
    ];
    expect(nearestInDirection(flank, "from", "right")).toBe("diagonal");
    expect(nearestInDirection(flank.filter((p) => p.id !== "diagonal"), "from", "right")).toBeNull();
    expect(nearestInDirection(flank, "from", "down")).toBe("steep");
  });

  it("weighs the sideways offset: a point straight ahead beats a nearer one off to the side", () => {
    const set = [
      { id: "from", x: 0, y: 0 },
      // Distance 60 + 0.5 * 0 = 60.
      { id: "ahead", x: 60, y: 0 },
      // Distance about 55.9 + 0.5 * 25 = 68.4, although nearer.
      { id: "aside", x: 50, y: 25 },
    ];
    expect(nearestInDirection(set, "from", "right")).toBe("ahead");
    // Without the straight one the other qualifies.
    expect(nearestInDirection(set.filter((p) => p.id !== "ahead"), "from", "right")).toBe("aside");
  });

  it("uses screen coordinates: down is a larger y", () => {
    const set = [
      { id: "from", x: 0, y: 0 },
      { id: "above", x: 0, y: -10 },
      { id: "below", x: 0, y: 500 },
    ];
    expect(nearestInDirection(set, "from", "down")).toBe("below");
    expect(nearestInDirection(set, "from", "up")).toBe("above");
  });

  it("breaks a tie by the smaller id", () => {
    const set = [
      { id: "from", x: 0, y: 0 },
      { id: "b", x: 50, y: -20 },
      { id: "a", x: 50, y: 20 },
    ];
    expect(nearestInDirection(set, "from", "right")).toBe("a");
    expect(nearestInDirection([...set].reverse(), "from", "right")).toBe("a");
  });

  it("ignores a point at the same place", () => {
    const set = [
      { id: "from", x: 5, y: 5 },
      { id: "twin", x: 5, y: 5 },
    ];
    expect(nearestInDirection(set, "from", "right")).toBeNull();
    expect(nearestInDirection(set, "from", "up")).toBeNull();
  });

  it("returns null for an unknown id and for no points", () => {
    expect(nearestInDirection(points, "nope", "up")).toBeNull();
    expect(nearestInDirection([], "centre", "up")).toBeNull();
  });
});
