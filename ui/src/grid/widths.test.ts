import { createRoot } from "solid-js";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  BIG_STEP,
  clampWidth,
  createColumnWidths,
  dragWidth,
  fitWidth,
  keyWidth,
  MAX_WIDTH,
  MIN_WIDTH,
  NARROW_QUERY,
  readWidths,
  STEP,
  widthsKey,
  writeWidths,
} from "./widths";

afterEach(() => {
  localStorage.clear();
  vi.unstubAllGlobals();
});

/** A matchMedia whose narrow query matches when `narrow` holds; returns a way to change it. */
function stubScreen(narrow: boolean) {
  const listeners = new Set<(e: MediaQueryListEvent) => void>();
  const list = {
    matches: narrow,
    media: NARROW_QUERY,
    addEventListener: (_: string, fn: (e: MediaQueryListEvent) => void) => listeners.add(fn),
    removeEventListener: (_: string, fn: (e: MediaQueryListEvent) => void) => listeners.delete(fn),
  };
  vi.stubGlobal("matchMedia", (query: string) => (query === NARROW_QUERY ? list : { matches: false, addEventListener() {}, removeEventListener() {} }));
  return (next: boolean) => {
    list.matches = next;
    for (const fn of listeners) fn({ matches: next } as MediaQueryListEvent);
  };
}

describe("the resize arithmetic", () => {
  it("keeps a width between the minimum and the maximum in whole pixels", () => {
    expect(clampWidth(10)).toBe(MIN_WIDTH);
    expect(clampWidth(99_999)).toBe(MAX_WIDTH);
    expect(clampWidth(120.6)).toBe(121);
    expect(clampWidth(Number.NaN)).toBe(MIN_WIDTH);
    expect(clampWidth(70, 80)).toBe(80);
  });

  it("follows a pointer drag on the trailing edge, mirrored right to left", () => {
    expect(dragWidth(140, 100, 160, false)).toBe(200);
    expect(dragWidth(140, 100, 60, false)).toBe(100);
    // Right to left the trailing edge is on the left: moving left widens.
    expect(dragWidth(140, 100, 60, true)).toBe(180);
    expect(dragWidth(140, 100, 160, true)).toBe(80);
    // Never below the minimum, however far the pointer goes.
    expect(dragWidth(140, 100, -500, false)).toBe(MIN_WIDTH);
  });

  it("steps with the arrow keys, further with Shift, mirrored right to left", () => {
    expect(keyWidth(140, "ArrowRight", false, false)).toBe(140 + STEP);
    expect(keyWidth(140, "ArrowLeft", false, false)).toBe(140 - STEP);
    expect(keyWidth(140, "ArrowRight", true, false)).toBe(140 + BIG_STEP);
    expect(keyWidth(140, "ArrowLeft", true, true)).toBe(140 + BIG_STEP);
    expect(keyWidth(140, "ArrowRight", false, true)).toBe(140 - STEP);
    expect(keyWidth(MIN_WIDTH, "ArrowLeft", true, false)).toBe(MIN_WIDTH);
    expect(keyWidth(140, "ArrowUp", false, false)).toBeNull();
    expect(keyWidth(140, "Home", false, false)).toBeNull();
  });

  it("fits to the widest content, never below the minimum", () => {
    expect(fitWidth([80.2, 191.4, 120])).toBe(193);
    expect(fitWidth([])).toBe(MIN_WIDTH);
    expect(fitWidth([10, 20])).toBe(MIN_WIDTH);
    expect(fitWidth([5000])).toBe(MAX_WIDTH);
  });
});

describe("stored widths", () => {
  it("names the list and the user in the key", () => {
    expect(widthsKey("hosts", "u-1")).toBe("tenko-grid-widths:u-1:hosts");
    expect(widthsKey("hosts", undefined)).toBe("tenko-grid-widths:-:hosts");
  });

  it("reads back what was written and drops what is not a width", () => {
    writeWidths("k", { a: 120, b: 80 });
    expect(readWidths("k")).toEqual({ a: 120, b: 80 });
    localStorage.setItem("k", JSON.stringify({ a: "wide", b: -4, c: 30, d: 140 }));
    expect(readWidths("k")).toEqual({ c: MIN_WIDTH, d: 140 });
    localStorage.setItem("k", "not json");
    expect(readWidths("k")).toBeNull();
    localStorage.setItem("k", "[1,2]");
    expect(readWidths("k")).toBeNull();
    writeWidths("k", {});
    expect(localStorage.getItem("k")).toBeNull();
  });

  it("keeps the widths per list and per user, stores them on commit and drops them on reset", () => {
    createRoot((dispose) => {
      const alex = createColumnWidths("hosts", "alex");
      expect(alex.custom()).toBe(false);
      alex.update({ name: 300, mode: 20 });
      expect(alex.get("name")).toBe(300);
      expect(alex.get("mode")).toBe(MIN_WIDTH);
      expect(alex.custom()).toBe(true);
      // Nothing is stored before the commit (a drag stores once, at its end).
      expect(localStorage.getItem("tenko-grid-widths:alex:hosts")).toBeNull();
      alex.commit();
      expect(JSON.parse(localStorage.getItem("tenko-grid-widths:alex:hosts") ?? "{}")).toEqual({ name: 300, mode: MIN_WIDTH });

      // The same list for the same user starts with them; another user or list does not.
      expect(createColumnWidths("hosts", "alex").get("name")).toBe(300);
      expect(createColumnWidths("hosts", "sam").custom()).toBe(false);
      expect(createColumnWidths("addresses", "alex").custom()).toBe(false);

      alex.reset();
      expect(alex.custom()).toBe(false);
      expect(alex.get("name")).toBeUndefined();
      expect(localStorage.getItem("tenko-grid-widths:alex:hosts")).toBeNull();
      dispose();
    });
  });

  it("ignores stored widths on a narrow screen and applies them again on a wide one", () => {
    writeWidths(widthsKey("hosts", "alex"), { name: 300 });
    const setNarrow = stubScreen(true);
    createRoot((dispose) => {
      const widths = createColumnWidths("hosts", "alex");
      expect(widths.narrow()).toBe(true);
      expect(widths.custom()).toBe(false);
      expect(widths.get("name")).toBeUndefined();
      setNarrow(false);
      expect(widths.custom()).toBe(true);
      expect(widths.get("name")).toBe(300);
      dispose();
    });
    // The stored widths stay for the wide screen.
    expect(readWidths(widthsKey("hosts", "alex"))).toEqual({ name: 300 });
  });

  it("counts the column menus that offer the reset", () => {
    createRoot((dispose) => {
      const widths = createColumnWidths("hosts", "alex");
      expect(widths.menu()).toBe(false);
      const detach = widths.attachMenu();
      expect(widths.menu()).toBe(true);
      detach();
      expect(widths.menu()).toBe(false);
      dispose();
    });
  });
});
