import { createRoot, createSignal } from "solid-js";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { vlanPalette, type VlanTokens } from "../../app/color/vlan";
import { setTheme } from "../../app/prefs";
import { assignVlanStyles, createVlanStyles, VLAN_SHAPES, vlanSlotOrder } from "./palette";

const LIGHT: VlanTokens = { l: 0.58, c: 0.14, h0: 255, background: "#FFFFFF" };
const DARK: VlanTokens = { l: 0.7, c: 0.13, h0: 255, background: "#171A21" };

/** Distance of two hue slots on a circle of `n` slots. */
function circularDistance(a: number, b: number, n: number): number {
  const d = Math.abs(a - b);
  return Math.min(d, n - d);
}

describe("vlanSlotOrder", () => {
  it("gives no slots for no VLANs", () => {
    expect(vlanSlotOrder(0)).toEqual([]);
    expect(vlanSlotOrder(-2)).toEqual([]);
    expect(vlanSlotOrder(Number.NaN)).toEqual([]);
  });

  it("gives the only slot to a single VLAN", () => {
    expect(vlanSlotOrder(1)).toEqual([0]);
  });

  it("is a permutation of 0..n-1 for n = 0..64", () => {
    for (let n = 0; n <= 64; n++) {
      const slots = vlanSlotOrder(n);
      expect(slots, `n = ${n}`).toHaveLength(n);
      expect([...slots].sort((a, b) => a - b), `n = ${n}`).toEqual(Array.from({ length: n }, (_, i) => i));
    }
  });

  it("starts with slot 0", () => {
    for (let n = 1; n <= 64; n++) expect(vlanSlotOrder(n)[0]).toBe(0);
  });

  it("keeps consecutive ids at least a quarter of the circle apart for n = 4..64", () => {
    for (let n = 4; n <= 64; n++) {
      const slots = vlanSlotOrder(n);
      const minimum = Math.floor(n / 4);
      for (let i = 1; i < n; i++) {
        const distance = circularDistance(slots[i - 1] as number, slots[i] as number, n);
        expect(distance, `n = ${n}, ids ${i - 1} and ${i}`).toBeGreaterThanOrEqual(minimum);
      }
    }
  });

  it("uses a stride near 38 percent of the circle", () => {
    // 10 slots: round(3.82) = 4 shares a factor with 10, the nearest coprime stride is 3.
    expect(vlanSlotOrder(10)).toEqual([0, 3, 6, 9, 2, 5, 8, 1, 4, 7]);
    // 13 slots: round(4.97) = 5 is coprime with 13.
    expect(vlanSlotOrder(13).slice(0, 4)).toEqual([0, 5, 10, 2]);
  });

  it("copes with a large VLAN count", () => {
    const slots = vlanSlotOrder(4094);
    expect(new Set(slots).size).toBe(4094);
  });
});

describe("assignVlanStyles", () => {
  it("keys the styles by sorted, de-duplicated id", () => {
    const styles = assignVlanStyles([30, 10, 20, 10], LIGHT);
    expect([...styles.keys()]).toEqual([10, 20, 30]);
    expect([...styles.values()].map((s) => s.vid)).toEqual([10, 20, 30]);
  });

  it("gives distinct colors and the first shapes in id order", () => {
    const styles = assignVlanStyles([30, 10, 20, 10], LIGHT);
    const list = [...styles.values()];
    expect(new Set(list.map((s) => s.hex)).size).toBe(3);
    expect(list.map((s) => s.shape)).toEqual(["square", "circle", "diamond"]);
  });

  it("takes the colors from the generated palette through the slot order", () => {
    const vids = [101, 102, 103, 104, 105, 106, 107];
    const palette = vlanPalette(vids.length, LIGHT);
    const slots = vlanSlotOrder(vids.length);
    const styles = assignVlanStyles(vids, LIGHT);
    vids.forEach((vid, i) => {
      const expected = palette[slots[i] as number];
      expect(styles.get(vid)).toMatchObject({ vid, hex: expected?.hex, hue: expected?.hue, contrast: expected?.contrast });
    });
  });

  it("gives neighbouring ids hues that are far apart", () => {
    const vids = Array.from({ length: 12 }, (_, i) => 10 * (i + 1));
    const hues = vids.map((vid) => assignVlanStyles(vids, LIGHT).get(vid)?.hue as number);
    for (let i = 1; i < hues.length; i++) {
      const d = Math.abs((hues[i] as number) - (hues[i - 1] as number));
      expect(Math.min(d, 360 - d)).toBeGreaterThanOrEqual(90);
    }
  });

  it("cycles through the shapes", () => {
    const vids = Array.from({ length: VLAN_SHAPES.length + 2 }, (_, i) => i + 1);
    const shapes = vids.map((vid) => assignVlanStyles(vids, LIGHT).get(vid)?.shape);
    expect(shapes.slice(0, VLAN_SHAPES.length)).toEqual([...VLAN_SHAPES]);
    expect(shapes[VLAN_SHAPES.length]).toBe(VLAN_SHAPES[0]);
    expect(shapes[VLAN_SHAPES.length + 1]).toBe(VLAN_SHAPES[1]);
  });

  it("ignores ids that are not VLAN ids", () => {
    const styles = assignVlanStyles([0, -5, 4095, 12.5, Number.NaN, Number.POSITIVE_INFINITY, 7, 4094], LIGHT);
    expect([...styles.keys()]).toEqual([7, 4094]);
  });

  it("gives an empty map for no ids", () => {
    expect(assignVlanStyles([], LIGHT).size).toBe(0);
  });

  it("gives a single VLAN the first hue and shape", () => {
    const style = assignVlanStyles([42], LIGHT).get(42);
    expect(style).toMatchObject({ vid: 42, hue: 255, shape: "square" });
    expect(style?.hex).toMatch(/^#[0-9A-F]{6}$/);
  });

  it("does not change the input", () => {
    const vids = [3, 1, 2];
    assignVlanStyles(vids, LIGHT);
    expect(vids).toEqual([3, 1, 2]);
  });

  describe.each([
    ["light", LIGHT],
    ["dark", DARK],
  ])("on the %s background", (_name, tokens) => {
    it("keeps at least 3:1 contrast for 1 to 24 VLANs", () => {
      for (let n = 1; n <= 24; n++) {
        const vids = Array.from({ length: n }, (_, i) => 100 + 7 * i);
        const styles = assignVlanStyles(vids, tokens);
        expect(styles.size).toBe(n);
        for (const style of styles.values()) {
          expect(style.contrast, `n = ${n}, VLAN ${style.vid}`).toBeGreaterThanOrEqual(3);
        }
      }
    });
  });
});

describe("createVlanStyles", () => {
  let sheet: HTMLStyleElement | undefined;

  beforeEach(() => {
    // The tokens of tokens.css for both themes, as far as readVlanTokens() reads them.
    sheet = document.createElement("style");
    sheet.textContent = `
      :root { --vlan-l: 0.58; --vlan-c: 0.14; --vlan-h0: 255; --surface: #FFFFFF; }
      :root[data-theme="dark"] { --vlan-l: 0.70; --vlan-c: 0.13; --vlan-h0: 255; --surface: #171A21; }
    `;
    document.head.appendChild(sheet);
  });

  afterEach(() => {
    setTheme("system");
    sheet?.remove();
  });

  it("recomputes when the ids change", () => {
    createRoot((dispose) => {
      const [vids, setVids] = createSignal<number[]>([20, 10]);
      const styles = createVlanStyles(vids);
      expect([...styles().keys()]).toEqual([10, 20]);
      setVids([5, 10, 20]);
      expect([...styles().keys()]).toEqual([5, 10, 20]);
      setVids([]);
      expect(styles().size).toBe(0);
      dispose();
    });
  });

  it("matches assignVlanStyles with the tokens of the document", () => {
    setTheme("light");
    createRoot((dispose) => {
      const styles = createVlanStyles(() => [1, 2, 3, 4]);
      expect(styles()).toEqual(assignVlanStyles([1, 2, 3, 4], LIGHT));
      dispose();
    });
  });

  it("reads the tokens again after the theme changed", async () => {
    setTheme("light");
    // The effect that watches the theme starts when the root has been created.
    const { styles, dispose } = createRoot((dispose) => ({ styles: createVlanStyles(() => [1, 2, 3, 4]), dispose }));
    expect(styles()).toEqual(assignVlanStyles([1, 2, 3, 4], LIGHT));

    setTheme("dark");
    await Promise.resolve();
    expect(styles()).toEqual(assignVlanStyles([1, 2, 3, 4], DARK));
    expect(styles()).not.toEqual(assignVlanStyles([1, 2, 3, 4], LIGHT));

    setTheme("light");
    await Promise.resolve();
    expect(styles()).toEqual(assignVlanStyles([1, 2, 3, 4], LIGHT));
    dispose();
  });
});
