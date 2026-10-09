import { afterEach, describe, it, expect } from "vitest";
import {
  contrastRatio,
  hexToLinear,
  linearToHex,
  oklchToLinearSrgb,
  readVlanTokens,
  relativeLuminance,
  vlanPalette,
  type VlanColor,
  type VlanTokens,
} from "./vlan";

const LIGHT: VlanTokens = { l: 0.58, c: 0.14, h0: 255, background: "#FFFFFF" };
const DARK: VlanTokens = { l: 0.7, c: 0.13, h0: 255, background: "#171A21" };

/** The four-VLAN instance in design/tokens.css: --vlan-lan, -lab, -iot and -dmz. */
const LIGHT_INSTANCE: VlanColor[] = [
  { hex: "#3A7BCB", hue: 255, contrast: 4.31 },
  { hex: "#B2548D", hue: 345, contrast: 4.62 },
  { hex: "#A36E09", hue: 75, contrast: 4.37 },
  { hex: "#0A9068", hue: 165, contrast: 4.03 },
];
const DARK_INSTANCE: VlanColor[] = [
  { hex: "#64A1EE", hue: 255, contrast: 6.51 },
  { hex: "#D77CB1", hue: 345, contrast: 6.12 },
  { hex: "#CD9130", hue: 75, contrast: 6.39 },
  { hex: "#37B78A", hue: 165, contrast: 6.92 },
];

const HEX = /^#[0-9A-F]{6}$/;

// The mockup's palette code (design/mockups/shell.js) as written, with its inputs passed in
// instead of read from the document. The port restructures it to avoid allocations; the
// results must not change.
type Rgb = [number, number, number];

function referenceOklch(L: number, C: number, h: number): Rgb {
  const a = C * Math.cos((h * Math.PI) / 180);
  const b = C * Math.sin((h * Math.PI) / 180);
  const l = Math.pow(L + 0.3963377774 * a + 0.2158037573 * b, 3);
  const m = Math.pow(L - 0.1055613458 * a - 0.0638541728 * b, 3);
  const s = Math.pow(L - 0.0894841775 * a - 1.291485548 * b, 3);
  return [
    4.0767416621 * l - 3.3077115913 * m + 0.2309699292 * s,
    -1.2684380046 * l + 2.6097574011 * m - 0.3413193965 * s,
    -0.0041960863 * l - 0.7034186147 * m + 1.707614701 * s,
  ];
}

function referenceLum(rgb: Rgb): number {
  return 0.2126 * rgb[0] + 0.7152 * rgb[1] + 0.0722 * rgb[2];
}

function referenceHexToLinear(input: string): Rgb {
  let hex = input.trim().replace("#", "");
  if (hex.length === 3) hex = hex.replace(/./g, "$&$&");
  const channel = (i: number) => {
    const v = parseInt(hex.slice(i, i + 2), 16) / 255;
    return v <= 0.04045 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
  };
  return [channel(0), channel(2), channel(4)];
}

function referenceLinearToHex(rgb: Rgb): string {
  return (
    "#" +
    rgb
      .map((input) => {
        let v = Math.min(1, Math.max(0, input));
        v = v <= 0.0031308 ? 12.92 * v : 1.055 * Math.pow(v, 1 / 2.4) - 0.055;
        return ("0" + Math.round(v * 255).toString(16)).slice(-2);
      })
      .join("")
      .toUpperCase()
  );
}

function referencePalette(n: number, L0: number, C0: number, h0: number, bg: string): VlanColor[] {
  const yb = referenceLum(referenceHexToLinear(bg));
  const darkBg = yb < 0.18;
  const out: VlanColor[] = [];
  for (let i = 0; i < n; i++) {
    const h = (h0 + (i * 360) / n) % 360;
    let L = L0;
    let C: number;
    let rgb: Rgb = [0, 0, 0];
    let cr = 0;
    for (let k = 0; k < 60; k++) {
      C = C0;
      rgb = referenceOklch(L, C, h);
      while (rgb.some((v) => v < -0.0005 || v > 1.0005) && C > 0.02) {
        C -= 0.005;
        rgb = referenceOklch(L, C, h);
      }
      const clamped = rgb.map((v) => Math.min(1, Math.max(0, v))) as Rgb;
      const y = referenceLum(clamped);
      cr = (Math.max(y, yb) + 0.05) / (Math.min(y, yb) + 0.05);
      if (cr >= 3) break;
      L += darkBg ? 0.01 : -0.01;
    }
    out.push({ hex: referenceLinearToHex(rgb), hue: Math.round(h), contrast: Math.round(cr * 100) / 100 });
  }
  return out;
}

/** OKLab chroma and hue (degrees) of a linear sRGB color, from Ottosson's published matrices. */
function oklchChromaAndHue([r, g, b]: Rgb): [number, number] {
  const l = Math.cbrt(0.4122214708 * r + 0.5363325363 * g + 0.0514459929 * b);
  const m = Math.cbrt(0.2119034982 * r + 0.6806995451 * g + 0.1073969566 * b);
  const s = Math.cbrt(0.0883024619 * r + 0.2817188376 * g + 0.6299787005 * b);
  const a = 1.9779984951 * l - 2.428592205 * m + 0.4505937099 * s;
  const c = 0.0259040371 * l + 0.7827717662 * m - 0.808675766 * s;
  return [Math.hypot(a, c), ((Math.atan2(c, a) * 180) / Math.PI + 360) % 360];
}

function reference(n: number, tokens: VlanTokens): VlanColor[] {
  return referencePalette(n, tokens.l, tokens.c, tokens.h0, tokens.background);
}

describe("vlanPalette", () => {
  it("reproduces the four light colors of tokens.css", () => {
    expect(vlanPalette(4, LIGHT)).toEqual(LIGHT_INSTANCE);
  });

  it("reproduces the four dark colors of tokens.css", () => {
    expect(vlanPalette(4, DARK)).toEqual(DARK_INSTANCE);
  });

  it("gives no colors for no VLANs", () => {
    expect(vlanPalette(0, LIGHT)).toEqual([]);
  });

  it("gives no colors for a count that is not a positive number", () => {
    expect(vlanPalette(-3, LIGHT)).toEqual([]);
    expect(vlanPalette(0.9, LIGHT)).toEqual([]);
    expect(vlanPalette(Number.NaN, LIGHT)).toEqual([]);
    expect(vlanPalette(Number.POSITIVE_INFINITY, LIGHT)).toEqual([]);
  });

  it("rounds a fractional count down", () => {
    expect(vlanPalette(3.9, LIGHT)).toEqual(vlanPalette(3, LIGHT));
  });

  it("gives the first VLAN the hue h0", () => {
    expect(vlanPalette(1, LIGHT)).toEqual([{ hex: "#3A7BCB", hue: 255, contrast: 4.31 }]);
    expect(vlanPalette(1, { ...LIGHT, h0: 30 })[0]?.hue).toBe(30);
  });

  it("keeps a negative h0 on the circle", () => {
    const [first, second] = vlanPalette(2, { ...LIGHT, h0: -30 });
    expect(first?.hue).toBe(330);
    expect(second?.hue).toBe(150);
  });

  it("does not depend on the tokens object after the call", () => {
    const tokens = { ...LIGHT };
    const first = vlanPalette(3, tokens);
    tokens.l = 0.2;
    expect(vlanPalette(3, LIGHT)).toEqual(first);
  });

  describe.each([
    ["light", LIGHT, 4],
    ["dark", DARK, 6],
  ] as const)("%s theme, 1 to 24 VLANs", (_name, tokens, readme) => {
    const counts = Array.from({ length: 24 }, (_, i) => i + 1);

    it("returns one well-formed color per VLAN", () => {
      for (const n of counts) {
        const palette = vlanPalette(n, tokens);
        expect(palette, `n = ${n}`).toHaveLength(n);
        for (const color of palette) {
          expect(color.hex, `n = ${n}`).toMatch(HEX);
          expect(Number.isInteger(color.hue)).toBe(true);
          expect(color.contrast).toBe(Math.round(color.contrast * 100) / 100);
        }
      }
    });

    it("spreads the hues evenly from h0", () => {
      for (const n of counts) {
        const hues = vlanPalette(n, tokens).map((color) => color.hue);
        hues.forEach((hue, i) => {
          expect(hue, `n = ${n}, VLAN ${i}`).toBe(Math.round((tokens.h0 + (i * 360) / n) % 360));
        });
        // Neighbours are 360 / n apart, give or take the rounding of both.
        hues.forEach((hue, i) => {
          const next = hues[(i + 1) % n] as number;
          const gap = (next - hue + 360) % 360 || 360;
          expect(Math.abs(gap - 360 / n), `n = ${n}, VLAN ${i}`).toBeLessThanOrEqual(1);
        });
      }
    });

    it("reaches 3:1 against the background for every color", () => {
      for (const n of counts) {
        for (const color of vlanPalette(n, tokens)) {
          expect(color.contrast, `n = ${n}, ${color.hex}`).toBeGreaterThanOrEqual(3);
        }
      }
    });

    it(`measures at least ${readme}:1 as the README claims`, () => {
      let minimum = Infinity;
      for (const n of counts) {
        for (const color of vlanPalette(n, tokens)) minimum = Math.min(minimum, color.contrast);
      }
      expect(minimum).toBeGreaterThanOrEqual(readme);
    });

    it("reports the contrast of the color it returns", () => {
      for (const n of counts) {
        for (const color of vlanPalette(n, tokens)) {
          // The hex is quantized to 8 bits per channel, the report is not.
          expect(contrastRatio(color.hex, tokens.background), `n = ${n}, ${color.hex}`).toBeCloseTo(color.contrast, 1);
        }
      }
    });

    it("gives distinct colors", () => {
      for (const n of counts) {
        const hexes = new Set(vlanPalette(n, tokens).map((color) => color.hex));
        expect(hexes.size, `n = ${n}`).toBe(n);
      }
    });

    it("matches the mockup function", () => {
      for (const n of counts) expect(vlanPalette(n, tokens), `n = ${n}`).toEqual(reference(n, tokens));
    });
  });

  describe("against other tokens", () => {
    const cases: [string, VlanTokens][] = [
      ["lightness that must be pulled down", { l: 0.9, c: 0.14, h0: 30, background: "#FFFFFF" }],
      ["lightness that must be pushed up", { l: 0.2, c: 0.13, h0: 200, background: "#171A21" }],
      ["chroma outside sRGB", { l: 0.7, c: 0.4, h0: 10, background: "#FFFFFF" }],
      ["chroma outside sRGB on dark", { l: 0.5, c: 0.4, h0: 140, background: "#171A21" }],
      ["a mid gray background", { l: 0.5, c: 0.1, h0: 10, background: "#808080" }],
      ["a three digit background", { l: 0.58, c: 0.14, h0: 255, background: "#fff" }],
      ["a background without the hash", { l: 0.7, c: 0.13, h0: 255, background: "171A21" }],
      ["zero chroma", { l: 0.58, c: 0, h0: 0, background: "#FFFFFF" }],
      ["a black background", { l: 0.1, c: 0.2, h0: 300, background: "#000000" }],
    ];

    it.each(cases)("matches the mockup function with %s", (_name, tokens) => {
      for (const n of [1, 2, 3, 5, 8, 13, 24]) expect(vlanPalette(n, tokens), `n = ${n}`).toEqual(reference(n, tokens));
    });

    it("pulls lightness down on a light background and up on a dark one", () => {
      const light = vlanPalette(1, { l: 0.9, c: 0.14, h0: 30, background: "#FFFFFF" })[0] as VlanColor;
      const unnudgedLight = linearToHex(oklchToLinearSrgb(0.9, 0.14, 30));
      expect(contrastRatio(unnudgedLight, "#FFFFFF")).toBeLessThan(3);
      expect(light.contrast).toBeGreaterThanOrEqual(3);
      expect(relativeLuminance(hexToLinear(light.hex))).toBeLessThan(relativeLuminance(hexToLinear(unnudgedLight)));

      const dark = vlanPalette(1, { l: 0.2, c: 0.13, h0: 200, background: "#171A21" })[0] as VlanColor;
      const unnudgedDark = linearToHex(oklchToLinearSrgb(0.2, 0.13, 200));
      expect(contrastRatio(unnudgedDark, "#171A21")).toBeLessThan(3);
      expect(dark.contrast).toBeGreaterThanOrEqual(3);
      expect(relativeLuminance(hexToLinear(dark.hex))).toBeGreaterThan(relativeLuminance(hexToLinear(unnudgedDark)));
    });

    it("keeps chroma that fits in sRGB and reduces it only where it does not", () => {
      // The light instance needs no lightness nudge, so a color is the plain OKLCH color
      // unless that leaves sRGB (hues 75 and 165 at chroma 0.14 do).
      const inside: boolean[] = [];
      vlanPalette(4, LIGHT).forEach((color, i) => {
        const full = oklchToLinearSrgb(0.58, 0.14, (255 + i * 90) % 360);
        inside.push(Math.min(...full) >= -0.0005 && Math.max(...full) <= 1.0005);
        if (inside[i]) expect(color.hex, `VLAN ${i}`).toBe(linearToHex(full));
        else expect(color.hex, `VLAN ${i}`).not.toBe(linearToHex(full));
      });
      expect(inside).toEqual([true, true, false, false]);
    });

    it("reduces chroma instead of shifting the hue when a color leaves sRGB", () => {
      const tokens: VlanTokens = { l: 0.6, c: 0.4, h0: 0, background: "#FFFFFF" };
      vlanPalette(12, tokens).forEach((color, i) => {
        const hue = (i * 360) / 12;
        const full = oklchToLinearSrgb(tokens.l, tokens.c, hue);
        expect(Math.max(...full) > 1.0005 || Math.min(...full) < -0.0005, `hue ${hue} is outside sRGB`).toBe(true);
        const [chroma, measured] = oklchChromaAndHue(hexToLinear(color.hex));
        expect(chroma, `hue ${hue}`).toBeGreaterThan(0.02);
        expect(chroma, `hue ${hue}`).toBeLessThan(0.3);
        // Clipping a channel instead would move the hue by tens of degrees.
        expect(Math.abs(((measured - hue + 540) % 360) - 180), `hue ${hue}`).toBeLessThanOrEqual(3);
      });
    });

    it("gives up after 60 nudges when the contrast cannot be reached", () => {
      // Lightness 1.2 on a mid gray: it takes 70 steps down to the 3:1 zone below about 0.51.
      // The 60th attempt, at 0.61, is what comes back.
      const tokens: VlanTokens = { l: 1.2, c: 0, h0: 0, background: "#BCBCBC" };
      const [color] = vlanPalette(1, tokens);
      expect(color?.contrast).toBeLessThan(3);
      expect(color?.hex).toBe(linearToHex(oklchToLinearSrgb(0.61, 0, 0)));
      expect(vlanPalette(1, tokens)).toEqual(reference(1, tokens));
    });
  });
});

describe("contrastRatio", () => {
  it("is 21 for black on white, in either order", () => {
    expect(contrastRatio("#FFFFFF", "#000000")).toBeCloseTo(21, 10);
    expect(contrastRatio("#000000", "#FFFFFF")).toBeCloseTo(21, 10);
  });

  it("is 1 for a color against itself", () => {
    expect(contrastRatio("#3A7BCB", "#3A7BCB")).toBe(1);
  });

  it("is the WCAG ratio of known pairs", () => {
    // #767676 on white is the classic AA threshold: 4.54:1.
    expect(contrastRatio("#767676", "#FFFFFF")).toBeCloseTo(4.54, 2);
    expect(contrastRatio("#777777", "#FFFFFF")).toBeCloseTo(4.48, 2);
  });
});

describe("hexToLinear and linearToHex", () => {
  it("maps black and white", () => {
    expect(hexToLinear("#000000")).toEqual([0, 0, 0]);
    expect(hexToLinear("#FFFFFF")).toEqual([1, 1, 1]);
  });

  it("linearizes with the sRGB curve", () => {
    const [r, g, b] = hexToLinear("#808080");
    expect(r).toBeCloseTo(0.2159, 4);
    expect(g).toBe(r);
    expect(b).toBe(r);
    // The linear segment near black.
    expect(hexToLinear("#010101")[0]).toBeCloseTo(1 / 255 / 12.92, 12);
  });

  it("accepts three digit colors, no hash, case and surrounding space", () => {
    expect(hexToLinear("#FA0")).toEqual(hexToLinear("#FFAA00"));
    expect(hexToLinear("fa0")).toEqual(hexToLinear("#FFAA00"));
    expect(hexToLinear("  #ffaa00 ")).toEqual(hexToLinear("#FFAA00"));
  });

  it("round-trips every 8-bit gray and the palette colors", () => {
    for (let v = 0; v < 256; v++) {
      const hex = `#${v.toString(16).padStart(2, "0").repeat(3).toUpperCase()}`;
      expect(linearToHex(hexToLinear(hex)), hex).toBe(hex);
    }
    for (const color of [...LIGHT_INSTANCE, ...DARK_INSTANCE]) {
      expect(linearToHex(hexToLinear(color.hex)), color.hex).toBe(color.hex);
    }
  });

  it("writes upper case, zero padded hex", () => {
    expect(linearToHex([0, 0, 0])).toBe("#000000");
    expect(linearToHex([1, 1, 1])).toBe("#FFFFFF");
    expect(linearToHex(hexToLinear("#0A0B0C"))).toBe("#0A0B0C");
  });

  it("clamps channels outside 0 to 1", () => {
    expect(linearToHex([2, -1, 1.0004])).toBe("#FF00FF");
    expect(linearToHex([0.5, 0.5, 0.5])).toBe("#BCBCBC");
  });

  it("matches the mockup helpers", () => {
    for (const hex of ["#3A7BCB", "#171A21", "#FFF", "#00ff7f", "0A9068"]) {
      expect(hexToLinear(hex), hex).toEqual(referenceHexToLinear(hex));
    }
    for (const rgb of [[0.2, 0.4, 0.6], [0.001, 0.003, 0.0032], [1.2, -0.1, 0.5]] as Rgb[]) {
      expect(linearToHex(rgb)).toBe(referenceLinearToHex(rgb));
    }
  });
});

describe("relativeLuminance", () => {
  it("is 0 for black and 1 for white", () => {
    expect(relativeLuminance([0, 0, 0])).toBe(0);
    expect(relativeLuminance([1, 1, 1])).toBeCloseTo(1, 12);
  });

  it("weights green most and blue least", () => {
    expect(relativeLuminance([1, 0, 0])).toBe(0.2126);
    expect(relativeLuminance([0, 1, 0])).toBe(0.7152);
    expect(relativeLuminance([0, 0, 1])).toBe(0.0722);
  });
});

describe("oklchToLinearSrgb", () => {
  it("maps the lightness axis of black, gray and white", () => {
    expect(oklchToLinearSrgb(0, 0, 0)).toEqual([0, 0, 0]);
    const white = oklchToLinearSrgb(1, 0, 123);
    white.forEach((v) => expect(v).toBeCloseTo(1, 8));
    // Without chroma the three channels are equal and L is the cube root of the value.
    const gray = oklchToLinearSrgb(0.5, 0, 0);
    gray.forEach((v) => expect(v).toBeCloseTo(0.125, 8));
  });

  it("ignores the hue at zero chroma", () => {
    expect(oklchToLinearSrgb(0.6, 0, 20)).toEqual(oklchToLinearSrgb(0.6, 0, 200));
  });

  it("puts the primaries where OKLab places them", () => {
    // oklch(0.628 0.2577 29.23) is sRGB red.
    const [r, g, b] = oklchToLinearSrgb(0.62796, 0.25768, 29.234);
    expect(r).toBeCloseTo(1, 3);
    expect(g).toBeCloseTo(0, 3);
    expect(b).toBeCloseTo(0, 3);
  });

  it("leaves 0 to 1 for a color outside sRGB", () => {
    const rgb = oklchToLinearSrgb(0.7, 0.4, 145);
    expect(Math.min(...rgb)).toBeLessThan(0);
  });

  it("returns a new array every time", () => {
    const first = oklchToLinearSrgb(0.5, 0.1, 10);
    const second = oklchToLinearSrgb(0.5, 0.1, 10);
    expect(first).toEqual(second);
    expect(first).not.toBe(second);
  });

  it("matches the mockup function", () => {
    for (const [L, C, h] of [
      [0.58, 0.14, 255],
      [0.7, 0.13, 75],
      [0.9, 0.3, 330],
    ] as const) {
      expect(oklchToLinearSrgb(L, C, h)).toEqual(referenceOklch(L, C, h));
    }
  });
});

describe("readVlanTokens", () => {
  const properties = ["--vlan-l", "--vlan-c", "--vlan-h0", "--surface"];

  afterEach(() => {
    for (const name of properties) document.documentElement.style.removeProperty(name);
  });

  function elementWith(style: Record<string, string>): HTMLElement {
    const element = document.createElement("div");
    for (const [name, value] of Object.entries(style)) element.style.setProperty(name, value);
    document.body.append(element);
    return element;
  }

  it("reads the custom properties of an element", () => {
    const element = elementWith({ "--vlan-l": "0.7", "--vlan-c": "0.13", "--vlan-h0": "30", "--surface": "#171A21" });
    expect(readVlanTokens(element)).toEqual({ l: 0.7, c: 0.13, h0: 30, background: "#171A21" });
    element.remove();
  });

  it("trims whitespace around the values", () => {
    const element = elementWith({ "--vlan-l": " 0.64 ", "--vlan-c": "\t0.11", "--vlan-h0": "10 ", "--surface": " #F5F6F8 " });
    expect(readVlanTokens(element)).toEqual({ l: 0.64, c: 0.11, h0: 10, background: "#F5F6F8" });
    element.remove();
  });

  it("falls back to 0.58, 0.14, 255 and #FFFFFF when the properties are missing", () => {
    const element = elementWith({});
    expect(readVlanTokens(element)).toEqual({ l: 0.58, c: 0.14, h0: 255, background: "#FFFFFF" });
    element.remove();
  });

  it("falls back per property", () => {
    const element = elementWith({ "--vlan-l": "0.7", "--surface": "#171A21" });
    expect(readVlanTokens(element)).toEqual({ l: 0.7, c: 0.14, h0: 255, background: "#171A21" });
    element.remove();
  });

  it("falls back for empty and non-numeric values", () => {
    const element = elementWith({
      "--vlan-l": "",
      "--vlan-c": "wide",
      "--vlan-h0": "255deg",
      "--surface": "var(--missing)",
    });
    expect(readVlanTokens(element)).toEqual({ l: 0.58, c: 0.14, h0: 255, background: "#FFFFFF" });
    element.remove();
  });

  it("keeps a hue of 0", () => {
    const element = elementWith({ "--vlan-h0": "0" });
    expect(readVlanTokens(element).h0).toBe(0);
    element.remove();
  });

  it("reads the document root by default", () => {
    expect(readVlanTokens()).toEqual({ l: 0.58, c: 0.14, h0: 255, background: "#FFFFFF" });
    const root = document.documentElement;
    root.style.setProperty("--vlan-l", "0.7");
    root.style.setProperty("--vlan-c", "0.13");
    root.style.setProperty("--vlan-h0", "255");
    root.style.setProperty("--surface", "#171A21");
    expect(readVlanTokens()).toEqual({ l: 0.7, c: 0.13, h0: 255, background: "#171A21" });
  });

  it("feeds vlanPalette with the theme tokens", () => {
    const element = elementWith({ "--vlan-l": "0.7", "--vlan-c": "0.13", "--vlan-h0": "255", "--surface": "#171A21" });
    expect(vlanPalette(4, readVlanTokens(element))).toEqual(DARK_INSTANCE);
    element.remove();
  });
});
