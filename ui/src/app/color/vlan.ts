/**
 * VLAN identity is generated, not fixed. The VLANs in view get hues spread evenly around the
 * OKLCH circle from `h0`, all at the theme's lightness and chroma. Chroma is reduced only as
 * far as needed to stay inside sRGB, and lightness is nudged (darker on a light background,
 * lighter on a dark one, in 0.01 steps, at most 60) until the color has at least 3:1 contrast
 * against the background.
 *
 * Pure functions, no state. Only `readVlanTokens` touches the DOM, and only when it is called.
 */

/** Linear-light sRGB, each channel nominally 0 to 1 (OKLCH conversion can leave that range). */
export type LinearRgb = [r: number, g: number, b: number];

export interface VlanTokens {
  /** OKLCH lightness, `--vlan-l`. */
  l: number;
  /** OKLCH chroma, `--vlan-c`. */
  c: number;
  /** Hue of the first VLAN in degrees, `--vlan-h0`. */
  h0: number;
  /** Background the colors must stand out against, as `#RGB` or `#RRGGBB`; `--surface`. */
  background: string;
}

export interface VlanColor {
  /** Upper case `#RRGGBB`. */
  hex: string;
  /** OKLCH hue in degrees, rounded. */
  hue: number;
  /** Contrast against the background, rounded to two decimals. */
  contrast: number;
}

const MIN_CONTRAST = 3;
const MAX_NUDGES = 60;
const LIGHTNESS_STEP = 0.01;
const CHROMA_STEP = 0.005;
const MIN_CHROMA = 0.02;
/** Backgrounds with a relative luminance below this count as dark. */
const DARK_BACKGROUND = 0.18;
/** Linear values this close to the sRGB cube count as inside it. */
const GAMUT_TOLERANCE = 0.0005;

const FALLBACK_L = 0.58;
const FALLBACK_C = 0.14;
const FALLBACK_H0 = 255;
const FALLBACK_BACKGROUND = "#FFFFFF";

const HEX_COLOR = /^#(?:[0-9a-f]{3}|[0-9a-f]{6})$/i;
const EACH_CHARACTER = /./g;

/** Writes the linear sRGB value of an OKLCH color (`h` in degrees) into `out`. */
function fillOklch(out: LinearRgb, L: number, C: number, h: number): void {
  const a = C * Math.cos((h * Math.PI) / 180);
  const b = C * Math.sin((h * Math.PI) / 180);
  const l = (L + 0.3963377774 * a + 0.2158037573 * b) ** 3;
  const m = (L - 0.1055613458 * a - 0.0638541728 * b) ** 3;
  const s = (L - 0.0894841775 * a - 1.291485548 * b) ** 3;
  out[0] = 4.0767416621 * l - 3.3077115913 * m + 0.2309699292 * s;
  out[1] = -1.2684380046 * l + 2.6097574011 * m - 0.3413193965 * s;
  out[2] = -0.0041960863 * l - 0.7034186147 * m + 1.707614701 * s;
}

/**
 * Linear sRGB of an OKLCH color: lightness 0 to 1, chroma from 0, hue in degrees. A color
 * outside the sRGB gamut gives channels below 0 or above 1; the caller decides what to do.
 */
export function oklchToLinearSrgb(L: number, C: number, h: number): LinearRgb {
  const out: LinearRgb = [0, 0, 0];
  fillOklch(out, L, C, h);
  return out;
}

function srgbToLinear(v: number): number {
  return v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
}

/** Linear sRGB of a `#RGB` or `#RRGGBB` color (the `#` is optional). Not a hex color gives NaN. */
export function hexToLinear(hex: string): LinearRgb {
  let digits = hex.trim().replace("#", "");
  if (digits.length === 3) digits = digits.replace(EACH_CHARACTER, "$&$&");
  return [
    srgbToLinear(Number.parseInt(digits.slice(0, 2), 16) / 255),
    srgbToLinear(Number.parseInt(digits.slice(2, 4), 16) / 255),
    srgbToLinear(Number.parseInt(digits.slice(4, 6), 16) / 255),
  ];
}

function linearToHexChannel(v: number): string {
  const c = Math.min(1, Math.max(0, v));
  const encoded = c <= 0.0031308 ? 12.92 * c : 1.055 * c ** (1 / 2.4) - 0.055;
  return Math.round(encoded * 255)
    .toString(16)
    .padStart(2, "0");
}

/** Upper case `#RRGGBB` of a linear sRGB value. Channels outside 0 to 1 are clamped. */
export function linearToHex(rgb: Readonly<LinearRgb>): string {
  return `#${linearToHexChannel(rgb[0])}${linearToHexChannel(rgb[1])}${linearToHexChannel(rgb[2])}`.toUpperCase();
}

/** WCAG relative luminance of a linear sRGB value: 0 for black, 1 for white. */
export function relativeLuminance(rgb: Readonly<LinearRgb>): number {
  return 0.2126 * rgb[0] + 0.7152 * rgb[1] + 0.0722 * rgb[2];
}

function contrastOfLuminances(a: number, b: number): number {
  return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
}

/** WCAG contrast ratio of two hex colors, 1 to 21. Not rounded. */
export function contrastRatio(hexA: string, hexB: string): number {
  return contrastOfLuminances(relativeLuminance(hexToLinear(hexA)), relativeLuminance(hexToLinear(hexB)));
}

function outsideGamut(rgb: Readonly<LinearRgb>): boolean {
  for (let i = 0; i < 3; i++) {
    const v = rgb[i] as number;
    if (v < -GAMUT_TOLERANCE || v > 1 + GAMUT_TOLERANCE) return true;
  }
  return false;
}

function clampInPlace(rgb: LinearRgb): void {
  for (let i = 0; i < 3; i++) rgb[i] = Math.min(1, Math.max(0, rgb[i] as number));
}

/**
 * The colors of `n` VLANs, in order: hue `(h0 + i * 360 / n) mod 360` for VLAN `i`. No VLANs
 * (or a count that is not a finite number of at least one) gives an empty list.
 */
export function vlanPalette(n: number, tokens: VlanTokens): VlanColor[] {
  const count = Number.isFinite(n) ? Math.floor(n) : 0;
  const out: VlanColor[] = [];
  if (count < 1) return out;

  const backgroundLuminance = relativeLuminance(hexToLinear(tokens.background));
  const step = backgroundLuminance < DARK_BACKGROUND ? LIGHTNESS_STEP : -LIGHTNESS_STEP;
  const rgb: LinearRgb = [0, 0, 0];

  for (let i = 0; i < count; i++) {
    let hue = (tokens.h0 + (i * 360) / count) % 360;
    if (hue < 0) hue += 360;

    let lightness = tokens.l;
    let contrast = 0;
    for (let k = 0; k < MAX_NUDGES; k++) {
      let chroma = tokens.c;
      fillOklch(rgb, lightness, chroma, hue);
      while (outsideGamut(rgb) && chroma > MIN_CHROMA) {
        chroma -= CHROMA_STEP;
        fillOklch(rgb, lightness, chroma, hue);
      }
      // linearToHex clamps the same way, so clamping here does not change the hex.
      clampInPlace(rgb);
      contrast = contrastOfLuminances(relativeLuminance(rgb), backgroundLuminance);
      if (contrast >= MIN_CONTRAST) break;
      lightness += step;
    }
    out.push({ hex: linearToHex(rgb), hue: Math.round(hue), contrast: Math.round(contrast * 100) / 100 });
  }
  return out;
}

function numberProperty(style: CSSStyleDeclaration, name: string, fallback: number): number {
  const text = style.getPropertyValue(name).trim();
  if (text === "") return fallback;
  const value = Number(text);
  return Number.isFinite(value) ? value : fallback;
}

function colorProperty(style: CSSStyleDeclaration, name: string, fallback: string): string {
  const text = style.getPropertyValue(name).trim();
  return HEX_COLOR.test(text) ? text : fallback;
}

/**
 * Reads `--vlan-l`, `--vlan-c`, `--vlan-h0` and `--surface` from the computed style of
 * `element` (the document root by default). A property that is empty or not a number (a hex
 * color for `--surface`) falls back to 0.58, 0.14, 255 and #FFFFFF.
 */
export function readVlanTokens(element: Element = document.documentElement): VlanTokens {
  const style = getComputedStyle(element);
  return {
    l: numberProperty(style, "--vlan-l", FALLBACK_L),
    c: numberProperty(style, "--vlan-c", FALLBACK_C),
    h0: numberProperty(style, "--vlan-h0", FALLBACK_H0),
    background: colorProperty(style, "--surface", FALLBACK_BACKGROUND),
  };
}
