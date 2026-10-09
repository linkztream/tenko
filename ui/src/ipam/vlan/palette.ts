/**
 * Colors and swatch shapes for the VLANs in view (design decision 11).
 *
 * The VLANs in view get hues spread evenly around the OKLCH circle (`vlanPalette`), each with
 * at least 3:1 contrast against the background. Two further rules apply to the lists and maps
 * of the IPAM views:
 *
 * - VLANs that are neighbours in id order never get neighbouring hues. The i-th VLAN takes hue
 *   slot `(i * s) mod n`, with a stride `s` near the golden section of the circle that has no
 *   common factor with `n`, so consecutive ids are far apart on the circle.
 * - Color is never the only cue: each VLAN also gets a swatch shape, and the chip always shows
 *   the VLAN id as text.
 *
 * Everything is a pure function except `createVlanStyles`, which reads the CSS tokens.
 */
import { createEffect, createMemo, createSignal, on } from "solid-js";
import { effectiveTheme } from "../../app/prefs";
import { readVlanTokens, vlanPalette, type VlanTokens } from "../../app/color/vlan";

/** Swatch shapes, the second cue next to the color. */
export const VLAN_SHAPES = ["square", "circle", "diamond", "triangle", "ring", "bar"] as const;
export type VlanShape = (typeof VLAN_SHAPES)[number];

export interface VlanStyle {
  vid: number;
  /** Upper case `#RRGGBB`. */
  hex: string;
  /** OKLCH hue in degrees, rounded. */
  hue: number;
  /** Contrast against the background, rounded to two decimals. */
  contrast: number;
  shape: VlanShape;
}

/** Valid VLAN ids (IEEE 802.1Q): 1 to 4094. */
const MIN_VID = 1;
const MAX_VID = 4094;

/** Share of the circle between the hues of two neighbouring ids: 1 - 1/phi, about 137.5 degrees. */
const STRIDE_SHARE = 0.382;

function gcd(a: number, b: number): number {
  let x = a;
  let y = b;
  while (y !== 0) [x, y] = [y, x % y];
  return x;
}

/**
 * The stride for `n` slots: the number nearest `n * 0.382` (rounded first, then searching
 * outward, the larger circular distance winning a tie) that has no common factor with `n`.
 * That makes `i * s mod n` a permutation of `0..n-1`.
 */
function strideFor(n: number): number {
  if (n <= 2) return 1;
  const start = Math.min(n - 1, Math.max(1, Math.round(n * STRIDE_SHARE)));
  for (let d = 0; d < n; d++) {
    const above = start + d;
    if (above < n && gcd(above, n) === 1) return above;
    const below = start - d;
    if (below >= 1 && gcd(below, n) === 1) return below;
  }
  return 1;
}

/**
 * A permutation of `0..n-1`: the hue slot of the i-th VLAN in id order. Consecutive VLANs get
 * slots that are far apart on the circle. `n` below 1 (or not a finite number) gives `[]`.
 */
export function vlanSlotOrder(n: number): number[] {
  const count = Number.isFinite(n) ? Math.floor(n) : 0;
  if (count < 1) return [];
  const stride = strideFor(count);
  const slots: number[] = [];
  for (let i = 0; i < count; i++) slots.push((i * stride) % count);
  return slots;
}

/**
 * Colors and shapes for a set of VLAN ids. Duplicates and ids outside 1 to 4094 (or not whole
 * numbers) are ignored; the ids are sorted ascending. The i-th id gets
 * `palette[slot(i)]` of `vlanPalette(count, tokens)` and the shape `VLAN_SHAPES[i mod 6]`.
 */
export function assignVlanStyles(vids: readonly number[], tokens: VlanTokens): Map<number, VlanStyle> {
  const ids = [...new Set(vids.filter((v) => Number.isInteger(v) && v >= MIN_VID && v <= MAX_VID))].sort((a, b) => a - b);
  const styles = new Map<number, VlanStyle>();
  if (ids.length === 0) return styles;

  const palette = vlanPalette(ids.length, tokens);
  const slots = vlanSlotOrder(ids.length);
  ids.forEach((vid, i) => {
    const color = palette[slots[i] as number];
    if (!color) return;
    styles.set(vid, {
      vid,
      hex: color.hex,
      hue: color.hue,
      contrast: color.contrast,
      shape: VLAN_SHAPES[i % VLAN_SHAPES.length] as VlanShape,
    });
  });
  return styles;
}

/**
 * Reactive styles for the VLAN ids `vids()` returns. Recomputes when the ids or the effective
 * theme change; the tokens come from `readVlanTokens()` (without CSS, as under jsdom, its
 * fallbacks apply). Call it inside a component or a reactive root.
 */
export function createVlanStyles(vids: () => readonly number[]): () => Map<number, VlanStyle> {
  // `setTheme()` updates its signal before it writes `<html data-theme>`, so reading the CSS
  // tokens in the same update would still see the old theme. The tokens are read one microtask
  // after the theme changed, still before the next paint.
  const [themeGeneration, setThemeGeneration] = createSignal(0);
  createEffect(
    on(
      effectiveTheme,
      () => {
        queueMicrotask(() => setThemeGeneration((g) => g + 1));
      },
      { defer: true },
    ),
  );

  return createMemo(() => {
    themeGeneration();
    return assignVlanStyles(vids(), readVlanTokens());
  });
}
