/**
 * Pan, zoom and keyboard navigation of the topology drawing, as pure functions.
 *
 * A `View` says which drawing point is at the top left of the screen and how much the drawing
 * is magnified. A drawing point (px, py) is at the screen point ((px - x) * scale, (py - y) * scale),
 * and the screen point (sx, sy) shows the drawing point (x + sx / scale, y + sy / scale).
 */

/** The drawing point at the top left of the screen and the zoom factor. */
export interface View {
  x: number;
  y: number;
  scale: number;
}

export const MIN_SCALE = 0.05;
export const MAX_SCALE = 4;

/** The largest scale `fit` picks, so that a tiny graph stays readable instead of huge. */
const MAX_FIT_SCALE = 1.5;
/** The share of the screen a fitted drawing may fill. */
const FIT_FILL = 0.95;

/** Limits a scale to `MIN_SCALE` to `MAX_SCALE`; a value that is not a number becomes 1. */
export function clampScale(scale: number): number {
  if (Number.isNaN(scale)) return 1;
  return Math.min(MAX_SCALE, Math.max(MIN_SCALE, scale));
}

/**
 * Fits a drawing of `width` x `height` into a screen of `screenWidth` x `screenHeight`, leaving
 * a margin of 5 percent (the drawing fills at most 95 percent of the tighter screen side),
 * centred, never above scale 1.5 and never outside the scale limits. An empty or zero-size
 * screen returns { x: 0, y: 0, scale: 1 }.
 */
export function fit(width: number, height: number, screenWidth: number, screenHeight: number): View {
  if (!(screenWidth > 0) || !(screenHeight > 0) || !Number.isFinite(screenWidth) || !Number.isFinite(screenHeight)) {
    return { x: 0, y: 0, scale: 1 };
  }
  const w = Number.isFinite(width) ? Math.max(0, width) : 0;
  const h = Number.isFinite(height) ? Math.max(0, height) : 0;
  const byWidth = w > 0 ? (screenWidth * FIT_FILL) / w : Infinity;
  const byHeight = h > 0 ? (screenHeight * FIT_FILL) / h : Infinity;
  const scale = clampScale(Math.min(byWidth, byHeight, MAX_FIT_SCALE));
  return centreOn({ x: 0, y: 0, scale }, w / 2, h / 2, screenWidth, screenHeight);
}

/**
 * Zooms by `factor` around the screen point (sx, sy) so that the drawing point under it stays
 * under it. The scale is clamped; a factor that is not a positive number leaves the view alone.
 */
export function zoomAt(view: View, factor: number, sx: number, sy: number): View {
  if (!(factor > 0) || !Number.isFinite(factor)) return view;
  const scale = clampScale(view.scale * factor);
  return {
    x: view.x + sx / view.scale - sx / scale,
    y: view.y + sy / view.scale - sy / scale,
    scale,
  };
}

/** Moves the view by a screen distance (dx, dy): the drawing follows the pointer. */
export function pan(view: View, dx: number, dy: number): View {
  return { x: view.x - dx / view.scale, y: view.y - dy / view.scale, scale: view.scale };
}

/** The view that puts the drawing point (px, py) at the centre of the screen, keeping the scale. */
export function centreOn(view: View, px: number, py: number, screenWidth: number, screenHeight: number): View {
  return {
    x: px - screenWidth / (2 * view.scale),
    y: py - screenHeight / (2 * view.scale),
    scale: view.scale,
  };
}

/** Rounds to 3 decimals; never gives -0. */
function round3(value: number): number {
  return Math.round(value * 1000) / 1000 + 0;
}

/** The SVG `transform` attribute value of the drawing group: `translate(tx ty) scale(s)`, numbers rounded to 3 decimals. */
export function transformOf(view: View): string {
  const tx = round3(-view.x * view.scale);
  const ty = round3(-view.y * view.scale);
  return `translate(${tx} ${ty}) scale(${round3(view.scale)})`;
}

export type Direction = "up" | "down" | "left" | "right";

/** The unit vector of a direction on the screen (y grows downward). */
const VECTORS: Record<Direction, { x: number; y: number }> = {
  up: { x: 0, y: -1 },
  down: { x: 0, y: 1 },
  left: { x: -1, y: 0 },
  right: { x: 1, y: 0 },
};

/** The cosine of the widest angle (60 degrees) between the direction and the way to a candidate. */
const COS_LIMIT = 0.5;
/** The weight of the offset perpendicular to the direction in the distance score. */
const OFFSET_WEIGHT = 0.5;

/**
 * Keyboard navigation between nodes: the id of the nearest point in the direction from the
 * point `from`, among the points whose angle from `from` is within 60 degrees of the direction
 * (screen coordinates, y grows downward). The distance is the Euclidean distance plus 0.5
 * times the offset perpendicular to the direction; a tie goes to the smaller id. Returns null
 * when there is no such point or `from` is not among the points.
 */
export function nearestInDirection(
  points: readonly { id: string; x: number; y: number }[],
  from: string,
  direction: Direction,
): string | null {
  const origin = points.find((p) => p.id === from);
  if (!origin) return null;
  const d = VECTORS[direction];

  let best: string | null = null;
  let bestScore = Infinity;
  for (const p of points) {
    if (p.id === from) continue;
    const dx = p.x - origin.x;
    const dy = p.y - origin.y;
    const distance = Math.hypot(dx, dy);
    const along = dx * d.x + dy * d.y;
    if (distance === 0 || along <= 0 || along < COS_LIMIT * distance) continue;
    const offset = Math.abs(dx * d.y - dy * d.x);
    const score = distance + OFFSET_WEIGHT * offset;
    if (score < bestScore || (score === bestScore && best !== null && p.id < best)) {
      best = p.id;
      bestScore = score;
    }
  }
  return best;
}
