// What the mirror views compute from a mirror: its state on the card. Pure functions, no API.
import type { MirrorItem } from "./api";

/** A mirror's state on its card: disabled, waiting for its first push, fresh or stale. */
export type MirrorState = "disabled" | "waiting" | "fresh" | "stale";

export function mirrorState(mirror: Pick<MirrorItem, "enabled" | "age_secs" | "stale">): MirrorState {
  if (mirror.enabled === false) return "disabled";
  if (mirror.age_secs === undefined || mirror.age_secs === null) return "waiting";
  return mirror.stale ? "stale" : "fresh";
}

/**
 * The short form of a mirror's id shown beside its name, which is not unique: its last eight
 * hexadecimal digits, as the server's findings and `Mirror::short_id` write it.
 */
export function shortId(id: string): string {
  return id.slice(-8);
}
