// The paths of the migration views (Windows takeover plan section 3.3, WP14.0): a mirror's page
// under the connectors area and the two zone actions under the DNS area. The shared table of
// links (src/app/paths.ts) belongs to the shell; these stay here until they are folded in.
import { seg } from "../app/paths";

/** The tabs of a mirror's page. */
export type MirrorTab = "scopes" | "losses" | "settings";

export const MIRROR_TABS: readonly MirrorTab[] = ["scopes", "losses", "settings"];

export const migratePaths = {
  mirror: (id: string, tab?: MirrorTab) => (tab && tab !== "scopes" ? `/connectors/mirrors/${seg(id)}/${tab}` : `/connectors/mirrors/${seg(id)}`),
  zoneFlip: (zone: string) => `/dns/zones/${seg(zone)}/flip`,
  zoneRelease: (zone: string) => `/dns/zones/${seg(zone)}/release`,
} as const;
