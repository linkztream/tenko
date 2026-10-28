// The badge of each rail item from the findings counts (design decision 17), and how it is drawn.
// Loaded with the findings part of the shell after the first page, so the first page load stays
// small: the counts come from a read after the shell is up anyway.
import { Show } from "solid-js";
import { formatNumber, t } from "../i18n";
import type { Area } from "./areas";
import { areaCounts, worst, type FindingArea, type FindingCounts } from "./findings";

/** What an item of the rail carries: a count coloured by the worst severity, or a dot. */
export type RailBadge = { kind: "count"; count: number; level: "act" | "review"; label: string } | { kind: "dot"; label: string };

type CountBadge = Extract<RailBadge, { kind: "count" }>;
const countOf = (badge: RailBadge): CountBadge | undefined => (badge.kind === "count" ? badge : undefined);

/** A count in the fill of its severity (99+ above 99), or a dot; labelled with the count and the area. */
export function RailBadgeView(props: { badge: RailBadge }) {
  return (
    <Show when={countOf(props.badge)} fallback={<span class="badge-dot" data-testid="rail-dot" aria-label={props.badge.label} />}>
      {(c) => (
        <span class={`badge-count ${c().level}`} data-testid="rail-badge" data-level={c().level} aria-label={c().label}>
          {c().count > 99 ? t("shell.nav.badge.many") : formatNumber(c().count)}
        </span>
      )}
    </Show>
  );
}

/** Areas whose badge is the count of their act and review findings (Jobs: the jobs waiting for a person). */
const COUNTED: ReadonlySet<Area["id"]> = new Set(["ipam", "dns", "dhcp", "discovery", "topology", "jobs"]);
/** Areas that show a dot while they have a finding to act on: an unhealthy connector or node. */
const DOTTED: ReadonlySet<Area["id"]> = new Set(["connectors", "nodes"]);

/**
 * The badge of one rail item; null when there is nothing to show. Info findings are never
 * counted. Settings shows a dot while a security setting is weaker than the Home profile (the
 * session's banner; not under Lab, whose banner already says so) or while a finding of the
 * settings area is to act on.
 */
export function railBadge(area: Area, counts: FindingCounts | null, weakened: boolean): RailBadge | null {
  const name = t(area.label);
  if (COUNTED.has(area.id)) {
    const level = areaCounts(counts, area.id as FindingArea);
    const severity = worst(level);
    if (!severity) return null;
    const count = level.act + level.review;
    const label =
      area.id === "jobs"
        ? t("shell.nav.badge.jobs", { area: name, count })
        : severity === "act"
          ? t("shell.nav.badge.act", { area: name, count, act: level.act })
          : t("shell.nav.badge.review", { area: name, count });
    return { kind: "count", count, level: severity, label };
  }
  if (DOTTED.has(area.id)) {
    const act = areaCounts(counts, area.id as FindingArea).act;
    return act > 0 ? { kind: "dot", label: t("shell.nav.badge.unhealthy", { area: name, count: act }) } : null;
  }
  if (area.id === "settings") {
    const act = areaCounts(counts, "settings").act;
    if (weakened) return { kind: "dot", label: t("shell.nav.badge.weakened", { area: name }) };
    return act > 0 ? { kind: "dot", label: t("shell.nav.badge.unhealthy", { area: name, count: act }) } : null;
  }
  return null;
}
