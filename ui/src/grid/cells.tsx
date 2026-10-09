// Cell renderers for the IPAM grids and panels: lifecycle status, assignment mode, flags, tags,
// utilization, relative time, DNS names and counts. Each one is a small component that renders
// the markup of the design (design/README.md, badges) and always carries a word, so state is
// never shown by color alone. The words come from src/ipam/words.ts.
import { For, Show } from "solid-js";
import type { AlarmLevel, AssignmentMode, Status } from "../api/types";
import { Icon } from "../components/Icon";
import { formatDateTime, formatList, formatNumber, formatRelative, t } from "../i18n";
import { alarmWord, countTitle, kindWord, modeHint, modeWord, siCount, statusWord } from "../ipam/words";
import "./cells.css";

/**
 * The lifecycle status of an object. Active is plain ink, planned has a dashed outline,
 * reserved a solid one, deprecated is muted and struck through. The word is always there.
 */
export function StatusBadge(props: { status: Status }) {
  return (
    <span class={`status-badge ${props.status}`} data-status={props.status}>
      {statusWord(props.status)}
    </span>
  );
}

/**
 * The assignment mode: glyph (from design.css) and word, with the IPAM-14 behavior as the
 * tooltip. With `showHint` the sentence follows the word.
 */
export function ModeBadge(props: { mode: AssignmentMode; showHint?: boolean }) {
  return (
    <>
      <span class={`mode ${props.mode}`} title={modeHint(props.mode)}>
        {modeWord(props.mode)}
      </span>
      <Show when={props.showHint}>
        <span class="muted mode-hint">{modeHint(props.mode)}</span>
      </Show>
    </>
  );
}

/** The lock flag of a host: automation is stopped. Renders nothing when the host is not locked. */
export function LockFlag(props: { locked?: boolean | null | undefined }) {
  return (
    <Show when={props.locked}>
      <span class="flag locked" title={t("ipam.flag.locked_hint")}>
        <Icon name="lock" size="xs" />
        {t("ipam.flag.locked")}
      </span>
    </Show>
  );
}

/**
 * Tags are data and are shown as they are. At most `max` (default 3) are drawn, then "+N" with
 * the rest in its tooltip.
 */
export function Tags(props: { tags?: readonly string[] | null | undefined; max?: number | undefined }) {
  const limit = () => Math.max(0, Math.floor(props.max ?? 3));
  const all = () => props.tags ?? [];
  const shown = () => all().slice(0, limit());
  const hidden = () => all().slice(limit());
  return (
    <Show when={all().length > 0}>
      <span class="tags">
        <For each={shown()}>{(tag) => <span class="tag">{tag}</span>}</For>
        <Show when={hidden().length > 0}>
          <span class="tag more" title={formatList(hidden(), "unit")}>
            +{formatNumber(hidden().length)}
          </span>
        </Show>
      </span>
    </Show>
  );
}

/** A percentage for the bar: finite, between 0 and 100. */
function barPercent(percent: number): number {
  return Number.isFinite(percent) ? Math.min(100, Math.max(0, percent)) : 0;
}

/**
 * Utilization of a prefix: a thin bar and the percentage with at most one decimal. Neutral
 * until the alarm level is warning or critical; then the bar changes color, an alert icon
 * appears and the level is also spoken as text, so color is never the only cue.
 */
export function UtilizationMeter(props: {
  percent: number;
  level?: AlarmLevel | undefined;
  used?: string | undefined;
  capacity?: string | undefined;
  compact?: boolean | undefined;
}) {
  const level = () => props.level ?? "normal";
  const cls = () => {
    let out = "meter";
    if (level() === "warning") out += " warn";
    else if (level() === "critical") out += " crit";
    if (props.compact) out += " compact";
    return out;
  };
  const title = () =>
    props.used !== undefined && props.capacity !== undefined
      ? t("ipam.meter.title", { used: siCount(props.used), capacity: siCount(props.capacity) })
      : undefined;
  return (
    <span class={cls()} style={{ "--v": `${barPercent(props.percent)}%` }} title={title()} data-level={level()}>
      <span class="bar">
        <i />
      </span>
      <Show when={level() !== "normal"}>
        <Icon name="alert" size="xs" class="alarm-icon" />
        <span class="sr-only">{alarmWord(level())}</span>
      </Show>
      <span class="val">
        {t("ipam.meter.value", {
          value: formatNumber(Number.isFinite(props.percent) ? props.percent : 0, { maximumFractionDigits: 1 }),
        })}
      </span>
    </span>
  );
}

/** The alarm level as a flag with an icon and a word. Nothing for normal. */
export function AlarmFlag(props: { level: AlarmLevel }) {
  return (
    <Show when={props.level !== "normal"}>
      <span class={`flag alarm-${props.level}`}>
        <Icon name="alert" size="xs" />
        {alarmWord(props.level)}
      </span>
    </Show>
  );
}

/**
 * A point in time as relative text ("3 minutes ago") in a time element, with the exact date
 * and time as the tooltip. A dash when there is none. It does not tick: it is as current as
 * the row it sits in.
 */
export function TimeAgo(props: { at: string | null | undefined }) {
  return (
    <Show when={props.at} fallback={<span class="muted">–</span>}>
      {(at) => (
        <time datetime={at()} title={formatDateTime(at())}>
          {formatRelative(at())}
        </time>
      )}
    </Show>
  );
}

/** The tag of an object in the trash; the tooltip says when it was deleted. */
export function DeletedTag(props: { deleted?: { at: string } | null | undefined }) {
  return (
    <Show when={props.deleted}>
      {(deleted) => (
        <span class="tag deleted" title={formatDateTime(deleted().at)}>
          {t("ipam.flag.deleted")}
        </span>
      )}
    </Show>
  );
}

/** A DNS name: the host label in ink, the domain after it muted. Nothing for an empty name. */
export function DnsName(props: { name?: string | null | undefined }) {
  const name = () => props.name?.trim() ?? "";
  const dot = () => name().indexOf(".");
  return (
    <Show when={name() !== ""}>
      <span class="hostname">
        {dot() < 0 ? name() : name().slice(0, dot())}
        <Show when={dot() >= 0}>
          <span class="domain">{name().slice(dot())}</span>
        </Show>
      </span>
    </Show>
  );
}

/**
 * A count that can grow, in the compact form of the design (982, 1.2K, 2^64); the exact value is
 * the tooltip. Takes decimal strings, so IPv6 sizes work.
 */
export function Count(props: { value: string | number | bigint; class?: string | undefined }) {
  return (
    <span class={props.class ? `num ${props.class}` : "num"} title={countTitle(props.value)}>
      {siCount(props.value)}
    </span>
  );
}

/** The lowercase noun of an object kind, in the plural for any count but one. */
export function Kind(props: { kind: string; count?: number | undefined }) {
  return <>{kindWord(props.kind, props.count)}</>;
}
