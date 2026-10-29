// The one utilization meter of a prefix's header (section 5.2 of the UI plan): in use of the
// usable addresses (docs/ipam.md section 1, `utilization.percent`), never the covered space, with
// the alarm line at the warning threshold and the scale it names. Colour only for an exception:
// the bar is neutral until the prefix is at its warning or critical level.
import { Show } from "solid-js";
import type { AlarmLevel, UtilizationView } from "../../api/types";
import { Count } from "../../grid/cells";
import { formatNumber, t, tx } from "../../i18n";
import { alarmWord } from "../words";

/** The percentage as the number rules say: one decimal under 10 %, whole numbers from there. */
export function percentText(percent: number): string {
  const value = Number.isFinite(percent) ? Math.max(0, percent) : 0;
  return t("ipam.meter.value", { value: formatNumber(value, { maximumFractionDigits: value < 10 ? 1 : 0 }) });
}

/** Where a percentage sits on the bar, 0 to 100. */
const onBar = (percent: number) => Math.max(0, Math.min(100, Number.isFinite(percent) ? percent : 0));

export function UsageMeter(props: {
  use: UtilizationView;
  level: AlarmLevel;
  alarm?: { warn_pct: number; crit_pct: number } | null | undefined;
}) {
  return (
    <div class="usage-meter" data-testid="usage-meter" data-level={props.level}>
      <span class="label">{t("ipam.meter.label")}</span>
      <span class="value" data-testid="usage-value">
        {percentText(props.use.percent)}
        <Show when={props.level !== "normal"}>
          <span class={`flag alarm-${props.level}`}>{alarmWord(props.level)}</span>
        </Show>
      </span>
      <span
        class="track"
        classList={{ warn: props.level === "warning", crit: props.level === "critical" }}
        role="meter"
        aria-label={t("ipam.meter.label")}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={onBar(props.use.percent)}
        aria-valuetext={percentText(props.use.percent)}
      >
        <span class="fill" style={{ "inline-size": `${onBar(props.use.percent)}%` }} />
        <Show when={props.alarm}>
          {(a) => <span class="alarm-line" data-testid="alarm-line" style={{ "inset-inline-start": `${onBar(a().warn_pct)}%` }} />}
        </Show>
      </span>
      <span class="of" data-testid="prefix-usage" title={t("ipam.prefix.usage_hint")}>
        {tx("ipam.prefix.usage", { used: <Count value={props.use.in_use} />, capacity: <Count value={props.use.capacity} /> })}
      </span>
      <span class="scale muted" data-testid="usage-scale">
        {t("ipam.meter.scale")}
        {" · "}
        <Show when={props.alarm} fallback={t("ipam.meter.no_alarm")}>
          {(a) => t("ipam.meter.alarm_at", { warn: a().warn_pct, crit: a().crit_pct })}
        </Show>
      </span>
    </div>
  );
}
