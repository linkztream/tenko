// The progress of a scan, or of one probe's part of it: a thin bar with the percentage after it.
import { formatNumber, t } from "../i18n";

/** `value` is a percentage; `label` names what progresses (the bar has no visible name). */
export function ProgressBar(props: { value: number; label: string; testid?: string }) {
  const percent = () => Math.max(0, Math.min(100, Math.round(props.value)));
  return (
    <span class="scan-progress">
      <span
        class="scan-bar"
        role="progressbar"
        aria-label={props.label}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={percent()}
        data-testid={props.testid}
        style={{ "--v": `${percent()}%` }}
      >
        <i />
      </span>
      <span class="num scan-percent">{t("scans.progress.percent", { percent: formatNumber(percent()) })}</span>
    </span>
  );
}

/** The state of a scan as a glyph and a word, in the colors of the job states. */
export function StateTag(props: { glyph: string; state: string; word: string; progress?: number }) {
  return (
    <span class={`jstate ${props.glyph}`} data-state={props.state} style={props.progress === undefined ? undefined : { "--p": `${props.progress}%` }}>
      {props.word}
    </span>
  );
}
