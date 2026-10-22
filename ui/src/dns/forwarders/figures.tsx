// The round-trip times and states of the upstreams (docs/dns.md, "Upstream response times"),
// shared by the forwarders page and the node's DNS settings page: the time shown for an
// upstream (the median of the last minute, else the smoothed time, else the last one), its
// state as a dot with words for screen readers, the upstream the next query goes to, and a
// title with every figure and the last error.
import { Show } from "solid-js";
import type { components } from "../../api/generated/schema";
import { formatDateTime, formatNumber, t } from "../../i18n";
import "./figures.css";

type S = components["schemas"];
export type UpstreamFigures = S["UpstreamFigures"];
export type UpstreamGroup = S["UpstreamGroupItem"];
export type UpstreamState = S["UpstreamStateItem"];

/** The time shown for an upstream in milliseconds: the median of the last minute, else the
 * smoothed time, else the last one; `undefined` when it never answered. */
export function shownRtt(figures: UpstreamFigures): number | undefined {
  return figures.p50_ms ?? figures.ewma_ms ?? figures.last_rtt_ms ?? undefined;
}

/** The class of the state's dot. */
export function stateDot(state: UpstreamState): string {
  return state === "up" ? "dot" : state === "degraded" ? "dot warn" : state === "down" ? "dot bad" : "dot idle";
}

/** Milliseconds for people: one decimal below 10 ms, whole milliseconds above; a dash for none. */
export function msText(ms: number | null | undefined): string {
  if (ms === null || ms === undefined) return "–";
  return t("dns.upstream.ms", { ms: formatNumber(ms, { maximumFractionDigits: ms < 10 ? 1 : 0 }) });
}

/** Every figure of an upstream in one line, for a title. */
export function figuresTitle(figures: UpstreamFigures): string {
  const parts = [
    t(`dns.upstream.state.${figures.state}`),
    t("dns.upstream.times", {
      last: msText(figures.last_rtt_ms),
      ewma: msText(figures.ewma_ms),
      p50: msText(figures.p50_ms),
      p99: msText(figures.p99_ms),
      answers: formatNumber(figures.window_answers),
    }),
    t("dns.upstream.counts", { answered: formatNumber(figures.answered), failed: formatNumber(figures.failed) }),
  ];
  if (figures.chosen) parts.push(t("dns.upstream.chosen_long"));
  if (figures.last_error) {
    parts.push(t("dns.upstream.last_error", { time: figures.last_error_at ? formatDateTime(figures.last_error_at) : "", error: figures.last_error }));
  }
  return parts.join(" ");
}

/** An upstream's state, time and choice in a row of the forwarders page. */
export function UpstreamBadge(props: { figures: UpstreamFigures }) {
  return (
    <span class="up-badge" data-testid="upstream-figures" data-state={props.figures.state} data-chosen={props.figures.chosen ? "true" : undefined} title={figuresTitle(props.figures)}>
      <span class={stateDot(props.figures.state)} aria-hidden="true" />
      <span class="sr-only">{t(`dns.upstream.state.${props.figures.state}`)}</span>
      <span class="mono" data-testid="upstream-rtt">
        {msText(shownRtt(props.figures))}
      </span>
      <Show when={props.figures.chosen}>
        <span class="tag accent" data-testid="upstream-chosen">
          {t("dns.upstream.chosen")}
        </span>
      </Show>
    </span>
  );
}
