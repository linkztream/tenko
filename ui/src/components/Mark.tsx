import { createUniqueId } from "solid-js";
import { MARK_HEAD, MARK_KNOCKOUT, MARK_TAILS, WORDMARK_DDI, WORDMARK_TENKO } from "./markPaths";

/**
 * The Tenko mark. One color (currentColor) everywhere; the two-tone variant, with the
 * tails in the accent, only on the sign-in page and in the first-run wizard (decision 15).
 * Decorative unless `label` is given.
 */
export function Mark(props: { duo?: boolean; class?: string; label?: string }) {
  const mask = `tenko-knock-${createUniqueId()}`;
  return (
    <svg
      class={props.class ?? "mark"}
      viewBox="0 2 48 48"
      role={props.label ? "img" : undefined}
      aria-label={props.label}
      aria-hidden={props.label ? undefined : "true"}
    >
      <defs>
        <mask id={mask} maskUnits="userSpaceOnUse" x="0" y="0" width="48" height="52">
          <rect width="48" height="52" fill="#fff" />
          <path d={MARK_KNOCKOUT} fill="#000" stroke="#000" stroke-width="3" stroke-linejoin="round" />
        </mask>
      </defs>
      <path mask={`url(#${mask})`} class={props.duo ? "mark-tails-duo" : undefined} fill="currentColor" d={MARK_TAILS} />
      <path fill="currentColor" fill-rule="evenodd" d={MARK_HEAD} />
    </svg>
  );
}

/** The wordmark "Tenko DDI" with exactly the letterforms of the 16 px header. */
export function Wordmark(props: { class?: string }) {
  return (
    <svg class={props.class ?? "wordmark"} viewBox="55 13 133 24" aria-hidden="true">
      <path fill="none" stroke="currentColor" stroke-width="3.6" stroke-linejoin="round" d={WORDMARK_TENKO} />
      <path
        fill="none"
        stroke="currentColor"
        stroke-width="2.6"
        stroke-linejoin="round"
        stroke-opacity="0.62"
        d={WORDMARK_DDI}
      />
    </svg>
  );
}
