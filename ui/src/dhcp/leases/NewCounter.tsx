// "New since you opened the page" (WP8.6): the number of leases granted since `since`, read from
// the history (one page of 1,000 grants at most, "1,000+" beyond that) and read again whenever the
// page reads its list again. It keeps its start time when the filters change (the scope filter
// narrows it), "Reset" moves the start to now, the Live toggle pauses it, and a history the
// principal may not read, or a server without one, hides it.
import { A } from "@solidjs/router";
import { createEffect, createSignal, on, onCleanup, Show, untrack, type Accessor } from "solid-js";
import { formatDateTime, formatNumber, t } from "../../i18n";
import { grantedSince } from "./api";
import { countOf, hidesCounter, newHref, type NewCount } from "./overview";

const SINCE: Intl.DateTimeFormatOptions = { dateStyle: "short", timeStyle: "medium" };

export function NewCounter(props: {
  /** When the counting started: RFC 3339. */
  since: string;
  /** The prefix of the scope filter, or the empty string. */
  scope: string;
  /** Changes whenever the page reads its list again. */
  version: Accessor<number>;
  /** Whether the Live toggle is on. */
  live: Accessor<boolean>;
  onReset: () => void;
}) {
  const [result, setResult] = createSignal<NewCount | undefined>();
  const [hidden, setHidden] = createSignal(false);
  let run = 0;
  let pending: AbortController | undefined;
  onCleanup(() => pending?.abort());

  let key = "";
  createEffect(
    on([() => props.since, () => props.scope, () => props.version()],([since, scope]) => {
      // Another start or scope is another count; a read of the same one only refreshes it.
      if (`${since}|${scope}` !== key) {
        key = `${since}|${scope}`;
        setResult(undefined);
      }
      if (hidden() || !untrack(props.live)) return;
      pending?.abort();
      const control = new AbortController();
      pending = control;
      const mine = ++run;
      grantedSince(since, scope, control.signal).then(
        (page) => {
          if (mine === run) setResult(countOf(page));
        },
        (err: unknown) => {
          if (mine === run && hidesCounter(err)) setHidden(true);
        },
      );
    }),
  );

  const state = () => (!props.live() ? "paused" : result()?.capped ? "capped" : "live");
  const text = () => {
    const found = result();
    if (state() === "paused") return t("dhcp.live.new_paused");
    if (found === undefined) return "…";
    return found.capped ? t("dhcp.live.new_capped", { count: formatNumber(found.count) }) : t("dhcp.live.new", { count: found.count });
  };

  return (
    <Show when={!hidden()}>
      <span class="dhcp-new" role="group" aria-label={t("dhcp.live.new_label")}>
        <span
          class="dhcp-fact"
          classList={{ muted: state() === "paused" }}
          role="status"
          title={t("dhcp.live.new_since", { time: formatDateTime(props.since, SINCE) })}
          data-testid="leases-new"
          data-count={String(result()?.count ?? 0)}
          data-state={state()}
        >
          {text()}
        </span>
        <A class="dhcp-fact" href={newHref(props.since, props.scope)} data-testid="leases-new-link">
          {t("dhcp.live.new_link")}
        </A>
        <button type="button" class="btn sm" title={t("dhcp.live.new_reset_hint")} data-testid="leases-new-reset" onClick={() => props.onReset()}>
          {t("dhcp.live.new_reset")}
        </button>
      </span>
    </Show>
  );
}
