// The live view of a DHCP list (WP7.5): follows the `dhcp` event topic and refreshes the visible
// page when a lease or history table changed, sampled by sampler.ts so a busy server costs one
// read per interval, not one per change. The toggle pauses it; turning it on reads once.
import { createSignal, onCleanup, Show, type Accessor } from "solid-js";
import { events as defaultStream, type ApiEvent, type EventStream } from "../../api/events";
import { t } from "../../i18n";
import { arrive, initialSampler, refreshed, SAMPLER, settle } from "./sampler";

/** The tables of the lease service an event names. */
export const LEASE_TABLE = "dhcp.leases";
export const HISTORY_TABLE = "dhcp.history";

/** Whether an event touches `table`: an event that names its tables is matched; one that names none counts. */
export function touches(event: ApiEvent, table: string): boolean {
  if (event.data.kind === "truncated") return true;
  const tables = event.data.tables;
  return Array.isArray(tables) ? tables.includes(table) : true;
}

export interface LiveRefresh {
  /** Whether the view follows the events. */
  live: Accessor<boolean>;
  setLive: (on: boolean) => void;
  /** The changes of the last second the view folded instead of applying. */
  folded: Accessor<number>;
}

export interface LiveRefreshOptions {
  /** The table whose events matter. */
  table: string;
  /** Reads the visible page again. */
  refresh: () => void;
  /** The revision the page was read at: an event at or below it is in the page already. */
  revision?: () => number | undefined;
  stream?: EventStream;
}

/** Must be called inside a component or another reactive owner. */
export function createLiveRefresh(options: LiveRefreshOptions): LiveRefresh {
  const stream = options.stream ?? defaultStream;
  const [live, setLiveSignal] = createSignal(true);
  const [folded, setFolded] = createSignal(0);
  let state = initialSampler();
  let timer: ReturnType<typeof setTimeout> | undefined;
  let settleTimer: ReturnType<typeof setTimeout> | undefined;

  const run = () => {
    timer = undefined;
    state = refreshed(state, Date.now());
    setFolded(state.folded);
    options.refresh();
    clearTimeout(settleTimer);
    settleTimer = setTimeout(() => {
      state = settle(state, Date.now());
      setFolded(state.folded);
    }, SAMPLER.windowMs);
  };

  const stop = () => {
    clearTimeout(timer);
    clearTimeout(settleTimer);
    timer = undefined;
    state = initialSampler();
    setFolded(0);
  };

  // eslint-disable-next-line solid/reactivity -- an event callback, like an event handler
  const off = stream.subscribe("dhcp", (event) => {
    if (!live() || !touches(event, options.table)) return;
    const seen = options.revision?.();
    if (event.revision !== undefined && seen !== undefined && event.revision <= seen) return;
    const step = arrive(state, Date.now());
    state = step.state;
    setFolded(state.folded);
    if (step.delay !== null) timer = setTimeout(run, step.delay);
  });
  // eslint-disable-next-line solid/reactivity -- an event callback, like an event handler
  const offReset = stream.onReset("dhcp", () => {
    if (live()) options.refresh();
  });
  onCleanup(() => {
    off();
    offReset();
    stop();
  });

  const setLive = (on: boolean) => {
    if (on === live()) return;
    setLiveSignal(on);
    if (on) options.refresh();
    else stop();
  };
  return { live, setLive, folded };
}

/** The "Live" toggle and the count of the changes folded; `testid` prefixes both test ids. */
export function LiveControls(props: { live: LiveRefresh; testid: string }) {
  return (
    <>
      <label class="choice dhcp-live" title={t("dhcp.live.hint")}>
        <input
          type="checkbox"
          checked={props.live.live()}
          data-testid={`${props.testid}-live`}
          onChange={(e) => props.live.setLive(e.currentTarget.checked)}
        />{" "}
        <span>{t("dhcp.live.label")}</span>
      </label>
      <span class="muted dhcp-folded" role="status" data-testid={`${props.testid}-folded`} data-count={props.live.folded()}>
        <Show when={props.live.folded() > 0}>{t("dhcp.live.folded", { count: props.live.folded() })}</Show>
      </span>
    </>
  );
}
