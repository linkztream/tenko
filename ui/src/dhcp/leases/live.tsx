// The live view of a DHCP list (WP7.5): follows the `dhcp` event topic and refreshes the visible
// page when a lease or history table changed, sampled by sampler.ts so a busy server costs one
// read per interval, not one per change. The toggle pauses it; turning it on reads once.
//
// A page states the revision its rows are complete at. An event at or below it is in the page; a
// newer one is not yet, and that holds for a page read after the event too: the server announces
// a lease change when the store commits it, and the DHCP role's table, which the lease list reads,
// takes it a moment later. So the view keeps the newest change it has an event for and reads
// again, sampled and with a growing pause, until a page reaches it.
import { createSignal, onCleanup, Show, type Accessor } from "solid-js";
import { events as defaultStream, type ApiEvent, type EventStream } from "../../api/events";
import { t } from "../../i18n";
import { arrive, initialSampler, refreshed, SAMPLER, settle } from "./sampler";

/** The longest pause between two reads of a page that is still older than a change seen. */
const BEHIND_MAX_MS = 5_000;
/**
 * The reads again for one change, at most: about 16 seconds of pauses. A table that does not
 * reach the change by then (a role whose feed failed and reads its rows again) is read again at
 * the next change, not every few seconds while the page is open; each read is a recorded command.
 */
const BEHIND_READS = 8;

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
  /** Reads the visible page again; resolves once the page is in. */
  refresh: () => Promise<void> | void;
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
  let behindTimer: ReturnType<typeof setTimeout> | undefined;
  /** The newest change of the table this view has an event for and has not shown yet. */
  let wanted: number | undefined;
  /** The reads in a row that came back older than `wanted`. */
  let behind = 0;
  /** The reads started; only the last one's page is checked (a newer read replaces an older one). */
  let reads = 0;
  let disposed = false;

  /** `count` changes arrived (none for a read again): a sampled refresh is scheduled when none is. */
  const schedule = (count: number) => {
    const step = arrive(state, Date.now(), count);
    state = step.state;
    setFolded(state.folded);
    if (step.delay !== null) timer = setTimeout(run, step.delay);
  };

  /** After a read: a page older than the newest change seen is read again, a little later each time. */
  const check = () => {
    if (disposed || !live() || wanted === undefined) return;
    const seen = options.revision?.();
    if (seen === undefined || seen >= wanted) {
      clearTimeout(behindTimer);
      wanted = undefined;
      behind = 0;
      return;
    }
    if (behind >= BEHIND_READS) return;
    behind += 1;
    clearTimeout(behindTimer);
    behindTimer = setTimeout(() => schedule(0), Math.min(BEHIND_MAX_MS, SAMPLER.intervalMs * 2 ** (behind - 1)));
  };

  /** Reads the page; once the last read started is in, checks it against the newest change seen. */
  const read = () => {
    reads += 1;
    const id = reads;
    void Promise.resolve(options.refresh()).then(() => {
      if (id === reads) check();
    });
  };

  const run = () => {
    timer = undefined;
    state = refreshed(state, Date.now());
    setFolded(state.folded);
    read();
    clearTimeout(settleTimer);
    settleTimer = setTimeout(() => {
      state = settle(state, Date.now());
      setFolded(state.folded);
    }, SAMPLER.windowMs);
  };

  const stop = () => {
    clearTimeout(timer);
    clearTimeout(settleTimer);
    clearTimeout(behindTimer);
    timer = undefined;
    wanted = undefined;
    behind = 0;
    state = initialSampler();
    setFolded(0);
  };

  const off = stream.subscribe(
    "dhcp",
    // eslint-disable-next-line solid/reactivity -- an event callback, like an event handler
    (event) => {
      if (!live() || !touches(event, options.table)) return;
      if (event.revision !== undefined) {
        wanted = Math.max(wanted ?? 0, event.revision);
        // A new change starts the reads again from the shortest pause.
        behind = 0;
      }
      schedule(1);
    },
    options.revision,
  );
  // eslint-disable-next-line solid/reactivity -- an event callback, like an event handler
  const offReset = stream.onReset("dhcp", () => {
    if (live()) read();
  });
  onCleanup(() => {
    disposed = true;
    off();
    offReset();
    stop();
  });

  const setLive = (on: boolean) => {
    if (on === live()) return;
    setLiveSignal(on);
    if (on) read();
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
