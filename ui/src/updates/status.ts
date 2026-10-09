// The update status for the places that only show a notice (the status bar item and the
// dashboard card): one shared copy, read when the first of them appears, again on every
// `admin` event, and every six hours. An account that may not read it (403) or a server
// without an update service (503) leaves it empty, and the notice shows nothing.
import { createSignal, onCleanup, type Accessor } from "solid-js";
import { events } from "../api/events";
import { isAdmin } from "../auth/session";
import { isQuiet, readUpdates, type UpdateStatus } from "./api";

/** How often the status is read without any event. */
export const REFRESH_MS = 6 * 60 * 60 * 1000;
/** Waits this long after an event, so a burst of events reads once. */
const DEBOUNCE_MS = 250;

const [shared, setShared] = createSignal<UpdateStatus | null>(null);
let users = 0;
let stop: (() => void) | undefined;
let reload: (() => void) | undefined;

function start(): () => void {
  let controller: AbortController | undefined;
  let debounce: ReturnType<typeof setTimeout> | undefined;
  let alive = true;

  const load = async () => {
    if (!isAdmin()) {
      setShared(null);
      return;
    }
    controller?.abort();
    controller = new AbortController();
    try {
      const status = await readUpdates(controller.signal);
      if (alive) setShared(status);
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") return;
      // No right or no service: nothing to show. Any other failure keeps what is on screen.
      if (alive && isQuiet(err)) setShared(null);
    }
  };
  reload = () => void load();

  void load();
  const offAdmin = events.subscribe("admin", () => {
    clearTimeout(debounce);
    debounce = setTimeout(() => void load(), DEBOUNCE_MS);
  });
  const offReset = events.onReset("admin", () => void load());
  const interval = setInterval(() => void load(), REFRESH_MS);

  return () => {
    alive = false;
    controller?.abort();
    clearTimeout(debounce);
    clearInterval(interval);
    offAdmin();
    offReset();
    reload = undefined;
    setShared(null);
  };
}

/**
 * The shared update status for the calling component (null while unknown, unavailable or not
 * readable by this account). Must be called inside a component.
 */
export function useUpdateStatus(): Accessor<UpdateStatus | null> {
  if (users === 0) stop = start();
  users += 1;
  onCleanup(() => {
    users -= 1;
    if (users === 0) {
      stop?.();
      stop = undefined;
    }
  });
  return shared;
}

/** Reads the shared status again now (after the updates page checked or changed something). */
export function refreshUpdateStatus(): void {
  reload?.();
}
