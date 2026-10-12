// Polling while a scan is under way: a scan ends on the probes, so the controllers learn of its
// progress by asking, and the `discovery` topic only announces the end. The live query of the
// page is refetched on this clock for as long as a scan is not terminal.
import { createEffect, createMemo, onCleanup } from "solid-js";

/** How often a running scan is read again. */
export const POLL_MS = 2000;

/** Calls `refresh` every `POLL_MS` while `active()` is true; must run inside a component. */
export function pollWhile(active: () => boolean, refresh: () => void): void {
  const on = createMemo(active);
  createEffect(() => {
    if (!on()) return;
    const timer = setInterval(refresh, POLL_MS);
    onCleanup(() => clearInterval(timer));
  });
}
