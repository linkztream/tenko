// The clipboard path of a revealed secret (IAM-16, API-11): copy the value, then clear the
// clipboard after the time the server names, but only when it still holds the value (when the
// browser does not let the page read the clipboard, it is cleared regardless: a password
// left behind is worse than a lost clipboard entry). The clearing runs here, outside the
// dialog, so closing the dialog early does not keep the value on the clipboard.
//
// What this does not protect against: other applications, clipboard managers and synced
// clipboards can read the value while it is there; a page that is closed before the timer
// runs out cannot clear it. The audit record of the reveal is the control (docs/secrets.md).

export type CopyOutcome = "copied" | "blocked";
export type ClearOutcome = "cleared" | "left" | "failed";

interface Pending {
  value: string;
  timer: ReturnType<typeof setTimeout>;
  onDone: ((outcome: ClearOutcome) => void) | undefined;
}

let pending: Pending | undefined;

/** Writes `value` to the clipboard; "blocked" when the browser does not allow it now. */
export async function copyValue(value: string): Promise<CopyOutcome> {
  const clipboard = typeof navigator === "undefined" ? undefined : navigator.clipboard;
  if (!clipboard || typeof clipboard.writeText !== "function") return "blocked";
  try {
    await clipboard.writeText(value);
    return "copied";
  } catch {
    return "blocked";
  }
}

/**
 * Clears the clipboard after `seconds` if it still holds `value`. A later call replaces an
 * earlier one (the clipboard then holds the later value). `onDone` hears the outcome.
 */
export function scheduleClear(value: string, seconds: number, onDone?: (outcome: ClearOutcome) => void): void {
  if (pending) {
    clearTimeout(pending.timer);
    pending = undefined;
  }
  pending = {
    value,
    onDone,
    timer: setTimeout(() => void clearNow(), Math.max(0, seconds) * 1000),
  };
}

/** Whether a clearing is scheduled. */
export function clearPending(): boolean {
  return pending !== undefined;
}

/** Clears now what `scheduleClear` would clear later, and forgets the value. */
export async function clearNow(): Promise<ClearOutcome | undefined> {
  const job = pending;
  pending = undefined;
  if (!job) return undefined;
  clearTimeout(job.timer);
  const clipboard = typeof navigator === "undefined" ? undefined : navigator.clipboard;
  let outcome: ClearOutcome = "cleared";
  if (!clipboard || typeof clipboard.writeText !== "function") {
    outcome = "failed";
  } else {
    let holdsValue = true;
    try {
      if (typeof clipboard.readText === "function") holdsValue = (await clipboard.readText()) === job.value;
    } catch {
      // The page may not read the clipboard: clear it regardless.
    }
    if (!holdsValue) {
      outcome = "left";
    } else {
      try {
        await clipboard.writeText("");
      } catch {
        outcome = "failed";
      }
    }
  }
  job.onDone?.(outcome);
  return outcome;
}
