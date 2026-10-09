// Waiting for the server to come back after the switch to a new version: the public health
// probe is asked every two seconds until it names the version that was installed, or until
// the new version had its time to become ready (and a minute more) and did not.

/** Time between two probes. */
export const PROBE_INTERVAL_MS = 2000;
/** The wait after the server's own limit for the new version to become ready. */
export const GRACE_SECS = 60;

/** How long to wait for the new version before giving up, from the server's ready timeout. */
export function restartTimeoutMs(readyTimeoutSecs: number): number {
  return (Math.max(0, readyTimeoutSecs) + GRACE_SECS) * 1000;
}

export interface RestartWatchOptions {
  /** The version that must answer. */
  target: string;
  /** Asks the health probe for its version; a rejected promise counts as no answer. */
  probe: () => Promise<string>;
  timeoutMs: number;
  onReady: () => void;
  onTimeout: () => void;
  intervalMs?: number;
}

/** Starts the watch; the returned function stops it. */
export function watchRestart(options: RestartWatchOptions): () => void {
  const interval = options.intervalMs ?? PROBE_INTERVAL_MS;
  const started = Date.now();
  let stopped = false;
  let timer: ReturnType<typeof setTimeout> | undefined;

  const tick = async () => {
    let version: string | undefined;
    try {
      version = await options.probe();
    } catch {
      version = undefined;
    }
    if (stopped) return;
    if (version === options.target) {
      stopped = true;
      options.onReady();
      return;
    }
    if (Date.now() - started >= options.timeoutMs) {
      stopped = true;
      options.onTimeout();
      return;
    }
    timer = setTimeout(() => void tick(), interval);
  };

  timer = setTimeout(() => void tick(), interval);
  return () => {
    stopped = true;
    clearTimeout(timer);
  };
}

/** What the page does to itself; a test replaces `reload`. */
export const pageActions = {
  reload: (): void => window.location.reload(),
};
