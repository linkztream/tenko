// What the top bar and the status bar show: node and store status, running and waiting
// jobs, and the selection count of the current view. Views set the selection with
// setSelectionStatus(); the shell clears it on navigation.
import { createRoot, createSignal, onCleanup } from "solid-js";
import { api } from "../api/client";
import { events } from "../api/events";
import type { JobState, SystemStatus } from "../api/types";

export interface SelectionStatus {
  selected: number;
  total: number;
}

const [selection, setSelection] = createSignal<SelectionStatus | null>(null);

/** The selection count shown in the status bar, or null for none. */
export { selection };

export function setSelectionStatus(value: SelectionStatus | null): void {
  setSelection(value);
}

export interface JobCounts {
  running: number;
  waiting: number;
}

const ACTIVE: readonly JobState[] = ["running", "waiting"];

/**
 * Polls GET /system/status every 30 s and refetches job counts on `jobs` events while a
 * component that called it is mounted. Returns accessors; null means unknown.
 */
export function createShellStatus() {
  const [system, setSystem] = createSignal<SystemStatus | null>(null);
  const [systemError, setSystemError] = createSignal(false);
  const [jobs, setJobs] = createSignal<JobCounts | null>(null);

  const loadSystem = async () => {
    try {
      setSystem(await api.get("/api/v1/system/status"));
      setSystemError(false);
    } catch {
      setSystemError(true);
    }
  };

  let jobTimer: ReturnType<typeof setTimeout> | undefined;
  const loadJobs = async () => {
    try {
      const page = await api.get("/api/v1/jobs", { query: { state: ACTIVE, limit: 1000 } });
      const counts: JobCounts = { running: 0, waiting: 0 };
      for (const job of page.items) {
        if (job.state === "running") counts.running += 1;
        else if (job.state === "waiting") counts.waiting += 1;
      }
      setJobs(counts);
    } catch {
      setJobs(null);
    }
  };

  void loadSystem();
  void loadJobs();
  const interval = setInterval(() => void loadSystem(), 30_000);
  const offJobs = events.subscribe("jobs", () => {
    clearTimeout(jobTimer);
    jobTimer = setTimeout(() => void loadJobs(), 250);
  });
  const offReset = events.onReset("jobs", () => void loadJobs());
  const offSystem = events.subscribe("system", () => void loadSystem());

  onCleanup(() => {
    clearInterval(interval);
    clearTimeout(jobTimer);
    offJobs();
    offReset();
    offSystem();
  });

  return { system, systemError, jobs };
}

/** A clock that ticks every second, for "last event 4 seconds ago". */
export const now = createRoot(() => {
  const [value, setValue] = createSignal(Date.now());
  if (typeof window !== "undefined") setInterval(() => setValue(Date.now()), 1000);
  return value;
});
