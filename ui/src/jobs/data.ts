// What the jobs views read and change besides their lists: the detail of a job as the list
// rows and the group checklist need it, and the two actions a person has on a job.
//
// The list of jobs (JobSummary) knows the index and state of the current step but not what the
// step does, and a group checklist needs the manual tasks of every job of the group. Neither
// has a list endpoint yet (contract request: the current step's kind and the manual tasks on
// the summary), so the detail is read once per revision of a job and kept for the tab.
import { api } from "../api/client";
import type { JobDetail, JobSummary } from "../api/types";

interface Cached {
  signature: string;
  promise: Promise<JobDetail | null>;
}

const details = new Map<string, Cached>();

/** Forgets every detail read so far (tests; a reset of the event stream). */
export function resetJobDetails(): void {
  details.clear();
}

/**
 * The detail of a job as of the revision of its summary, or null when it cannot be read.
 * A newer revision reads again; the same revision reuses the answer.
 */
export function readJobDetail(job: Pick<JobSummary, "id" | "revision" | "state" | "steps_done">): Promise<JobDetail | null> {
  const signature = `${job.revision}:${job.state}:${job.steps_done}`;
  const hit = details.get(job.id);
  if (hit && hit.signature === signature) return hit.promise;
  const promise: Promise<JobDetail | null> = api.get("/api/v1/jobs/{id}", { path: { id: job.id } }).catch(() => {
    // A failed read is not kept, so the next render tries again.
    if (details.get(job.id)?.promise === promise) details.delete(job.id);
    return null;
  });
  details.set(job.id, { signature, promise });
  return promise;
}

/** Runs `fn` over `items` with at most `limit` calls in flight; results keep the order of the items. */
export async function mapLimit<T, R>(items: readonly T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out = new Array<R>(items.length);
  let next = 0;
  const worker = async () => {
    for (;;) {
      const i = next;
      next += 1;
      if (i >= items.length) return;
      out[i] = await fn(items[i] as T);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return out;
}

/** Marks the manual task of a step done. A blank note is not sent. */
export function completeStep(id: string, index: number, note: string): Promise<JobSummary> {
  const path = { id, index };
  if (note.trim() === "") return api.post("/api/v1/jobs/{id}/steps/{index}/complete", { path });
  return api.post("/api/v1/jobs/{id}/steps/{index}/complete", { path, body: { note } });
}

/** Asks to cancel a job. A queued job is cancelled at once; a running one rolls back. */
export function cancelJob(id: string): Promise<JobSummary> {
  return api.post("/api/v1/jobs/{id}/cancel", { path: { id } });
}
