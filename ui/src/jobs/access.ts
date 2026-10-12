// What the signed-in account may do with jobs. Cancelling a job and marking a task done need the
// `execute` right on jobs, which the operator and administrator roles have, and, for a scoped
// operator, every target of the job inside its scope (docs/access.md section 10). A viewer reads
// jobs but sees the buttons disabled with the reason, instead of an error after the click.
import { may } from "../auth/gate";
import type { ObjectRef } from "../api/types";

/**
 * Whether the account may cancel a job or complete one of its tasks. The write filter of the
 * session holds the role check (a global administrator or operator may, a viewer or the auditor
 * may not, a scoped operator only with its grants); the targets decide the rest. Reactive.
 */
export function canExecuteJob(job: { id: string; targets: readonly ObjectRef[] }): boolean {
  return may.job(job);
}
