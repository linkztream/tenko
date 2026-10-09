// What the signed-in account may do with jobs. Cancelling a job and marking a task done need the
// `execute` right on jobs, which the operator and administrator roles have; a viewer reads jobs
// but sees the buttons disabled with the reason, instead of an error after the click.
import { hasRole } from "../auth/session";

export function canExecuteJobs(): boolean {
  return hasRole("admin") || hasRole("operator");
}
