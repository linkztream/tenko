// The path of the updates page. The shared table of links (src/app/paths.ts) belongs to
// the application shell; the updates area keeps its own entry here until it is folded in.
import { safeNext } from "../app/paths";

export const UPDATES_PATH = "/updates";

/** Where "Sign in again" returns to after the fresh sign-in (only inside the application). */
export function updatesReturn(): string {
  return safeNext(UPDATES_PATH);
}
