// The paths of the secrets area. The shared table of links (src/app/paths.ts) belongs to the
// application shell; the secrets area keeps its own entries here until they are folded in.
import { seg } from "../app/paths";

export const SECRETS_PATH = "/secrets";

/** The secrets page, optionally with one secret open. */
export function secretsPath(id?: string): string {
  return id ? `${SECRETS_PATH}/${seg(id)}` : SECRETS_PATH;
}
