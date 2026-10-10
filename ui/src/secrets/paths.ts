// The paths of the secrets area. The shared table of links (src/app/paths.ts) belongs to the
// application shell; the secrets area keeps its own entries here until they are folded in.
import { seg } from "../app/paths";

/** The secrets page, a sub-page of Settings. */
export const SECRETS_PATH = "/settings/secrets";

/** Where the page lived before it moved under Settings; the old address redirects. */
export const LEGACY_SECRETS_PATH = "/secrets";

/** The secrets page, optionally with one secret open. */
export function secretsPath(id?: string): string {
  return id ? `${SECRETS_PATH}/${seg(id)}` : SECRETS_PATH;
}

/**
 * The new address for a path under the old one: "/secrets/<id>" becomes "/settings/secrets/<id>".
 * Anything that is not under the old address stays as it is.
 */
export function migratedSecretsPath(pathname: string): string {
  if (pathname === LEGACY_SECRETS_PATH || pathname.startsWith(`${LEGACY_SECRETS_PATH}/`)) {
    return SECRETS_PATH + pathname.slice(LEGACY_SECRETS_PATH.length);
  }
  return pathname;
}
