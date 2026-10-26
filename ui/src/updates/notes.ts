// Where the public release notes of a version are. The manifest carries the notes as text and no
// address, so the page builds the address of the release page from the release source the
// installation is configured with: a source on a code host reads
// `<repository>/releases/latest/download/releases.json` (or `.../releases/download/<tag>/...`),
// and the page of a release is `<repository>/releases/tag/v<version>`. Nothing is built for a
// source of another shape (a mirror, a test server), for a source that is not `https`, and
// while the check is off with no manifest loaded.
import type { UpdateStatus } from "./api";

const SOURCE_PATH = /^(\/.+?)\/releases\/(?:latest\/download|download\/[^/]+)\/[^/]+$/;

/** The repository address behind a release source (no trailing slash), or null. */
export function repositoryOf(source: string): string | null {
  let url: URL;
  try {
    url = new URL(source);
  } catch {
    return null;
  }
  if (url.protocol !== "https:" || url.username !== "" || url.password !== "") return null;
  const match = SOURCE_PATH.exec(url.pathname);
  if (!match) return null;
  return `${url.origin}${match[1]}`;
}

/** The address of the release page of `version`, or null when there is nothing to link to. */
export function releaseNotesUrl(status: UpdateStatus, version: string): string | null {
  if (!status.check.enabled && !status.manifest) return null;
  const repository = repositoryOf(status.check.source);
  if (!repository) return null;
  return `${repository}/releases/tag/v${encodeURIComponent(version)}`;
}
