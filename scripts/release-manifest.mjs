// Builds the release manifest `releases.json` that running installations read to learn
// about updates, and the `SHA256SUMS` file that goes with the release assets.
//
//   node scripts/release-manifest.mjs --version 0.2.0 --assets dist \
//     --base-url https://github.com/linkztream/tenko/releases/download/v0.2.0 \
//     [--changelog CHANGELOG.md] [--previous releases.json \
//     --verify-previous https://github.com/linkztream/tenko/releases/download] \
//     [--image ghcr.io/linkztream/tenko:0.2.0] [--format 1] [--out releases.json]
//
// The release text comes from the section `## [0.2.0] - <date>` of the changelog (the
// Unreleased section is never released). Every file in --assets named
// `tenko-<version>-<platform>` or `tenko-<version>-<platform>.exe` becomes an asset with its
// SHA-256 and size; other files are ignored with a note. The releases of --previous are kept
// (an entry for the same version is replaced), newest first. Node's standard library only.
//
// The previous manifest is a release asset that whoever can write the releases can rewrite,
// so nothing in it is taken on trust: before an earlier release is kept, its files and their
// digests are checked against the SHA256SUMS of that release, fetched from
// `<--verify-previous>/v<version>/SHA256SUMS` (the release's own asset, by tag; never from a
// URL the entry names). An entry that does not match, or whose release has no SHA256SUMS, is
// dropped with a warning; a fetch that fails otherwise stops the run. SHA256SUMS lists the
// manifest itself, computed from the final text, so that what is attested and signed covers
// the manifest too (formatReleaseFiles).
//
// WP6.7: installer packages. A file named `tenko-<version>-<platform>.<ext>`, where <ext> is a
// key of INSTALLER_KINDS (today `msi`), becomes an entry of the release's `installers` with
// the same fields as an asset plus `kind`, and a line of SHA256SUMS. Installers are not
// assets: an installation that updates itself downloads the binary of its platform from
// `assets` and never an installer, and readers of schema 1 ignore the unknown key. A release
// without installers has no `installers` key.
//
// Manifest schema 1:
//   { "schema": 1, "project": "tenko", "releases": [ { "version", "date", "notes", "security",
//     "requires_action", "action"?, "format"?, "image"?, "assets": [ { "platform", "name",
//     "url", "sha256", "size" } ], "installers"?: [ { "kind", "platform", "name", "url",
//     "sha256", "size" } ] } ] }
//
// Exit codes: 0 success, 1 the inputs are wrong (no such changelog section, no assets, ...),
// 2 bad command line.

import { createHash } from "node:crypto";
import { createReadStream, readFileSync } from "node:fs";
import { mkdir, readdir, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import { parseArgs } from "node:util";

import { ChangelogError, compareVersions, isMainModule, isSemver, parseChangelog } from "./changelog.mjs";

/** The schema number of the manifest. */
export const SCHEMA = 1;
/** The project name in the manifest. */
export const PROJECT = "tenko";
/** A manifest with more releases than this is refused. */
export const MAX_RELEASES = 1000;

/**
 * The bounds an installation applies to a release's texts when it reads the manifest
 * (`crates/tenko-api/src/dto/release.rs`: MAX_NOTES_BYTES and MAX_ACTION_BYTES). A longer text
 * makes the whole manifest invalid for every installation, so the generator cuts the text at
 * a line boundary and says where the rest is.
 */
export const MAX_NOTES_BYTES = 64 * 1024;
export const MAX_ACTION_BYTES = 16 * 1024;
const CUT_MARK = "\n\n(The notes continue in CHANGELOG.md of the repository.)";

/**
 * Returns `text` unchanged when it fits in `maxBytes` (UTF-8), else the longest prefix that
 * ends at a line boundary and still fits together with the cut mark.
 *
 * @param {string} text
 * @param {number} maxBytes
 * @returns {string}
 */
export function boundText(text, maxBytes) {
  if (Buffer.byteLength(text, "utf8") <= maxBytes) return text;
  const room = maxBytes - Buffer.byteLength(CUT_MARK, "utf8");
  let cut = Buffer.from(text, "utf8").subarray(0, room).toString("utf8");
  if (cut.endsWith("�")) cut = cut.slice(0, -1);
  const lastLine = cut.lastIndexOf("\n");
  if (lastLine > 0) cut = cut.slice(0, lastLine);
  return cut.trimEnd() + CUT_MARK;
}

/** The inputs are wrong; the message says how. */
export class ManifestError extends Error {
  /** @param {string} message */
  constructor(message) {
    super(message);
    this.name = "ManifestError";
  }
}

const PLATFORM = /^[a-z][a-z0-9]*-[a-z0-9][a-z0-9_]*$/;

/**
 * The platform of a release asset, or null when the file is not an asset of this version.
 * A name is `tenko-<version>-<platform>` or `tenko-<version>-<platform>.exe`, where a
 * platform is `<os>-<arch>` such as `linux-x86_64`, `linux-aarch64` or `windows-x86_64`.
 *
 * @param {string} name file name
 * @param {string} version
 * @returns {string | null}
 */
export function assetPlatform(name, version) {
  const prefix = `tenko-${version}-`;
  if (!name.startsWith(prefix)) return null;
  let rest = name.slice(prefix.length);
  if (rest.endsWith(".exe")) rest = rest.slice(0, -".exe".length);
  return PLATFORM.test(rest) ? rest : null;
}

// WP6.7: installer packages ------------------------------------------------------------

/** The installer kinds by file extension (without the dot). */
export const INSTALLER_KINDS = new Map([["msi", "msi"]]);

/**
 * The kind and platform of an installer package of this version, or null when the file is
 * not one. A name is `tenko-<version>-<platform>.<ext>` with <ext> a key of INSTALLER_KINDS,
 * for example `tenko-0.2.0-windows-x86_64.msi`.
 *
 * @param {string} name file name
 * @param {string} version
 * @returns {{ kind: string, platform: string } | null}
 */
export function installerOf(name, version) {
  const prefix = `tenko-${version}-`;
  if (!name.startsWith(prefix)) return null;
  const rest = name.slice(prefix.length);
  const dot = rest.lastIndexOf(".");
  if (dot < 0) return null;
  const kind = INSTALLER_KINDS.get(rest.slice(dot + 1));
  const platform = rest.slice(0, dot);
  return kind !== undefined && PLATFORM.test(platform) ? { kind, platform } : null;
}

// ---------------------------------------------------------------------------------------

/**
 * SHA-256 and size of a file, read as a stream.
 * @param {string} file
 * @returns {Promise<{ sha256: string, size: number }>}
 */
export function hashFile(file) {
  return new Promise((resolve, reject) => {
    const hash = createHash("sha256");
    let size = 0;
    const stream = createReadStream(file);
    stream.on("data", (chunk) => {
      hash.update(chunk);
      size += chunk.length;
    });
    stream.on("error", reject);
    stream.on("end", () => resolve({ sha256: hash.digest("hex"), size }));
  });
}

/**
 * `<base-url>/<name>` with exactly one slash between.
 * @param {string} baseUrl
 * @param {string} name
 * @returns {string}
 */
export function assetUrl(baseUrl, name) {
  return `${baseUrl.replace(/\/+$/, "")}/${name}`;
}

/**
 * @typedef {object} Asset
 * @property {string} platform
 * @property {string} name
 * @property {string} url
 * @property {string} sha256 64 lowercase hexadecimal digits
 * @property {number} size bytes
 */

/**
 * @typedef {object} Release
 * @property {string} version
 * @property {string} date
 * @property {string} notes
 * @property {boolean} security
 * @property {boolean} requires_action
 * @property {string} [action]
 * @property {number} [format]
 * @property {string} [image]
 * @property {Asset[]} assets
 * @property {Installer[]} [installers] WP6.7: installer packages, absent when there are none
 */

/**
 * @typedef {object} Installer WP6.7: an installer package; the fields of an asset plus its kind
 * @property {string} kind for example `msi`
 * @property {string} platform
 * @property {string} name
 * @property {string} url
 * @property {string} sha256
 * @property {number} size
 */

/**
 * Builds the manifest entry of one release from the changelog and the files of `assetsDir`.
 *
 * @param {object} input
 * @param {string} input.version SemVer, without a leading `v`
 * @param {string} input.changelogText the text of CHANGELOG.md
 * @param {string} input.assetsDir directory with the release binaries
 * @param {string} input.baseUrl where the assets will be downloadable from
 * @param {string} [input.image] container image reference
 * @param {number} [input.format] data-directory format number of the binaries
 * @returns {Promise<{ release: Release, ignored: string[] }>} `ignored` lists the other files
 * @throws {ManifestError | ChangelogError}
 */
export async function buildRelease({ version, changelogText, assetsDir, baseUrl, image, format }) {
  if (!isSemver(version)) {
    throw new ManifestError(`--version ${JSON.stringify(version)} is not a semantic version (write 0.2.0, without a leading v)`);
  }
  let base;
  try {
    base = new URL(baseUrl);
  } catch {
    base = null;
  }
  if (base === null || (base.protocol !== "https:" && base.protocol !== "http:")) {
    throw new ManifestError(`--base-url ${JSON.stringify(baseUrl)} is not an http(s) URL`);
  }
  if (format !== undefined && (!Number.isSafeInteger(format) || format < 1)) {
    throw new ManifestError(`--format must be a positive integer, got ${JSON.stringify(format)}`);
  }
  if (image !== undefined && image === "") throw new ManifestError("--image must not be empty");

  const section = parseChangelog(changelogText).sections.find((s) => s.version === version);
  if (section === undefined) {
    throw new ManifestError(
      `the changelog has no section "## [${version}] - YYYY-MM-DD"; the Unreleased section is never released, so move its entries under the new version first`,
    );
  }

  const entries = (await readdir(assetsDir, { withFileTypes: true })).sort((a, b) =>
    a.name < b.name ? -1 : a.name > b.name ? 1 : 0,
  );
  /** @type {Asset[]} */
  const assets = [];
  /** @type {string[]} */
  const ignored = [];
  /** @type {Installer[]} */
  const installers = [];
  for (const entry of entries) {
    const platform = entry.isFile() ? assetPlatform(entry.name, version) : null;
    // WP6.7: installer packages.
    const installer = entry.isFile() && platform === null ? installerOf(entry.name, version) : null;
    if (installer !== null) {
      const { sha256, size } = await hashFile(path.join(assetsDir, entry.name));
      installers.push({ ...installer, name: entry.name, url: assetUrl(baseUrl, entry.name), sha256, size });
      continue;
    }
    if (platform === null) {
      ignored.push(entry.name);
      continue;
    }
    const clash = assets.find((a) => a.platform === platform);
    if (clash !== undefined) {
      throw new ManifestError(`two assets for platform ${platform}: ${clash.name} and ${entry.name}`);
    }
    const { sha256, size } = await hashFile(path.join(assetsDir, entry.name));
    assets.push({ platform, name: entry.name, url: assetUrl(baseUrl, entry.name), sha256, size });
  }
  if (assets.length === 0) {
    throw new ManifestError(
      `no release asset for version ${version} in ${assetsDir} (expected files named tenko-${version}-<os>-<arch>[.exe]; found ${entries.length === 0 ? "no files" : entries.map((e) => e.name).join(", ")})`,
    );
  }
  assets.sort((a, b) => (a.platform < b.platform ? -1 : a.platform > b.platform ? 1 : 0));

  /** @type {Release} */
  const release = {
    version,
    date: /** @type {string} */ (section.date),
    notes: boundText(section.body, MAX_NOTES_BYTES),
    security: section.security,
    requires_action: section.requiresAction,
    ...(section.requiresAction ? { action: boundText(section.action, MAX_ACTION_BYTES) } : {}),
    ...(format === undefined ? {} : { format }),
    ...(image === undefined ? {} : { image }),
    assets,
    // WP6.7: installer packages, sorted by name like SHA256SUMS.
    ...(installers.length === 0 ? {} : { installers }),
  };
  return { release, ignored };
}

/**
 * Merges a release into the manifest read from --previous (or none): every earlier release
 * is kept except an entry for the same version, which is replaced; newest first. The inputs
 * are not modified.
 *
 * @param {{ schema?: unknown, project?: unknown, releases?: unknown } | null | undefined} previous
 * @param {Release} release
 * @returns {{ schema: number, project: string, releases: Release[] }}
 * @throws {ManifestError}
 */
export function mergeManifest(previous, release) {
  /** @type {Release[]} */
  let kept = [];
  if (previous !== null && previous !== undefined) {
    if (typeof previous !== "object" || previous.schema !== SCHEMA || previous.project !== PROJECT || !Array.isArray(previous.releases)) {
      throw new ManifestError(`the previous manifest is not a schema ${SCHEMA} manifest of project ${PROJECT}`);
    }
    for (const r of previous.releases) {
      if (r === null || typeof r !== "object" || typeof r.version !== "string" || !isSemver(r.version)) {
        throw new ManifestError(`the previous manifest has a release without a valid version: ${JSON.stringify(r)}`);
      }
      if (r.version !== release.version) kept.push(r);
    }
  }
  kept = [...kept, release];
  if (kept.length > MAX_RELEASES) {
    throw new ManifestError(`the manifest would hold ${kept.length} releases; the limit is ${MAX_RELEASES}`);
  }
  kept.sort((a, b) => {
    const c = compareVersions(b.version, a.version); // newest first
    if (c !== 0) return c;
    return a.version < b.version ? 1 : a.version > b.version ? -1 : 0; // same precedence: build metadata, descending
  });
  return { schema: SCHEMA, project: PROJECT, releases: kept };
}

/**
 * The manifest as written to disk: pretty JSON with a trailing newline.
 * @param {unknown} manifest
 * @returns {string}
 */
export function formatManifest(manifest) {
  return `${JSON.stringify(manifest, null, 2)}\n`;
}

/**
 * The checksum file of a release in the `sha256sum` format, `<hex>  <name>` per line.
 * @param {Release} release
 * @returns {string}
 */
export function formatChecksums(release) {
  // WP6.7: the installer packages are listed with the binaries.
  return [...release.assets, ...(release.installers ?? [])]
    .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))
    .map((a) => `${a.sha256}  ${a.name}\n`)
    .join("");
}

/**
 * The two files of a release as written to disk: the manifest, and the checksum file that
 * lists the release's assets and installers and the manifest itself. The manifest's line is
 * the digest of the text returned here, so the manifest must be final (merged, sorted) before
 * this is called, and the text must be written unchanged; the names are sorted as in
 * formatChecksums, so the workflow's later lines (installers, SBOMs) sort in the same way.
 *
 * @param {{ schema: number, project: string, releases: Release[] }} manifest the final manifest
 * @param {Release} release the release being made, whose files are listed
 * @param {string} [manifestName] the file name of the manifest in the checksum file
 * @returns {{ manifest: string, checksums: string }}
 */
export function formatReleaseFiles(manifest, release, manifestName = "releases.json") {
  const text = formatManifest(manifest);
  const digest = createHash("sha256").update(text, "utf8").digest("hex");
  const lines = [...release.assets, ...(release.installers ?? [])].map((a) => ({ name: a.name, sha256: a.sha256 }));
  lines.push({ name: manifestName, sha256: digest });
  lines.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  return { manifest: text, checksums: lines.map((a) => `${a.sha256}  ${a.name}\n`).join("") };
}

/**
 * The names and digests of a SHA256SUMS file in the `sha256sum` format (`<hex>  <name>`, or
 * `<hex> *<name>` for binary mode). Lines of another shape are ignored; the digests are
 * returned in lowercase.
 *
 * @param {string} text
 * @returns {Map<string, string>} name to digest
 */
export function parseChecksums(text) {
  /** @type {Map<string, string>} */
  const sums = new Map();
  for (const line of text.split("\n")) {
    const m = /^([0-9A-Fa-f]{64}) [ *](.+)$/.exec(line.replace(/\r$/, ""));
    if (m !== null) sums.set(/** @type {string} */ (m[2]), /** @type {string} */ (m[1]).toLowerCase());
  }
  return sums;
}

/**
 * The check of a previous manifest's releases against the SHA256SUMS each of them published.
 * The input is validated as mergeManifest validates it and is not modified; the result holds
 * copies of the entries that passed, unchanged, and the version and reason of each entry that
 * was dropped. An entry passes when every asset and installer names a file under the
 * release's own download directory, `<downloadUrl>/v<version>/`, and that release's
 * SHA256SUMS, fetched from the same directory, lists the file with the same digest.
 *
 * Dropped: a digest or a name the release's SHA256SUMS does not have, a URL elsewhere, an
 * entry without a file to check, a release without SHA256SUMS (404). Thrown, so that the run
 * stops: any other failure to fetch, which says nothing about the entry.
 *
 * @param {{ schema?: unknown, project?: unknown, releases?: unknown } | null | undefined} previous
 * @param {object} options
 * @param {string} options.downloadUrl the download directory of the releases, without the tag
 * @param {(url: string) => Promise<{ status: number, text: string }>} options.fetchText
 * @param {string} [options.skipVersion] the version being released, whose entry is replaced
 * @returns {Promise<{ previous: { schema: number, project: string, releases: Release[] }, dropped: { version: string, reason: string }[] }>}
 * @throws {ManifestError}
 */
export async function verifyPreviousReleases(previous, { downloadUrl, fetchText, skipVersion }) {
  if (previous === null || previous === undefined || typeof previous !== "object" || previous.schema !== SCHEMA || previous.project !== PROJECT || !Array.isArray(previous.releases)) {
    throw new ManifestError(`the previous manifest is not a schema ${SCHEMA} manifest of project ${PROJECT}`);
  }
  const base = downloadUrl.replace(/\/+$/, "");
  /** @type {Release[]} */
  const kept = [];
  /** @type {{ version: string, reason: string }[]} */
  const dropped = [];
  for (const r of previous.releases) {
    if (r === null || typeof r !== "object" || typeof r.version !== "string" || !isSemver(r.version)) {
      throw new ManifestError(`the previous manifest has a release without a valid version: ${JSON.stringify(r)}`);
    }
    if (r.version === skipVersion) {
      kept.push(structuredClone(r));
      continue;
    }
    const reason = await checkRelease(r, `${base}/v${r.version}/`, fetchText);
    if (reason === null) kept.push(structuredClone(r));
    else dropped.push({ version: r.version, reason });
  }
  return { previous: { schema: SCHEMA, project: PROJECT, releases: kept }, dropped };
}

/**
 * Why one earlier release is dropped, or null when it passes (verifyPreviousReleases).
 * @param {Release} r
 * @param {string} dir the release's download directory, with a trailing slash
 * @param {(url: string) => Promise<{ status: number, text: string }>} fetchText
 * @returns {Promise<string | null>}
 */
async function checkRelease(r, dir, fetchText) {
  const files = [...(Array.isArray(r.assets) ? r.assets : []), ...(Array.isArray(r.installers) ? r.installers : [])];
  if (files.length === 0) return "it lists no file to check";
  for (const f of files) {
    if (f === null || typeof f !== "object" || typeof f.name !== "string" || typeof f.sha256 !== "string" || typeof f.url !== "string") {
      return `it has a file entry without a name, url and sha256: ${JSON.stringify(f)}`;
    }
    if (f.url !== `${dir}${f.name}`) return `${f.name} points at ${f.url}, not at the release's own download directory ${dir}`;
  }
  const url = `${dir}SHA256SUMS`;
  let response;
  try {
    response = await fetchText(url);
  } catch (error) {
    throw new ManifestError(`cannot fetch ${url}: ${/** @type {Error} */ (error).message}`);
  }
  if (response.status === 404) return `its release has no SHA256SUMS (${url} answered 404)`;
  if (response.status !== 200) throw new ManifestError(`cannot fetch ${url}: HTTP status ${response.status}`);
  const sums = parseChecksums(response.text);
  for (const f of files) {
    const published = sums.get(f.name);
    if (published === undefined) return `${f.name} is not listed in the SHA256SUMS of its release`;
    if (published !== f.sha256.toLowerCase()) return `${f.name} has the digest ${f.sha256} in the manifest, but its release published ${published}`;
  }
  return null;
}

/** The largest SHA256SUMS fetched for the check of an earlier release. */
const MAX_CHECKSUMS_BYTES = 1024 * 1024;

/**
 * Fetches a text with the global fetch, bounded in time and size (the default fetchText of
 * verifyPreviousReleases). Redirects are followed, as GitHub's release downloads redirect.
 * @param {string} url
 * @returns {Promise<{ status: number, text: string }>}
 */
async function fetchChecksums(url) {
  const response = await fetch(url, { signal: AbortSignal.timeout(30_000), redirect: "follow" });
  if (response.status !== 200) return { status: response.status, text: "" };
  const bytes = new Uint8Array(await response.arrayBuffer());
  if (bytes.byteLength > MAX_CHECKSUMS_BYTES) throw new Error(`${url} is larger than ${MAX_CHECKSUMS_BYTES} bytes`);
  return { status: 200, text: new TextDecoder().decode(bytes) };
}

// ---------------------------------------------------------------------------------------
// Command line

const USAGE = `Usage: node scripts/release-manifest.mjs --version <X.Y.Z> --assets <dir> --base-url <url> [options]

Options:
  --version <v>      the release, without a leading v (required)
  --assets <dir>     directory with the files tenko-<version>-<os>-<arch>[.exe] and the
                     installer packages tenko-<version>-<os>-<arch>.msi (required)
  --base-url <url>   where the assets are downloadable from; the URL of an asset is
                     <base-url>/<file name> (required)
  --changelog <file> the changelog (default CHANGELOG.md)
  --previous <file>  the releases.json of earlier releases, merged into the result after
                     each of them is checked with --verify-previous
  --verify-previous <url>
                     the download directory of the releases, without the tag (the earlier
                     release's SHA256SUMS is fetched from <url>/v<version>/SHA256SUMS);
                     required with --previous
  --image <ref>      container image of the release
  --format <n>       data-directory format number of the binaries
  --out <file>       the manifest to write (default releases.json); SHA256SUMS, which lists
                     it, goes next to it
  --help             print this text
`;

class UsageError extends Error {}

/**
 * Runs the command and returns the exit status.
 * @param {string[]} argv
 * @returns {Promise<number>}
 */
export async function main(argv) {
  /** @type {import("node:util").ParseArgsConfig["options"]} */
  const options = {
    version: { type: "string" },
    assets: { type: "string" },
    "base-url": { type: "string" },
    changelog: { type: "string" },
    previous: { type: "string" },
    "verify-previous": { type: "string" },
    image: { type: "string" },
    format: { type: "string" },
    out: { type: "string" },
    help: { type: "boolean", short: "h" },
  };
  try {
    let parsed;
    try {
      parsed = parseArgs({ args: argv, options, allowPositionals: true, strict: true });
    } catch (error) {
      throw new UsageError(/** @type {Error} */ (error).message);
    }
    const v = /** @type {Record<string, string | boolean | undefined>} */ (parsed.values);
    if (v.help) {
      process.stdout.write(USAGE);
      return 0;
    }
    if (parsed.positionals.length > 0) throw new UsageError(`unexpected argument ${JSON.stringify(parsed.positionals[0])}`);
    for (const required of ["version", "assets", "base-url"]) {
      if (typeof v[required] !== "string" || v[required] === "") throw new UsageError(`--${required} is required`);
    }
    let format;
    if (typeof v.format === "string") {
      if (!/^[1-9]\d*$/.test(v.format)) throw new UsageError(`--format must be a positive integer, got ${JSON.stringify(v.format)}`);
      format = Number(v.format);
    }
    if (typeof v.previous === "string") {
      if (typeof v["verify-previous"] !== "string" || v["verify-previous"] === "") throw new UsageError("--verify-previous is required with --previous");
      let url;
      try {
        url = new URL(v["verify-previous"]);
      } catch {
        url = null;
      }
      if (url === null || (url.protocol !== "https:" && url.protocol !== "http:")) {
        throw new UsageError(`--verify-previous ${JSON.stringify(v["verify-previous"])} is not an http(s) URL`);
      }
    }
    const changelogFile = /** @type {string} */ (v.changelog ?? "CHANGELOG.md");
    const outFile = /** @type {string} */ (v.out ?? "releases.json");

    const changelogText = readFileSync(changelogFile, "utf8");
    /** @type {unknown} */
    let previous = null;
    if (typeof v.previous === "string") {
      try {
        previous = JSON.parse(readFileSync(v.previous, "utf8"));
      } catch (error) {
        throw new ManifestError(`cannot read the previous manifest ${v.previous}: ${/** @type {Error} */ (error).message}`);
      }
    }

    const assetsDir = /** @type {string} */ (v.assets);
    if (!(await stat(assetsDir)).isDirectory()) throw new ManifestError(`${assetsDir} is not a directory`);

    const { release, ignored } = await buildRelease({
      version: /** @type {string} */ (v.version),
      changelogText,
      assetsDir,
      baseUrl: /** @type {string} */ (v["base-url"]),
      image: /** @type {string | undefined} */ (v.image),
      format,
    });
    /** @type {{ version: string, reason: string }[]} */
    let dropped = [];
    if (previous !== null) {
      const checked = await verifyPreviousReleases(/** @type {any} */ (previous), {
        downloadUrl: /** @type {string} */ (v["verify-previous"]),
        fetchText: fetchChecksums,
        skipVersion: release.version,
      });
      previous = checked.previous;
      dropped = checked.dropped;
    }
    for (const d of dropped) {
      process.stderr.write(`release-manifest: warning: dropped release ${d.version} from the manifest: ${d.reason}\n`);
      if (process.env.GITHUB_ACTIONS === "true") process.stdout.write(`::warning title=releases.json::dropped release ${d.version}: ${d.reason}\n`);
    }
    const manifest = mergeManifest(/** @type {any} */ (previous), release);

    // The manifest is final here; SHA256SUMS lists it by the digest of the text written.
    const files = formatReleaseFiles(manifest, release, path.basename(outFile));
    await mkdir(path.dirname(path.resolve(outFile)), { recursive: true });
    await writeFile(outFile, files.manifest);
    const sumsFile = path.join(path.dirname(outFile), "SHA256SUMS");
    await writeFile(sumsFile, files.checksums);

    for (const name of ignored) process.stdout.write(`ignored ${name}: not a release asset of ${release.version}\n`);
    // WP6.7: installers count in the summary and in the checksums.
    const installerCount = release.installers?.length ?? 0;
    const checksums = release.assets.length + installerCount + 1;
    process.stdout.write(
      `${outFile}: release ${release.version}, ${release.assets.length} asset${release.assets.length === 1 ? "" : "s"}${installerCount === 0 ? "" : `, ${installerCount} installer${installerCount === 1 ? "" : "s"}`}, ${manifest.releases.length} release${manifest.releases.length === 1 ? "" : "s"} in the manifest${dropped.length === 0 ? "" : `, ${dropped.length} earlier release${dropped.length === 1 ? "" : "s"} dropped`}\n`,
    );
    process.stdout.write(`${sumsFile}: ${checksums} checksum${checksums === 1 ? "" : "s"}\n`);
    return 0;
  } catch (error) {
    if (error instanceof UsageError) {
      process.stderr.write(`release-manifest: ${error.message}\n\n${USAGE}`);
      return 2;
    }
    if (error instanceof ManifestError || error instanceof ChangelogError) {
      process.stderr.write(`release-manifest: ${error.message}\n`);
      return 1;
    }
    const e = /** @type {NodeJS.ErrnoException} */ (error);
    process.stderr.write(`release-manifest: ${e.message}\n`);
    return e.code === "ENOENT" || e.code === "ENOTDIR" ? 1 : 2;
  }
}

if (isMainModule(import.meta.url)) {
  process.exitCode = await main(process.argv.slice(2));
}
