// Builds the release manifest `releases.json` that running installations read to learn
// about updates, and the `SHA256SUMS` file that goes with the release assets.
//
//   node scripts/release-manifest.mjs --version 0.2.0 --assets dist \
//     --base-url https://github.com/linkztream/tenko/releases/download/v0.2.0 \
//     [--changelog CHANGELOG.md] [--previous releases.json] [--image ghcr.io/linkztream/tenko:0.2.0] \
//     [--format 1] [--out releases.json]
//
// The release text comes from the section `## [0.2.0] - <date>` of the changelog (the
// Unreleased section is never released). Every file in --assets named
// `tenko-<version>-<platform>` or `tenko-<version>-<platform>.exe` becomes an asset with its
// SHA-256 and size; other files are ignored with a note. The releases of --previous are kept
// (an entry for the same version is replaced), newest first. Node's standard library only.
//
// Manifest schema 1:
//   { "schema": 1, "project": "tenko", "releases": [ { "version", "date", "notes", "security",
//     "requires_action", "action"?, "format"?, "image"?, "assets": [ { "platform", "name",
//     "url", "sha256", "size" } ] } ] }
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
  for (const entry of entries) {
    const platform = entry.isFile() ? assetPlatform(entry.name, version) : null;
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
    notes: section.body,
    security: section.security,
    requires_action: section.requiresAction,
    ...(section.requiresAction ? { action: section.action } : {}),
    ...(format === undefined ? {} : { format }),
    ...(image === undefined ? {} : { image }),
    assets,
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
  return release.assets
    .slice()
    .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))
    .map((a) => `${a.sha256}  ${a.name}\n`)
    .join("");
}

// ---------------------------------------------------------------------------------------
// Command line

const USAGE = `Usage: node scripts/release-manifest.mjs --version <X.Y.Z> --assets <dir> --base-url <url> [options]

Options:
  --version <v>      the release, without a leading v (required)
  --assets <dir>     directory with the files tenko-<version>-<os>-<arch>[.exe] (required)
  --base-url <url>   where the assets are downloadable from; the URL of an asset is
                     <base-url>/<file name> (required)
  --changelog <file> the changelog (default CHANGELOG.md)
  --previous <file>  the releases.json of earlier releases, merged into the result
  --image <ref>      container image of the release
  --format <n>       data-directory format number of the binaries
  --out <file>       the manifest to write (default releases.json); SHA256SUMS goes next to it
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
    const manifest = mergeManifest(/** @type {any} */ (previous), release);

    await mkdir(path.dirname(path.resolve(outFile)), { recursive: true });
    await writeFile(outFile, formatManifest(manifest));
    const sumsFile = path.join(path.dirname(outFile), "SHA256SUMS");
    await writeFile(sumsFile, formatChecksums(release));

    for (const name of ignored) process.stdout.write(`ignored ${name}: not a release asset of ${release.version}\n`);
    process.stdout.write(
      `${outFile}: release ${release.version}, ${release.assets.length} asset${release.assets.length === 1 ? "" : "s"}, ${manifest.releases.length} release${manifest.releases.length === 1 ? "" : "s"} in the manifest\n`,
    );
    process.stdout.write(`${sumsFile}: ${release.assets.length} checksum${release.assets.length === 1 ? "" : "s"}\n`);
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
