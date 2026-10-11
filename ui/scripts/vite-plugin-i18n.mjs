// @ts-check
// Vite plugin that compiles the XLIFF language packs of ui/i18n into virtual modules. A pack is
// its main file `<code>.xlf` and the fragment files of `<code>.d/` (see scripts/i18n/compile.mjs);
// a change to any of them reloads the dev server.
//
//   virtual:tenko-i18n/meta          sourceLocale, locales, lazy loaders and message packs
//                                    (contract: src/i18n/virtual.d.ts)
//   virtual:tenko-i18n/<code>        default export: the core message table of one language
//   virtual:tenko-i18n/<code>/<pack> default export: one message pack of one language
//   virtual:tenko-i18n/parser        `parse(message)`: the full ICU message parser with the
//                                    options of the build (markup is text), for the language
//                                    packs the browser loads at run time (src/i18n/remote.ts)
//
// Message packs (option `packs`: pack name to key prefixes) keep the messages of lazily
// loaded areas out of the core table, so the first page load does not carry them. A view
// that uses them loads its packs with its route chunk (see `withPacks` in src/i18n).
//
// The build aliases the parser package to its no-parser entry, because the built-in messages
// arrive as syntax trees. The parser module imports the real entry by its file path, which the
// alias does not match, so the parser lands in a chunk of its own that only uploaded languages
// load.
//
// A build fails when a language pack is invalid or when src/i18n/generated/keys.ts is stale
// (run `npm run i18n`). The dev server and vitest rewrite keys.ts instead, and the dev server
// reloads the page when a language pack changes; a broken edit is logged and the last good
// tables stay in use.
//
// A production build also emits one merged XLIFF document per built-in language as
// `i18n/<code>.xlf` (see renderMergedXliff): the units of the main file and the fragments in
// one file. The server embeds it with the UI and reads the key set and the built-in messages
// from it, to validate uploaded language packs and to write templates. The dev server and
// vitest do not bundle, so they do not emit it.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  formatDiagnostics,
  languageFiles,
  loadCatalog,
  renderKeysTs,
  renderLocaleModule,
  renderMergedXliff,
  renderMetaModule,
  packOf,
} from "./i18n/compile.mjs";

/** @typedef {import("./i18n/compile.mjs").Catalog} Catalog */

const VIRTUAL_PREFIX = "virtual:tenko-i18n/";
const RESOLVED_PREFIX = "\0" + VIRTUAL_PREFIX;
const PARSER_ID = "parser";

/**
 * The parser module: the real entry of @formatjs/icu-messageformat-parser by file path.
 * @returns {string}
 */
function renderParserModule() {
  const entry = fileURLToPath(import.meta.resolve("@formatjs/icu-messageformat-parser")).split(path.sep).join("/");
  return [
    `import { parse as parseIcu } from ${JSON.stringify(entry)};`,
    "/** @param {string} message */",
    "export function parse(message) {",
    "  return parseIcu(message, { ignoreTag: true });",
    "}",
    "",
  ].join("\n");
}

/**
 * @param {string} a
 * @param {string} b
 */
function samePath(a, b) {
  return process.platform === "win32" ? a.toLowerCase() === b.toLowerCase() : a === b;
}

/**
 * @param {{ dir?: string, keysOut?: string, packs?: Readonly<Record<string, readonly string[]>> }} [options]
 *   `dir` is the directory of the XLIFF files (default `ui/i18n`), `keysOut` the generated
 *   key types (default `ui/src/i18n/generated/keys.ts`), `packs` the message packs (pack
 *   name to key prefixes; none by default, then the core table holds every key).
 * @returns {import("vite").Plugin}
 */
export function i18n(options = {}) {
  const packs = options.packs ?? {};
  const packNames = Object.keys(packs);
  const uiDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const dir = path.resolve(options.dir ?? path.join(uiDir, "i18n"));
  const keysOut = path.resolve(options.keysOut ?? path.join(uiDir, "src", "i18n", "generated", "keys.ts"));
  const keysLabel = path.relative(uiDir, keysOut).split(path.sep).join("/");

  /**
   * The last catalog without errors.
   * @type {Catalog | undefined}
   */
  let catalog;
  /** True when keys.ts may be rewritten: dev server and vitest, not a production build. */
  let writeKeys = false;

  /** The XLIFF files of the language directory: the main files and the fragment files. */
  function xliffFiles() {
    return languageFiles(dir);
  }

  /**
   * True for a fragment directory (`sv.d`) directly in the language directory.
   * @param {string} resolved
   */
  function isFragmentDir(resolved) {
    return resolved.endsWith(".d") && samePath(path.dirname(resolved), dir);
  }

  /**
   * True for a main file (`sv.xlf`) or a fragment file (`sv.d/cluster.xlf`) of the language directory.
   * @param {string} resolved
   */
  function isLanguageFile(resolved) {
    if (!resolved.endsWith(".xlf")) return false;
    const parent = path.dirname(resolved);
    return samePath(parent, dir) || isFragmentDir(parent);
  }

  /**
   * Brings keys.ts up to date with the catalog when allowed.
   * @param {Catalog} next
   * @returns {boolean} true when keys.ts is stale and could not be rewritten
   */
  function syncKeys(next) {
    const content = renderKeysTs(next);
    let current = null;
    try {
      current = fs.readFileSync(keysOut, "utf8").replace(/\r\n/g, "\n");
    } catch {
      // missing file: stale
    }
    if (current === content) return false;
    if (!writeKeys) return true;
    fs.mkdirSync(path.dirname(keysOut), { recursive: true });
    fs.writeFileSync(keysOut, content);
    return false;
  }

  /**
   * The catalog, loaded on first use.
   * @param {import("vite").Rollup.PluginContext} ctx
   * @returns {Catalog}
   */
  function currentCatalog(ctx) {
    if (catalog === undefined) {
      const loaded = loadCatalog(dir);
      if (loaded.errors.length > 0) ctx.error(formatDiagnostics(loaded.errors, uiDir));
      catalog = loaded;
    }
    return catalog;
  }

  return {
    name: "tenko-i18n",

    configResolved(config) {
      writeKeys = config.command === "serve" || process.env["VITEST"] !== undefined;
    },

    buildStart() {
      // Watch mode rebuilds when a language pack changes, also one that failed to load.
      for (const file of xliffFiles()) this.addWatchFile(file);

      const loaded = loadCatalog(dir);
      if (loaded.errors.length > 0) this.error(formatDiagnostics(loaded.errors, uiDir));
      catalog = loaded;
      if (syncKeys(loaded)) this.error(`${keysLabel} is out of date; run npm run i18n`);
    },

    resolveId(id) {
      return id.startsWith(VIRTUAL_PREFIX) ? "\0" + id : undefined;
    },

    load(id) {
      if (!id.startsWith(RESOLVED_PREFIX)) return undefined;
      const [code = "", pack] = id.slice(RESOLVED_PREFIX.length).split("/");
      if (code === PARSER_ID && pack === undefined) return renderParserModule();
      const current = currentCatalog(this);
      if (code === "meta") return renderMetaModule(current, { importPrefix: VIRTUAL_PREFIX, packs: packNames });
      if (pack !== undefined && !packNames.includes(pack)) return this.error(`unknown message pack ${JSON.stringify(pack)}`);
      if (current.messages.has(code)) {
        return renderLocaleModule(current, code, {
          include: (key) => packOf(key, packs) === pack,
        });
      }
      const known = current.locales.map((l) => l.code).join(", ");
      return this.error(`unknown language ${JSON.stringify(code)} (available: ${known})`);
    },

    generateBundle() {
      const current = currentCatalog(this);
      for (const locale of current.locales) {
        this.emitFile({
          type: "asset",
          fileName: `i18n/${locale.code}.xlf`,
          source: renderMergedXliff(current, locale.code),
        });
      }
    },

    configureServer(server) {
      const logger = server.config.logger;

      /** Reloads the catalog after a language pack changed. */
      const reload = () => {
        const next = loadCatalog(dir);
        if (next.errors.length > 0) {
          logger.error(
            `[i18n] invalid language pack, keeping the last good messages\n${formatDiagnostics(next.errors, uiDir)}`,
            { timestamp: true },
          );
          return;
        }
        const previous = catalog;
        catalog = next;
        try {
          syncKeys(next);
        } catch (error) {
          logger.error(`[i18n] cannot write ${keysLabel}: ${error instanceof Error ? error.message : String(error)}`, {
            timestamp: true,
          });
        }

        const names = new Set(["meta"]);
        for (const c of [previous, next]) {
          for (const locale of c?.locales ?? []) {
            names.add(locale.code);
            for (const pack of packNames) names.add(`${locale.code}/${pack}`);
          }
        }
        for (const environment of Object.values(server.environments)) {
          for (const name of names) {
            const module = environment.moduleGraph.getModuleById(RESOLVED_PREFIX + name);
            if (module) environment.moduleGraph.invalidateModule(module);
          }
        }
        server.environments.client.hot.send({ type: "full-reload", path: "*" });
        logger.info(`[i18n] reloaded ${next.locales.map((l) => l.code).join(", ")}`, { timestamp: true });
      };

      const files = xliffFiles();
      server.watcher.add([...new Set([dir, ...files.map((f) => path.dirname(f)), ...files])]);
      /** @param {string} file */
      const onFileEvent = (file) => {
        if (isLanguageFile(path.resolve(file))) reload();
      };
      /**
       * A fragment directory (`sv.d`) that appears or disappears changes the language.
       * @param {string} directory
       */
      const onDirectoryEvent = (directory) => {
        const resolved = path.resolve(directory);
        if (!isFragmentDir(resolved)) return;
        server.watcher.add(resolved);
        reload();
      };
      server.watcher.on("add", onFileEvent);
      server.watcher.on("change", onFileEvent);
      server.watcher.on("unlink", onFileEvent);
      server.watcher.on("addDir", onDirectoryEvent);
      server.watcher.on("unlinkDir", onDirectoryEvent);
    },
  };
}
