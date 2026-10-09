// @ts-check
// Vite plugin that compiles the XLIFF language packs of ui/i18n into virtual modules.
//
//   virtual:tenko-i18n/meta          sourceLocale, locales, lazy loaders and message packs
//                                    (contract: src/i18n/virtual.d.ts)
//   virtual:tenko-i18n/<code>        default export: the core message table of one language
//   virtual:tenko-i18n/<code>/<pack> default export: one message pack of one language
//
// Message packs (option `packs`: pack name to key prefixes) keep the messages of lazily
// loaded areas out of the core table, so the first page load does not carry them. A view
// that uses them loads its packs with its route chunk (see `withPacks` in src/i18n).
//
// A build fails when a language pack is invalid or when src/i18n/generated/keys.ts is stale
// (run `npm run i18n`). The dev server and vitest rewrite keys.ts instead, and the dev server
// reloads the page when a language pack changes; a broken edit is logged and the last good
// tables stay in use.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  formatDiagnostics,
  loadCatalog,
  renderKeysTs,
  renderLocaleModule,
  renderMetaModule,
  packOf,
} from "./i18n/compile.mjs";

/** @typedef {import("./i18n/compile.mjs").Catalog} Catalog */

const VIRTUAL_PREFIX = "virtual:tenko-i18n/";
const RESOLVED_PREFIX = "\0" + VIRTUAL_PREFIX;

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

  /** The XLIFF files in the language directory. */
  function xliffFiles() {
    try {
      return fs
        .readdirSync(dir, { withFileTypes: true })
        .filter((e) => e.isFile() && e.name.endsWith(".xlf"))
        .map((e) => path.join(dir, e.name));
    } catch {
      return [];
    }
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

      server.watcher.add([dir, ...xliffFiles()]);
      /** @param {string} file */
      const onFileEvent = (file) => {
        const resolved = path.resolve(file);
        if (resolved.endsWith(".xlf") && samePath(path.dirname(resolved), dir)) reload();
      };
      server.watcher.on("add", onFileEvent);
      server.watcher.on("change", onFileEvent);
      server.watcher.on("unlink", onFileEvent);
    },
  };
}
