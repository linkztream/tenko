// Tests of scripts/sbom-prune.mjs: the cargo tree listing, the restriction of a CycloneDX
// SBOM to it (components, dependency entries, the root, the report of what is missing), and
// the command line. Run with `node --test "scripts/*.test.mjs"`.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, test } from "node:test";
import { fileURLToPath } from "node:url";

import { SbomError, componentKey, parseTreeList, pruneBom } from "./sbom-prune.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const script = path.join(here, "sbom-prune.mjs");

const REGISTRY = "registry+https://github.com/rust-lang/crates.io-index";

/** A component as cargo cyclonedx writes it. */
function crate(name, version) {
  return { type: "library", "bom-ref": `${REGISTRY}#${name}@${version}`, name, version, scope: "required" };
}

/** A small SBOM: tenko depends on serde and quinn, quinn on rand; serde_derive is a proc macro. */
function sampleBom() {
  const root = { type: "application", "bom-ref": "path+file:///src/crates/tenko#0.2.0", name: "tenko", version: "0.2.0" };
  return {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    version: 1,
    metadata: { component: root },
    components: [crate("serde", "1.0.228"), crate("serde_derive", "1.0.228"), crate("quinn", "0.11.12"), crate("rand", "0.10.3")],
    dependencies: [
      { ref: root["bom-ref"], dependsOn: [`${REGISTRY}#serde@1.0.228`, `${REGISTRY}#quinn@0.11.12`] },
      { ref: `${REGISTRY}#serde@1.0.228`, dependsOn: [`${REGISTRY}#serde_derive@1.0.228`] },
      { ref: `${REGISTRY}#serde_derive@1.0.228`, dependsOn: [] },
      { ref: `${REGISTRY}#quinn@0.11.12`, dependsOn: [`${REGISTRY}#rand@0.10.3`] },
      { ref: `${REGISTRY}#rand@0.10.3`, dependsOn: [] },
    ],
  };
}

const TREE = [
  "serde v1.0.228",
  "serde_derive v1.0.228 (proc-macro)",
  "serde v1.0.228 (*)",
  "tenko v0.2.0 (/src/crates/tenko)",
  "",
].join("\n");

describe("parseTreeList", () => {
  test("reads name and version and ignores the path, (proc-macro), (*) and blank lines", () => {
    assert.deepEqual([...parseTreeList(TREE)].sort(), ["serde@1.0.228", "serde_derive@1.0.228", "tenko@0.2.0"]);
  });

  test("reads CRLF line ends and build metadata in a version", () => {
    const list = parseTreeList("toml_edit v0.25.17+spec-1.1.0\r\nwindows-link v0.2.1 (*)\r\n");
    assert.deepEqual([...list].sort(), ["toml_edit@0.25.17+spec-1.1.0", "windows-link@0.2.1"]);
  });

  test("refuses a line that is not name vX.Y.Z, naming the line", () => {
    assert.throws(() => parseTreeList("serde v1.0.228\n├── quinn v0.11.12\n"), (e) => e instanceof SbomError && /line 2/.test(e.message));
  });

  test("refuses an empty listing", () => {
    assert.throws(() => parseTreeList("\n\n"), SbomError);
  });
});

describe("pruneBom", () => {
  test("removes the components that are not compiled, with their dependency entries and references", () => {
    const bom = sampleBom();
    const result = pruneBom(bom, parseTreeList(TREE));
    assert.equal(result.kept, 2);
    assert.deepEqual(result.removed, ["quinn@0.11.12", "rand@0.10.3"]);
    assert.deepEqual(result.missing, []);
    assert.deepEqual(result.bom.components.map(componentKey), ["serde@1.0.228", "serde_derive@1.0.228"]);
    assert.deepEqual(
      result.bom.dependencies.map((/** @type {any} */ d) => d.ref),
      ["path+file:///src/crates/tenko#0.2.0", `${REGISTRY}#serde@1.0.228`, `${REGISTRY}#serde_derive@1.0.228`],
    );
    assert.deepEqual(result.bom.dependencies[0].dependsOn, [`${REGISTRY}#serde@1.0.228`]);
    assert.deepEqual(result.bom.metadata, bom.metadata, "the root component is kept");
    assert.equal(bom.components.length, 4, "the input is not changed");
  });

  test("reports a crate of the listing that the SBOM lacks, except the root", () => {
    const keep = parseTreeList(`${TREE}windows-link v0.2.1\n`);
    const result = pruneBom(sampleBom(), keep);
    assert.deepEqual(result.missing, ["windows-link@0.2.1"]);
    assert.equal(result.kept, 2);
  });

  test("keeps an SBOM without dependencies", () => {
    const bom = sampleBom();
    delete bom.dependencies;
    const result = pruneBom(bom, parseTreeList(TREE));
    assert.equal(result.bom.dependencies, undefined);
    assert.equal(result.kept, 2);
  });

  test("refuses a document that is not CycloneDX", () => {
    assert.throws(() => pruneBom({ spdxVersion: "SPDX-2.3" }, parseTreeList(TREE)), SbomError);
    assert.throws(() => pruneBom({ bomFormat: "CycloneDX" }, parseTreeList(TREE)), SbomError);
  });

  test("refuses to leave an SBOM without components", () => {
    assert.throws(() => pruneBom(sampleBom(), parseTreeList("other v1.0.0\n")), (e) => e instanceof SbomError && /no component/.test(e.message));
  });
});

describe("command line", () => {
  /** @param {string[]} args */
  function cli(args) {
    const r = spawnSync(process.execPath, [script, ...args], { cwd: here, encoding: "utf8" });
    return { status: r.status, stdout: r.stdout, stderr: r.stderr };
  }

  test("writes the restricted SBOM and says what it removed", () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), "sbom-prune-"));
    try {
      writeFileSync(path.join(dir, "bom.json"), JSON.stringify(sampleBom()));
      writeFileSync(path.join(dir, "tree.txt"), TREE);
      const out = path.join(dir, "out", "tenko-0.2.0-linux-x86_64.cdx.json");
      const r = cli(["--bom", path.join(dir, "bom.json"), "--tree", path.join(dir, "tree.txt"), "--out", out]);
      assert.equal(r.status, 0, r.stderr);
      assert.match(r.stdout, /2 components \(cargo tree: 3 crates\); removed 2, missing 0/);
      assert.match(r.stdout, /removed \(not compiled\): quinn@0\.11\.12, rand@0\.10\.3/);
      const written = JSON.parse(readFileSync(out, "utf8"));
      assert.deepEqual(written.components.map(componentKey), ["serde@1.0.228", "serde_derive@1.0.228"]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("exits 1 when the SBOM is not JSON or the file is missing", () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), "sbom-prune-"));
    try {
      writeFileSync(path.join(dir, "bom.json"), "not json");
      writeFileSync(path.join(dir, "tree.txt"), TREE);
      const args = ["--tree", path.join(dir, "tree.txt"), "--out", path.join(dir, "out.json")];
      assert.equal(cli(["--bom", path.join(dir, "bom.json"), ...args]).status, 1);
      assert.equal(cli(["--bom", path.join(dir, "missing.json"), ...args]).status, 1);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("exits 2 on a bad command line", () => {
    const r = cli(["--bom", "bom.json"]);
    assert.equal(r.status, 2);
    assert.match(r.stderr, /--tree is required/);
    assert.equal(cli(["--nope"]).status, 2);
  });
});
