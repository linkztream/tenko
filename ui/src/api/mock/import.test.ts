// The import and export part of the mock API through `fetch`, against the msw server that
// src/app/testing/setup.ts starts: upload, analysis, mapping, preview, apply, discard and the
// CSV exports. Uploads go through Node's FormData and File (see import-testkit.ts).
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import type { components } from "../generated/schema";
import { startSession } from "./auth";
import { audit } from "./audit-store";
import { findUserByName, resetMockDb } from "./db";
import { analyze } from "./import-analysis";
import { filesForm, releaseNodeFormData, testFile, useNodeFormData } from "./import-testkit";
import { readCsv } from "./import-sheets";
import { importRecords, vaultDigests } from "./import-store";
import { shapeOf, parseMac, parseRange } from "./import-shape";
import { targetForHeader } from "./import-vocab";
import { ADDRESS_IDS, HOST_IDS, ipamState } from "./ipam/api";
import { findJob, jobStore } from "./job-store";

type S = components["schemas"];
type View = S["ImportView"];
type Preview = S["ImportPreview"];
type Mapping = S["Mapping"];
type Problem = S["ProblemDetails"] & { errors?: { field: string; code: string }[] };

beforeAll(useNodeFormData);
afterAll(releaseNodeFormData);
beforeEach(() => {
  resetMockDb("signed-in");
});

// ---------------------------------------------------------------------------------
// Helpers

interface Answer<T> {
  status: number;
  headers: Headers;
  body: T;
}

async function answer<T>(res: Response): Promise<Answer<T>> {
  const text = await res.text();
  return { status: res.status, headers: res.headers, body: (text ? JSON.parse(text) : undefined) as T };
}

async function upload(...files: [name: string, content: string | Uint8Array][]): Promise<Answer<View>> {
  const form = filesForm(files.map(([name, content]) => testFile(name, content)));
  return answer<View>(await fetch("/api/v1/imports", { method: "POST", body: form }));
}

async function uploaded(name: string, content: string | Uint8Array): Promise<View> {
  const res = await upload([name, content]);
  expect(res.status).toBe(201);
  return res.body;
}

async function send<T>(method: string, path: string, body?: unknown): Promise<Answer<T>> {
  const init: RequestInit = { method };
  if (body !== undefined) {
    init.headers = { "content-type": "application/json" };
    init.body = JSON.stringify(body);
  }
  return answer<T>(await fetch(path, init));
}

const preview = (id: string, rows = 1000) => send<Preview>("GET", `/api/v1/imports/${id}/preview?rows=${rows}`);
const apply = (id: string, acknowledge: string[] = []) => send<{ job_id: string }>("POST", `/api/v1/imports/${id}/apply`, { acknowledge });

/** Puts a mapping onto an import: the suggestion with the changes `edit` makes. */
async function remap(view: View, edit: (mapping: Mapping) => void): Promise<View> {
  const mapping = structuredClone(view.mapping);
  edit(mapping);
  const res = await send<View>("PUT", `/api/v1/imports/${view.id}/mapping`, mapping);
  expect(res.status).toBe(200);
  return res.body;
}

const BOM = String.fromCharCode(0xfeff);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** Three hosts in the free end of the LAN of the seed, with a semicolon, a quote and a BOM. */
const PLAN_CSV = [
  "IP;Name;Description;MAC;Status",
  "192.0.2.201;app01;Front end;00-00-5E-00-53-E1;active",
  "192.0.2.202;app02;;00-00-5E-00-53-E2;",
  '192.0.2.203;"db;01";"Primary ""db"" server";;reserved',
  "192.0.2.204;;;;",
].join("\r\n");

function planCsv(): string {
  return BOM + PLAN_CSV;
}

function cell<T extends { column: string }>(items: readonly T[], column: string): T {
  const found = items.find((item) => item.column === column);
  if (!found) throw new Error(`no column ${column}`);
  return found;
}

function sheetOf(view: View, name: string): S["SheetAnalysis"] {
  const found = view.sheets.find((s) => s.sheet === name);
  if (!found) throw new Error(`no sheet ${name}`);
  return found;
}

function lossOf(p: Preview, sheet: string | null, code: string) {
  const group = p.loss.find((g) => (g.sheet ?? null) === sheet);
  return (group?.entries ?? []).filter((e) => e.code === code);
}

const allLoss = (p: Preview) => p.loss.flatMap((g) => g.entries.map((e) => ({ sheet: g.sheet ?? null, ...e })));

// ---------------------------------------------------------------------------------
// Value shapes and header words

describe("shapes and vocabulary", () => {
  it("tells addresses, networks, ranges, MAC addresses, DUIDs, numbers and text apart", () => {
    expect(shapeOf("192.0.2.10")).toBe("address");
    expect(shapeOf(" 192.000.002.010 ")).toBe("address");
    expect(shapeOf("[2001:db8::1]")).toBe("address");
    expect(shapeOf("255.255.255.0")).toBe("address");
    expect(shapeOf("192.0.2.0/24")).toBe("cidr");
    expect(shapeOf("192.0.2.0/255.255.255.0")).toBe("cidr");
    expect(shapeOf("192.0.2.10-20")).toBe("range");
    expect(shapeOf("2026-10-09")).toBe("text");
    expect(shapeOf("00-00-5E-00-53-01")).toBe("mac");
    expect(shapeOf("0000.5e00.5301")).toBe("mac");
    expect(shapeOf("00:03:00:01:00:00:5e:00:53:01")).toBe("duid");
    expect(shapeOf("123456789012")).toBe("number");
    expect(shapeOf("1,5")).toBe("number");
    expect(shapeOf("web01")).toBe("text");
    expect(shapeOf("  ")).toBe("empty");
    expect(parseMac("00005E005301")).toBe("00:00:5e:00:53:01");
    expect(parseRange("192.0.2.20-10")).toBeNull();
  });

  it("suggests targets from English and Swedish header words", () => {
    const cases: [string, string][] = [
      ["IP", "address"],
      ["Nic1", "address"],
      ["Beteckning", "host"],
      ["Enhet", "host"],
      ["login", "login"],
      ["Pass", "password"],
      ["dns_name", "dns_name"],
      ["custom.rack", "custom.rack"],
    ];
    for (const [header, target] of cases) expect(targetForHeader(header), header).toBe(target);
    expect(targetForHeader("Colour")).toBeNull();
    // Accents are folded: the Swedish words are matched without them.
    expect(targetForHeader(`Anv${String.fromCharCode(0xe4)}ndare`)).toBe("login");
    expect(targetForHeader(`L${String.fromCharCode(0xf6)}senord`)).toBe("password");
  });

  it("reads a CSV file: BOM, delimiter sniffing, quotes and blank lines", () => {
    const file = readCsv("plan.csv", new TextEncoder().encode(`${BOM}a;b\n"x;1";"say ""hi"""\n\nlast;row\n`));
    expect(file.text).toEqual({ encoding: "UTF-8", bom: true, delimiter: ";" });
    const sheet = file.sheets[0];
    expect(sheet?.name).toBe("plan");
    expect(sheet?.rows.map((r) => r.map((c) => c.text))).toEqual([["a", "b"], ["x;1", 'say "hi"'], [], ["last", "row"]]);
    const tabs = readCsv("t.tsv", new TextEncoder().encode("a\tb\n1\t2\n"));
    expect(tabs.text?.delimiter).toBe("\t");
    expect(readCsv("one.csv", new TextEncoder().encode("a\nb\n")).text?.delimiter).toBe(",");
  });

  it("analyzes a sheet without a header row by the shapes of its values", () => {
    const file = readCsv("192.0.2.200.csv", new TextEncoder().encode("192.0.2.201,00-00-5E-00-53-01\n192.0.2.202,00-00-5E-00-53-02\n"));
    const { sheets } = analyze([file]);
    const sheet = sheets[0];
    expect(sheet?.suggested.header_row).toBeUndefined();
    expect(sheet?.suggested.columns?.map((c) => c.target)).toEqual(["address", "mac"]);
    expect(sheet?.suggested.kind).toBe("network");
    expect(sheet?.mask_source).toBe("row_count");
  });
});

// ---------------------------------------------------------------------------------
// Upload

describe("POST /imports", () => {
  it("answers 201 with the view of a CSV file: decoding, columns, shapes and suggestions", async () => {
    const res = await upload(["ip-plan.csv", planCsv()]);
    expect(res.status).toBe(201);
    const view = res.body;
    expect(view.id).toMatch(UUID);
    expect(res.headers.get("location")).toBe(`/api/v1/imports/${view.id}`);
    expect(view.state).toBe("uploaded");
    expect(view.mapped).toBe(false);
    expect(view.job_id).toBeUndefined();
    expect(Date.parse(view.expires) - Date.parse(view.created)).toBe(24 * 3600 * 1000);
    expect(view.files).toEqual([
      { name: "ip-plan.csv", format: "csv", size: new TextEncoder().encode(planCsv()).length, text: { encoding: "UTF-8", bom: true, delimiter: ";" } },
    ]);

    expect(view.sheets).toHaveLength(1);
    const sheet = view.sheets[0] as S["SheetAnalysis"];
    expect(sheet).toMatchObject({ sheet: "ip-plan", file: "ip-plan.csv", rows: 5, data_rows: 4, width: 5, listed_in_index: false });
    expect(sheet.mask_source).toBeUndefined();
    expect(sheet.columns.map((c) => [c.column, c.header, c.suggested])).toEqual([
      ["A", "IP", "address"],
      ["B", "Name", "host"],
      ["C", "Description", "description"],
      ["D", "MAC", "mac"],
      ["E", "Status", "status"],
    ]);
    expect(cell(sheet.columns, "A").shapes).toMatchObject({ address: 4, text: 0 });
    expect(cell(sheet.columns, "D").shapes).toMatchObject({ mac: 2, empty: 2 });
    expect(cell(sheet.columns, "B").samples).toEqual(["app01", "app02", "db;01"]);
    expect(cell(sheet.columns, "C").samples).toEqual(["Front end", 'Primary "db" server']);

    expect(sheet.suggested).toEqual({
      sheet: "ip-plan",
      kind: "list",
      header_row: 1,
      columns: ["A:address", "B:host", "C:description", "D:mac", "E:status"].map((pair) => {
        const [column, target] = pair.split(":");
        return { column, target };
      }),
    });
    expect(view.mapping.sheets).toEqual([sheet.suggested]);
    expect(view.mapping.options).toEqual({ conflict: "update", credentials: "import" });
  });

  it("offers every target, the credential ones flagged, and the custom fields of the IPAM mock", async () => {
    const { targets } = await uploaded("plan.csv", "ip\n192.0.2.201\n");
    const names = targets.map((t) => t.target);
    expect(names.slice(0, 5)).toEqual(["ignore", "address", "prefix", "mask", "host"]);
    expect(names).toContain("interfaces");
    expect(names.filter((n) => n.startsWith("custom."))).toEqual(["custom.asset_tag", "custom.rack", "custom.warranty_until"]);
    expect(targets.filter((t) => t.credential).map((t) => t.target)).toEqual(["login", "password"]);
    expect(targets.find((t) => t.target === "prefix")?.label).toBe("Network (CIDR)");
  });

  it("reads several files as several sheets with unique names", async () => {
    const res = await upload(["a.csv", "ip\n192.0.2.201\n"], ["b.txt", "ip\n192.0.2.202\n"], ["a.csv", "ip\n192.0.2.203\n"]);
    expect(res.status).toBe(201);
    expect(res.body.sheets.map((s) => s.sheet)).toEqual(["a", "b", "a (2)"]);
    expect(res.body.files.map((f) => f.name)).toEqual(["a.csv", "b.txt", "a.csv"]);
  });

  it("treats a sheet named like an address as a network whose mask comes from the rows", async () => {
    const rows = Array.from({ length: 255 }, (_, i) => `192.0.2.${i + 1}`).join("\n");
    const view = await uploaded("203.0.113.0.csv", `IP\n${rows.replace(/192\.0\.2/g, "203.0.113")}\n`);
    const sheet = view.sheets[0] as S["SheetAnalysis"];
    expect(sheet.suggested).toMatchObject({ kind: "network", cidr: "203.0.113.0/24" });
    expect(sheet.mask_source).toBe("row_count");
    const named = await uploaded("203.0.113.0_26.csv", "IP\n203.0.113.1\n");
    expect(named.sheets[0]?.suggested).toMatchObject({ cidr: "203.0.113.0/26" });
    expect(named.sheets[0]?.mask_source).toBe("name");
  });

  it("refuses an upload without a file, an empty one and one over 20 MiB", async () => {
    const none = await answer<Problem>(await fetch("/api/v1/imports", { method: "POST", body: new FormData() }));
    expect(none.status).toBe(400);
    expect(none.body.code).toBe("import.upload.empty");
    const blank = await upload(["empty.csv", ""]);
    expect(blank.status).toBe(400);
    expect((blank.body as unknown as Problem).code).toBe("import.upload.empty");
    const big = await upload(["big.csv", new Uint8Array(20 * 1024 * 1024 + 1).fill(97)]);
    expect(big.status).toBe(413);
    expect(big.body).toMatchObject({ code: "import.upload.too_large", params: { limit: String(20 * 1024 * 1024) } });
  });

  it("refuses what is neither CSV nor a workbook, and a body that is not multipart", async () => {
    for (const [name, content] of [
      ["plan.pdf", "%PDF-1.7\n1 0 obj"],
      ["plan.csv", new Uint8Array([97, 44, 0, 98, 10])],
      ["page.csv", "<html><body>no</body></html>"],
    ] as const) {
      const res = await upload([name, content]);
      expect(res.status, name).toBe(415);
      expect((res.body as unknown as Problem).code).toBe("import.upload.unsupported");
    }
    const json = await send<Problem>("POST", "/api/v1/imports", { files: [] });
    expect(json.status).toBe(400);
    expect(json.body.code).toBe("import.upload.malformed");
  });

  it("needs a session", async () => {
    resetMockDb("signed-out");
    const res = await upload(["plan.csv", "ip\n192.0.2.201\n"]);
    expect(res.status).toBe(401);
    expect((res.body as unknown as Problem).code).toBe("auth.unauthenticated");
  });
});

// ---------------------------------------------------------------------------------
// The canned workbook

describe("a workbook upload", () => {
  async function workbook(): Promise<View> {
    return uploaded("ip-plan.xlsx", "not unpacked by the mock");
  }

  it("answers the canned workbook of docs/plans/import-fixtures.md", async () => {
    const view = await workbook();
    expect(view.files).toEqual([{ name: "ip-plan.xlsx", format: "xlsx", size: 24 }]);
    expect(view.sheets.map((s) => s.sheet)).toEqual([
      "Index",
      "192.0.2.0",
      "203.0.113.0",
      "192.0.2.64",
      "198.51.100.0",
      "192.0.2.128",
      "192.0.2.9",
      "203.0.113.128",
      "192.0.2.192",
      "198.51.100.128",
    ]);
    expect(view.sheets.map((s) => [s.sheet, s.rows])).toEqual([
      ["Index", 7],
      ["192.0.2.0", 256],
      ["203.0.113.0", 126],
      ["192.0.2.64", 6],
      ["198.51.100.0", 5],
      ["192.0.2.128", 2],
      ["192.0.2.9", 2],
      ["203.0.113.128", 5],
      ["192.0.2.192", 2],
      ["198.51.100.128", 0],
    ]);
    for (const format of ["xls", "ods"] as const) {
      const other = await uploaded(`plan.${format}`, "x");
      expect(other.files[0]?.format).toBe(format);
      expect(other.sheets).toHaveLength(10);
    }
  });

  it("reads the kinds, the masks and where they come from", async () => {
    const view = await workbook();
    const kinds = Object.fromEntries(view.sheets.map((s) => [s.sheet, [s.suggested.kind, s.suggested.cidr ?? null, s.mask_source ?? null, s.listed_in_index]]));
    expect(kinds).toEqual({
      Index: ["index", null, null, false],
      "192.0.2.0": ["network", "192.0.2.0/24", "index", true],
      "203.0.113.0": ["network", "203.0.113.0/24", "index", true],
      "192.0.2.64": ["network", "192.0.2.64/26", "index", true],
      "198.51.100.0": ["network", "198.51.100.0/26", "index", true],
      "192.0.2.128": ["network", "192.0.2.128/26", "index", true],
      "192.0.2.9": ["host", null, null, true],
      "203.0.113.128": ["network", "203.0.113.128/29", "row_count", false],
      "192.0.2.192": ["network", "192.0.2.192/31", "row_count", false],
      "198.51.100.128": ["skip", null, null, true],
    });
    expect(sheetOf(view, "Index").suggested.columns).toEqual([
      { column: "A", target: "prefix" },
      { column: "B", target: "description" },
    ]);
    // The canned workbook describes the networks the seeded IPAM state has: it suggests a VRF of its own.
    expect(view.mapping.options).toEqual({ vrf: "ip-plan", conflict: "update", credentials: "import" });
  });

  it("hides credential samples and flags the stray and the unlabeled columns", async () => {
    const view = await workbook();
    const gear = sheetOf(view, "192.0.2.0");
    expect(cell(gear.columns, "C")).toMatchObject({ header: "Login", suggested: "login", samples: ["(hidden)"] });
    expect(cell(gear.columns, "D")).toMatchObject({ header: "Pass", suggested: "password", samples: ["(hidden)"] });
    expect(JSON.stringify(view)).not.toContain("test-pass");
    expect(JSON.stringify(view)).not.toContain("HP v1810");
    expect(cell(gear.columns, "A").shapes).toMatchObject({ address: 255 });
    expect(cell(gear.columns, "B").samples).toHaveLength(5);

    const servers = sheetOf(view, "203.0.113.0");
    expect(cell(servers.columns, "A").shapes).toMatchObject({ address: 123, range: 1, text: 1 });
    expect(cell(servers.columns, "E")).toMatchObject({ suggested: "ignore", samples: ["rack B2"] });
    expect(cell(servers.columns, "E").header).toBeUndefined();
  });

  it("reads the device layout: one interface per NIC column", async () => {
    const devices = sheetOf(await workbook(), "198.51.100.0");
    expect(devices.suggested.columns).toEqual([
      { column: "A", target: "host" },
      { column: "B", target: "address", interface: "nic1" },
      { column: "C", target: "address", interface: "nic2" },
      { column: "D", target: "address", interface: "nic3" },
      { column: "E", target: "address", interface: "nic4" },
      { column: "F", target: "login" },
      { column: "G", target: "password" },
    ]);
    expect(cell(devices.columns, "F")).toMatchObject({ header: "login", samples: ["(hidden)"] });
  });

  it("borrows the roles of the sheet without a header row from the layout of its workbook", async () => {
    const bare = sheetOf(await workbook(), "192.0.2.128");
    expect(bare.roles_from).toBe("192.0.2.0");
    expect(bare.suggested.header_row).toBeUndefined();
    expect(bare.suggested.columns?.map((c) => c.target)).toEqual(["address", "host", "login", "password"]);
    expect(cell(bare.columns, "B").header).toBeUndefined();
    expect(cell(bare.columns, "C").samples).toEqual(["(hidden)"]);
  });

  it("skips an empty sheet that Index does not list", async () => {
    // An empty file is "no file"; a file with only a line break is a sheet without values.
    const view = await uploaded("203.0.113.64.csv", "\n");
    expect(view.sheets[0]?.suggested).toMatchObject({ kind: "skip", columns: [] });
    const p = (await preview(view.id)).body;
    expect(lossOf(p, "203.0.113.64", "import.sheet.empty")).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------------
// Reading an upload and the mapping

describe("GET /imports/{id} and PUT /imports/{id}/mapping", () => {
  it("shows the same view again, and 404 for an id nobody uploaded", async () => {
    const view = await uploaded("plan.csv", PLAN_CSV);
    const again = await send<View>("GET", `/api/v1/imports/${view.id}`);
    expect(again.status).toBe(200);
    expect(again.body).toEqual(view);
    const unknown = await send<Problem>("GET", "/api/v1/imports/0190d1c2-0000-7000-8000-00000000ffff");
    expect(unknown.status).toBe(404);
    expect(unknown.body.code).toBe("import.not_found");
    const bad = await send<Problem>("GET", "/api/v1/imports/not-an-id");
    expect(bad.status).toBe(400);
  });

  it("keeps an upload to its owner and answers 410 once it expired", async () => {
    const view = await uploaded("plan.csv", PLAN_CSV);
    const record = importRecords().get(view.id);
    expect(record).toBeDefined();
    startSession(findUserByName("sam") as never, "password");
    expect((await send<Problem>("GET", `/api/v1/imports/${view.id}`)).status).toBe(404);
    startSession(findUserByName("alex") as never, "passkey");
    (record as { expires: number }).expires = Date.now() - 1;
    const gone = await send<Problem>("GET", `/api/v1/imports/${view.id}`);
    expect(gone.status).toBe(410);
    expect(gone.body.code).toBe("import.expired");
    expect((await send<Problem>("GET", `/api/v1/imports/${view.id}`)).status).toBe(404);
  });

  it("stores a mapping, answers the view with mapped set and changes the preview", async () => {
    const view = await uploaded("plan.csv", PLAN_CSV);
    const mapped = await remap(view, (m) => {
      const sheet = m.sheets[0] as S["SheetMapping"];
      sheet.columns = (sheet.columns ?? []).map((c) => (c.column === "E" ? { column: "E", target: "ignore" } : c));
      m.options = { ...m.options, conflict: "skip" };
    });
    expect(mapped.state).toBe("mapped");
    expect(mapped.mapped).toBe(true);
    expect(mapped.mapping.options?.conflict).toBe("skip");
    expect(mapped.mapping.sheets[0]?.columns?.map((c) => c.target)).toEqual(["address", "host", "description", "mac", "ignore"]);
    expect((await send<View>("GET", `/api/v1/imports/${view.id}`)).body.mapped).toBe(true);
    const p = (await preview(view.id)).body;
    // The status column is left out now: its values are listed instead of imported.
    expect(lossOf(p, "plan", "import.column.unmapped")).toMatchObject([{ row: 2, column: "E", severity: "warning" }]);
  });

  const first = (m: Mapping): S["SheetMapping"] => m.sheets[0] as S["SheetMapping"];
  const column = (m: Mapping, index: number): S["ColumnMapping"] => (first(m).columns ?? [])[index] as S["ColumnMapping"];
  const bad: [string, (m: Mapping) => void, string][] = [
    ["a sheet the upload does not have", (m) => { first(m).sheet = "other"; }, "sheets[0].sheet"],
    ["a sheet kind that is not one", (m) => { first(m).kind = "table" as never; }, "sheets[0].kind"],
    ["a network sheet without a network", (m) => { first(m).kind = "network"; }, "sheets[0].cidr"],
    ["a network with host bits", (m) => { Object.assign(first(m), { kind: "network", cidr: "192.0.2.5/24" }); }, "sheets[0].cidr"],
    ["a network that is not one", (m) => { Object.assign(first(m), { kind: "network", cidr: "web01" }); }, "sheets[0].cidr"],
    ["a column letter that is not one", (m) => { column(m, 0).column = "A1"; }, "sheets[0].columns[0].column"],
    ["a column the sheet does not have", (m) => { column(m, 0).column = "K"; }, "sheets[0].columns[0].column"],
    ["a column mapped twice", (m) => { column(m, 1).column = "A"; }, "sheets[0].columns[1].column"],
    ["a target nobody knows", (m) => { column(m, 0).target = "colour"; }, "sheets[0].columns[0].target"],
    ["two columns with one single target", (m) => { column(m, 2).target = "host"; }, "sheets[0].columns[2].target"],
    ["a header row outside the sheet", (m) => { first(m).header_row = 9; }, "sheets[0].header_row"],
    ["an unknown conflict policy", (m) => { m.options = { conflict: "merge" as never }; }, "options.conflict"],
    ["no sheet at all", (m) => { m.sheets = []; }, "sheets"],
  ];

  it.each(bad)("answers 422 with a field error for %s", async (_what, edit, field) => {
    const view = await uploaded("plan.csv", PLAN_CSV);
    const mapping = structuredClone(view.mapping);
    edit(mapping);
    const res = await send<Problem>("PUT", `/api/v1/imports/${view.id}/mapping`, mapping);
    expect(res.status).toBe(422);
    expect(res.body.code).toBe("import.mapping.invalid");
    expect(res.body.errors?.[0]).toMatchObject({ field, code: "import.mapping.invalid" });
    expect((await send<View>("GET", `/api/v1/imports/${view.id}`)).body.mapped).toBe(false);
  });

  it("accepts a header row of 1 and a column letter in lower case", async () => {
    const view = await uploaded("plan.csv", PLAN_CSV);
    const mapped = await remap(view, (m) => {
      ((m.sheets[0]?.columns ?? [])[0] as { column: string }).column = "a";
    });
    expect(mapped.mapping.sheets[0]?.columns?.[0]?.column).toBe("A");
  });
});

// ---------------------------------------------------------------------------------
// Preview

describe("GET /imports/{id}/preview", () => {
  it("counts what a CSV file creates and lists its rows and its loss report", async () => {
    const view = await uploaded("ip-plan.csv", planCsv());
    const res = await preview(view.id);
    expect(res.status).toBe(200);
    const p = res.body;
    expect(p.id).toBe(view.id);
    expect(p.can_apply).toBe(true);
    expect(p.blockers).toEqual([]);
    expect(p.plan_error).toBeUndefined();
    expect(p.summary.counts).toEqual([
      { kind: "address", action: "create", count: 3 },
      { kind: "host", action: "create", count: 3 },
      { kind: "interface", action: "create", count: 3 },
    ]);
    expect(p.summary.lines).toEqual(["3 addresses created", "3 hosts created", "3 interfaces created"]);
    expect(p.summary.rows).toEqual({ total: 4, free: 1, imported: 3, skipped: 0 });
    expect(p.total_rows).toBe(4);
    expect(p.sheets).toEqual([{ sheet: "ip-plan", kind: "list", rows: 4, free: 1, imported: 3, skipped: 0 }]);
    expect(p.summary.plan?.lines).toEqual(["3 addresses created", "3 hosts created", "3 interfaces created"]);
    expect(p.summary.chunks).toBe(1);
    expect(p.base_revision).toBeGreaterThan(0);

    expect(p.rows.map((r) => [r.location.row, r.status])).toEqual([
      [2, "imported"],
      [3, "imported"],
      [4, "imported"],
      [5, "free"],
    ]);
    // The interface nic1 is named after the row was read, so the row does not list it.
    expect(p.rows[0]?.items).toEqual([
      { key: { kind: "host", name: "app01" }, action: "create" },
      { key: { kind: "address", vrf: "default", ip: "192.0.2.201" }, action: "create" },
    ]);
    // "db;01" is not a host name: it is normalized and the label stays as the description.
    expect(p.rows[2]?.items[0]).toEqual({ key: { kind: "host", name: "db-01" }, action: "create" });
    expect(allLoss(p).map((e) => [e.code, e.row, e.column, e.severity])).toEqual([["import.name.normalized", 4, "B", "info"]]);
    expect(p.summary.loss).toEqual({ info: 1, warning: 0, error: 0 });
    expect(p.credentials).toMatchObject({ hosts: 0, new: 0, allowed: true });
  });

  it("lists as many rows as asked for and refuses a bad query", async () => {
    const view = await uploaded("ip-plan.csv", planCsv());
    const two = (await preview(view.id, 2)).body;
    expect(two.rows).toHaveLength(2);
    expect(two.total_rows).toBe(4);
    for (const query of ["rows=0", "rows=1001", "rows=ten", "other=1"]) {
      const res = await send<Problem>("GET", `/api/v1/imports/${view.id}/preview?${query}`);
      expect(res.status, query).toBe(400);
      expect(res.body.code).toBe("sys.invalid_query");
    }
  });

  it("compares with the IPAM state: unchanged, update and kept under the conflict policy", async () => {
    const csv = "IP,Name,Interface,Description,Status\n192.0.2.10,pve1,eth0,Hypervisor,\n192.0.2.11,nas,eth0,,active\n192.0.2.201,app01,eth0,,\n";
    const view = await uploaded("hosts.csv", csv);
    const counts = (p: Preview) => Object.fromEntries(p.summary.counts.map((c) => [`${c.kind}/${c.action}`, c.count]));

    const update = (await preview(view.id)).body;
    expect(counts(update)).toEqual({
      "address/create": 1,
      "address/update": 1,
      "address/unchanged": 1,
      "host/create": 1,
      "host/unchanged": 2,
      "interface/create": 1,
      "interface/unchanged": 2,
    });
    const row = update.rows.find((r) => r.location.row === 2);
    expect(row?.items.map((i) => [i.key.kind, i.action])).toEqual([
      ["host", "unchanged"],
      ["interface", "unchanged"],
      ["address", "update"],
    ]);
    expect(update.can_apply).toBe(true);

    const skipped = (await preview((await remap(view, (m) => void (m.options = { ...m.options, conflict: "skip" }))).id)).body;
    expect(counts(skipped)["address/kept"]).toBe(1);
    expect(skipped.summary.lines).toContain("1 address kept as stored (conflict)");
    expect(skipped.can_apply).toBe(true);
    expect(lossOf(skipped, "hosts", "import.conflict.kept")[0]).toMatchObject({ row: 2, severity: "warning" });

    const failing = (await preview((await remap(view, (m) => void (m.options = { ...m.options, conflict: "fail" }))).id)).body;
    expect(failing.can_apply).toBe(false);
    expect(failing.blockers).toEqual(["import.conflict.kept"]);
    const refused = await apply(view.id);
    expect(refused.status).toBe(409);
    expect(refused.body).toMatchObject({ code: "import.plan.blocked", params: { codes: "import.conflict.kept" } });
  });

  it("reports a plan that cannot run as plan_error and blocks apply", async () => {
    const view = await uploaded("nets.csv", "network,description\n192.0.2.0/25,First half\n");
    // 192.0.2.0/24 is a network in the seed: a prefix inside it overlaps.
    const p = (await preview(view.id)).body;
    expect(p.can_apply).toBe(false);
    expect(p.plan_error).toMatchObject({ code: "ipam.prefix.overlap", status: 409 });
    expect(p.blockers).toEqual(["ipam.prefix.overlap"]);
    expect(p.summary.plan).toBeUndefined();
    expect(p.warnings).toEqual([]);
    const res = await apply(view.id);
    expect(res.status).toBe(409);
    expect((res.body as unknown as Problem).code).toBe("ipam.prefix.overlap");
  });
});

describe("GET /imports/{id}/rows", () => {
  interface RowsPage {
    items: Preview["rows"];
    next_cursor: string | null;
    total_rows: number;
    base_revision: number;
  }
  const rows = (id: string, query = "") => send<RowsPage & { code?: string }>("GET", `/api/v1/imports/${id}/rows${query ? `?${query}` : ""}`);

  /** Every row, following next_cursor from the first page to the end. */
  async function walk(id: string, limit: number): Promise<{ items: RowsPage["items"]; pages: number }> {
    const items: RowsPage["items"] = [];
    let pages = 0;
    let query = `limit=${limit}`;
    for (;;) {
      const page = await rows(id, query);
      expect(page.status).toBe(200);
      pages += 1;
      expect(page.body.items.length).toBeLessThanOrEqual(limit);
      items.push(...page.body.items);
      if (!page.body.next_cursor) break;
      query = `limit=${limit}&cursor=${page.body.next_cursor}`;
      expect(pages).toBeLessThan(100);
    }
    return { items, pages };
  }

  it("pages through every row of the latest preview with the cursor, as the preview lists them", async () => {
    const view = await uploaded("ip-plan.xlsx", "x");
    const full = (await preview(view.id, 1000)).body;
    expect(full.total_rows).toBeGreaterThan(200);
    const { items, pages } = await walk(view.id, 100);
    expect(items).toEqual(full.rows);
    expect(pages).toBe(Math.ceil(full.total_rows / 100));
    const first = (await rows(view.id)).body;
    expect(first.items).toHaveLength(200);
    expect(first).toMatchObject({ total_rows: full.total_rows, base_revision: full.base_revision });
    expect(first.next_cursor).toEqual(expect.any(String));
  });

  it("needs a preview of the current mapping: 409 import.preview.stale before it and after a mapping change", async () => {
    const view = await uploaded("ip-plan.csv", planCsv());
    const before = await rows(view.id);
    expect(before.status).toBe(409);
    expect(before.body.code).toBe("import.preview.stale");
    await preview(view.id, 1);
    const page = await rows(view.id, "limit=2");
    expect(page.status).toBe(200);
    expect(page.body.items).toHaveLength(2);
    const cursor = page.body.next_cursor as string;
    await remap(view, (m) => {
      m.options = { ...m.options, conflict: "skip" };
    });
    for (const query of [`limit=2&cursor=${cursor}`, "limit=2"]) {
      const stale = await rows(view.id, query);
      expect(stale.status, query).toBe(409);
      expect(stale.body.code).toBe("import.preview.stale");
    }
    // A new preview makes the rows readable again, from the first row.
    await preview(view.id, 1);
    expect((await rows(view.id, "limit=2")).status).toBe(200);
  });

  it("refuses a bad limit, an unknown parameter and a cursor that is not its own", async () => {
    const view = await uploaded("ip-plan.csv", planCsv());
    const other = await uploaded("ip-plan.csv", planCsv());
    await preview(view.id, 1);
    await preview(other.id, 1);
    for (const query of ["limit=0", "limit=1001", "limit=ten", "rows=2"]) {
      const res = await rows(view.id, query);
      expect(res.status, query).toBe(400);
      expect(res.body.code).toBe("sys.invalid_query");
    }
    const foreign = (await rows(other.id, "limit=1")).body.next_cursor as string;
    for (const cursor of ["not-a-cursor", foreign]) {
      const res = await rows(view.id, `cursor=${cursor}`);
      expect(res.status, cursor).toBe(400);
      expect(res.body.code).toBe("sys.invalid_cursor");
    }
    expect((await rows("0190d1c2-0000-7000-8000-00000000ffff")).status).toBe(404);
  });
});

describe("the preview of the canned workbook", () => {
  async function previewed(edit?: (m: Mapping) => void): Promise<{ view: View; p: Preview }> {
    const view = await uploaded("ip-plan.xlsx", "x");
    const mapped = edit ? await remap(view, edit) : view;
    return { view: mapped, p: (await preview(view.id)).body };
  }

  it("reports every loss of rule 6 of the fixture specification at its cell", async () => {
    const { p } = await previewed();
    const where = (code: string) =>
      allLoss(p)
        .filter((e) => e.code === code)
        .map((e) => [e.sheet, e.row ?? null, e.column ?? null, e.severity]);
    expect(where("import.address.unparsable")).toEqual([["203.0.113.0", 51, "A", "error"]]);
    expect(where("import.column.unmapped")).toEqual([["203.0.113.0", 9, "E", "warning"]]);
    expect(where("import.credential.suspicious")).toEqual([["192.0.2.0", 3, "C", "warning"]]);
    expect(where("import.address.is_network")).toEqual([["192.0.2.64", 2, "A", "warning"]]);
    expect(where("import.credential.numeric")).toEqual([["192.0.2.9", 2, "D", "warning"]]);
    expect(where("import.prefix.unlisted")).toEqual([
      ["203.0.113.128", null, null, "info"],
      ["192.0.2.192", null, null, "info"],
    ]);
    expect(where("import.sheet.empty")).toEqual([["198.51.100.128", null, null, "info"]]);
    expect(where("import.prefix.proposed")).toEqual([
      ["203.0.113.0", 126, "A", "info"],
      ["198.51.100.0", 2, "C", "info"],
    ]);
    expect(where("import.name.normalized").map((e) => e[0])).toEqual(["192.0.2.0", "192.0.2.0", "192.0.2.128", "192.0.2.128", "192.0.2.192"]);
    expect(p.summary.loss.error).toBe(1);
    expect(lossOf(p, "203.0.113.0", "import.address.unparsable")[0]?.detail).toContain("`n/a`");
  });

  it("counts rows: free addresses of the pre-filled lists, imported and skipped rows", async () => {
    const { p } = await previewed();
    expect(p.summary.rows).toEqual({ total: 404, free: 352, imported: 51, skipped: 1 });
    const gear = p.sheets.find((s) => s.sheet === "192.0.2.0");
    expect(gear).toMatchObject({ kind: "network", cidr: "192.0.2.0/24", rows: 255, free: 235, imported: 20, skipped: 0 });
    expect(p.sheets.find((s) => s.sheet === "203.0.113.0")).toMatchObject({ rows: 125, free: 117, imported: 7, skipped: 1 });
    expect(p.sheets.find((s) => s.sheet === "198.51.100.128")).toMatchObject({ rows: 0, imported: 0 });
    const freeRow = p.rows.find((r) => r.location.sheet === "192.0.2.0" && r.location.row === 4);
    expect(freeRow).toMatchObject({ status: "free", items: [] });
    expect(p.rows.length).toBe(404);
  });

  it("creates the networks, the devices and their four NICs, and proposes the prefixes it needs", async () => {
    const { p } = await previewed();
    const counts = Object.fromEntries(p.summary.counts.map((c) => [`${c.kind}/${c.action}`, c.count]));
    expect(counts).toMatchObject({ "prefix/create": 10, "credential/create": 11 });
    expect(counts["host/create"]).toBe(41);
    expect(p.proposals).toEqual([
      { cidr: "198.51.100.64/26", addresses: ["198.51.100.67"], accepted: true, origin: { sheet: "198.51.100.0", row: 2, column: "C" } },
      { cidr: "2001:db8::/64", addresses: ["2001:db8::10"], accepted: true, origin: { sheet: "203.0.113.0", row: 126, column: "A" } },
    ]);
    const device = p.rows.find((r) => r.location.sheet === "198.51.100.0" && r.location.row === 2);
    expect(device?.items.filter((i) => i.key.kind === "interface").map((i) => (i.key as { name: string }).name)).toEqual(["nic1", "nic2", "nic3", "nic4"]);
    expect(device?.items.filter((i) => i.key.kind === "address").map((i) => (i.key as { ip: string }).ip)).toEqual([
      "198.51.100.3",
      "198.51.100.67",
      "203.0.113.3",
      "192.0.2.3",
    ]);
    // The prefix that holds the others is a supernet; every address lying directly in it is warned about.
    expect(p.warnings.every((w) => w.code === "ipam.address.in_supernet")).toBe(true);
    expect(p.warnings.length).toBeGreaterThan(20);
    expect(p.can_apply).toBe(true);
  });

  it("turns the rows of a rejected proposal into import.address.no_prefix and leaves them out", async () => {
    const { p } = await previewed((m) => {
      m.options = { ...m.options, proposals: [{ cidr: "198.51.100.64/26", accept: false }] };
    });
    expect(p.proposals.map((x) => [x.cidr, x.accepted])).toEqual([
      ["198.51.100.64/26", false],
      ["2001:db8::/64", true],
    ]);
    const dropped = lossOf(p, "198.51.100.0", "import.address.no_prefix");
    expect(dropped).toHaveLength(1);
    expect(dropped[0]).toMatchObject({ row: 2, column: "C", severity: "error" });
    expect(allLoss(p).some((e) => e.code === "import.prefix.proposed" && e.sheet === "198.51.100.0")).toBe(false);
    const row = p.rows.find((r) => r.location.sheet === "198.51.100.0" && r.location.row === 2);
    expect(row?.items.some((i) => i.key.kind === "address" && i.key.ip === "198.51.100.67")).toBe(true);
    const created = p.summary.counts.find((c) => c.kind === "prefix" && c.action === "create");
    expect(created?.count).toBe(9);
    // The row still reads as imported; the address itself is gone from the plan.
    expect(p.summary.counts.find((c) => c.kind === "address" && c.action === "create")?.count).toBe(46);
  });

  it("keeps credentials out with the skip policy and lists the columns it left alone", async () => {
    const { p } = await previewed((m) => void (m.options = { ...m.options, credentials: "skip" }));
    expect(p.credentials).toMatchObject({ hosts: 0, new: 0, changed: 0, unchanged: 0, allowed: true });
    expect(p.summary.counts.some((c) => c.kind === "credential")).toBe(false);
    const skipped = allLoss(p).filter((e) => e.code === "import.credential.skipped");
    // Every credential column that holds values is listed once, at its first value.
    expect(skipped.map((e) => `${e.sheet}!${e.column}`).sort()).toEqual(
      [
        "192.0.2.0!C",
        "192.0.2.0!D",
        "192.0.2.64!C",
        "192.0.2.64!D",
        "192.0.2.128!C",
        "192.0.2.128!D",
        "192.0.2.9!C",
        "192.0.2.9!D",
        "198.51.100.0!F",
        "198.51.100.0!G",
      ].sort(),
    );
    expect(allLoss(p).some((e) => e.code === "import.credential.suspicious")).toBe(false);
  });

  it("says in plain words what happens to credentials, counts them, and lets an administrator store them", async () => {
    const { p } = await previewed();
    expect(p.credentials).toMatchObject({ hosts: 11, new: 11, changed: 0, unchanged: 0, allowed: true });
    expect(p.credentials.reason).toBeUndefined();
    expect(p.credentials.statement).toContain("11 hosts have a login or password in the file");
    expect(p.credentials.statement).toContain("stored encrypted in the vault");
    expect(p.credentials.statement).toContain("(11 new, 0 replaced, 0 already stored)");
    const row = p.rows.find((r) => r.location.sheet === "192.0.2.0" && r.location.row === 3);
    expect(row?.items.find((i) => i.key.kind === "credential")).toEqual({ key: { kind: "credential", host: "sw_rack" }, action: "create" });
    expect(JSON.stringify(p)).not.toContain("test-pass");
  });

  it("blocks the import when the account may not store credentials", async () => {
    const view = await uploaded("ip-plan.xlsx", "x");
    startSession(findUserByName("sam") as never, "password");
    // sam is not the owner: the import is invisible, so upload again as sam.
    const own = await uploaded("ip-plan.xlsx", "x");
    expect(view.id).not.toBe(own.id);
    const p = (await preview(own.id)).body;
    expect(p.credentials.allowed).toBe(false);
    expect(p.credentials.reason).toBe("forbidden");
    expect((p.credentials as { detail?: string }).detail).toContain("may not store or reveal operator secrets");
    expect(p.blockers).toContain("import.credentials.vault_required");
    expect(p.can_apply).toBe(false);
    const res = await apply(own.id);
    expect(res.status).toBe(403);
    expect(res.body).toMatchObject({ code: "import.credentials.vault_required" });
    expect((res.body as unknown as Problem).params).toMatchObject({ reason: "forbidden" });
    // Leaving the credential columns out lets the rest through.
    await remap(own, (m) => void (m.options = { ...m.options, credentials: "skip" }));
    expect((await preview(own.id)).body.can_apply).toBe(true);
  });

  it("shows the plan error of the default VRF when the suggested VRF is cleared", async () => {
    const { p } = await previewed((m) => {
      const { vrf: _vrf, ...rest } = m.options ?? {};
      m.options = rest;
    });
    expect(p.can_apply).toBe(false);
    expect(p.plan_error?.code).toBe("ipam.prefix.has_ranges");
    expect(p.blockers).toEqual(["ipam.prefix.has_ranges"]);
    expect(p.proposals).toEqual([]);
  });
});

// ---------------------------------------------------------------------------------
// Warnings that need an acknowledgement

describe("acknowledging a warning", () => {
  const NETWORKS = "network,description\n2001:db8:4::/46,Test site\n";

  it("blocks the apply until the nibble boundary warning is acknowledged", async () => {
    const view = await uploaded("nets.csv", NETWORKS);
    const p = (await preview(view.id)).body;
    expect(p.warnings).toHaveLength(1);
    expect(p.warnings[0]).toMatchObject({ code: "ipam.prefix.nibble_boundary", requires_ack: true });
    expect(p.warnings[0]?.acknowledged).toBeFalsy();
    expect(p.can_apply).toBe(false);
    expect(p.blockers).toEqual(["ipam.plan.unacknowledged"]);

    const blocked = await apply(view.id);
    expect(blocked.status).toBe(409);
    expect(blocked.body).toMatchObject({ code: "import.plan.blocked", params: { codes: "ipam.prefix.nibble_boundary" } });

    const accepted = await apply(view.id, ["ipam.prefix.nibble_boundary"]);
    expect(accepted.status).toBe(202);
    const prefix = [...ipamState().data.prefix.values()].find((x) => x.cidr === "2001:db8:4::/46");
    expect(prefix).toBeDefined();
  });

  it("takes an acknowledgement from the mapping options too", async () => {
    const view = await uploaded("nets.csv", NETWORKS);
    await remap(view, (m) => void (m.options = { ...m.options, acknowledge: ["ipam.prefix.nibble_boundary"] }));
    const p = (await preview(view.id)).body;
    expect(p.warnings[0]?.acknowledged).toBe(true);
    expect(p.can_apply).toBe(true);
    expect((await apply(view.id)).status).toBe(202);
  });
});

// ---------------------------------------------------------------------------------
// Apply

describe("POST /imports/{id}/apply", () => {
  it("creates the objects, the job and the audit record, and refuses a second apply", async () => {
    const view = await uploaded("ip-plan.csv", planCsv());
    const data = ipamState().data;
    const hostsBefore = data.host.size;
    const res = await apply(view.id);
    expect(res.status).toBe(202);
    const jobId = res.body.job_id;
    expect(jobId).toMatch(UUID);
    expect(res.headers.get("location")).toBe(`/jobs/${jobId}`);

    // Hosts with their interfaces, then the addresses on those interfaces.
    const state = ipamState().data;
    expect(state.host.size).toBe(hostsBefore + 3);
    const host = [...state.host.values()].find((h) => h.name === "app01");
    const iface = [...state.interface.values()].find((i) => i.host === host?.id);
    expect(iface).toMatchObject({ name: "nic1", mac: "00:00:5e:00:53:e1" });
    const address = [...state.address.values()].find((a) => a.ip === "192.0.2.201");
    expect(address).toMatchObject({ interface: iface?.id, status: "active" });
    const db01 = [...state.host.values()].find((h) => h.name === "db-01");
    expect(db01?.meta.description).toBe('db;01');
    const reserved = [...state.address.values()].find((a) => a.ip === "192.0.2.203");
    expect(reserved?.status).toBe("reserved");
    expect([...state.address.values()].find((a) => a.ip === "192.0.2.204")).toBeUndefined();

    // The job: an import.apply job that finished, with the three steps of the engine.
    const job = findJob(jobId);
    expect(job?.job.spec).toMatchObject({ kind: "import.apply", title: "jobs.title.import_apply", targets: [{ kind: "import", id: view.id }], timeout: 3600 });
    expect(job?.job.spec.steps.map((s) => s.kind)).toEqual(["import.parse", "import.plan", "import.apply_chunk"]);
    expect(job?.job.state).toBe("succeeded");
    const fetched = await send<{ job: { state: string } }>("GET", `/api/v1/jobs/${jobId}`);
    expect(fetched.body.job.state).toBe("succeeded");

    // The audit log names the import.
    const record = audit.records.find((r) => r.draft.action === "import.apply");
    expect(record?.draft.objects).toEqual([{ kind: "import", id: view.id }]);

    // The view remembers the job.
    const after = (await send<View>("GET", `/api/v1/imports/${view.id}`)).body;
    expect(after.state).toBe("applied");
    expect(after.job_id).toBe(jobId);

    // A second apply and a new mapping are refused; a preview plans nothing new.
    const again = await apply(view.id);
    expect(again.status).toBe(409);
    expect((again.body as unknown as Problem).code).toBe("import.state.conflict");
    const late = await send<Problem>("PUT", `/api/v1/imports/${view.id}/mapping`, after.mapping);
    expect(late.status).toBe(409);
    expect(late.body.code).toBe("import.state.conflict");
    const p = (await preview(view.id)).body;
    expect(p.summary.counts.every((c) => c.action === "unchanged")).toBe(true);
    expect(p.summary.lines).toEqual(["no changes"]);
  });

  it("applies the canned workbook into its own VRF and stores the credentials", async () => {
    const view = await uploaded("ip-plan.xlsx", "x");
    const res = await apply(view.id);
    expect(res.status).toBe(202);
    const state = ipamState().data;
    const vrf = [...state.vrf.values()].find((v) => v.name === "ip-plan");
    expect(vrf).toBeDefined();
    const prefixes = [...state.prefix.values()].filter((p) => p.vrf === vrf?.id);
    expect(prefixes.map((p) => `${p.cidr}:${p.role}`).sort()).toEqual(
      [
        "192.0.2.0/24:supernet",
        "192.0.2.64/26:network",
        "192.0.2.128/26:network",
        "192.0.2.192/31:network",
        "198.51.100.0/26:network",
        "198.51.100.64/26:network",
        "198.51.100.128/26:network",
        "203.0.113.0/24:supernet",
        "203.0.113.128/29:network",
        "2001:db8::/64:network",
      ].sort(),
    );
    expect(prefixes.find((p) => p.cidr === "192.0.2.64/26")?.meta.description).toBe("NAS");
    const edge = [...state.host.values()].find((h) => h.name === "fw-edge");
    const nics = [...state.interface.values()].filter((i) => i.host === edge?.id).map((i) => i.name).sort();
    expect(nics).toEqual(["nic1", "nic2", "nic3", "nic4"]);
    const edgeAddresses = [...state.address.values()].filter((a) => nics.length && a.vrf === vrf?.id && a.interface && [...state.interface.values()].some((i) => i.id === a.interface && i.host === edge?.id));
    expect(edgeAddresses.map((a) => a.ip).sort()).toEqual(["192.0.2.3", "198.51.100.3", "198.51.100.67", "203.0.113.3"]);
    // The credentials are kept as digests, never as text.
    expect(vaultDigests().size).toBe(11);
    expect([...vaultDigests().values()].join("")).not.toContain("test-pass-fw");
    const p = (await preview(view.id)).body;
    expect(p.credentials).toMatchObject({ hosts: 11, new: 0, unchanged: 11 });
  });

  it("gives a retry with the same Idempotency-Key the same job", async () => {
    const view = await uploaded("ip-plan.csv", planCsv());
    const post = async () =>
      answer<{ job_id: string }>(
        await fetch(`/api/v1/imports/${view.id}/apply`, {
          method: "POST",
          headers: { "content-type": "application/json", "idempotency-key": "apply-1" },
          body: "{}",
        }),
      );
    const first = await post();
    const retry = await post();
    expect([first.status, retry.status]).toEqual([202, 202]);
    expect(retry.body.job_id).toBe(first.body.job_id);
    expect(retry.headers.get("location")).toBe(`/jobs/${first.body.job_id}`);
    expect(jobStore.jobs.filter((j) => j.job.spec.targets.some((t) => t.id === view.id))).toHaveLength(1);
    // Another key is another request: the import was applied already.
    expect((await apply(view.id)).status).toBe(409);
  });

  it("answers 404 for an unknown import and takes a body without acknowledgements", async () => {
    const unknown = await send<Problem>("POST", "/api/v1/imports/0190d1c2-0000-7000-8000-00000000ffff/apply", {});
    expect(unknown.status).toBe(404);
    const view = await uploaded("ip-plan.csv", planCsv());
    const bare = await answer<{ job_id: string }>(await fetch(`/api/v1/imports/${view.id}/apply`, { method: "POST" }));
    expect(bare.status).toBe(202);
  });
});

// ---------------------------------------------------------------------------------
// Discarding

describe("DELETE /imports/{id}", () => {
  it("discards the upload", async () => {
    const view = await uploaded("ip-plan.csv", planCsv());
    const res = await send<undefined>("DELETE", `/api/v1/imports/${view.id}`);
    expect(res.status).toBe(204);
    expect(res.body).toBeUndefined();
    expect((await send<Problem>("GET", `/api/v1/imports/${view.id}`)).status).toBe(404);
    expect((await send<Problem>("DELETE", `/api/v1/imports/${view.id}`)).status).toBe(404);
    expect(importRecords().size).toBe(0);
  });

  it("still discards an import that was applied: the objects stay", async () => {
    const view = await uploaded("ip-plan.csv", planCsv());
    expect((await apply(view.id)).status).toBe(202);
    expect((await send<undefined>("DELETE", `/api/v1/imports/${view.id}`)).status).toBe(204);
    expect([...ipamState().data.host.values()].some((h) => h.name === "app01")).toBe(true);
  });
});

// ---------------------------------------------------------------------------------
// Export

describe("GET /exports/{kind}.csv", () => {
  async function download(kind: string): Promise<{ res: Response; text: string; rows: string[][] }> {
    const res = await fetch(`/api/v1/exports/${kind}.csv`);
    // `text()` drops a byte order mark; keep it to see it.
    const text = new TextDecoder("utf-8", { ignoreBOM: true }).decode(await res.arrayBuffer());
    const rows = text
      .replace(BOM, "")
      .split("\r\n")
      .filter((line) => line !== "")
      .map((line) => line.split(","));
    return { res, text, rows };
  }

  it("serves the three files with the headers of the import vocabulary, a BOM and CRLF", async () => {
    for (const [kind, header] of [
      ["prefixes", "prefix,vrf,role,status,vlan,vlan_name,site,alarm_warn,alarm_crit,alloc,description,tags,custom.rack"],
      ["hosts", "host,tenant,mode,lock,site,description,interfaces,tags,custom.asset_tag,custom.rack,custom.warranty_until"],
      ["addresses", "address,vrf,status,dns_name,host,interface,mac,duid,description,tags"],
    ] as const) {
      const { res, text } = await download(kind);
      expect(res.status, kind).toBe(200);
      expect(res.headers.get("content-type")).toBe("text/csv; charset=utf-8");
      expect(res.headers.get("content-disposition")).toBe(`attachment; filename="${kind}.csv"`);
      expect(text.startsWith(BOM)).toBe(true);
      expect(text.endsWith("\r\n")).toBe(true);
      expect(text.slice(1).split("\r\n")[0]).toBe(header);
    }
  });

  it("writes the cells as the server's export does and leaves soft-deleted objects out", async () => {
    const addresses = (await download("addresses")).rows;
    expect(addresses).toContainEqual(["192.0.2.1", "default", "active", "gw.example.test", "gw", "eth0", "00:00:5e:00:53:01", "", "", ""]);
    expect(addresses.map((r) => r[0])).not.toContain("192.0.2.35");
    // The VRF isolated has its own 192.0.2.10; rows are ordered by VRF, then address.
    expect(addresses.filter((r) => r[0] === "192.0.2.10").map((r) => r[1])).toEqual(["default", "isolated"]);
    expect(addresses.find((r) => r[0] === "192.0.2.10" && r[1] === "isolated")?.[4]).toBe("");

    const hosts = (await download("hosts")).rows;
    expect(hosts.map((r) => r[0])).not.toContain("old-printer");
    expect(hosts).toContainEqual(["nas", "default", "reserved", "true", "", "Storage server", "eth0=00:00:5e:00:53:0b", "infra", "A-0042", "", ""]);
    expect(hosts.find((r) => r[0] === "ap-garage")?.[4]).toBe("Garage");
    // A host without a known MAC address lists its interface by name only.
    expect(hosts.find((r) => r[0] === "doorbell")?.[6]).toBe("eth0");

    const prefixes = (await download("prefixes")).rows;
    expect(prefixes.map((r) => r[0])).not.toContain("2001:db8:0:99::/64");
    expect(prefixes).toContainEqual(["192.0.2.0/24", "default", "network", "active", "10", "LAN", "Home", "80", "95", "lowest", "LAN", "home", ""]);
    expect(prefixes.find((r) => r[0] === "203.0.113.0/24")?.[2]).toBe("supernet");
  });

  it("needs a session", async () => {
    resetMockDb("signed-out");
    const res = await fetch("/api/v1/exports/hosts.csv");
    expect(res.status).toBe(401);
  });

  it("round trips: importing the three exports plans no change", async () => {
    const files = await Promise.all(
      ["prefixes", "hosts", "addresses"].map(async (kind) => [`${kind}.csv`, (await download(kind)).text] as [string, string]),
    );
    const res = await upload(...files);
    expect(res.status).toBe(201);
    expect(res.body.sheets.map((s) => [s.sheet, s.suggested.kind])).toEqual([
      ["prefixes", "list"],
      ["hosts", "list"],
      ["addresses", "list"],
    ]);
    const p = (await preview(res.body.id)).body;
    expect(p.plan_error).toBeUndefined();
    expect(p.summary.counts.length).toBeGreaterThan(0);
    expect(p.summary.counts.filter((c) => c.action !== "unchanged")).toEqual([]);
    expect(p.summary.lines).toEqual(["no changes"]);
    expect(p.summary.rows.skipped).toBe(0);
    expect(p.summary.loss.error).toBe(0);
    expect(p.can_apply).toBe(true);
    expect(p.warnings).toEqual([]);
    expect(p.summary.counts.map((c) => c.kind).sort()).toEqual(["address", "host", "interface", "prefix", "vlan"]);
  });

  it("round trips addresses.csv alone, with the ids of the seed untouched", async () => {
    const { text } = await download("addresses");
    const view = await uploaded("addresses.csv", text);
    expect(view.sheets[0]?.suggested.kind).toBe("list");
    const p = (await preview(view.id)).body;
    expect(p.summary.counts.filter((c) => c.action !== "unchanged")).toEqual([]);
    expect(p.summary.rows.imported).toBe(p.summary.rows.total);
    expect(ADDRESS_IDS["192.0.2.1"]).toBeDefined();
    expect(HOST_IDS.gw).toBeDefined();
  });
});
