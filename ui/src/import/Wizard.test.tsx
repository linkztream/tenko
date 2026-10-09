// The import wizard against the import mock API (src/api/mock/routes-import.ts): upload a
// CSV file through the file input, read the suggested mapping, change a target, preview,
// acknowledge a warning, apply, and follow the job to the result; resume an import from the URL
// and discard one. Uploads go through Node's FormData and File (see import-testkit.ts).
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { importRecords } from "../api/mock/import-store";
import { filesForm, releaseNodeFormData, testFile, useNodeFormData } from "../api/mock/import-testkit";
import { jobStore } from "../api/mock/job-store";
import { ipamState } from "../api/mock/ipam/api";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { signInAlex } from "../auth/account/testkit";
import { api } from "../api/client";
import type { ImportView } from "./api";
import Wizard from "./Wizard";

const PLAN_CSV = [
  "IP,Name,Description,MAC,Status",
  "192.0.2.201,app01,Front end,00-00-5E-00-53-E1,active",
  "192.0.2.202,app02,,00-00-5E-00-53-E2,",
  "192.0.2.203,db01,Primary database,,reserved",
].join("\r\n");

// The view is rendered without the shell's <main>, which holds all page content in the app.
const NO_SHELL = { disable: ["region"] } as const;

const NETWORKS_CSV = "network,description\n2001:db8:4::/46,Test site\n";

beforeAll(useNodeFormData);
afterAll(releaseNodeFormData);
beforeEach(async () => {
  await signInAlex();
});

function open(url = "/ipam/import") {
  return renderRoute(Wizard, { url, path: "/ipam/import" });
}

/** Picks files in the file input and starts the upload. */
async function upload(name: string, content: string) {
  const input = await screen.findByTestId("import-file-input");
  fireEvent.change(input, { target: { files: [testFile(name, content)] } });
  const start = await screen.findByTestId("import-upload-start");
  await waitFor(() => expect((start as HTMLButtonElement).disabled).toBe(false));
  fireEvent.click(start);
  return screen.findByTestId("import-mapping");
}

/** The preview of a workbook has hundreds of rows to render; give it time. */
const SLOW = { timeout: 15_000 };

async function preview() {
  fireEvent.click(await screen.findByTestId("import-preview"));
  return screen.findByTestId("import-summary", {}, SLOW);
}

/** Uploads through the API, for the tests that resume an import. */
async function stage(name: string, content: string): Promise<ImportView> {
  return api.post("/api/v1/imports", { body: filesForm([testFile(name, content)]), idempotencyKey: null });
}

function columnRow(column: string): HTMLElement {
  const row = screen
    .getAllByTestId("import-column")
    .find((el) => el.dataset.column === column);
  if (!row) throw new Error(`no column ${column}`);
  return row;
}

describe("import wizard", () => {
  it("uploads a CSV file and shows the columns with their suggested targets", async () => {
    open();
    expect(await screen.findByTestId("import-upload")).toBeTruthy();
    const mapping = await upload("ip-plan.csv", PLAN_CSV);

    const sheet = within(mapping).getByTestId("import-sheet");
    expect(sheet.dataset.sheet).toBe("ip-plan");
    expect(screen.getAllByTestId("import-column").map((row) => [row.dataset.column, row.dataset.target])).toEqual([
      ["A", "address"],
      ["B", "host"],
      ["C", "description"],
      ["D", "mac"],
      ["E", "status"],
    ]);
    // The samples of a column are joined with a middle dot.
    const dot = String.fromCharCode(0xb7);
    expect(within(columnRow("B")).getByText(["app01", "app02", "db01"].join(` ${dot} `))).toBeTruthy();
    expect((within(sheet).getByTestId("import-sheet-kind") as HTMLSelectElement).value).toBe("list");
    expect(importRecords().size).toBe(1);
  });

  it("changes a target, previews the import, applies it and links what was created", async () => {
    const { location } = open();
    await upload("ip-plan.csv", PLAN_CSV);

    // The status column is left out: the preview lists its values instead of importing them.
    const select = within(columnRow("E")).getByTestId("import-column-target") as HTMLSelectElement;
    fireEvent.change(select, { target: { value: "ignore" } });
    await waitFor(() => expect(columnRow("E").dataset.target).toBe("ignore"));

    const summary = await preview();
    const kinds = within(summary).getAllByRole("row").map((row) => row.getAttribute("data-kind"));
    expect(kinds).toEqual(expect.arrayContaining(["host", "interface", "address"]));
    const losses = screen.getAllByTestId("import-loss-entry");
    expect(losses.map((el) => el.dataset.code)).toContain("import.column.unmapped");
    const apply = screen.getByTestId("import-apply") as HTMLButtonElement;
    await waitFor(() => expect(apply.disabled).toBe(false));
    expect(location()).toContain("id=");
    const importId = [...importRecords().keys()][0];

    fireEvent.click(apply);
    const result = await screen.findByTestId("import-result");
    await waitFor(() => expect(within(result).getByTestId("import-again")).toBeTruthy());

    // What was created is linked, and the job that did it.
    const created = await screen.findByTestId("import-created");
    const links = within(created).getAllByRole("link");
    expect(links.map((a) => a.textContent)).toEqual(expect.arrayContaining(["app01", "192.0.2.201 (default)"]));
    expect(links.find((a) => a.textContent === "app01")?.getAttribute("href")).toContain("app01");
    const jobLink = within(result).getByTestId("import-open-job");
    const job = jobStore.jobs.find((j) => j.job.spec.targets.some((t) => t.id === importId));
    expect(job?.job.state).toBe("succeeded");
    expect(jobLink.getAttribute("href")).toContain(job?.job.id ?? "missing");
    expect([...ipamState().data.host.values()].some((h) => h.name === "app01")).toBe(true);
  });

  it("lists the warning that needs an acknowledgement and keeps apply off until it is given", async () => {
    open();
    await upload("networks.csv", NETWORKS_CSV);
    await preview();
    const apply = screen.getByTestId("import-apply") as HTMLButtonElement;
    expect(apply.disabled).toBe(true);
    expect(screen.getByTestId("import-blockers").querySelector('[data-code="ipam.plan.unacknowledged"]')).not.toBeNull();
    const ack = (await screen.findByTestId("import-ack")) as HTMLInputElement;
    expect(ack.dataset.code).toBe("ipam.prefix.nibble_boundary");
    expect(ack.checked).toBe(false);
    fireEvent.click(ack);
    await waitFor(() => expect(ack.checked).toBe(true));
  });

  // The preview says can_apply: false with the blocker ipam.plan.unacknowledged, as the server
  // does; the acknowledgement given here clears it, and apply sends it.
  it("applies a warning once it is acknowledged", async () => {
    open();
    await upload("networks.csv", NETWORKS_CSV);
    await preview();
    const apply = screen.getByTestId("import-apply") as HTMLButtonElement;
    fireEvent.click(await screen.findByTestId("import-ack"));
    await waitFor(() => expect(apply.disabled).toBe(false));
    expect(screen.queryByTestId("import-blockers")).toBeNull();
    fireEvent.click(apply);
    await screen.findByTestId("import-created");
    expect([...ipamState().data.prefix.values()].some((p) => p.cidr === "2001:db8:4::/46")).toBe(true);
  });

  // A list of hosts (the hosts.csv of the export is one) names its rows by host, not by address.
  it("previews a list of hosts that has no address column", async () => {
    open();
    await upload("hosts.csv", "host,mode\napp01,static\n");
    const button = (await screen.findByTestId("import-preview")) as HTMLButtonElement;
    expect(button.disabled).toBe(false);
  });

  it("shows the loss report and the proposals of a workbook and lets a proposal be rejected", async () => {
    open();
    await upload("ip-plan.xlsx", "x");
    expect(screen.getAllByTestId("import-sheet")).toHaveLength(10);
    expect((screen.getByTestId("import-option-vrf") as HTMLInputElement).value).toBe("ip-plan");
    await preview();
    const codes = new Set(screen.getAllByTestId("import-loss-entry").map((el) => el.dataset.code));
    for (const code of [
      "import.address.unparsable",
      "import.column.unmapped",
      "import.credential.suspicious",
      "import.address.is_network",
      "import.credential.numeric",
      "import.prefix.unlisted",
      "import.sheet.empty",
      "import.prefix.proposed",
    ]) {
      expect(codes.has(code), code).toBe(true);
    }
    expect(within(screen.getByTestId("import-credentials")).getByText(/11 hosts/)).toBeTruthy();
    const proposals = screen.getByTestId("import-proposals");
    const box = within(proposals).getAllByRole("checkbox")[0] as HTMLInputElement;
    expect(box.checked).toBe(true);
    fireEvent.click(box);
    await waitFor(() => {
      const codesNow = screen.getAllByTestId("import-loss-entry").map((el) => el.dataset.code);
      expect(codesNow).toContain("import.address.no_prefix");
    });
  });

  it("resumes an import named in the URL at its mapping", async () => {
    const view = await stage("ip-plan.csv", PLAN_CSV);
    open(`/ipam/import?id=${view.id}`);
    expect(await screen.findByTestId("import-mapping")).toBeTruthy();
    expect(screen.getAllByTestId("import-column")).toHaveLength(5);
    expect(screen.queryByTestId("import-upload")).toBeNull();
  });

  it("resumes an applied import at its result and falls back to the upload for an unknown one", async () => {
    const view = await stage("ip-plan.csv", PLAN_CSV);
    const accepted = await api.post("/api/v1/imports/{id}/apply", { path: { id: view.id }, body: { acknowledge: [] }, idempotencyKey: "apply-1" });
    const first = open(`/ipam/import?id=${view.id}`);
    const result = await screen.findByTestId("import-result");
    expect(within(result).getByTestId("import-open-job").getAttribute("href")).toContain(accepted.job_id);
    first.unmount();

    open("/ipam/import?id=0190d1c2-0000-7000-8000-00000000ffff");
    expect(await screen.findByTestId("import-upload")).toBeTruthy();
    expect((await screen.findByRole("alert")).textContent).toMatch(/import/i);
  });

  it("discards the import and returns to the upload step", async () => {
    const { location } = open();
    await upload("ip-plan.csv", PLAN_CSV);
    expect(importRecords().size).toBe(1);
    fireEvent.click(await screen.findByTestId("import-discard"));
    expect(await screen.findByTestId("import-upload")).toBeTruthy();
    await waitFor(() => expect(importRecords().size).toBe(0));
    expect(location()).not.toContain("id=");
  });

  it("passes the accessibility checks on the mapping and the preview", async () => {
    open();
    await upload("ip-plan.csv", PLAN_CSV);
    expect(await axeViolations(document.body, NO_SHELL)).toEqual([]);
    await preview();
    await screen.findByTestId("import-changes");
    expect(await axeViolations(document.body, NO_SHELL)).toEqual([]);
  });

  it("passes the accessibility checks on the mapping and the preview of the workbook", async () => {
    open();
    await upload("ip-plan.xlsx", "x");
    expect(await axeViolations(document.body, NO_SHELL)).toEqual([]);
    await preview();
    await screen.findByTestId("import-loss");
    expect(await axeViolations(document.body, NO_SHELL)).toEqual([]);
  });
});
