// Scenario: cluster nodes end to end (OPS-04 enrolment and mutual TLS, OPS-08 the agreed protocol,
// OPS-28 the observation buffer; docs/cluster.md). The controller runs with the internal CA and
// a cluster port of its own with one-second heartbeats (`serverOptions: { cluster: true }`); a
// second `tenko` process (support/probe.ts) is the probe node: `tenko node enrol` with the token
// the UI showed, then `tenko serve --roles probe`, which connects over mutual TLS. Everything the
// nodes pages show is checked in the browser and against the public API.
//
// - An administrator creates an enrolment token in the dialog of the nodes page. The token, the
//   fingerprint of the CA root and the command to run on the node are shown once; afterwards the
//   token list shows the waiting token without its text, in the page and in the API. The token
//   read from the dialog enrols the probe (the registry and the token list follow it live), the
//   probe connects and heartbeats, the node panel and the dashboard tile show it, and a batch it
//   sends reaches the observations. A used token stays in the list, marked used (docs/cluster.md,
//   section 1.1), and the same token enrols nothing twice.
// - Revoking the node from its panel removes it from the registry, makes the probe report that it
//   was revoked, is audited, and leaves the job of the edit on its job page.
// - A token deleted before use cannot enrol anything and leaves nothing on the node.
// - The nodes page with a connected node and the token dialog render in Swedish.
//
// Arrangement: tokens that a scenario does not test through the dialog are created through the
// API; the observation batch is queued with `tenko node inject` (the diagnostic path from a
// probe to the reconciler). Documentation values only: node address 192.0.2.20, ARP sightings of
// 192.0.2.30 and 192.0.2.31, MAC 00:00:5e:00:53:30.
//
// What stays manual: certificate renewal and expiry (a year-long certificate, covered by the
// Rust suites), a node that shares no protocol major with the controller (`nodes-version-mismatch`,
// `node-mismatch`; the transport tests and the component tests cover it), token expiry (the
// shortest lifetime is a minute), the copy buttons of the token dialog (they need the clipboard
// permission of the browser), the buffer filling during an outage (`node_cluster.rs`), roles other
// than `probe` (their processes do not exist yet) and the nodes page as a viewer.

import { existsSync } from "node:fs";
import { join } from "node:path";
import type { Locator } from "@playwright/test";
import { ADMIN, ApiError, type Api, type Schemas } from "./support/api";
import { expect, test } from "./support/fixtures";
import { expectRendered } from "./support/i18n";
import { ProbeNode } from "./support/probe";
import { cell, gridRow, withId, withKey } from "./support/ui";

type NodeView = Schemas["NodeView"];
type Created = Schemas["CreatedEnrolment"];

test.use({ transport: "internal_ca", serverOptions: { cluster: true } });

/** The id the first node of a controller gets (docs/cluster.md, section 1.3). */
const NODE = 1001;
const NODE_NAME = "probe-dmz";
const NODE_ADDRESS = "192.0.2.20";

/** The hexadecimal digits of a fingerprint, whatever its separators and case. */
function digits(text: string): string {
  return text.replace(/[^0-9a-f]/gi, "").toLowerCase();
}

/** The identifier an audit record and a job give a node as an object (the node number in the last group). */
function nodeObject(node: number): string {
  return `00000000-0000-0000-0000-${node.toString(16).padStart(12, "0")}`;
}

/** The non-empty lines of an element's text. */
async function textLines(locator: Locator): Promise<string[]> {
  return (await locator.innerText())
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line !== "");
}

/** A token through the API, for the scenarios that do not test the dialog. */
async function createToken(api: Api, name: string): Promise<Created> {
  return api.post<Created>("/nodes/enrolments", { roles: ["probe"], name }, { idempotencyKey: null });
}

/** The node as the API shows it. */
function nodeView(api: Api, id = NODE): Promise<NodeView> {
  return api.get<NodeView>(`/nodes/${id}`);
}

/** Waits until the controller counts the node as connected and returns its view. */
async function waitForConnected(api: Api, id = NODE): Promise<NodeView> {
  await expect
    .poll(async () => (await nodeView(api, id)).connected, { message: `node ${id} to be connected`, timeout: 30_000 })
    .toBe(true);
  return nodeView(api, id);
}

/** The state of the node process, from `tenko node status --json`. */
async function processState(probe: ProbeNode): Promise<string> {
  const status = await probe.status();
  return String((status.process as { state?: string } | null | undefined)?.state ?? "");
}

/** The error of a call that must fail. */
async function failureOf(call: Promise<unknown>): Promise<ApiError> {
  try {
    await call;
  } catch (error) {
    if (error instanceof ApiError) return error;
    throw error;
  }
  throw new Error("the call succeeded");
}

test("a token is shown once, enrols a probe that connects, and the node shows in the registry, its panel, the dashboard and the observations", async ({
  page,
  api,
  server,
  signedIn,
}) => {
  expect(signedIn.session.user.name).toBe(ADMIN.name);
  expect(digits(server.caFingerprint)).toHaveLength(64);
  const probe = await ProbeNode.create();
  try {
    let token = "";
    let secret = "";
    let enrolmentId = "";

    await test.step("the dialog shows the token, the fingerprint and the command once", async () => {
      await page.goto("/nodes");
      await expect(page.getByTestId("page-nodes")).toBeVisible();
      await expect(page.getByTestId("nodes-empty")).toBeVisible();
      await expect(page.getByTestId("nodes-cluster")).toContainText(`127.0.0.1:${server.clusterPort}`);

      await page.getByTestId("nodes-enrol").click();
      const form = page.getByTestId("dialog-enrol");
      await expect(form).toBeVisible();
      await expect(form.getByTestId("field-role-probe")).toBeChecked();
      await expect(form.getByTestId("field-role-dns")).not.toBeChecked();
      await expect(form.getByTestId("field-role-dhcp")).not.toBeChecked();
      await form.getByTestId("field-name").fill(NODE_NAME);
      await form.getByTestId("form-submit").click();

      const dialog = page.getByTestId("dialog-enrol-token");
      await expect(dialog).toBeVisible();
      await expect(form).toHaveCount(0);
      await expect(dialog.getByTestId("enrol-once")).toBeVisible();
      token = (await dialog.getByTestId("enrol-token").innerText()).trim();
      expect(token).toMatch(/^tnk1\.[0-9a-f]{32}\.[A-Za-z0-9_-]{43}$/);
      const [, id, tail] = token.split(".");
      enrolmentId = id!;
      secret = tail!;

      // The fingerprint is the one the controller printed at start; the command names this
      // controller, the token and the fingerprint.
      expect(digits(await dialog.getByTestId("enrol-fingerprint").innerText())).toBe(digits(server.caFingerprint));
      const command = (await dialog.getByTestId("enrol-command").innerText()).trim();
      expect(command).toMatch(/^tenko node enrol --controller /);
      expect(command).toContain(`--controller ${server.url}`);
      expect(command).toContain(`--token ${token}`);
      expect(command.toLowerCase()).toContain(digits(server.caFingerprint));

      await dialog.getByTestId("enrol-done").click();
      await expect(dialog).toHaveCount(0);
    });

    await test.step("afterwards the token list shows the waiting token without its text", async () => {
      const row = page.getByTestId("nodes-tokens").getByTestId("enrolment");
      await expect(row).toHaveCount(1);
      await expect(row).toHaveAttribute("data-state", "pending");
      const list = await api.get<Schemas["EnrolmentList"]>("/nodes/enrolments");
      expect(list.items).toHaveLength(1);
      const waiting = list.items[0]!;
      expect(waiting.id.replaceAll("-", "")).toBe(enrolmentId);
      expect(waiting).toMatchObject({ name: NODE_NAME, roles: ["probe"], state: "pending" });
      expect(waiting.used ?? null).toBeNull();
      await expect(row).toHaveAttribute("data-id", waiting.id);
      expect(JSON.stringify(list)).not.toContain(secret);
      expect(await page.content()).not.toContain(secret);

      // A reload forgets the dialog for good: the page has the row and no token text.
      await page.reload();
      await expect(page.getByTestId("page-nodes")).toBeVisible();
      await expect(row).toHaveCount(1);
      await expect(row).toHaveAttribute("data-state", "pending");
      await expect(page.getByTestId("dialog-enrol-token")).toHaveCount(0);
      expect(await page.content()).not.toContain(secret);
    });

    const nodeRow = gridRow(page, "nodes", NODE_NAME);
    const tokenRow = page.getByTestId("nodes-tokens").getByTestId("enrolment");

    await test.step("the probe enrols with that token and the registry follows", async () => {
      const enrolled = await probe.enrol(server, token, { name: NODE_NAME, address: NODE_ADDRESS });
      expect(enrolled.code, enrolled.stderr).toBe(0);
      expect(enrolled.stdout).toContain(`enrolled as node ${NODE} (${NODE_NAME}) with role(s) probe`);
      expect(enrolled.stdout).toContain(`localhost:${server.clusterPort}`);

      // The node is in the registry before its process runs: enrolled, not connected.
      await expect(nodeRow).toBeVisible();
      await expect(nodeRow).toHaveAttribute("data-id", String(NODE));
      await expect(page.getByTestId("nodes-empty")).toHaveCount(0);
      await expect(cell(nodeRow, "address")).toHaveText(NODE_ADDRESS);
      await expect(nodeRow.getByTestId("node-link")).toHaveAttribute("data-state", "disconnected");
      const enrolledNode = await nodeView(api);
      expect(enrolledNode).toMatchObject({ name: NODE_NAME, roles: ["probe"], address: NODE_ADDRESS, connected: false });

      // The token is used and says which node it enrolled.
      await expect(tokenRow).toHaveCount(1);
      await expect(tokenRow).toHaveAttribute("data-state", "used");
      const used = (await api.get<Schemas["EnrolmentList"]>("/nodes/enrolments")).items[0]!;
      expect(used.state).toBe("used");
      expect(used.used?.node).toBe(NODE);
      const enrolledLink = tokenRow.getByTestId("enrolment-node");
      await expect(enrolledLink).toHaveAttribute("data-id", String(NODE));
      await expect(enrolledLink).toHaveAttribute("href", `/nodes/${NODE}`);

      // The same token enrols nothing a second time: another node directory is refused.
      const second = await ProbeNode.create();
      try {
        const again = await second.enrol(server, token, { name: "probe-lab" });
        expect(again.code).toBe(6);
        expect(again.stderr).toContain("cluster.enrolment.used");
        expect(existsSync(join(second.dataDir, "node", "identity.json"))).toBe(false);
      } finally {
        await second.stop();
      }
      expect((await api.get<Schemas["Page_NodeView"]>("/nodes")).items).toHaveLength(1);
    });

    await test.step("the node process connects and the list shows it connected", async () => {
      await probe.serve();
      await expect(nodeRow.getByTestId("node-link")).toHaveAttribute("data-state", "connected");
      const view = await waitForConnected(api);
      expect(view).toMatchObject({ name: NODE_NAME, roles: ["probe"], address: NODE_ADDRESS, connected: true });
      expect(view.protocol.agreed).toBe(1);
      expect(view.connection?.major).toBe(1);
      expect(view.connection?.peer).toBeTruthy();
      expect(view.version).toBeTruthy();

      // The heartbeats keep coming: the last beat moves on (the interval is one second).
      const beat = (node: NodeView) => Date.parse(node.connection?.last_beat ?? "") || 0;
      const first = beat(view);
      await expect
        .poll(async () => beat(await nodeView(api)), { message: "the last heartbeat to advance", timeout: 30_000 })
        .toBeGreaterThan(first);
      expect((await nodeView(api)).last_seen).toBeTruthy();
    });

    await test.step("the panel shows the roles, the address, the certificate, the connection and the buffer", async () => {
      await cell(nodeRow, "address").click();
      await expect(page).toHaveURL(new RegExp(`/nodes/${NODE}$`));
      const panel = page.getByTestId("node-panel");
      await expect(panel).toBeVisible();
      await expect(panel).toHaveAttribute("data-id", String(NODE));
      await expect(panel.getByTestId("node-link")).toHaveAttribute("data-state", "connected");
      await expect(panel).toContainText(NODE_ADDRESS);

      const view = await waitForConnected(api);
      const connection = view.connection!;
      await expect(panel.getByTestId("node-certificate")).toContainText(view.certificate.serial);
      const lines = panel.getByTestId("node-connection");
      await expect.poll(() => textLines(lines)).toContain(connection.peer!);
      await expect.poll(() => textLines(lines)).toContain(String(connection.major));
      expect(connection.buffered_batches).toBe(0);
      await expect(panel.getByTestId("node-buffer")).toContainText(String(connection.buffered_batches));
      await expect(panel.getByTestId("node-revoke")).toBeVisible();
    });

    await test.step("the dashboard counts the connected node once the status does", async () => {
      await expect
        .poll(
          async () => {
            const cluster = (await api.get<Schemas["SystemStatus"]>("/system/status")).cluster;
            return [cluster?.nodes, cluster?.connected];
          },
          { message: "the status to count the node and its connection", timeout: 30_000 },
        )
        .toEqual([1, 1]);
      await page.goto("/");
      await expect(page.getByTestId("page-dashboard")).toBeVisible();
      // U3: the nodes block of the start page's system panel, drawn once the cluster has a node.
      await expect(page.getByTestId("dashboard-nodes")).toBeVisible();
      await expect(page.getByTestId("dashboard-nodes")).toHaveAttribute("data-value", "1");
      await page.getByTestId("dashboard-nodes").click();
      await expect(page.getByTestId("page-nodes")).toBeVisible();
      await expect(page).toHaveURL(/\/nodes$/);
    });

    await test.step("a batch from the node reaches the reconciler and the observations view", async () => {
      const now = new Date().toISOString();
      await probe.inject({
        method: "arp",
        complete: false,
        collected_at: now,
        sightings: [
          { observed_at: now, subject: { type: "address", data: { ip: "192.0.2.30", mac: "00:00:5e:00:53:30" } } },
          { observed_at: now, subject: { type: "address", data: { ip: "192.0.2.31" } } },
        ],
      });
      const source = `probe:${NODE}:arp`;
      let facts: Schemas["ObservedFact"][] = [];
      await expect
        .poll(
          async () => {
            facts = (await api.get<Schemas["Page_ObservedFact"]>("/observations", { source })).items;
            return facts.length;
          },
          { message: "the two sightings to reach the reconciler", timeout: 30_000 },
        )
        .toBe(2);
      expect(facts.map((fact) => fact.source_key)).toEqual([source, source]);
      expect(facts.map((fact) => (fact.observed.data as { ip?: string }).ip).sort()).toEqual(["192.0.2.30", "192.0.2.31"]);

      await page.goto(`/discovery/observations?source=${source}`);
      await expect(page.getByTestId("page-discovery-observations")).toBeVisible();
      await expect(page.getByTestId("filter-source")).toBeVisible();
      const grid = page.getByTestId("grid-observations");
      await expect(grid.getByTestId("row")).toHaveCount(2);
      for (const fact of facts) {
        const row = withKey(grid, "row", fact.subject_key);
        const data = fact.observed.data as { ip: string; mac?: string | null };
        await expect(row).toHaveAttribute("data-id", `${fact.source_key}|${fact.subject_key}`);
        await expect(cell(row, "observed")).toContainText(data.ip);
        if (data.mac) await expect(cell(row, "observed")).toContainText(data.mac);
        await expect(cell(row, "source")).toContainText(NODE_NAME);
        await expect(cell(row, "state").locator('[data-state="current"]')).toBeVisible();
        await expect(cell(row, "sightings")).toHaveText("1");
      }
    });
  } finally {
    await probe.stop();
  }
});

test("revoking a node from its panel removes it, makes the probe report the revocation, is audited and leaves a succeeded job", async ({
  page,
  api,
  server,
  signedIn,
}) => {
  expect(signedIn.session.user.name).toBe(ADMIN.name);
  const created = await createToken(api, NODE_NAME);
  const probe = await ProbeNode.create();
  try {
    const enrolled = await probe.enrol(server, created.token, { name: NODE_NAME, address: NODE_ADDRESS });
    expect(enrolled.code, enrolled.stderr).toBe(0);
    await probe.serve();
    await waitForConnected(api);
    expect(await processState(probe)).toBe("connected");

    await test.step("the administrator revokes the node and confirms", async () => {
      await page.goto(`/nodes/${NODE}`);
      const panel = page.getByTestId("node-panel");
      await expect(panel).toBeVisible();
      await expect(panel.getByTestId("node-link")).toHaveAttribute("data-state", "connected");
      await panel.getByTestId("node-revoke").click();
      const confirm = page.getByTestId("dialog-confirm");
      await expect(confirm).toBeVisible();
      // Nothing happens before the confirmation.
      expect((await nodeView(api)).name).toBe(NODE_NAME);
      await confirm.getByTestId("confirm-ok").click();
      await expect(withKey(page, "toast", "ok")).toBeVisible();
      await expect(confirm).toHaveCount(0);
    });

    await test.step("the node leaves the registry", async () => {
      await expect(page).toHaveURL(/\/nodes$/);
      await expect(page.getByTestId("node-panel")).toHaveCount(0);
      await expect(page.getByTestId("nodes-empty")).toBeVisible();
      await expect(page.getByTestId("grid-nodes").getByTestId("row")).toHaveCount(0);
      const gone = await failureOf(nodeView(api));
      expect(gone.status).toBe(404);
      expect(gone.code).toBe("cluster.node.not_found");
      expect((await api.get<Schemas["Page_NodeView"]>("/nodes")).items).toHaveLength(0);
      await expect
        .poll(async () => {
          const cluster = (await api.get<Schemas["SystemStatus"]>("/system/status")).cluster;
          return [cluster?.nodes, cluster?.connected];
        }, { message: "the status to drop the node", timeout: 30_000 })
        .toEqual([0, 0]);
    });

    await test.step("the probe learns that it was revoked", async () => {
      expect(await probe.waitForOutput("cluster.node.revoked")).toBe(true);
      await expect.poll(() => processState(probe), { message: "the node process to report the revocation", timeout: 30_000 }).toBe("revoked");
    });

    await test.step("the audit log has the creation, the enrolment and the revocation", async () => {
      const log = (await api.get<Schemas["Page_AuditRecord"]>("/audit", { order: "asc", limit: 1000 })).items;
      const find = (action: string) => log.filter((record) => record.draft.action === action);
      expect(find("cluster.enrolment.create")).toHaveLength(1);
      const enrol = find("cluster.node.enrol");
      expect(enrol).toHaveLength(1);
      expect(enrol[0]!.draft.outcome.kind).toBe("success");
      const revoke = find("cluster.node.revoke");
      expect(revoke).toHaveLength(1);
      const revocation = revoke[0]!;
      expect(revocation.draft.outcome.kind).toBe("success");
      expect(revocation.principal.kind).toBe("user");
      expect(revocation.draft.objects).toContainEqual({ kind: "node", id: nodeObject(NODE) });
      expect(revocation.seq).toBeGreaterThan(enrol[0]!.seq);

      await page.goto("/audit");
      await expect(page.getByTestId("page-audit")).toBeVisible();
      await page.getByTestId("audit-filter-action").fill("cluster.node.revoke");
      const grid = page.getByTestId("grid-audit");
      await expect(grid.getByTestId("row")).toHaveCount(1);
      const row = gridRow(page, "audit", String(revocation.seq));
      await expect(row).toBeVisible();
      await expect(cell(row, "action")).toContainText("cluster.node.revoke");
    });

    await test.step("the edit left a job that succeeded, and its page shows it", async () => {
      const jobs = (await api.get<Schemas["Page_JobSummary"]>("/jobs", { kind: "cluster.edit" })).items;
      const revokeJobs = jobs.filter((job) => job.created.by.kind === "user" && job.targets.some((target) => target.id === nodeObject(NODE)));
      expect(revokeJobs).toHaveLength(1);
      const job = revokeJobs[0]!;
      expect(job.state).toBe("succeeded");

      await page.goto("/jobs?kind=cluster.edit");
      await expect(page.getByTestId("page-jobs")).toBeVisible();
      const row = gridRow(page, "jobs", job.id);
      await expect(row).toBeVisible();
      await expect(cell(row, "kind")).toHaveText("cluster.edit");
      await cell(row, "kind").click();
      await expect(page).toHaveURL(new RegExp(`/jobs/${job.id}$`));
      await expect(page.getByTestId("page-job")).toBeVisible();
      await expect(page.getByTestId("job-state")).toHaveAttribute("data-state", "succeeded");
      await expect(page.getByTestId("job-facts")).toContainText(job.id);
      await expect(page.getByTestId("job-step")).toHaveCount(1);
      await expect(page.getByTestId("job-step")).toHaveAttribute("data-state", "done");
      const detail = await api.get<Schemas["JobDetail"]>(`/jobs/${job.id}`);
      expect(detail.job.state).toBe("succeeded");
      expect(detail.job.spec.kind).toBe("cluster.edit");
    });
  } finally {
    await probe.stop();
  }
});

test("a token deleted before use cannot enrol a node and leaves nothing on the node", async ({ page, api, server, signedIn }) => {
  expect(signedIn.session.user.name).toBe(ADMIN.name);
  const withdrawn = await createToken(api, NODE_NAME);
  const kept = await createToken(api, "probe-lab");
  const probe = await ProbeNode.create();
  try {
    await test.step("the administrator deletes the first token from the list", async () => {
      await page.goto("/nodes");
      await expect(page.getByTestId("page-nodes")).toBeVisible();
      const rows = page.getByTestId("nodes-tokens").getByTestId("enrolment");
      await expect(rows).toHaveCount(2);
      const row = withId(page.getByTestId("nodes-tokens"), "enrolment", withdrawn.enrolment.id);
      await expect(row).toHaveAttribute("data-state", "pending");
      await row.getByTestId("enrolment-delete").click();
      const confirm = page.getByTestId("dialog-confirm");
      await expect(confirm).toBeVisible();
      // Nothing is deleted before the confirmation.
      expect((await api.get<Schemas["EnrolmentList"]>("/nodes/enrolments")).items).toHaveLength(2);
      await confirm.getByTestId("confirm-ok").click();
      await expect(confirm).toHaveCount(0);
      await expect(row).toHaveCount(0);
      await expect(rows).toHaveCount(1);
      await expect(rows).toHaveAttribute("data-id", kept.enrolment.id);
      await expect(rows).toHaveAttribute("data-state", "pending");
      const list = (await api.get<Schemas["EnrolmentList"]>("/nodes/enrolments")).items;
      expect(list.map((token) => token.id)).toEqual([kept.enrolment.id]);
    });

    await test.step("the deleted token is refused and nothing is written on the node", async () => {
      const refused = await probe.enrol(server, withdrawn.token, { name: NODE_NAME, address: NODE_ADDRESS });
      expect(refused.code).toBe(6);
      expect(refused.stderr).toContain("cluster.enrolment.invalid_token");
      expect(refused.stdout).not.toContain("enrolled as node");
      for (const file of ["identity.json", "ca-root.pem", "node-cert.pem", "node-key.pem", "node-key.dpapi"]) {
        expect(existsSync(join(probe.dataDir, "node", file)), file).toBe(false);
      }
      expect((await api.get<Schemas["Page_NodeView"]>("/nodes")).items).toHaveLength(0);
      await expect(page.getByTestId("nodes-empty")).toBeVisible();

      // The refusal is audited with its code, and the deletion with the user who did it.
      const log = (await api.get<Schemas["Page_AuditRecord"]>("/audit", { order: "asc", limit: 1000 })).items;
      const refusal = log.filter((record) => record.draft.action === "cluster.node.enrol");
      expect(refusal).toHaveLength(1);
      expect(refusal[0]!.draft.outcome).toEqual({ kind: "failed", code: "cluster.enrolment.invalid_token" });
      const deletion = log.filter((record) => record.draft.action === "cluster.enrolment.delete");
      expect(deletion).toHaveLength(1);
      expect(deletion[0]!.principal.kind).toBe("user");
      expect(deletion[0]!.draft.outcome.kind).toBe("success");
    });

    await test.step("the refusal left no mark: the other token still enrols this node directory", async () => {
      const enrolled = await probe.enrol(server, kept.token, { address: NODE_ADDRESS });
      expect(enrolled.code, enrolled.stderr).toBe(0);
      expect(enrolled.stdout).toContain(`enrolled as node ${NODE} (probe-lab) with role(s) probe`);
      expect(existsSync(join(probe.dataDir, "node", "identity.json"))).toBe(true);
      const row = gridRow(page, "nodes", "probe-lab");
      await expect(row).toBeVisible();
      await expect(row).toHaveAttribute("data-id", String(NODE));
      await expect(page.getByTestId("nodes-tokens").getByTestId("enrolment")).toHaveAttribute("data-state", "used");
    });
  } finally {
    await probe.stop();
  }
});

test.describe("a Swedish browser", () => {
  test.use({ locale: "sv-SE" });

  test("shows the nodes page with a connected node, its panel and the token dialog in Swedish", async ({ page, api, server, signedIn }, testInfo) => {
    expect(signedIn.session.user.name).toBe(ADMIN.name);
    const created = await createToken(api, NODE_NAME);
    const probe = await ProbeNode.create();
    try {
      const enrolled = await probe.enrol(server, created.token, { name: NODE_NAME, address: NODE_ADDRESS });
      expect(enrolled.code, enrolled.stderr).toBe(0);
      await probe.serve();
      await waitForConnected(api);

      // The node list, its docked panel and the token list in one page.
      await page.goto(`/nodes/${NODE}`);
      const root = page.getByTestId("page-nodes");
      await expect(gridRow(page, "nodes", NODE_NAME).getByTestId("node-link")).toHaveAttribute("data-state", "connected");
      const panel = page.getByTestId("node-panel");
      await expect(panel).toBeVisible();
      await expect(panel.getByTestId("node-link")).toHaveAttribute("data-state", "connected");
      await expect(panel.getByTestId("node-connection")).toContainText((await nodeView(api)).connection!.peer!);
      await expect(page.getByTestId("nodes-tokens").getByTestId("enrolment")).toHaveAttribute("data-state", "used");
      await expectRendered(page, root, "sv", testInfo, "nodes");

      // The form that creates a token, then the token shown once.
      await page.getByTestId("nodes-enrol").click();
      const form = page.getByTestId("dialog-enrol");
      await expect(form).toBeVisible();
      await expectRendered(page, form, "sv", testInfo, "enrol");
      await form.getByTestId("field-name").fill("probe-lab");
      await form.getByTestId("form-submit").click();
      const dialog = page.getByTestId("dialog-enrol-token");
      await expect(dialog).toBeVisible();
      await expect(dialog.getByTestId("enrol-once")).toBeVisible();
      expect(digits(await dialog.getByTestId("enrol-fingerprint").innerText())).toBe(digits(server.caFingerprint));
      await expectRendered(page, dialog, "sv", testInfo, "enrol-token");
      await dialog.getByTestId("enrol-done").click();
      await expect(dialog).toHaveCount(0);
      await expect(page.getByTestId("nodes-tokens").getByTestId("enrolment")).toHaveCount(2);
    } finally {
      await probe.stop();
    }
  });
});

// The cluster summary that the dashboard's nodes block (`dashboard-nodes`, U3: drawn while the
// cluster has more than one node) and the nodes page
// (`nodes-cluster`) show comes from `GET /system/status`, which they read again after an event
// of the `cluster` topic. The controller refreshes that summary when a node's record changes
// (enrolment, connection, revocation) and then announces it with a `cluster` event of its own,
// so the open pages never keep the numbers from before the change (found by WP2.11, fixed by
// WP2.12; it used to refresh every five seconds only, and no event followed).
test("the dashboard tile and the cluster summary follow a node that enrols, connects and is revoked while they are open", async ({
  page,
  api,
  server,
  signedIn,
}) => {
  expect(signedIn.session.user.name).toBe(ADMIN.name);
  const created = await createToken(api, NODE_NAME);
  // The dashboard stays open in `page`; the node list is open in a second page of the browser.
  await page.goto("/");
  const link = page.getByTestId("dashboard-nodes");
  const hint = page.getByTestId("dashboard-nodes-hint");
  // One node, the controller: the block is not drawn and the Hidden line names the cluster's metrics.
  await expect(page.getByTestId("dashboard-attention")).toBeVisible();
  await expect(link).toHaveCount(0);
  await expect(page.getByTestId("hidden-line-item").and(page.locator("[data-item='controller']"))).toBeVisible();
  const nodes = await page.context().newPage();
  await nodes.goto("/nodes");
  await expect(nodes.getByTestId("nodes-empty")).toBeVisible();
  await expect(nodes.getByTestId("nodes-cluster")).toBeVisible();
  const probe = await ProbeNode.create();
  try {
    // Enrolled: counted as a node, not yet as a connected one.
    const enrolled = await probe.enrol(server, created.token, { name: NODE_NAME, address: NODE_ADDRESS });
    expect(enrolled.code, enrolled.stderr).toBe(0);
    await expect(hint).toHaveAttribute("data-total", "1");
    await expect(link).toHaveAttribute("data-value", "0");

    // Connected: the tile counts it and the nodes page names its version.
    await probe.serve();
    const view = await waitForConnected(api);
    await expect(gridRow(nodes, "nodes", NODE_NAME).getByTestId("node-link")).toHaveAttribute("data-state", "connected");
    await expect(link).toHaveAttribute("data-value", "1");
    await expect(hint).toHaveAttribute("data-total", "1");
    await expect(nodes.getByTestId("nodes-cluster")).toContainText(view.version!);

    // Revoked: one node again, so the block goes.
    await api.delete(`/nodes/${NODE}`);
    await expect(link).toHaveCount(0);
    await expect(nodes.getByTestId("nodes-empty")).toBeVisible();
  } finally {
    await probe.stop();
  }
});
