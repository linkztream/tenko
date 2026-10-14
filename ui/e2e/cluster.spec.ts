// Scenario WP3.11a: the cluster page of a single controller end to end (OPS-03, OPS-26;
// docs/cluster.md, sections 1 and 12). The server is the plain Lab instance with its cluster
// port closed: one controller, which is the leader and the only voter.
//
// - The page lists the one member with its role, the leader mark and its health, and the summary
//   shows the quorum `single`, the term, the leader, one voter and the failures it tolerates
//   (none). There is nothing to promote and no step-down; removing the member opens the dialog
//   with its preview, which refuses with the reasons of a single member and keeps the confirm
//   button disabled, so nothing is sent. The digest check asks the one member and its row agrees.
// - "Add a controller" creates a controller token: the dialog hides the role choice, shows the
//   command (it starts with `tenko cluster join`) once, and the token list of the nodes page and
//   `GET /nodes/enrolments` show it pending with the role controller and without its text.
// - A viewer reads the page without any action; the page renders in Swedish.
// - The queue (/cluster/queue) and the partition state: `test.fixme` scenarios, written against
//   the test ids, that wait for WP3.9. They need a lab that can isolate a controller from the
//   other two (a cluster of three controllers with their cluster ports on the loopback, as
//   `tenko cluster join` builds it, and a way to cut one of them off and to heal it again; see
//   `isolatedController` below) and the queue routes of WP3.9. A server without them answers
//   the queue view with its "no queue on this server" note, which the first scenario checks.
//
// Arrangement: accounts and the extra tokens come through the API. Documentation values only:
// the token name `controller-b`, the node address 192.0.2.40 and the prefix 198.51.100.0/24 of
// the queued change. What stays manual: a cluster of three controllers (promotion, removal with
// a successor, step-down and a digest that differs need the lab that WP3.9 brings,
// and the component tests cover their previews), and the join itself, whose process does not
// run as a second controller here.

import type { Page } from "@playwright/test";
import { signInAsViewer } from "./support/accounts";
import { ADMIN, type Api, type Schemas } from "./support/api";
import { expect, test } from "./support/fixtures";
import { expectRendered } from "./support/i18n";
import type { TenkoServer } from "./support/server";
import { withId } from "./support/ui";

type EnrolmentList = Schemas["EnrolmentList"];

/** The members of the cluster as the API lists them. */
interface Members {
  node: number;
  term: number;
  leader: number | null;
  quorum: { state: string };
  members: Array<{ node: number; role: string; leader: boolean; name?: string | null }>;
}

/** The cluster as `GET /cluster/members` shows it. */
function members(api: Api): Promise<Members> {
  return api.get<Members>("/cluster/members");
}

test("a single controller is the leader and the only voter, offers nothing to promote or hand over, and refuses its own removal", async ({
  page,
  api,
  signedIn,
}) => {
  expect(signedIn.session.user.name).toBe(ADMIN.name);
  const cluster = await members(api);
  expect(cluster.members).toHaveLength(1);
  const self = cluster.members[0]!;
  expect(self).toMatchObject({ role: "voter", leader: true });
  expect(cluster.quorum.state).toBe("single");

  await test.step("the summary and the one member", async () => {
    await page.goto("/cluster");
    await expect(page.getByTestId("page-cluster")).toBeVisible();
    await expect(page.getByTestId("cluster-quorum")).toHaveAttribute("data-state", "single");
    await expect(page.getByTestId("cluster-term")).toHaveText(new RegExp(`^\\s*${cluster.term.toLocaleString("en-US")}\\s*$`));
    await expect(page.getByTestId("cluster-leader")).toHaveAttribute("data-node", String(self.node));
    await expect(page.getByTestId("cluster-node")).toHaveAttribute("data-node", String(self.node));
    // One voter tolerates no failure.
    await expect(page.getByTestId("cluster-voters")).toHaveAttribute("data-count", "1");

    const rows = page.getByTestId("cluster-members").locator("tbody tr");
    await expect(rows).toHaveCount(1);
    const row = page.getByTestId(`member-row-${self.node}`);
    await expect(row).toHaveAttribute("data-role", "voter");
    await expect(row).toHaveAttribute("data-state", "leader");
    await expect(row.getByTestId("member-leader")).toBeVisible();
    await expect(row.getByTestId("member-health")).toHaveAttribute("data-state", "leader");
  });

  await test.step("the compatibility cell and the data format agree with the server", async () => {
    const full = (await members(api)).members[0] as { protocol_majors?: number[]; raft_wire?: string | null; formats?: number[] };
    const cell = page.getByTestId(`member-compat-${self.node}`);
    const majors = full.protocol_majors ?? [];
    await expect(cell.getByTestId("compat-majors")).toHaveText(majors.length > 0 ? majors.map((m) => `v${m}`).join(", ") : "–");
    await expect(cell.getByTestId("compat-wire")).toHaveText(full.raft_wire ?? "–");
    const formats = full.formats ?? [];
    if (formats.length === 0) await expect(cell.getByTestId("compat-formats")).toHaveText("–");
    else await expect(cell.getByTestId("compat-formats")).toContainText(String(formats[0]));

    const status = await api.get<{ data_format?: { stored: number; binary: number; pending?: unknown } | null }>("/system/status");
    const panel = page.getByTestId("cluster-format");
    if (status.data_format) {
      await expect(panel).toBeVisible();
      await expect(panel).toHaveAttribute("data-state", "current");
      await expect(panel.getByTestId("format-stored")).toHaveText(String(status.data_format.stored));
      await expect(panel.getByTestId("format-binary")).toHaveText(String(status.data_format.binary));
      expect(status.data_format.stored).toBe(status.data_format.binary);
      expect(status.data_format.pending ?? null).toBeNull();
      await expect(panel.getByTestId("format-blockers")).toHaveCount(0);
    }
    await expect(page.getByTestId("cluster-warning")).toHaveCount(0);
  });

  await test.step("no promotion and no step-down; the removal is refused with the reasons of a single member", async () => {
    await expect(page.getByTestId(`member-promote-${self.node}`)).toHaveCount(0);
    await expect(page.getByTestId("cluster-step-down")).toHaveCount(0);

    await page.getByTestId(`member-remove-${self.node}`).click();
    const dialog = page.getByTestId("dialog-remove");
    await expect(dialog).toBeVisible();
    await expect(dialog.getByTestId("preview-voters")).toHaveAttribute("data-before", "1");
    await expect(dialog.getByTestId("preview-voters")).toHaveAttribute("data-after", "0");
    const blockers = dialog.getByTestId("preview-blockers");
    await expect(blockers.locator('[data-blocker="single"]')).toHaveCount(1);
    await expect(blockers.locator('[data-blocker="last_voter"]')).toHaveCount(1);
    await expect(dialog.getByTestId("remove-confirm")).toBeDisabled();
    await page.keyboard.press("Escape");
    await expect(dialog).toHaveCount(0);
    // Nothing was sent.
    expect((await members(api)).members).toHaveLength(1);
  });

  await test.step("the digest check asks the one member and its row agrees", async () => {
    await expect(page.getByTestId("digests-result")).toHaveCount(0);
    await page.getByTestId("cluster-check-digests").click();
    await expect(page.getByTestId("digests-overall")).toHaveAttribute("data-state", "agree");
    const rows = page.getByTestId("cluster-digests").locator("[data-testid^='digest-row-']");
    await expect(rows).toHaveCount(1);
    const row = page.getByTestId(`digest-row-${self.node}`);
    await expect(row.getByTestId("digest-state")).toHaveAttribute("data-state", "agrees");
    const report = await api.get<Schemas["DigestReport"]>("/cluster/digests");
    expect(report.agree).toBe(true);
    expect(report.members).toHaveLength(1);
    expect(report.members[0]!.sha256).toMatch(/^[0-9a-f]{64}$/);
  });
});

test("Add a controller creates a controller token whose command joins a cluster, shown once and pending in the token list", async ({
  page,
  api,
  server,
  signedIn,
}) => {
  expect(signedIn.session.user.name).toBe(ADMIN.name);
  await page.goto("/cluster");
  await expect(page.getByTestId("page-cluster")).toBeVisible();

  let secret = "";
  await test.step("the dialog has no role choice and shows the token once", async () => {
    await page.getByTestId("cluster-add-controller").click();
    const form = page.getByTestId("dialog-enrol");
    await expect(form).toBeVisible();
    await expect(form.locator("[data-testid^='field-role-']")).toHaveCount(0);
    await form.getByTestId("field-name").fill("controller-b");
    await form.getByTestId("form-submit").click();

    const dialog = page.getByTestId("dialog-enrol-token");
    await expect(dialog).toBeVisible();
    await expect(form).toHaveCount(0);
    await expect(dialog.getByTestId("enrol-once")).toBeVisible();
    const token = (await dialog.getByTestId("enrol-token").innerText()).trim();
    expect(token).toMatch(/^tnk1\.[0-9a-f]{32}\.[A-Za-z0-9_-]{43}$/);
    secret = token.split(".")[2]!;
    const command = (await dialog.getByTestId("enrol-command").innerText()).trim();
    expect(command).toMatch(/^tenko cluster join /);
    expect(command).toContain(token);
    expect(command).toContain(server.url);
    await dialog.getByTestId("enrol-done").click();
    await expect(dialog).toHaveCount(0);
  });

  await test.step("the token is pending with the role controller, in the API and on the nodes page, without its text", async () => {
    const list = await api.get<EnrolmentList>("/nodes/enrolments");
    expect(list.items).toHaveLength(1);
    expect(list.items[0]).toMatchObject({ name: "controller-b", roles: ["controller"], state: "pending" });
    expect(JSON.stringify(list)).not.toContain(secret);

    await page.goto("/nodes");
    await expect(page.getByTestId("page-nodes")).toBeVisible();
    const row = withId(page.getByTestId("nodes-tokens"), "enrolment", list.items[0]!.id);
    await expect(row).toHaveAttribute("data-state", "pending");
    expect(await page.content()).not.toContain(secret);
    // The cluster page is not a place to see the token again.
    await page.goto("/cluster");
    await expect(page.getByTestId("page-cluster")).toBeVisible();
    expect(await page.content()).not.toContain(secret);
  });
});

test("a viewer sees the cluster page without any action", async ({ page, api, signedIn }) => {
  expect(signedIn.session.user.name).toBe(ADMIN.name);
  const self = (await members(api)).members[0]!;
  await signInAsViewer(api);

  await page.goto("/cluster");
  await expect(page.getByTestId("page-cluster")).toBeVisible();
  await expect(page.getByTestId(`member-row-${self.node}`)).toBeVisible();
  await expect(page.getByTestId("cluster-quorum")).toHaveAttribute("data-state", "single");
  await expect(page.getByTestId("cluster-add-controller")).toHaveCount(0);
  await expect(page.getByTestId(`member-remove-${self.node}`)).toHaveCount(0);
  await expect(page.getByTestId(`member-promote-${self.node}`)).toHaveCount(0);
  await expect(page.getByTestId("cluster-step-down")).toHaveCount(0);
  // Everyone can check that the members agree, and read the queue.
  await page.getByTestId("cluster-check-digests").click();
  await expect(page.getByTestId("digests-overall")).toHaveAttribute("data-state", "agree");
  await expect(page.getByTestId("cluster-queue-link")).toBeVisible();
});

test.describe("a Swedish browser", () => {
  test.use({ locale: "sv-SE" });

  test("shows the cluster page, the digest check and the dialogs in Swedish", async ({ page, api, signedIn }, testInfo) => {
    expect(signedIn.session.user.name).toBe(ADMIN.name);
    const self = (await members(api)).members[0]!;
    await page.goto("/cluster");
    const root = page.getByTestId("page-cluster");
    await expect(page.getByTestId(`member-row-${self.node}`)).toBeVisible();
    await expectRendered(page, root, "sv", testInfo, "cluster");

    await page.getByTestId("cluster-check-digests").click();
    await expect(page.getByTestId("digests-overall")).toHaveAttribute("data-state", "agree");
    await expectRendered(page, root, "sv", testInfo, "cluster-digests");

    await page.getByTestId(`member-remove-${self.node}`).click();
    const remove = page.getByTestId("dialog-remove");
    await expect(remove.getByTestId("preview-blockers")).toBeVisible();
    await expectRendered(page, remove, "sv");
    await page.keyboard.press("Escape");
    await expect(remove).toHaveCount(0);

    await page.getByTestId("cluster-add-controller").click();
    const form = page.getByTestId("dialog-enrol");
    await expect(form).toBeVisible();
    await expectRendered(page, form, "sv");
    await page.keyboard.press("Escape");

    await page.getByTestId("cluster-queue-link").click();
    await expect(page.getByTestId("page-cluster-queue")).toBeVisible();
    await expectRendered(page, page.getByTestId("page-cluster-queue"), "sv", testInfo, "cluster-queue");
  });
});

test("the queue view of a server without a partition says so calmly", async ({ page, signedIn }) => {
  expect(signedIn.session.user.name).toBe(ADMIN.name);
  await page.goto("/cluster/queue");
  await expect(page.getByTestId("page-cluster-queue")).toBeVisible();
  // Either the server keeps no queue yet (a note) or it keeps an empty one (WP3.9): never an error.
  await expect(page.getByTestId("error-notice")).toHaveCount(0);
  await expect(page.getByTestId("queue-unavailable").or(page.getByTestId("queue-local-empty"))).toBeVisible();
  await expect(page.getByTestId("cluster-banner")).toHaveCount(0);
  await expect(page.getByTestId("status-stale")).toHaveCount(0);
});

// ---------------------------------------------------------------------------------------------
// WP3.9: a controller without a quorum queues the IPAM writes it refuses. These scenarios need a
// lab with three controllers and a way to cut one off.

/** A controller cut off from the others, and the means to bring it back. */
interface Isolated {
  /** The isolated controller; the browser talks to it. */
  server: TenkoServer;
  /** Restores the connection to the other controllers and waits until the quorum is back. */
  heal: () => Promise<void>;
  /** Writes through a controller that still has its quorum. */
  api: Api;
}

/** Starts the lab and isolates a controller. Not available before WP3.9; the scenarios wait for it. */
async function isolatedController(): Promise<Isolated> {
  throw new Error("a lab that isolates a controller from its cluster is not available yet (WP3.9)");
}

/** Opens the prefix form of the IPAM page, fills `cidr`, and submits it to the plan dialog. */
async function submitPrefix(page: Page, cidr: string): Promise<void> {
  await page.goto("/ipam");
  await expect(page.getByTestId("page-ipam")).toBeVisible();
  await page.getByTestId("ipam-add-prefix").click();
  const form = page.getByTestId("dialog-prefix-form");
  await form.getByTestId("field-cidr").fill(cidr);
  await form.getByTestId("form-submit").click();
  await expect(page.getByTestId("plan-preview")).toBeVisible();
  await page.getByTestId("plan-confirm").click();
}

test.fixme("a write refused with 503 cluster.no_quorum opens the refused-change dialog and queues the change (waits for WP3.9)", async ({
  page,
  signedIn,
}) => {
  expect(signedIn.session.user.name).toBe(ADMIN.name);
  await isolatedController();
  await submitPrefix(page, "198.51.100.0/24");
  const dialog = page.getByTestId("dialog-no-quorum");
  await expect(dialog).toBeVisible();
  await expect(dialog.getByTestId("no-quorum-hint")).toBeVisible();
  await dialog.getByTestId("no-quorum-queue").click();
  await expect(dialog.getByTestId("no-quorum-queued")).toBeVisible();
  await dialog.getByTestId("no-quorum-close").click();
  await expect(dialog).toHaveCount(0);
  // The write is queued on this controller, not applied.
  await page.goto("/cluster/queue");
  await expect(page.getByTestId("queue-local").locator("[data-testid^='queue-item-']")).toHaveCount(1);
});

test.fixme("the queue view lists the queued change and cancels it (waits for WP3.9)", async ({ page, signedIn }) => {
  expect(signedIn.session.user.name).toBe(ADMIN.name);
  await isolatedController();
  await submitPrefix(page, "198.51.100.0/24");
  await page.getByTestId("no-quorum-queue").click();
  await expect(page.getByTestId("no-quorum-queued")).toBeVisible();
  await page.getByTestId("no-quorum-close").click();

  await page.goto("/cluster/queue");
  const local = page.getByTestId("queue-local");
  const item = local.locator("[data-testid^='queue-item-']");
  await expect(item).toHaveCount(1);
  await expect(item.getByTestId("queue-item-state")).toHaveAttribute("data-state", "queued");
  await expect(item.getByTestId("queue-item-summary")).toContainText("198.51.100.0/24");
  const id = (await item.getAttribute("data-id"))!;
  await page.getByTestId(`queue-cancel-${id}`).click();
  await page.getByTestId("confirm-ok").click();
  await expect(page.getByTestId("queue-local-empty")).toBeVisible();
});

test.fixme("after the heal an unchanged change applies and a conflicting one is re-applied and discarded (waits for WP3.9)", async ({
  page,
  signedIn,
}) => {
  expect(signedIn.session.user.name).toBe(ADMIN.name);
  const lab = await isolatedController();
  // Two changes queued while isolated: a new prefix, and a prefix that the other side takes first.
  await submitPrefix(page, "198.51.100.0/24");
  await page.getByTestId("no-quorum-queue").click();
  await page.getByTestId("no-quorum-close").click();
  await submitPrefix(page, "203.0.113.0/24");
  await page.getByTestId("no-quorum-queue").click();
  await page.getByTestId("no-quorum-close").click();
  await lab.api.post("/prefixes", { cidr: "203.0.113.0/24", description: "taken meanwhile" });
  await lab.heal();

  await page.goto("/cluster/queue");
  const changes = page.getByTestId("queue-changes");
  await expect(changes.locator("[data-testid^='queued-change-'][data-state='applied']")).toHaveCount(1);
  const conflict = changes.locator("[data-testid^='queued-change-'][data-state='conflict']");
  await expect(conflict).toHaveCount(1);
  await expect(conflict.getByTestId("queued-change-conflict")).toBeVisible();
  const id = (await conflict.getAttribute("data-id"))!;
  // Re-apply after a new preview; the preview shows the conflict, so the person discards instead.
  await page.getByTestId(`queued-reapply-${id}`).click();
  await expect(page.getByTestId("dialog-reapply")).toBeVisible();
  await page.keyboard.press("Escape");
  await page.getByTestId(`queued-discard-${id}`).click();
  await page.getByTestId("confirm-ok").click();
  await expect(changes.locator("[data-testid^='queued-change-'][data-state='conflict']")).toHaveCount(0);
});

test.fixme("the partition banner and the stale status item show while the controller is isolated and go with the heal (waits for WP3.9)", async ({
  page,
  signedIn,
}) => {
  expect(signedIn.session.user.name).toBe(ADMIN.name);
  const lab = await isolatedController();
  await page.goto("/cluster");
  await expect(page.getByTestId("page-cluster")).toBeVisible();
  await expect(page.getByTestId("cluster-banner")).toHaveAttribute("data-state", "isolated");
  await expect(page.getByTestId("status-stale")).toBeVisible();
  await expect(page.getByTestId("cluster-quorum")).toHaveAttribute("data-state", "isolated");
  await lab.heal();
  await expect(page.getByTestId("status-stale")).toHaveCount(0);
  await expect(page.getByTestId("cluster-banner")).toHaveCount(0);
});
