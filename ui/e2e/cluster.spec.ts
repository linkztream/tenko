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
// - The queue (/cluster/queue) of a server that is not isolated says so calmly.
// - The partition state and the queue (OPS-26), at the end of the file: THESE SCENARIOS FAKE THE
//   CLUSTER ROUTES, because the e2e server is one controller and cannot lose a quorum. The faked
//   routes (support/cluster-mock.ts) refuse the IPAM write with 503 `cluster.no_quorum`, keep the
//   queue and answer the heal; the real behaviour is proven by the Rust lab tests
//   `crates/tenko/tests/acceptance_cluster.rs` and `acceptance_partition.rs`. The member actions
//   (promote, remove, step down) are in cluster-membership.spec.ts.
//
// Arrangement: accounts and the extra tokens come through the API. Documentation values only:
// the token name `controller-b`, the node address 192.0.2.40 and the prefixes 198.51.100.0/24
// and 203.0.113.0/24 of the queued changes. What stays manual: the join itself, whose process
// does not run as a second controller here.

import type { Page } from "@playwright/test";
import { signInAsViewer } from "./support/accounts";
import { ADMIN, type Api, type Schemas } from "./support/api";
import { FakeCluster, threeVoters } from "./support/cluster-mock";
import { expect, test } from "./support/fixtures";
import { expectRendered } from "./support/i18n";
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
// WP3.9: a controller without a quorum queues the IPAM writes it refuses. A lab that cuts a
// controller off from the other two does not exist in the e2e harness (one real controller), so
// these scenarios fake the cluster routes: support/cluster-mock.ts answers `/cluster/*`,
// `/queue*` and the quorum of `/system/status` in the browser, refuses the IPAM write with 503
// `cluster.no_quorum` while "isolated", and lets everything else (the plan dialog's dry run,
// events) reach the real server. The heal is announced the way the product learns of it: the
// shell reads `/system/status` again after an event of the `system` topic. The real behaviour is
// proven by the Rust lab tests `acceptance_partition.rs` and `acceptance_cluster.rs`.

/** Opens the prefix form of the IPAM page, fills `cidr`, and submits it to the plan dialog. */
async function submitPrefix(page: Page, cidr: string): Promise<void> {
  await page.goto("/ipam");
  await expect(page.getByTestId("page-ipam")).toBeVisible();
  await page.getByTestId("ipam-add-prefix").click();
  const form = page.getByTestId("dialog-prefix-form");
  await form.getByTestId("field-cidr").fill(cidr);
  await form.getByTestId("form-submit").click();
  await expect(page.getByTestId("plan-summary")).toBeVisible();
  await page.getByTestId("plan-confirm").click();
}

/** Submits a prefix to the isolated controller and queues the refused write in the dialog. */
async function queuePrefix(page: Page, cidr: string): Promise<void> {
  await submitPrefix(page, cidr);
  const dialog = page.getByTestId("dialog-no-quorum");
  await dialog.getByTestId("no-quorum-queue").click();
  await expect(dialog.getByTestId("no-quorum-queued")).toBeVisible();
  await dialog.getByTestId("no-quorum-close").click();
  await expect(dialog).toHaveCount(0);
  await closeRefusedWrite(page);
}

/** The plan dialog and the form of a refused write stay open under its dialog; the person closes them. */
async function closeRefusedWrite(page: Page): Promise<void> {
  await page.getByTestId("plan-cancel").click();
  await expect(page.getByTestId("plan-summary")).toHaveCount(0);
  await page.getByTestId("dialog-prefix-form").getByTestId("form-cancel").click();
  await expect(page.getByTestId("dialog-prefix-form")).toHaveCount(0);
}

test("OPS-26: a write refused with 503 cluster.no_quorum opens the refused-change dialog and queues the change (faked cluster routes)", async ({
  page,
  signedIn,
}) => {
  expect(signedIn.session.user.id).toBeTruthy();
  const fake = await FakeCluster.install(page, { members: threeVoters() });
  fake.isolate();
  await submitPrefix(page, "198.51.100.0/24");
  const dialog = page.getByTestId("dialog-no-quorum");
  await expect(dialog).toBeVisible();
  await expect(dialog.getByTestId("no-quorum-hint")).toBeVisible();
  // The write itself was sent once and refused; nothing is queued until the person asks.
  expect(fake.sent.map((s) => `${s.method} ${s.path}`)).toEqual(["POST /api/v1/prefixes"]);
  expect(fake.queued()).toHaveLength(0);

  await dialog.getByTestId("no-quorum-queue").click();
  await expect(dialog.getByTestId("no-quorum-queued")).toBeVisible();
  // The queue request carries the refused write as it was sent.
  expect(fake.sent).toHaveLength(2);
  expect(fake.sent[1]).toMatchObject({
    method: "POST",
    path: "/api/v1/queue",
    body: { method: "POST", path: "/prefixes", query: null, body: { cidr: "198.51.100.0/24" }, if_match: null },
  });
  await dialog.getByTestId("no-quorum-close").click();
  await expect(dialog).toHaveCount(0);
  // The write is queued on this controller, not applied.
  await page.goto("/cluster/queue");
  const items = page.getByTestId("queue-local").locator("tr[data-testid^='queue-item-']");
  await expect(items).toHaveCount(1);
  await expect(items.getByTestId("queue-item-state")).toHaveAttribute("data-state", "queued");
  await expect(items.getByTestId("queue-item-summary")).toBeVisible();
  await expect(items).toContainText("198.51.100.0/24");
});

test("OPS-26: the queue view lists the queued change and cancels it with a DELETE (faked cluster routes)", async ({ page, signedIn }) => {
  expect(signedIn.session.user.id).toBeTruthy();
  const fake = await FakeCluster.install(page, { members: threeVoters() });
  fake.isolate();
  await queuePrefix(page, "198.51.100.0/24");

  await page.goto("/cluster/queue");
  const local = page.getByTestId("queue-local");
  const item = local.locator("tr[data-testid^='queue-item-']");
  await expect(item).toHaveCount(1);
  await expect(item.getByTestId("queue-item-state")).toHaveAttribute("data-state", "queued");
  await expect(item.getByTestId("queue-item-summary")).toBeVisible();
  const id = (await item.getAttribute("data-id"))!;
  expect(id).toBe(fake.queued()[0]!.id);

  // Keeping the change sends nothing; cancelling asks first.
  const before = fake.sent.length;
  await page.getByTestId(`queue-cancel-${id}`).click();
  await expect(page.getByTestId("dialog-cancel-queued")).toBeVisible();
  await page.getByTestId("confirm-cancel").click();
  await expect(page.getByTestId("dialog-cancel-queued")).toHaveCount(0);
  expect(fake.sent).toHaveLength(before);

  await page.getByTestId(`queue-cancel-${id}`).click();
  await page.getByTestId("confirm-ok").click();
  await expect(page.getByTestId("queue-local-empty")).toBeVisible();
  expect(fake.sent.at(-1)).toMatchObject({ method: "DELETE", path: `/api/v1/queue/${id}` });
  expect(fake.queued()).toHaveLength(0);
});

test("OPS-26: after the heal an unchanged change applies and a conflicting one is re-applied or discarded (faked cluster routes)", async ({
  page,
  api,
  signedIn,
}) => {
  expect(signedIn.session.user.id).toBeTruthy();
  const fake = await FakeCluster.install(page, { members: threeVoters() });
  fake.isolate();
  // Two changes queued while isolated: a new prefix, and a prefix that the other side takes first.
  await queuePrefix(page, "198.51.100.0/24");
  await queuePrefix(page, "203.0.113.0/24");
  await expect(page.getByTestId("cluster-banner")).toHaveAttribute("data-state", "isolated");

  fake.heal(["203.0.113.0/24"]);
  await fake.refreshShell(api);
  // The heal ends the isolation; the banner now asks for the decision of the one that conflicts.
  const banner = page.getByTestId("cluster-banner");
  await expect(banner).toHaveAttribute("data-state", "conflicts");
  await expect(page.getByTestId("status-stale")).toHaveCount(0);
  await page.getByTestId("cluster-banner-link").click();

  await expect(page.getByTestId("page-cluster-queue")).toBeVisible();
  const changes = page.getByTestId("queue-changes");
  const applied = changes.locator("tr[data-testid^='queued-change-'][data-state='applied']");
  await expect(applied).toHaveCount(1);
  await expect(applied).toContainText("198.51.100.0/24");
  const conflict = changes.locator("tr[data-testid^='queued-change-'][data-state='conflict']");
  await expect(conflict).toHaveCount(1);
  await expect(conflict.getByTestId("queued-change-conflict")).toHaveAttribute("data-code", "queue.plan_changed");
  const id = (await conflict.getAttribute("data-id"))!;
  const appliedId = (await applied.getAttribute("data-id"))!;

  // Re-apply asks for a new preview first (a dry run); closing it applies nothing.
  await page.getByTestId(`queued-reapply-${id}`).click();
  const reapply = page.getByTestId("dialog-reapply");
  await expect(reapply).toBeVisible();
  await expect.poll(() => fake.sent.some((s) => s.path === `/api/v1/queue/conflicts/${id}/reapply` && s.query.includes("dry_run=true"))).toBe(true);
  expect(fake.sent.some((s) => s.path.endsWith("/reapply") && !s.query.includes("dry_run"))).toBe(false);
  await page.keyboard.press("Escape");
  await expect(reapply).toHaveCount(0);

  // The person gives up on the conflicting change and dismisses the one that was applied.
  await page.getByTestId(`queued-discard-${id}`).click();
  await page.getByTestId("dialog-discard-queued").getByTestId("confirm-ok").click();
  await expect(conflict).toHaveCount(0);
  expect(fake.sent.at(-1)).toMatchObject({ method: "DELETE", path: `/api/v1/queue/conflicts/${id}` });
  await page.getByTestId(`queued-dismiss-${appliedId}`).click();
  await expect(page.getByTestId("queue-changes-empty")).toBeVisible();
  expect(fake.sent.at(-1)).toMatchObject({ method: "DELETE", path: `/api/v1/queue/conflicts/${appliedId}` });
  // Nothing waits for a decision any more, so the banner is gone.
  await expect(page.getByTestId("cluster-banner")).toHaveCount(0);
});

test("OPS-26: a conflicting change is applied again after a new preview (faked cluster routes)", async ({ page, api, signedIn }) => {
  expect(signedIn.session.user.id).toBeTruthy();
  const fake = await FakeCluster.install(page, { members: threeVoters() });
  fake.isolate();
  await queuePrefix(page, "203.0.113.0/24");
  fake.heal(["203.0.113.0/24"]);
  await fake.refreshShell(api);
  await expect(page.getByTestId("cluster-banner")).toHaveAttribute("data-state", "conflicts");
  await page.getByTestId("cluster-banner-link").click();

  const conflict = page.getByTestId("queue-changes").locator("tr[data-testid^='queued-change-'][data-state='conflict']");
  await expect(conflict).toHaveCount(1);
  const id = (await conflict.getAttribute("data-id"))!;
  await page.getByTestId(`queued-reapply-${id}`).click();
  await expect(page.getByTestId("dialog-reapply")).toBeVisible();
  await expect(page.getByTestId("plan-confirm")).toBeEnabled();
  await page.getByTestId("plan-confirm").click();
  await expect(page.getByTestId("dialog-reapply")).toHaveCount(0);
  // The preview was a dry run, the confirmation the real re-apply, and the record is gone.
  const posts = fake.sent.filter((s) => s.method === "POST" && s.path === `/api/v1/queue/conflicts/${id}/reapply`);
  expect(posts.map((s) => s.query)).toEqual(["dry_run=true", ""]);
  await expect(page.getByTestId("queue-changes-empty")).toBeVisible();
});

test("OPS-26: the partition banner and the stale status item show while the controller is isolated and go with the heal (faked cluster routes)", async ({
  page,
  api,
  signedIn,
}) => {
  expect(signedIn.session.user.id).toBeTruthy();
  const fake = await FakeCluster.install(page, { members: threeVoters() });
  fake.isolate(4);
  await page.goto("/cluster");
  await expect(page.getByTestId("page-cluster")).toBeVisible();
  await expect(page.getByTestId("cluster-banner")).toHaveAttribute("data-state", "isolated");
  await expect(page.getByTestId("cluster-banner")).toHaveAttribute("role", "alert");
  await expect(page.getByTestId("status-stale")).toBeVisible();
  await expect(page.getByTestId("cluster-quorum")).toHaveAttribute("data-state", "isolated");
  // The banner leads to the queue view.
  await expect(page.getByTestId("cluster-banner-link")).toHaveAttribute("href", "/cluster/queue");

  fake.heal();
  await fake.refreshShell(api);
  await expect(page.getByTestId("status-stale")).toHaveCount(0);
  await expect(page.getByTestId("cluster-banner")).toHaveCount(0);
  // The cluster page follows with its own live read.
  await fake.refreshCluster(api);
  await expect(page.getByTestId("cluster-quorum")).toHaveAttribute("data-state", "healthy");
});

test("OPS-26: while a leader is elected the banner says so and no copy is called stale (faked cluster routes)", async ({ page, api, signedIn }) => {
  expect(signedIn.session.user.id).toBeTruthy();
  const fake = await FakeCluster.install(page, { members: threeVoters() });
  fake.elect();
  await page.goto("/cluster");
  await expect(page.getByTestId("cluster-banner")).toHaveAttribute("data-state", "electing");
  await expect(page.getByTestId("status-stale")).toHaveCount(0);

  fake.heal();
  await fake.refreshShell(api);
  await expect(page.getByTestId("cluster-banner")).toHaveCount(0);
});

test.describe("a Swedish browser, isolated", () => {
  test.use({ locale: "sv-SE" });

  test("OPS-26: renders the banner, the refused-change dialog and the queue view in Swedish (faked cluster routes)", async ({ page, api, signedIn }, testInfo) => {
    expect(signedIn.session.user.id).toBeTruthy();
    const fake = await FakeCluster.install(page, { members: threeVoters() });
    fake.isolate();
    await submitPrefix(page, "198.51.100.0/24");
    const dialog = page.getByTestId("dialog-no-quorum");
    await expect(dialog.getByTestId("no-quorum-hint")).toBeVisible();
    await expectRendered(page, dialog, "sv", testInfo, "cluster-no-quorum");
    await dialog.getByTestId("no-quorum-queue").click();
    await expect(dialog.getByTestId("no-quorum-queued")).toBeVisible();
    await dialog.getByTestId("no-quorum-show-queue").click();
    // The IPAM dialogs under it go with the page when the link leads to the queue.
    await expect(page.getByTestId("page-cluster-queue")).toBeVisible();
    await expect(page.getByTestId("cluster-banner")).toHaveAttribute("data-state", "isolated");
    await expect(page.getByTestId("status-stale")).toBeVisible();
    await expectRendered(page, page.getByTestId("cluster-banner"), "sv");
    await expectRendered(page, page.getByTestId("page-cluster-queue"), "sv", testInfo, "cluster-queue-isolated");

    // After the heal the change waits for a decision in the banner and in the list.
    fake.heal(["198.51.100.0/24"]);
    await fake.refreshShell(api);
    // The queue view is open: the drain announces itself on the `ipam` topic, as the real one does.
    await fake.refreshQueue(api);
    await expect(page.getByTestId("cluster-banner")).toHaveAttribute("data-state", "conflicts");
    await page.getByTestId("cluster-banner-link").click();
    await expect(page.locator("tr[data-testid^='queued-change-'][data-state='conflict']")).toHaveCount(1);
    await expectRendered(page, page.getByTestId("cluster-banner"), "sv");
    await expectRendered(page, page.getByTestId("page-cluster-queue"), "sv", testInfo, "cluster-queue-conflict");
  });
});
