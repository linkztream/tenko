// Scenario 5: moving a host to another network (E8, IPAM-19), the UI half. An address of the
// source network is dragged onto the target network in the prefix tree; the move preview
// lists the change and the grouped checklist; the confirmation starts a job in a job group;
// the manual steps (DHCP, DNS, layer 2, observation) are completed in the jobs view until the
// job succeeds. A second test cancels the job of a move and checks the rollback.
//
// Where the gesture starts: the tree is on the IPAM page only, so the drag source is the
// address list of the source network (a row of the `prefix-addresses` grid). The row carries
// the address, which moves with its host's interface; the hosts grid has no tree to drop on.
// The drag is driven by `locator.dragTo` (HTML5 drag events, see support/move.ts).
//
// What stays manual for E8: the real device, DHCP server, DNS server and switch the tasks
// are about, and the observation of the device at the new address (all manual steps here
// are ticked off by a person). The test server has no network controller and the target
// network has no VLAN, so the preview leaves the network change to a person and says why;
// the change through a controller is proven against the in-memory controller in the Rust
// and component tests.

import { ADMIN, type Schemas } from "./support/api";
import { expect, test } from "./support/fixtures";
import {
  addressesOf,
  arrangeMoveLab,
  DNS_NAME,
  dragOnto,
  groupOf,
  HOST_NAME,
  jobsOfGroup,
  MANUAL_STEP_KINDS,
  MOVE_FAILED_TAG,
  moveJobs,
  NEW_IP,
  OLD_IP,
  SOURCE_CIDR,
  stepAt,
  TARGET_CIDR,
} from "./support/move";
import { cell, gridRow, withId, withKey } from "./support/ui";

/** A pattern for exactly these values in this order, with any white space between them. */
function inOrder(...values: string[]): RegExp {
  const escaped = values.map((value) => value.replaceAll(".", "\\."));
  return new RegExp(`^\\s*${escaped.join("\\s*")}\\s*$`);
}

/** Step kinds of the preview, in job order, with the automatic ones left out. */
const MANUAL_PREVIEW_KINDS = ["dhcp.manual", "dns.manual", "l2.move", "observe"];

test("an address dragged onto another network moves its host, and the manual steps are done in the jobs view", async ({
  page,
  api,
  signedIn,
}) => {
  expect(signedIn.session.user.name).toBe(ADMIN.name);
  const lab = await arrangeMoveLab(api);

  // What the server plans for the move, to compare with what the preview page shows.
  const planned = await api.post<Schemas["MovePreview"]>(
    "/moves",
    { objects: [{ kind: "address", id: lab.address.id }], target: lab.target.id },
    { query: { dry_run: true } },
  );
  const plannedItem = planned.items[0]!;
  expect(plannedItem.old_ip).toBe(OLD_IP);
  expect(plannedItem.new_ip).toBe(NEW_IP);
  const plannedKinds = plannedItem.steps.map((step) => step.kind);
  expect(plannedKinds).toEqual(["ipam.intent", "dhcp.manual", "dns.manual", "l2.move", "observe", "cleanup"]);
  // The network change is a task for a person: the target has no VLAN, so no controller could make it.
  expect(plannedItem.l2).toMatchObject({ action: "manual", reason: "ipam.move.l2.no_vlan" });
  expect(planned.controllers ?? []).toEqual([]);
  expect(planned.fingerprint).toMatch(/^[0-9a-f]{32}$/);

  // The address list of the source network offers the address as a drag source.
  await page.goto(`/ipam/prefixes/${SOURCE_CIDR}`);
  await expect(page.getByTestId("page-ipam")).toBeVisible();
  const addressRow = gridRow(page, "prefix-addresses", OLD_IP);
  await expect(cell(addressRow, "host")).toHaveText(HOST_NAME);
  const targetNode = withKey(page, "tree-node", TARGET_CIDR);
  await expect(withId(page, "tree-node", lab.target.id)).toHaveCount(1);
  await dragOnto(addressRow, targetNode);

  // The drop opens the move preview; nothing has changed yet.
  await expect(page.getByTestId("page-move-preview")).toBeVisible();
  const url = new URL(page.url());
  expect(url.pathname).toBe("/ipam/move");
  expect(url.searchParams.get("target")).toBe(lab.target.id);
  expect(url.searchParams.get("objects")).toBe(`address:${lab.address.id}`);
  const item = page.getByTestId("move-item");
  await expect(item).toHaveCount(1);
  await expect(item).toHaveAttribute("data-key", HOST_NAME);
  await expect(item).toHaveAttribute("data-id", lab.address.id);
  // Old address, then new address: the same host part (.15) in the target network. The
  // cell holds the two addresses and nothing else; the DNS cell the name, then both.
  await expect(cell(item, "ip")).toHaveText(inOrder(OLD_IP, NEW_IP));
  await expect(cell(item, "dns")).toHaveText(inOrder(DNS_NAME, OLD_IP, NEW_IP));
  // The network change: by hand, because the target network has no VLAN.
  const l2 = cell(item, "l2");
  await expect(l2).toHaveAttribute("data-testid", "move-l2");
  await expect(l2).toHaveAttribute("data-action", "manual");
  await expect(l2).toHaveAttribute("data-reason", "ipam.move.l2.no_vlan");

  // The steps of the device in job order, automatic and manual ones.
  await item.getByTestId("move-steps-toggle").click();
  const steps = item.getByTestId("move-steps");
  await expect(steps).toBeVisible();
  const stepKeys = await steps.getByTestId("move-step").evaluateAll((nodes) => nodes.map((node) => node.getAttribute("data-key")));
  expect(stepKeys).toEqual(plannedKinds);

  // The grouped checklist: one group per manual step kind, in the order of the job.
  const checklist = page.getByTestId("move-checklist");
  await expect(checklist).toBeVisible();
  const groupKeys = await checklist
    .getByTestId("move-checklist-group")
    .evaluateAll((nodes) => nodes.map((node) => node.getAttribute("data-key")));
  expect(groupKeys).toEqual(MANUAL_PREVIEW_KINDS);
  await expect(checklist.getByTestId("move-task")).toHaveCount(MANUAL_PREVIEW_KINDS.length);
  for (const kind of MANUAL_PREVIEW_KINDS) {
    await expect(withKey(checklist, "move-checklist-group", kind).getByTestId("move-task")).toHaveCount(1);
  }

  // Previewing starts nothing.
  expect(await moveJobs(api)).toHaveLength(0);
  expect((await addressesOf(api, lab.host.id)).map((address) => address.ip)).toEqual([OLD_IP]);

  // Confirm: the page hands over to the jobs list of the job group.
  await expect(page.getByTestId("move-start")).toBeEnabled();
  await page.getByTestId("move-start").click();
  await expect(page.getByTestId("page-jobs")).toBeVisible();
  const group = groupOf(page);
  const groupPanel = page.getByTestId("job-group");
  await expect(groupPanel).toBeVisible();
  const jobs = await jobsOfGroup(api, group);
  expect(jobs).toHaveLength(1);
  const job = jobs[0]!;
  expect(job.kind).toBe("ipam.move");
  expect(job.targets).toContainEqual({ kind: "host", id: lab.host.id });
  const jobRow = gridRow(page, "jobs", job.id);
  await expect(jobRow).toBeVisible();

  // The checklist of the group shows the tasks that wait, one step at a time. The first task
  // is the DHCP reservation: tick it off in the group checklist.
  const checklistOfGroup = page.getByTestId("job-group-checklist");
  const dhcp = withKey(checklistOfGroup, "job-group-kind", MANUAL_STEP_KINDS[0]);
  await expect(dhcp).toBeVisible();
  await expect(dhcp.getByTestId("job-group-task")).toHaveAttribute("data-job", job.id);
  await dhcp.getByTestId("job-group-task-complete").click();
  await expect(dhcp).toHaveCount(0);

  // The next task, the DNS records, is done on the page of the job, with a note.
  const dns = withKey(checklistOfGroup, "job-group-kind", MANUAL_STEP_KINDS[1]);
  await expect(dns).toBeVisible();
  await jobRow.click();
  await expect(page.getByTestId("page-job")).toBeVisible();
  await expect(page).toHaveURL(new RegExp(`/jobs/${job.id}$`));
  const dnsIndex = plannedKinds.indexOf("dns.manual");
  const dnsStep = stepAt(page, dnsIndex);
  await expect(page.getByTestId("job-steps").getByTestId("job-step")).toHaveCount(plannedKinds.length);
  await expect(dnsStep).toHaveAttribute("data-state", "waiting_for_manual");
  await expect(stepAt(page, plannedKinds.indexOf("dhcp.manual"))).toHaveAttribute("data-state", "done");
  await dnsStep.getByTestId("job-step-note").fill("Records switched to 198.51.100.15 on the test resolver");
  await dnsStep.getByTestId("job-step-complete").click();
  await expect(dnsStep).toHaveAttribute("data-state", "done");

  // Back to the group for the layer 2 change and the observation.
  await page.getByTestId("job-group-link").click();
  await expect(page.getByTestId("job-group")).toBeVisible();
  for (const kind of [MANUAL_STEP_KINDS[2], MANUAL_STEP_KINDS[3]]) {
    const section = withKey(page.getByTestId("job-group-checklist"), "job-group-kind", kind);
    await expect(section).toBeVisible();
    await section.getByTestId("job-group-task-complete").click();
    await expect(section).toHaveCount(0);
  }

  // The automatic cleanup follows and the job succeeds: nothing is left to do in the group.
  await expect(withKey(page.getByTestId("job-group"), "job-group-state", "succeeded")).toBeVisible();
  await expect(cell(gridRow(page, "jobs", job.id), "state").getByTestId("job-state")).toHaveAttribute("data-state", "succeeded");
  await expect(page.getByTestId("job-group-task")).toHaveCount(0);

  // The job in the API: every step done, the note of the DNS task in its log.
  const detail = await api.waitForJob(job.id);
  expect(detail.job.state).toBe("succeeded");
  expect(detail.job.steps.map((step) => step.state.state)).toEqual(plannedKinds.map(() => "done"));
  expect(detail.transitions.map((transition) => transition.note)).toContain("Records switched to 198.51.100.15 on the test resolver");

  // The result in the UI: the new address is active in the target network, the old one is gone.
  await page.goto(`/ipam/prefixes/${TARGET_CIDR}`);
  const moved = gridRow(page, "prefix-addresses", NEW_IP);
  await expect(moved).toBeVisible();
  await expect(cell(moved, "host")).toHaveText(HOST_NAME);
  await expect(cell(moved, "dns_name")).toHaveText(DNS_NAME);
  await expect(cell(moved, "status").getByTestId("status-badge")).toHaveAttribute("data-status", "active");
  await page.goto(`/ipam/prefixes/${SOURCE_CIDR}`);
  await expect(page.getByTestId("grid-prefix-addresses")).toBeVisible();
  await expect(gridRow(page, "prefix-addresses", OLD_IP)).toHaveCount(0);

  // The result in the API: one live address on the interface, in the target network.
  const addresses = await addressesOf(api, lab.host.id);
  expect(addresses.map((address) => address.ip)).toEqual([NEW_IP]);
  expect(addresses[0]).toMatchObject({ status: "active", interface: lab.interface.id, prefix: lab.target.id, dns_name: DNS_NAME });
  const host = await api.get<Schemas["Host"]>(`/hosts/${lab.host.id}`);
  expect(host.meta.tags ?? []).not.toContain(MOVE_FAILED_TAG);
});

test("cancelling the job of a move rolls it back and tags the host", async ({ page, api, signedIn }) => {
  expect(signedIn.session.user.name).toBe(ADMIN.name);
  const lab = await arrangeMoveLab(api);
  const submitted = await api.post<Schemas["MoveSubmitted"]>("/moves", {
    objects: [{ kind: "host", id: lab.host.id }],
    target: lab.target.id,
  });
  const jobId = submitted.jobs[0]!.job_id;

  // The job runs its automatic step and waits for the DHCP task.
  await page.goto(`/jobs/${jobId}`);
  await expect(page.getByTestId("page-job")).toBeVisible();
  await expect(stepAt(page, 1)).toHaveAttribute("data-state", "waiting_for_manual");
  await expect(page.getByTestId("page-job").getByTestId("job-state")).toHaveAttribute("data-state", "waiting");

  // Cancel and confirm.
  await page.getByTestId("job-cancel").click();
  const confirm = page.getByTestId("dialog-confirm");
  await expect(confirm.getByTestId("job-cancel-text")).toBeVisible();
  await confirm.getByTestId("confirm-ok").click();
  await expect(confirm).toHaveCount(0);

  // The job rolls back, then ends cancelled with its reason, and no task is left to do.
  await expect(page.getByTestId("page-job").getByTestId("job-state")).toHaveAttribute("data-state", "cancelled");
  await expect(page.getByTestId("job-cancel")).toHaveCount(0);
  await expect(page.getByTestId("job-error")).toBeVisible();
  await expect(page.getByTestId("job-step-task")).toHaveCount(0);
  const detail = await api.waitForJob(jobId);
  expect(detail.job.state).toBe("cancelled");
  expect(detail.job.cancel_requested).toBeTruthy();
  expect(detail.transitions.map((transition) => transition.state)).toContain("rolling_back");

  // The host keeps its old address and carries the tag of a failed move.
  const host = await api.get<Schemas["Host"]>(`/hosts/${lab.host.id}`);
  expect(host.meta.tags ?? []).toContain(MOVE_FAILED_TAG);
  const addresses = await addressesOf(api, lab.host.id);
  expect(addresses.map((address) => address.ip)).toEqual([OLD_IP]);
});
