// WP3.8a: the member actions of the cluster page (OPS-03, OPS-26; docs/cluster.md, section 12):
// promote a learner, remove a member, hand leadership over, and the digest check of a cluster
// whose members disagree.
//
// THESE SCENARIOS FAKE THE CLUSTER ROUTES. The e2e server is one controller, so a learner, a
// second voter and a member that holds other data cannot exist for real. The faked routes
// (support/cluster-mock.ts) answer `/cluster/*` in the browser with bodies shaped like the
// server's; everything else (sign-in, events, the page itself) is real. What is proven here is
// the UI: the preview of each dialog, the request it sends (method, path, body) and that it
// sends nothing before the person confirms, the refusals that keep the confirm button disabled,
// an answer of the server shown in the dialog, and the page following the answer and a change
// made elsewhere. The cluster itself is proven by the Rust lab tests
// (`crates/tenko/tests/acceptance_cluster.rs`, `acceptance_partition.rs`).
//
// Scenarios:
// - Promote: a caught-up learner to an odd number of voters sends an empty body; a lagging
//   learner needs "force" (and an even result is the second reason); a replacement sends
//   `replace`; while a membership change runs, every dialog refuses and sends nothing.
// - Remove: a learner, a voter (with the notes of an even number and no tolerance) and the
//   leader (which names itself); a refusal of the server (409) stays in the dialog and the
//   retry works.
// - Step down: the successor is named and the request has no body; the leader moves; without
//   a caught-up voter the dialog refuses; a follower has no step-down.
// - A viewer has no action; a member added elsewhere shows without a reload; the digest check
//   marks the member that differs; Swedish dialogs.

import { signInAsViewer } from "./support/accounts";
import { FakeCluster, member, threeVoters, threeVotersAndLearner } from "./support/cluster-mock";
import { expect, test } from "./support/fixtures";
import { expectRendered } from "./support/i18n";

const API = "/api/v1/cluster";

/** A cluster of two voters and a caught-up learner: promoting it makes three voters (odd). */
const TWO_VOTERS_AND_LEARNER = [member(1, { leader: true }), member(2, { lag: 0 }), member(3, { role: "learner", lag: 0 })];

test("OPS-03: promoting a caught-up learner shows the preview first and then sends one POST with an empty body", async ({ page, signedIn }) => {
  expect(signedIn.session.user.id).toBeTruthy();
  const fake = await FakeCluster.install(page, { members: TWO_VOTERS_AND_LEARNER });
  await page.goto("/cluster");
  await expect(page.getByTestId("cluster-voters")).toHaveAttribute("data-count", "2");
  await expect(page.getByTestId("member-row-3")).toHaveAttribute("data-role", "learner");

  await page.getByTestId("member-promote-3").click();
  const dialog = page.getByTestId("dialog-promote");
  await expect(dialog.getByTestId("preview-voters")).toHaveAttribute("data-before", "2");
  await expect(dialog.getByTestId("preview-voters")).toHaveAttribute("data-after", "3");
  await expect(dialog.getByTestId("preview-tolerated")).toHaveAttribute("data-before", "0");
  await expect(dialog.getByTestId("preview-tolerated")).toHaveAttribute("data-after", "1");
  await expect(dialog.getByTestId("preview-blockers")).toHaveCount(0);
  await expect(dialog.getByTestId("preview-forceable")).toHaveCount(0);
  await expect(dialog.getByTestId("field-force")).toHaveCount(0);
  await expect(dialog.getByTestId("promote-confirm")).toBeEnabled();
  // The preview is computed in the page: nothing was sent.
  expect(fake.sent).toEqual([]);

  await dialog.getByTestId("promote-confirm").click();
  await expect(dialog).toHaveCount(0);
  expect(fake.sent).toEqual([{ method: "POST", path: `${API}/members/3/promote`, query: "", body: {} }]);
  // The answer of the server replaces the table.
  await expect(page.getByTestId("member-row-3")).toHaveAttribute("data-role", "voter");
  await expect(page.getByTestId("member-promote-3")).toHaveCount(0);
  await expect(page.getByTestId("cluster-voters")).toHaveAttribute("data-count", "3");
  await expect(page.getByTestId("toast").first()).toBeVisible();
});

test("OPS-03: a learner that is behind needs the force box, and the request carries force", async ({ page, signedIn }) => {
  expect(signedIn.session.user.id).toBeTruthy();
  const fake = await FakeCluster.install(page, { members: threeVotersAndLearner(4200) });
  await page.goto("/cluster");
  await expect(page.getByTestId("member-row-4")).toHaveAttribute("data-state", "catching_up");

  await page.getByTestId("member-promote-4").click();
  const dialog = page.getByTestId("dialog-promote");
  // Three voters become four (even) and the learner is far behind: both can be forced.
  const forceable = dialog.getByTestId("preview-forceable");
  await expect(forceable.locator('[data-blocker="even_voters"]')).toHaveCount(1);
  await expect(forceable.locator('[data-blocker="not_caught_up"]')).toHaveCount(1);
  await expect(dialog.getByTestId("preview-blockers")).toHaveCount(0);
  await expect(dialog.getByTestId("promote-confirm")).toBeDisabled();

  await dialog.getByTestId("field-force").check();
  await expect(dialog.getByTestId("preview-forceable")).toHaveCount(0);
  await expect(dialog.getByTestId("preview-caveats").locator('[data-caveat="forced"]')).toHaveCount(1);
  await expect(dialog.getByTestId("promote-confirm")).toBeEnabled();
  expect(fake.sent).toEqual([]);

  await dialog.getByTestId("promote-confirm").click();
  await expect(dialog).toHaveCount(0);
  expect(fake.sent).toEqual([{ method: "POST", path: `${API}/members/4/promote`, query: "", body: { force: true } }]);
  await expect(page.getByTestId("member-row-4")).toHaveAttribute("data-role", "voter");
  await expect(page.getByTestId("cluster-voters")).toHaveAttribute("data-count", "4");
});

test("OPS-03: promoting with a replacement keeps the odd number and sends replace", async ({ page, signedIn }) => {
  expect(signedIn.session.user.id).toBeTruthy();
  const fake = await FakeCluster.install(page, { members: threeVotersAndLearner(0) });
  await page.goto("/cluster");

  await page.getByTestId("member-promote-4").click();
  const dialog = page.getByTestId("dialog-promote");
  await expect(dialog.getByTestId("preview-forceable").locator('[data-blocker="even_voters"]')).toHaveCount(1);
  await expect(dialog.getByTestId("promote-confirm")).toBeDisabled();

  // Replacing a voter in the same change keeps three voters.
  await dialog.getByTestId("field-replace").selectOption("3");
  await expect(dialog.getByTestId("preview-voters")).toHaveAttribute("data-before", "3");
  await expect(dialog.getByTestId("preview-voters")).toHaveAttribute("data-after", "3");
  await expect(dialog.getByTestId("preview-forceable")).toHaveCount(0);
  await expect(dialog.getByTestId("preview-caveats").locator('[data-caveat="replaces"]')).toHaveCount(1);
  await expect(dialog.getByTestId("promote-confirm")).toBeEnabled();

  await dialog.getByTestId("promote-confirm").click();
  await expect(dialog).toHaveCount(0);
  expect(fake.sent).toEqual([{ method: "POST", path: `${API}/members/4/promote`, query: "", body: { replace: 3 } }]);
  await expect(page.getByTestId("member-row-3")).toHaveCount(0);
  await expect(page.getByTestId("member-row-4")).toHaveAttribute("data-role", "voter");
  await expect(page.getByTestId("cluster-voters")).toHaveAttribute("data-count", "3");
});

test("OPS-03: while a membership change runs, promote, remove and step-down are refused and send nothing", async ({ page, signedIn }) => {
  expect(signedIn.session.user.id).toBeTruthy();
  const fake = await FakeCluster.install(page, { members: threeVotersAndLearner(0) });
  fake.setChanging(true);
  await page.goto("/cluster");
  await expect(page.getByTestId("cluster-changing")).toBeVisible();

  await page.getByTestId("member-promote-4").click();
  let dialog = page.getByTestId("dialog-promote");
  await expect(dialog.getByTestId("preview-blockers").locator('[data-blocker="changing"]')).toHaveCount(1);
  await expect(dialog.getByTestId("promote-confirm")).toBeDisabled();
  await page.keyboard.press("Escape");
  await expect(dialog).toHaveCount(0);

  await page.getByTestId("member-remove-4").click();
  dialog = page.getByTestId("dialog-remove");
  await expect(dialog.getByTestId("preview-blockers").locator('[data-blocker="changing"]')).toHaveCount(1);
  await expect(dialog.getByTestId("remove-confirm")).toBeDisabled();
  await page.keyboard.press("Escape");
  await expect(dialog).toHaveCount(0);

  await page.getByTestId("cluster-step-down").click();
  dialog = page.getByTestId("dialog-step-down");
  await expect(dialog.getByTestId("preview-blockers").locator('[data-blocker="changing"]')).toHaveCount(1);
  await expect(dialog.getByTestId("step-down-confirm")).toBeDisabled();
  await page.keyboard.press("Escape");
  expect(fake.sent).toEqual([]);
});

test("OPS-03: removing a learner and then a voter sends one DELETE each, with the notes the preview gives", async ({ page, signedIn }) => {
  expect(signedIn.session.user.id).toBeTruthy();
  const fake = await FakeCluster.install(page, { members: threeVotersAndLearner(0) });
  await page.goto("/cluster");

  await test.step("a learner leaves: the voters stay, the certificates are revoked", async () => {
    await page.getByTestId("member-remove-4").click();
    const dialog = page.getByTestId("dialog-remove");
    await expect(dialog.getByTestId("preview-voters")).toHaveAttribute("data-before", "3");
    await expect(dialog.getByTestId("preview-voters")).toHaveAttribute("data-after", "3");
    await expect(dialog.getByTestId("preview-caveats").locator("[data-caveat]")).toHaveCount(1);
    await expect(dialog.getByTestId("preview-caveats").locator('[data-caveat="revokes"]')).toHaveCount(1);
    await expect(dialog.getByTestId("preview-blockers")).toHaveCount(0);
    expect(fake.sent).toEqual([]);
    await dialog.getByTestId("remove-confirm").click();
    await expect(dialog).toHaveCount(0);
    await expect(page.getByTestId("member-row-4")).toHaveCount(0);
  });

  await test.step("a voter leaves: two voters tolerate no failure", async () => {
    await page.getByTestId("member-remove-3").click();
    const dialog = page.getByTestId("dialog-remove");
    await expect(dialog.getByTestId("preview-voters")).toHaveAttribute("data-before", "3");
    await expect(dialog.getByTestId("preview-voters")).toHaveAttribute("data-after", "2");
    await expect(dialog.getByTestId("preview-tolerated")).toHaveAttribute("data-before", "1");
    await expect(dialog.getByTestId("preview-tolerated")).toHaveAttribute("data-after", "0");
    const caveats = dialog.getByTestId("preview-caveats");
    await expect(caveats.locator('[data-caveat="even_after"]')).toHaveCount(1);
    await expect(caveats.locator('[data-caveat="no_tolerance"]')).toHaveCount(1);
    await dialog.getByTestId("remove-confirm").click();
    await expect(dialog).toHaveCount(0);
    await expect(page.getByTestId("member-row-3")).toHaveCount(0);
    await expect(page.getByTestId("cluster-voters")).toHaveAttribute("data-count", "2");
  });

  expect(fake.sent).toEqual([
    { method: "DELETE", path: `${API}/members/4`, query: "", body: null },
    { method: "DELETE", path: `${API}/members/3`, query: "", body: null },
  ]);
});

test("OPS-03: removing the leader names the consequence and another voter leads afterwards", async ({ page, signedIn }) => {
  expect(signedIn.session.user.id).toBeTruthy();
  const fake = await FakeCluster.install(page, { members: threeVoters() });
  await page.goto("/cluster");
  await expect(page.getByTestId("cluster-leader")).toHaveAttribute("data-node", "1");

  await page.getByTestId("member-remove-1").click();
  const dialog = page.getByTestId("dialog-remove");
  const caveats = dialog.getByTestId("preview-caveats");
  await expect(caveats.locator('[data-caveat="removes_leader"]')).toHaveCount(1);
  await expect(caveats.locator('[data-caveat="removes_self"]')).toHaveCount(1);
  await dialog.getByTestId("remove-confirm").click();
  await expect(dialog).toHaveCount(0);
  expect(fake.sent).toEqual([{ method: "DELETE", path: `${API}/members/1`, query: "", body: null }]);
  // The controller that answered left; the answer names the new leader and the page follows it.
  await expect(page.getByTestId("cluster-leader")).toHaveAttribute("data-node", "2");
  await expect(page.getByTestId("member-row-1")).toHaveCount(0);
  await expect(page.getByTestId("cluster-term")).toHaveText(/8/);
});

test("OPS-03: a refusal of the server stays in the dialog and the retry works", async ({ page, signedIn }) => {
  expect(signedIn.session.user.id).toBeTruthy();
  const fake = await FakeCluster.install(page, { members: threeVotersAndLearner(0) });
  fake.refuseNext("DELETE", /\/members\/4$/, {
    status: 409,
    code: "cluster.member.changing",
    detail: "another membership change is in progress",
  });
  await page.goto("/cluster");

  await page.getByTestId("member-remove-4").click();
  const dialog = page.getByTestId("dialog-remove");
  await dialog.getByTestId("remove-confirm").click();
  await expect(dialog.getByTestId("error-notice")).toHaveAttribute("data-code", "cluster.member.changing");
  await expect(page.getByTestId("member-row-4")).toBeVisible();

  await dialog.getByTestId("remove-confirm").click();
  await expect(dialog).toHaveCount(0);
  await expect(page.getByTestId("member-row-4")).toHaveCount(0);
  // Both attempts were sent, the first refused.
  expect(fake.sent.map((s) => `${s.method} ${s.path}`)).toEqual([`DELETE ${API}/members/4`, `DELETE ${API}/members/4`]);
});

test("OPS-03: handing leadership over names the successor, sends POST without a body and the leader moves", async ({ page, signedIn }) => {
  expect(signedIn.session.user.id).toBeTruthy();
  const fake = await FakeCluster.install(page, { members: threeVoters() });
  await page.goto("/cluster");
  await expect(page.getByTestId("cluster-leader")).toHaveAttribute("data-node", "1");
  await expect(page.getByTestId("cluster-term")).toHaveText(/7/);

  await page.getByTestId("cluster-step-down").click();
  const dialog = page.getByTestId("dialog-step-down");
  // Node 2 is the voter that is most caught up (no entries behind against two).
  await expect(dialog.getByTestId("step-down-successor")).toHaveAttribute("data-node", "2");
  await expect(dialog.getByTestId("preview-voters")).toHaveAttribute("data-before", "3");
  await expect(dialog.getByTestId("preview-voters")).toHaveAttribute("data-after", "3");
  await expect(dialog.getByTestId("preview-caveats").locator('[data-caveat="reconnect"]')).toHaveCount(1);
  await expect(dialog.getByTestId("preview-blockers")).toHaveCount(0);
  expect(fake.sent).toEqual([]);

  await dialog.getByTestId("step-down-confirm").click();
  await expect(dialog).toHaveCount(0);
  expect(fake.sent).toEqual([{ method: "POST", path: `${API}/step-down`, query: "", body: null }]);
  await expect(page.getByTestId("cluster-leader")).toHaveAttribute("data-node", "2");
  await expect(page.getByTestId("cluster-term")).toHaveText(/8/);
  await expect(page.getByTestId("member-row-2")).toHaveAttribute("data-state", "leader");
  await expect(page.getByTestId("member-row-1")).toHaveAttribute("data-state", "caught_up");
  // This controller does not lead any more, so the action is gone.
  await expect(page.getByTestId("cluster-step-down")).toHaveCount(0);
});

test("OPS-03: without a caught-up voter the step-down is refused", async ({ page, signedIn }) => {
  expect(signedIn.session.user.id).toBeTruthy();
  const fake = await FakeCluster.install(page, { members: [member(1, { leader: true }), member(2, { lag: 0, contactMs: 30_000 })] });
  await page.goto("/cluster");
  await expect(page.getByTestId("member-row-2")).toHaveAttribute("data-state", "out_of_contact");

  await page.getByTestId("cluster-step-down").click();
  const dialog = page.getByTestId("dialog-step-down");
  await expect(dialog.getByTestId("preview-blockers").locator('[data-blocker="no_successor"]')).toHaveCount(1);
  await expect(dialog.getByTestId("step-down-successor")).toHaveCount(0);
  await expect(dialog.getByTestId("step-down-confirm")).toBeDisabled();
  await page.keyboard.press("Escape");
  expect(fake.sent).toEqual([]);
});

test("OPS-03: the page of a follower offers no step-down", async ({ page, signedIn }) => {
  expect(signedIn.session.user.id).toBeTruthy();
  const fake = await FakeCluster.install(page, { members: threeVoters(), node: 2 });
  await page.goto("/cluster");
  // The controller that answers is node 2; node 1 leads, so there is nothing to hand over here.
  await expect(page.getByTestId("cluster-node")).toHaveAttribute("data-node", "2");
  await expect(page.getByTestId("cluster-leader")).toHaveAttribute("data-node", "1");
  await expect(page.getByTestId("member-row-3")).toBeVisible();
  await expect(page.getByTestId("cluster-step-down")).toHaveCount(0);
  expect(fake.sent).toEqual([]);
});

test("OPS-03: a viewer sees the members and checks the digests but has no member action", async ({ page, api, signedIn }) => {
  expect(signedIn.session.user.id).toBeTruthy();
  await FakeCluster.install(page, { members: threeVotersAndLearner(0) });
  await signInAsViewer(api);
  await page.goto("/cluster");
  await expect(page.getByTestId("member-row-4")).toBeVisible();
  await expect(page.getByTestId("cluster-add-controller")).toHaveCount(0);
  await expect(page.getByTestId("cluster-step-down")).toHaveCount(0);
  for (const node of [1, 2, 3, 4]) {
    await expect(page.getByTestId(`member-remove-${node}`)).toHaveCount(0);
    await expect(page.getByTestId(`member-promote-${node}`)).toHaveCount(0);
  }
  await page.getByTestId("cluster-check-digests").click();
  await expect(page.getByTestId("digests-overall")).toHaveAttribute("data-state", "agree");
  await expect(page.locator("[data-testid^='digest-row-']")).toHaveCount(4);
});

test("OPS-03: a member added elsewhere shows on the open page without a reload", async ({ page, api, signedIn }) => {
  expect(signedIn.session.user.id).toBeTruthy();
  const fake = await FakeCluster.install(page, { members: threeVoters() });
  await page.goto("/cluster");
  await expect(page.locator("[data-testid^='member-row-']")).toHaveCount(3);

  // Another administrator adds a learner; the real server announces the change on the cluster topic.
  fake.setMembers(threeVotersAndLearner(0));
  await fake.refreshCluster(api);
  await expect(page.getByTestId("member-row-4")).toHaveAttribute("data-role", "learner");
  await expect(page.getByTestId("member-promote-4")).toBeVisible();
});

test("OPS-03: the digest check marks the member that holds other data", async ({ page, signedIn }) => {
  expect(signedIn.session.user.id).toBeTruthy();
  const fake = await FakeCluster.install(page, { members: threeVoters() });
  fake.setDigestMismatch(3);
  await page.goto("/cluster");
  await page.getByTestId("cluster-check-digests").click();
  await expect(page.getByTestId("digests-overall")).toHaveAttribute("data-state", "differ");
  await expect(page.getByTestId("digest-row-1").getByTestId("digest-state")).toHaveAttribute("data-state", "agrees");
  await expect(page.getByTestId("digest-row-2").getByTestId("digest-state")).toHaveAttribute("data-state", "agrees");
  await expect(page.getByTestId("digest-row-3").getByTestId("digest-state")).toHaveAttribute("data-state", "differs");
  // The member that differs shows another value than the ones that agree.
  const value = (node: number) => page.getByTestId(`digest-row-${node}`).getByTestId("digest-value").innerText();
  expect(await value(3)).not.toEqual(await value(1));
  expect(await value(1)).toEqual(await value(2));
});

test.describe("a Swedish browser", () => {
  test.use({ locale: "sv-SE" });

  test("OPS-03: renders the member table and the promote, remove and step-down dialogs in Swedish", async ({ page, signedIn }, testInfo) => {
    expect(signedIn.session.user.id).toBeTruthy();
    await FakeCluster.install(page, { members: threeVotersAndLearner(4200) });
    await page.goto("/cluster");
    await expect(page.getByTestId("member-row-4")).toBeVisible();
    await expectRendered(page, page.getByTestId("page-cluster"), "sv", testInfo, "cluster-members");

    await page.getByTestId("member-promote-4").click();
    const promote = page.getByTestId("dialog-promote");
    await expect(promote.getByTestId("preview-forceable")).toBeVisible();
    await expectRendered(page, promote, "sv", testInfo, "cluster-promote");
    await promote.getByTestId("field-force").check();
    await expect(promote.getByTestId("preview-caveats")).toBeVisible();
    await expectRendered(page, promote, "sv");
    await page.keyboard.press("Escape");

    await page.getByTestId("member-remove-3").click();
    const remove = page.getByTestId("dialog-remove");
    await expect(remove.getByTestId("preview-caveats")).toBeVisible();
    await expectRendered(page, remove, "sv");
    await page.keyboard.press("Escape");

    await page.getByTestId("cluster-step-down").click();
    const stepDown = page.getByTestId("dialog-step-down");
    await expect(stepDown.getByTestId("step-down-successor")).toBeVisible();
    await expectRendered(page, stepDown, "sv", testInfo, "cluster-step-down");
  });
});
