// Scenario WP2.11: discovery end to end (IPAM-12 to IPAM-17, IPAM-19, IPAM-21; docs/reconciliation.md).
// The source of the observations is an instance of the bundled sample connector, arranged
// through the API (support/discovery.ts): with the network 192.0.2.0/24 in place, one run
// of three hosts gives three open `discovered_host` proposals (keys `discovered_host/mac:
// 00:00:5e:00:53:00` to `:02`) and one open `outside_prefixes` proposal for 2001:db8::/64,
// because the sample hosts also have IPv6 addresses that no known network contains. The
// reconciler writes them two seconds after the run (its debounce); the tests wait for them
// through the API.
//
// - The inbox lists the open proposals with kind and severity, the filters narrow it, a
//   proposal opens in the docked panel with its evidence and the suggested change, and a
//   person decides it: approve (the plan dialog with its dry run, then the inline job of the
//   decision on the job page) and reject with a reason. "Run now" then reports the rejected
//   subject as suppressed and opens nothing new. The dashboard tile counts the open ones.
// - The observations list the facts of two sources, filter by type, state and source, and
//   open the picture of a subject (summary, facts per source, intent, proposals); the host
//   page shows the same facts for the host that was created from the proposal.
// - An adoption policy on the prefix lets the reconciler adopt the open discovered-host
//   proposals by itself; clearing it makes the prefix inherit the default `manual` again.
// - Approving the outside-prefixes proposal creates the network, which supersedes the open
//   discovered-host proposals with ones that include the IPv6 address.
// - The inbox, an open proposal with its approve and reject dialogs and the report of a run,
//   the observations and the picture of a subject in Swedish.
// - The status bar item `status-proposals` shows the number of open proposals on any page,
//   follows a rejection made elsewhere without a reload, disappears at zero and links to the
//   inbox.
//
// Documentation values only: 192.0.2.0/24, 2001:db8::/32, MAC 00:00:5e:00:53:xx, names under
// example.test; the rejection reason is invented. What stays manual: an adoption that the
// planner refuses (a reserved host inside a DHCP pool, which leaves the proposal open with
// its error code) and observations from probes, which need a node with a scanner. The
// refused adoption is covered by crates/tenko-ipam/tests/proposals.rs and by
// ui/src/discovery/ProposalsView.test.tsx.

import type { Locator, Page } from "@playwright/test";
import type { Api, Schemas } from "./support/api";
import {
  createSampleConnector,
  observations,
  proposals,
  reconcile,
  runConnector,
  sampleHost,
  waitForProposals,
  type ConnectorView,
  type Proposal,
} from "./support/discovery";
import { expect, test } from "./support/fixtures";
import { expectRendered } from "./support/i18n";
import { hostByName, prefixByCidr, type Host, type Prefix } from "./support/ipam";
import { cell, withId, withIndex, withKey } from "./support/ui";

type Decision = Schemas["Decision"];

/** The state the sample connector leaves behind: the network, the source and its proposals. */
interface Arranged {
  prefix: Prefix;
  connector: ConnectorView;
  /** The open `discovered_host` proposals, by sample host number. */
  hosts: Proposal[];
  /** The open `outside_prefixes` proposal for 2001:db8::/64. */
  outside: Proposal;
}

/** The regular expression of a MAC address in any notation the UI may show it in. */
function macPattern(mac: string): RegExp {
  return new RegExp(mac.split(":").join("[-:.]?"), "i");
}

/**
 * Creates 192.0.2.0/24 and an instance of the sample connector with `hosts` hosts, runs it
 * and waits until the reconciler has opened a proposal per host and the one for the IPv6
 * network.
 */
async function arrange(api: Api, hosts = 3): Promise<Arranged> {
  await api.post("/prefixes", { cidr: "192.0.2.0/24" });
  const prefix = (await prefixByCidr(api, "192.0.2.0/24"))!;
  const connector = await createSampleConnector(api, "Lab sample", { hosts });
  await runConnector(api, connector.id);
  const open = await waitForProposals(api, { state: "open" }, hosts + 1);
  const byIndex = Array.from({ length: hosts }, (_, n) => {
    const found = open.find((p) => p.key === `discovered_host/mac:${sampleHost(n).mac}`);
    expect(found, `a discovered-host proposal for sample host ${n}`).toBeDefined();
    return found!;
  });
  const outside = open.find((p) => p.kind === "outside_prefixes");
  expect(outside?.key).toBe("outside_prefixes/" + outside?.subject.vrf + "/2001:db8::/64");
  return { prefix, connector, hosts: byIndex, outside: outside! };
}

/** Approves a proposal through the API, as a person would. */
async function approve(api: Api, proposal: Proposal): Promise<Decision> {
  return api.post<Decision>(`/proposals/${proposal.id}/approve`);
}

/** The proposal with this id as the API has it now. */
async function proposalOf(api: Api, id: string): Promise<Proposal> {
  return api.get<Proposal>(`/proposals/${id}`);
}

/** The changes of a previewed plan for one kind of object and one action, inside `scope`. */
function planChanges(scope: Page | Locator, kind: string, action: string): Locator {
  return scope.locator(`[data-testid="plan-change"][data-kind="${kind}"][data-action="${action}"]`);
}

/** The ids of the rows of the inbox, in the order shown. */
async function rowIds(page: Page): Promise<string[]> {
  return page.getByTestId("grid-proposals").getByTestId("row").evaluateAll((rows) => rows.map((row) => row.getAttribute("data-id") ?? ""));
}

/** Opens the proposal `id` in the inbox by clicking its row and waits for the docked panel. */
async function openProposal(page: Page, id: string): Promise<Locator> {
  await cell(withId(page.getByTestId("grid-proposals"), "row", id), "summary").click();
  await expect(page).toHaveURL(new RegExp(`/discovery/${id}(\\?.*)?$`));
  const panel = withId(page, "proposal-panel", id);
  await expect(panel).toBeVisible();
  return panel;
}

test("the inbox lists the open proposals, a person approves one and rejects another, and the rejected subject stays closed", async ({
  page,
  api,
  signedIn,
}) => {
  expect(signedIn.session.user.name).toBe("admin");
  const { connector, hosts, outside } = await arrange(api);
  const sourceKey = `inventory:${connector.id}`;
  const [approved, rejected, left] = hosts as [Proposal, Proposal, Proposal];
  const first = sampleHost(0);

  // The dashboard tile counts the open proposals and links to the inbox.
  await page.goto("/");
  await expect(page.getByTestId("page-dashboard")).toBeVisible();
  const tile = page.getByTestId("dashboard-proposals");
  await expect(tile.getByTestId("dashboard-proposals-link")).toHaveText(String((await proposals(api, { state: "open" })).length));
  await tile.getByTestId("dashboard-proposals-link").click();
  await expect(page.getByTestId("page-discovery")).toBeVisible();
  await expect(page).toHaveURL(/\/discovery$/);

  // The inbox lists the open ones, newest first, with kind and severity.
  const grid = page.getByTestId("grid-proposals");
  await expect(grid.getByTestId("row")).toHaveCount(4);
  for (const proposal of hosts) {
    const row = withId(grid, "row", proposal.id);
    await expect(row).toBeVisible();
    await expect(cell(row, "kind").locator('[data-kind="discovered_host"]')).toBeVisible();
    await expect(cell(row, "severity").locator('[data-severity="info"]')).toBeVisible();
    await expect(cell(row, "state").locator('[data-state="open"]')).toBeVisible();
    await expect(cell(row, "sources").locator(`[data-source="${sourceKey}"]`)).toBeVisible();
  }
  const outsideRow = withId(grid, "row", outside.id);
  await expect(cell(outsideRow, "kind").locator('[data-kind="outside_prefixes"]')).toBeVisible();
  await expect(cell(outsideRow, "severity").locator('[data-severity="warning"]')).toBeVisible();

  // The filters narrow the inbox, and they live in the URL.
  await page.getByTestId("filter-kind-outside_prefixes").click();
  await expect(grid.getByTestId("row")).toHaveCount(1);
  await expect(outsideRow).toBeVisible();
  await expect(page).toHaveURL(/kind=outside_prefixes/);
  await page.getByTestId("filter-kind-outside_prefixes").click();
  await expect(grid.getByTestId("row")).toHaveCount(4);
  await page.getByTestId("filter-severity-info").click();
  await expect(grid.getByTestId("row")).toHaveCount(3);
  await expect(outsideRow).toHaveCount(0);
  await page.getByTestId("filter-severity-info").click();
  await expect(grid.getByTestId("row")).toHaveCount(4);

  // A proposal opens in the docked panel: summary, subject, evidence and the suggested change.
  const panel = await openProposal(page, approved.id);
  await expect(panel.getByTestId("proposal-summary")).toContainText(first.name);
  await expect(panel.locator('[data-kind="discovered_host"]').first()).toBeVisible();
  await expect(panel.locator('[data-state="open"]').first()).toBeVisible();
  await expect(panel.getByTestId("proposal-subject-link")).toContainText(macPattern(first.mac));
  // One entry per pair of the host fact: its MAC address with each of its addresses.
  const evidence = panel.getByTestId("evidence");
  await expect(evidence).toHaveCount(2);
  await expect(withKey(panel, "evidence", sourceKey)).toHaveCount(2);
  await expect(withIndex(panel, "evidence", 0)).toContainText(first.ipv4);
  await expect(withIndex(panel, "evidence", 1)).toContainText(first.ipv6);
  await expect(evidence).toContainText([macPattern(first.mac), macPattern(first.mac)]);
  await expect(evidence).toContainText([first.name, first.name]);
  const change = panel.getByTestId("proposal-change");
  await expect(planChanges(change, "host", "create")).toHaveCount(1);
  await expect(planChanges(change, "interface", "create")).toHaveCount(1);
  await expect(planChanges(change, "address", "create")).toHaveCount(1);
  // Nothing is written by looking at it.
  expect(await hostByName(api, first.name)).toBeUndefined();

  // Approve: the plan dialog previews the commands first (a dry run), the apply writes them.
  await panel.getByTestId("discovery-approve").click();
  const approve = page.getByTestId("dialog-approve");
  await expect(approve).toBeVisible();
  await expect(approve.getByTestId("plan-summary")).toBeVisible();
  await expect(planChanges(approve, "host", "create")).toHaveCount(1);
  expect(await hostByName(api, first.name)).toBeUndefined();
  expect((await proposalOf(api, approved.id)).state).toBe("open");
  await approve.getByTestId("plan-confirm").click();
  await expect(approve).toHaveCount(0);

  // The decision ran as an inline job; the toast, which fades after seven seconds, leads to its page.
  await withIndex(page, "toast-action", 0).click();
  await expect(page.getByTestId("page-job")).toBeVisible();
  await expect(page).toHaveURL(/\/jobs\/[0-9a-f-]{36}$/);
  const jobId = new URL(page.url()).pathname.split("/").pop()!;
  await expect(page.getByTestId("page-job").getByTestId("job-state")).toHaveAttribute("data-state", "succeeded");
  const job = await api.waitForJob(jobId);
  expect(job.job.state).toBe("succeeded");
  expect(job.job.error ?? null).toBeNull();
  await page.goBack();
  await expect(page.getByTestId("page-discovery")).toBeVisible();
  await expect(panel).toBeVisible();

  // The panel follows the decision.
  await expect(panel.getByTestId("proposal-decision")).toBeVisible();
  await expect(panel.getByTestId("proposal-decision").locator('[data-state="accepted"]')).toBeVisible();
  await expect(panel.getByTestId("discovery-approve")).toHaveCount(0);
  const accepted = await proposalOf(api, approved.id);
  expect(accepted.state).toBe("accepted");
  expect(accepted.decided?.by).toMatchObject({ kind: "user" });

  // The host exists: dynamic, tagged `discovered`, with an interface that carries the MAC
  // address and the address 192.0.2.10 on it.
  const host = (await hostByName(api, first.name)) as Host;
  expect(host.mode).toBe("dynamic");
  expect(host.meta.tags ?? []).toContain("discovered");
  const interfaces = await api.get<Schemas["Page_Interface"]>(`/hosts/${host.id}/interfaces`);
  expect(interfaces.items.map((i) => i.mac?.toLowerCase())).toEqual([first.mac]);
  const addresses = await api.get<Schemas["Page_AddressRow"]>("/addresses", { prefix: (await prefixByCidr(api, "192.0.2.0/24"))!.id });
  const address = addresses.items.find((a) => a.ip === first.ipv4);
  expect(address?.interface).toBe(interfaces.items[0]!.id);
  expect(accepted.results).toContainEqual({ kind: "host", id: host.id });
  expect(accepted.results).toContainEqual({ kind: "address", id: address!.id });

  // Reject another with a reason: the dialog, the state, the reason as stored.
  const reason = "Managed by the lab team, not by IPAM";
  await expect(grid.getByTestId("row")).toHaveCount(3);
  await expect(withId(grid, "row", approved.id)).toHaveCount(0);
  const rejectedPanel = await openProposal(page, rejected.id);
  await rejectedPanel.getByTestId("discovery-reject").click();
  const dialog = page.getByTestId("dialog-reject");
  await expect(dialog).toBeVisible();
  await dialog.getByTestId("field-reason").fill(reason);
  await dialog.getByTestId("form-submit").click();
  await expect(dialog).toHaveCount(0);
  await expect(rejectedPanel.getByTestId("proposal-decision").locator('[data-state="rejected"]')).toBeVisible();
  await expect(rejectedPanel.getByTestId("proposal-decision")).toContainText(reason);
  const rejection = await proposalOf(api, rejected.id);
  expect(rejection.state).toBe("rejected");
  expect(rejection.reason).toBe(reason);
  expect(rejection.decided?.by).toMatchObject({ kind: "user" });

  // The state filter shows the decided ones.
  await page.getByTestId("filter-state").selectOption("rejected");
  await expect(grid.getByTestId("row")).toHaveCount(1);
  await expect(cell(withId(grid, "row", rejected.id), "state").locator('[data-state="rejected"]')).toBeVisible();
  await page.getByTestId("filter-state").selectOption("accepted");
  await expect(grid.getByTestId("row")).toHaveCount(1);
  await expect(cell(withId(grid, "row", approved.id), "state").locator('[data-state="accepted"]')).toBeVisible();
  await page.getByTestId("filter-state").selectOption("open");
  await expect(grid.getByTestId("row")).toHaveCount(2);
  expect((await rowIds(page)).sort()).toEqual([left.id, outside.id].sort());

  // "Run now": the report counts the rejected subject as suppressed and opens nothing new.
  await page.getByTestId("discovery-reconcile").click();
  const report = page.getByTestId("dialog-reconcile-report");
  await expect(report).toBeVisible();
  await expect(withKey(report, "report-count", "suppressed")).toHaveText("1");
  await expect(withKey(report, "report-count", "opened")).toHaveText("0");
  await expect(withKey(report, "report-count", "adopted")).toHaveText("0");
  await expect(withKey(report, "report-count", "adoption_failures")).toHaveText("0");
  await page.keyboard.press("Escape");
  await expect(report).toHaveCount(0);

  // No new open proposal for the rejected subject, in the UI or in the API.
  const stillOpen = await proposals(api, { state: "open" });
  expect(stillOpen.map((p) => p.id).sort()).toEqual([left.id, outside.id].sort());
  expect(stillOpen.map((p) => p.key)).not.toContain(rejected.key);
  expect((await reconcile(api)).suppressed).toBe(1);
  await expect(grid.getByTestId("row")).toHaveCount(2);
  await expect(withId(grid, "row", rejected.id)).toHaveCount(0);

  // The dashboard tile follows: two proposals are left.
  await page.goto("/");
  await expect(page.getByTestId("dashboard-proposals-link")).toHaveText("2");
});

test("the observations list the facts of two sources and open the picture of a subject and of the host made from it", async ({
  page,
  api,
  signedIn,
}) => {
  expect(signedIn.session.user.name).toBe("admin");
  const { connector, hosts } = await arrange(api);
  const first = sampleHost(0);
  const firstSource = `inventory:${connector.id}`;

  // The first host becomes intent; a second instance reports the same host again, so the
  // device has facts from two sources.
  const decision = await approve(api, hosts[0]!);
  expect(decision.proposal.state).toBe("accepted");
  const second = await createSampleConnector(api, "Second sample", { hosts: 1 });
  await runConnector(api, second.id);
  const secondSource = `inventory:${second.id}`;
  // The new evidence changes what the proposal for 2001:db8::/64 says, so the reconciler
  // replaces it; waiting for that keeps the proposals of the device still while it is read.
  await expect
    .poll(async () => (await proposals(api, { state: "superseded" })).map((p) => p.kind), {
      message: "the outside-prefixes proposal to be replaced by one with the evidence of both sources",
    })
    .toEqual(["outside_prefixes"]);
  const host = (await hostByName(api, first.name)) as Host;
  const facts = await observations(api);
  expect(facts.map((f) => f.source_key).sort()).toEqual([firstSource, firstSource, firstSource, secondSource].sort());
  const factId = (f: { source_key: string; subject_key: string }) => `${f.source_key}|${f.subject_key}`;

  // The list: every current fact, with its subject key and its counted sightings.
  await page.goto("/discovery/observations");
  await expect(page.getByTestId("page-discovery-observations")).toBeVisible();
  const grid = page.getByTestId("grid-observations");
  await expect(grid.getByTestId("row")).toHaveCount(facts.length);
  for (const fact of facts) {
    const row = withId(grid, "row", factId(fact));
    await expect(row).toHaveAttribute("data-key", fact.subject_key);
    await expect(cell(row, "state").locator('[data-state="current"]')).toBeVisible();
    await expect(cell(row, "sightings")).toHaveText(String(fact.sightings ?? 1));
  }

  // The filters: by type, by state and by source.
  await page.getByTestId("filter-type-services").click();
  await expect(page.getByTestId("observations-empty")).toBeVisible();
  await expect(grid.getByTestId("row")).toHaveCount(0);
  await page.getByTestId("filter-type-services").click();
  await page.getByTestId("filter-type-host").click();
  await expect(grid.getByTestId("row")).toHaveCount(facts.length);
  await page.getByTestId("filter-type-host").click();
  await page.getByTestId("filter-current-expired").click();
  await expect(page.getByTestId("observations-empty")).toBeVisible();
  await page.getByTestId("filter-current-all").click();
  await expect(grid.getByTestId("row")).toHaveCount(facts.length);
  await page.getByTestId("filter-current-current").click();
  await expect(grid.getByTestId("row")).toHaveCount(facts.length);
  await page.goto(`/discovery/observations?source=${second.id}`);
  await expect(page.getByTestId("filter-source")).toBeVisible();
  await expect(grid.getByTestId("row")).toHaveCount(1);
  await expect(withId(grid, "row", `${secondSource}|host:sample/0`)).toBeVisible();
  await page.goto(`/discovery/observations?source=${firstSource}`);
  await expect(grid.getByTestId("row")).toHaveCount(3);
  await expect(withId(grid, "row", `${secondSource}|host:sample/0`)).toHaveCount(0);
  // Removing the source chip lists every fact again.
  await page.getByTestId("filter-source").getByTestId("filter-chip-remove").click();
  await expect(page.getByTestId("filter-source")).toHaveCount(0);
  await expect(page).not.toHaveURL(/[?&]source=/);
  await expect(grid.getByTestId("row")).toHaveCount(facts.length);

  // The lookup opens the picture of any subject; one that no fact names says so.
  await page.goto("/discovery/observations");
  const lookup = page.getByTestId("discovery-lookup");
  await lookup.getByTestId("field-subject").fill("00:00:5e:00:53:7f");
  await lookup.getByTestId("form-submit").click();
  await expect(page.getByTestId("page-discovery-subject")).toBeVisible();
  await expect(page.getByTestId("subject-unknown")).toBeVisible();
  await page.goBack();
  await lookup.getByTestId("field-subject").fill(first.mac);
  await lookup.getByTestId("form-submit").click();
  const subject = page.getByTestId("page-discovery-subject");
  await expect(subject).toHaveAttribute("data-key", first.mac);
  await expect(page).toHaveURL(new RegExp(`/discovery/observations/${first.mac.replaceAll(":", "(:|%3A)")}$`, "i"));

  // The reconciler records when it last saw the intent behind the device.
  await expect
    .poll(async () => (await api.get<Schemas["SubjectView"]>(`/observations/${first.mac}`)).sightings.length)
    .toBeGreaterThan(0);
  await page.reload();
  await expect(subject.getByTestId("subject-sightings")).toBeVisible();

  // The summary: the device across both sources.
  const picture = await api.get<Schemas["SubjectView"]>(`/observations/${first.mac}`);
  expect(picture.summary.macs).toEqual([first.mac]);
  expect([...picture.summary.sources].sort()).toEqual([firstSource, secondSource].sort());
  await expect(subject.getByTestId("subject-summary")).toBeVisible();
  await expect(subject.getByTestId("subject-macs")).toContainText(macPattern(first.mac));
  await expect(subject.getByTestId("subject-ips")).toContainText(first.ipv4);
  await expect(subject.getByTestId("subject-ips")).toContainText(first.ipv6);
  await expect(subject.getByTestId("subject-names")).toContainText(first.name);
  await expect(subject.getByTestId("subject-os")).toContainText("Linux");
  await expect(subject.getByTestId("subject-sources")).toContainText("Lab sample");
  await expect(subject.getByTestId("subject-sources")).toContainText("Second sample");

  // One fact per source, both current.
  await expect(subject.getByTestId("subject-facts").getByTestId("fact")).toHaveCount(2);
  for (const source of [firstSource, secondSource]) {
    await expect(withKey(subject, "fact", `${source}|host:sample/0`)).toHaveAttribute("data-state", "current");
  }

  // The intent behind the device is the host that the approved proposal created.
  const intent = subject.getByTestId("subject-intent");
  expect(picture.intent.hosts).toEqual([host.id]);
  expect(picture.intent.interfaces).toHaveLength(1);
  expect(picture.intent.addresses.length).toBeGreaterThan(0);
  for (const [kind, ids] of [
    ["host", picture.intent.hosts],
    ["interface", picture.intent.interfaces],
    ["address", picture.intent.addresses],
  ] as const) {
    for (const id of ids) await expect(intent.locator(`[data-kind="${kind}"][data-id="${id}"]`).first()).toBeVisible();
  }

  // Its proposals: the approved one, and the outside-prefixes proposals (the open one and the
  // one it replaced) that name the device as evidence.
  const about = await proposals(api, { subject: first.mac });
  expect(about.map((p) => p.id)).toContain(hosts[0]!.id);
  await expect(subject.getByTestId("subject-proposals").getByTestId("subject-proposal")).toHaveCount(about.length);
  for (const proposal of about) {
    await expect(withId(subject, "subject-proposal", proposal.id).locator(`[data-state="${proposal.state}"]`)).toBeVisible();
  }
  await withId(subject, "subject-proposal", hosts[0]!.id).getByTestId("subject-proposal-link").click();
  await expect(page).toHaveURL(new RegExp(`/discovery/${hosts[0]!.id}$`));
  await expect(withId(page, "proposal-panel", hosts[0]!.id).getByTestId("proposal-decision")).toBeVisible();

  // The host page shows the facts about the host from both sources.
  await page.goto(`/ipam/hosts/${first.name}`);
  await expect(page.getByTestId("page-host")).toBeVisible();
  const section = page.getByTestId("host-observations");
  await expect(section.getByTestId("host-observations-summary")).toBeVisible();
  await expect(section.getByTestId("fact")).toHaveCount(2);
  await expect(withKey(section, "fact", `${firstSource}|host:sample/0`)).toHaveAttribute("data-state", "current");
  await expect(withKey(section, "fact", `${secondSource}|host:sample/0`)).toHaveAttribute("data-state", "current");
  await expect(section.getByTestId("host-os")).toContainText("Linux");
  await expect(section.getByTestId("host-observation-link")).toHaveCount(3);
  for (const key of [first.mac, first.ipv4, first.name]) await expect(withKey(section, "host-observation-link", key)).toBeVisible();
  await expect(section.getByTestId("host-proposal")).toHaveCount(0);

  // A link leads to the picture of the device.
  await withKey(section, "host-observation-link", first.mac).click();
  await expect(page.getByTestId("page-discovery-subject")).toHaveAttribute("data-key", first.mac);
});

test("an adoption policy on the prefix lets the reconciler adopt the open discovered hosts, and clearing it restores the default", async ({
  page,
  api,
  signedIn,
}) => {
  expect(signedIn.session.user.name).toBe("admin");
  const { prefix, hosts, outside } = await arrange(api);
  const policyPath = `/prefixes/${prefix.id}/adoption`;

  // A prefix without a policy inherits the default `manual`.
  await page.goto("/ipam/prefixes/192.0.2.0/24");
  await expect(page.getByTestId("page-ipam")).toBeVisible();
  await page.getByTestId("prefix-tab-adoption").click();
  const adoption = page.getByTestId("prefix-adoption");
  await expect(adoption.getByTestId("adoption-effective")).toHaveAttribute("data-mode", "manual");
  await expect(adoption.getByTestId("adoption-source")).toHaveAttribute("data-source", "default");
  await expect(adoption.getByTestId("adoption-clear")).toHaveCount(0);
  const before = await api.get<Schemas["PolicyView"]>(policyPath);
  expect(before.policy ?? null).toBeNull();
  expect(before.effective.mode).toBe("manual");
  expect(before.source ?? null).toBeNull();

  // Set `adopt_hosts` for the prefix.
  await adoption.getByTestId("adoption-edit").click();
  const form = page.getByTestId("dialog-adoption-form");
  await expect(form).toBeVisible();
  await form.getByTestId("field-mode-adopt_hosts").check();
  await form.getByTestId("form-submit").click();
  await expect(form).toHaveCount(0);
  await expect(adoption.getByTestId("adoption-effective")).toHaveAttribute("data-mode", "adopt_hosts");
  await expect(adoption.getByTestId("adoption-source")).toHaveAttribute("data-source", "own");
  await expect(adoption.getByTestId("adoption-clear")).toBeVisible();
  const set = await api.get<Schemas["PolicyView"]>(policyPath);
  expect(set.policy?.mode).toBe("adopt_hosts");
  expect(set.effective.mode).toBe("adopt_hosts");
  expect(set.effective.host_mode ?? "dynamic").toBe("dynamic");
  expect(set.revision).toBeGreaterThan(before.revision);

  // The reconciler adopts the three open proposals by itself, within its debounce interval;
  // the proposal for the IPv6 network is never adopted.
  await waitForProposals(api, { state: "accepted" }, 3);
  const adopted = await proposals(api, { state: "accepted" });
  expect(adopted.map((p) => p.id).sort()).toEqual(hosts.map((p) => p.id).sort());
  for (const proposal of adopted) {
    expect(proposal.adopted_by).toBe(prefix.id);
    expect(proposal.decided?.by).toMatchObject({ kind: "system", component: "reconciler" });
    expect(proposal.adoption_error ?? null).toBeNull();
  }
  expect((await proposals(api, { state: "open" })).map((p) => p.id)).toEqual([outside.id]);
  for (const index of [0, 1, 2]) {
    const host = await hostByName(api, sampleHost(index).name);
    expect(host?.mode).toBe("dynamic");
    expect(host?.meta.tags ?? []).toContain("discovered");
  }

  // The inbox of the prefix has nothing open any more; the adopted ones are decided.
  await adoption.getByTestId("adoption-proposals").click();
  await expect(page.getByTestId("page-discovery")).toBeVisible();
  await expect(page).toHaveURL(new RegExp(`/discovery\\?prefix=${prefix.id}$`));
  await expect(page.getByTestId("filter-prefix")).toBeVisible();
  await expect(page.getByTestId("discovery-empty")).toBeVisible();
  await page.getByTestId("filter-state").selectOption("accepted");
  const grid = page.getByTestId("grid-proposals");
  await expect(grid.getByTestId("row")).toHaveCount(3);
  for (const proposal of hosts) {
    await expect(cell(withId(grid, "row", proposal.id), "state").locator('[data-state="accepted"]')).toBeVisible();
  }
  const panel = await openProposal(page, hosts[0]!.id);
  await expect(panel.getByTestId("proposal-decision")).toContainText(prefix.cidr);
  await page.goto("/discovery");
  await expect(page.getByTestId("grid-proposals").getByTestId("row")).toHaveCount(1);
  await expect(withId(page.getByTestId("grid-proposals"), "row", outside.id)).toBeVisible();

  // Clear the policy: the prefix inherits the default again.
  await page.goto("/ipam/prefixes/192.0.2.0/24");
  await page.getByTestId("prefix-tab-adoption").click();
  await expect(adoption.getByTestId("adoption-source")).toHaveAttribute("data-source", "own");
  await adoption.getByTestId("adoption-clear").click();
  await expect(adoption.getByTestId("adoption-source")).toHaveAttribute("data-source", "default");
  await expect(adoption.getByTestId("adoption-effective")).toHaveAttribute("data-mode", "manual");
  await expect(adoption.getByTestId("adoption-clear")).toHaveCount(0);
  const cleared = await api.get<Schemas["PolicyView"]>(policyPath);
  expect(cleared.policy ?? null).toBeNull();
  expect(cleared.effective.mode).toBe("manual");
  expect(cleared.source ?? null).toBeNull();
});

test("approving the outside-prefixes proposal creates the network and supersedes the open host proposals with ones that include the IPv6 address", async ({
  page,
  api,
  signedIn,
}) => {
  expect(signedIn.session.user.name).toBe("admin");
  const { hosts, outside } = await arrange(api);
  const first = sampleHost(0);

  // The proposal suggests the network 2001:db8::/64; approving it creates it.
  await page.goto(`/discovery/${outside.id}`);
  const panel = withId(page, "proposal-panel", outside.id);
  await expect(panel).toBeVisible();
  await expect(panel.locator('[data-kind="outside_prefixes"]').first()).toBeVisible();
  await expect(panel.locator('[data-severity="warning"]').first()).toBeVisible();
  await expect(planChanges(panel.getByTestId("proposal-change"), "prefix", "create")).toHaveCount(1);
  expect(await prefixByCidr(api, "2001:db8::/64")).toBeUndefined();
  await panel.getByTestId("discovery-approve").click();
  const approveDialog = page.getByTestId("dialog-approve");
  await expect(planChanges(approveDialog, "prefix", "create")).toHaveCount(1);
  await approveDialog.getByTestId("plan-confirm").click();
  await expect(approveDialog).toHaveCount(0);
  await expect(panel.getByTestId("proposal-decision").locator('[data-state="accepted"]')).toBeVisible();
  const network = await prefixByCidr(api, "2001:db8::/64");
  expect(network?.role).toBe("network");
  expect(network?.meta.tags ?? []).toContain("discovered");

  // The network is known now: the reconciler replaces each open host proposal with one
  // that adds the IPv6 address.
  await expect
    .poll(async () => (await proposals(api, { state: "superseded" })).length, { message: "the host proposals to be superseded" })
    .toBe(3);
  const open = await waitForProposals(api, { state: "open" }, 3);
  expect(open.every((p) => p.kind === "discovered_host")).toBe(true);
  for (const old of hosts) {
    const replaced = await proposalOf(api, old.id);
    expect(replaced.state).toBe("superseded");
    const next = open.find((p) => p.key === old.key);
    expect(next, `a new proposal for ${old.key}`).toBeDefined();
    expect(replaced.superseded_by).toBe(next!.id);
    expect(next!.id).not.toBe(old.id);
    expect((next!.commands ?? []).filter((c) => c.op === "create_address")).toHaveLength(2);
  }

  // The old proposal says so and leads to the new one, which now suggests both addresses.
  await page.goto(`/discovery/${hosts[0]!.id}`);
  const oldPanel = withId(page, "proposal-panel", hosts[0]!.id);
  await expect(oldPanel.locator('[data-state="superseded"]').first()).toBeVisible();
  await expect(oldPanel.getByTestId("discovery-approve")).toHaveCount(0);
  await oldPanel.getByTestId("proposal-superseded-by").click();
  const next = open.find((p) => p.key === hosts[0]!.key)!;
  await expect(page).toHaveURL(new RegExp(`/discovery/${next.id}$`));
  const nextPanel = withId(page, "proposal-panel", next.id);
  await expect(nextPanel.locator('[data-state="open"]').first()).toBeVisible();
  await expect(nextPanel.getByTestId("evidence")).toHaveCount(2);
  const addresses = planChanges(nextPanel.getByTestId("proposal-change"), "address", "create");
  await expect(addresses).toHaveCount(2);

  // The inbox lists the three new ones as open and the old ones as superseded.
  await page.getByTestId("filter-state").selectOption("superseded");
  const grid = page.getByTestId("grid-proposals");
  await expect(grid.getByTestId("row")).toHaveCount(3);
  for (const old of hosts) await expect(cell(withId(grid, "row", old.id), "state").locator('[data-state="superseded"]')).toBeVisible();
  await page.getByTestId("filter-state").selectOption("open");
  await expect(grid.getByTestId("row")).toHaveCount(3);

  // Approving the new proposal of host 0 creates the host with both addresses.
  await approve(api, next);
  const host = (await hostByName(api, first.name)) as Host;
  const created = await api.get<Schemas["Page_AddressRow"]>("/addresses", { host: host.id });
  expect(created.items.map((a) => a.ip).sort()).toEqual([first.ipv4, first.ipv6].sort());
  expect(host.mode).toBe("dynamic");
});

test.describe("a Swedish browser", () => {
  test.use({ locale: "sv-SE" });

  test("shows the inbox, an open proposal with its approve dialog and the observations in Swedish", async ({
    page,
    api,
    signedIn,
  }, testInfo) => {
    expect(signedIn.session.user.name).toBe("admin");
    const { hosts } = await arrange(api);
    const first = sampleHost(0);

    // The inbox with its proposals.
    await page.goto("/discovery");
    const inbox = page.getByTestId("page-discovery");
    await expect(page.getByTestId("grid-proposals").getByTestId("row")).toHaveCount(4);
    await expectRendered(page, inbox, "sv", testInfo, "discovery-inbox");

    // An open proposal with the plan of its suggested change, and the approve dialog.
    const panel = await openProposal(page, hosts[0]!.id);
    await expect(planChanges(panel.getByTestId("proposal-change"), "host", "create")).toHaveCount(1);
    await expect(panel.getByTestId("evidence")).toHaveCount(2);
    await expectRendered(page, panel, "sv", testInfo, "proposal-panel");
    await panel.getByTestId("discovery-approve").click();
    const dialog = page.getByTestId("dialog-approve");
    await expect(dialog.getByTestId("plan-summary")).toBeVisible();
    await expectRendered(page, dialog, "sv");
    await page.keyboard.press("Escape");
    await expect(dialog).toHaveCount(0);

    // The rejection dialog and the report of a run.
    await panel.getByTestId("discovery-reject").click();
    const reject = page.getByTestId("dialog-reject");
    await expect(reject).toBeVisible();
    await expectRendered(page, reject, "sv");
    await page.keyboard.press("Escape");
    await expect(reject).toHaveCount(0);
    await page.getByTestId("discovery-reconcile").click();
    const report = page.getByTestId("dialog-reconcile-report");
    await expect(withKey(report, "report-count", "unchanged")).toBeVisible();
    await expectRendered(page, report, "sv");
    await page.keyboard.press("Escape");

    // The observations and the picture of one subject.
    await page.goto("/discovery/observations");
    await expect(page.getByTestId("grid-observations").getByTestId("row")).toHaveCount(3);
    await expectRendered(page, page.getByTestId("page-discovery-observations"), "sv", testInfo, "observations");
    await page.goto(`/discovery/observations/${first.mac}`);
    const subject = page.getByTestId("page-discovery-subject");
    await expect(subject.getByTestId("subject-facts").getByTestId("fact")).toHaveCount(1);
    await expect(subject.getByTestId("subject-proposals").getByTestId("subject-proposal").first()).toBeVisible();
    await expectRendered(page, subject, "sv", testInfo, "subject");
  });
});

test("the status bar item counts the open proposals, follows a rejection without a reload and links to the inbox", async ({
  page,
  api,
  signedIn,
}) => {
  expect(signedIn.session.user.name).toBe("admin");
  const { hosts, outside } = await arrange(api);
  const open = [...hosts, outside];
  expect(open).toHaveLength(4);

  // Nothing but the dashboard is open, and the item already counts what the sample produced.
  await page.goto("/");
  await expect(page.getByTestId("page-dashboard")).toBeVisible();
  const item = page.getByTestId("status-proposals");
  await expect(item).toHaveText(/^\s*4\s+open proposals\s*$/);

  // A rejection by someone else (here: the API) changes the number on the open page.
  await api.post(`/proposals/${hosts[0]!.id}/reject`, { reason: "A lab host, not part of the plan" });
  await expect(item).toHaveText(/^\s*3\s+open proposals\s*$/);
  expect((await proposals(api, { state: "open" })).length).toBe(3);

  // Down to one, which the item words in the singular, then to none, when it goes away.
  for (const proposal of open.slice(1, 3)) {
    await api.post(`/proposals/${proposal.id}/reject`, { reason: "A lab host, not part of the plan" });
  }
  await expect(item).toHaveText(/^\s*1\s+open proposal\s*$/);
  await api.post(`/proposals/${open[3]!.id}/reject`, { reason: "A lab network, not part of the plan" });
  await expect(item).toHaveCount(0);
  expect(await proposals(api, { state: "open" })).toHaveLength(0);
});

test("the status bar item on another page links to the proposal inbox", async ({ page, api, signedIn }) => {
  expect(signedIn.session.user.name).toBe("admin");
  await arrange(api);
  await page.goto("/ipam");
  await expect(page.getByTestId("page-ipam")).toBeVisible();
  await page.getByTestId("status-proposals").click();
  await expect(page.getByTestId("page-discovery")).toBeVisible();
  await expect(page).toHaveURL(/\/discovery$/);
  await expect(page.getByTestId("grid-proposals").getByTestId("row")).toHaveCount(4);
});
