// The cluster page (WP3.11a): the summary, the member table with the health of each member, the
// previews of promoting, removing and stepping down, the digest check, the join token of a
// controller, what viewers see, and the keyboard and accessibility checks. It runs against the
// mock cluster of src/api/mock/cluster-store.ts.
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { api } from "../api/client";
import { clusterState, CLUSTER_IDS, mockCluster } from "../api/mock/cluster-store";
import { commit } from "../api/mock/db";
import { server } from "../api/mock/node";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { bridgeMockEvents } from "../audit/testkit";
import { signInAlex } from "../auth/account/testkit";
import { setSessionForTest } from "../auth/session";
import ClusterPage from "./ClusterPage";
import type { MemberView } from "./model";

const { leader: LEADER, voterA, voterB, learner } = CLUSTER_IDS;
const NAMES: Record<number, string> = {
  [LEADER]: "ctl-1.example.test",
  [voterA]: "ctl-2.example.test",
  [voterB]: "ctl-3.example.test",
  [learner]: "ctl-4.example.test",
};

let stopBridge: (() => void) | undefined;

beforeEach(async () => {
  await signInAlex();
});

afterEach(() => {
  stopBridge?.();
  stopBridge = undefined;
  setSessionForTest(null);
});

/** Signs the seeded account in as another role instead of an administrator. */
async function signInWithRole(role: "operator" | "viewer") {
  await signInAlex({
    prepare: (user) => {
      user.roles = [role];
    },
  });
}

function openCluster() {
  return renderRoute(ClusterPage, {
    url: "/cluster",
    path: "/cluster",
    routes: { "/cluster/queue": () => <div data-testid="queue-stub" />, "/jobs/:id": () => <div data-testid="job-stub" /> },
  });
}

/** The page with its member table loaded. */
async function openLoaded() {
  const view = openCluster();
  await screen.findByTestId("cluster-members");
  return view;
}

const row = (node: number) => screen.getByTestId(`member-row-${node}`);
const nodesListed = () => screen.queryAllByTestId(/^member-row-/).map((r) => Number(r.dataset.id));
const toastTitles = () => screen.queryAllByTestId("toast").map((el) => el.querySelector(".t")?.textContent);

/** The member as the mock holds it, for a test that wants another state. */
function member(node: number): MemberView {
  const found = clusterState().members.get(node);
  if (!found) throw new Error(`no member ${node}`);
  return found;
}
function patch(node: number, change: Partial<MemberView>) {
  clusterState().members.set(node, { ...member(node), ...change });
}

/** The calls of the page to one endpoint, with their bodies; the mock still answers. */
function recordCalls(method: "post" | "delete", path: string) {
  const bodies: unknown[] = [];
  server.use(
    http[method](path, async ({ request }) => {
      const text = await request.clone().text();
      bodies.push(text ? JSON.parse(text) : null);
      return undefined;
    }),
  );
  return bodies;
}

/** Checks that an action is a control the keyboard reaches, then activates it as Enter does. */
function pressWithKeyboard(element: HTMLElement) {
  expect(["BUTTON", "A"]).toContain(element.tagName);
  expect(element.tabIndex).toBeGreaterThanOrEqual(0);
  expect((element as HTMLButtonElement).disabled).not.toBe(true);
  element.focus();
  expect(document.activeElement).toBe(element);
  fireEvent.click(element);
}

describe("the cluster page", () => {
  it("shows the summary of the seeded cluster", async () => {
    await openLoaded();
    const summary = screen.getByTestId("cluster-summary");
    expect(screen.getByTestId("page-cluster")).toBeTruthy();
    expect(within(summary).getByTestId("cluster-quorum").dataset.state).toBe("healthy");
    expect(within(summary).getByTestId("cluster-quorum").textContent).toBe("In contact with a quorum");
    expect(within(summary).getByTestId("cluster-term").textContent).toBe("7");
    expect(within(summary).getByTestId("cluster-leader").textContent).toBe(NAMES[LEADER]);
    expect(within(summary).getByTestId("cluster-voters").textContent).toBe("3 voters · Tolerates 1 failure");
    expect(within(summary).getByTestId("cluster-node").textContent).toBe(NAMES[LEADER]);
    expect(screen.queryByTestId("cluster-changing")).toBeNull();
  });

  it("lists the members, the leader first, then the voters and the learner", async () => {
    await openLoaded();
    expect(nodesListed()).toEqual([LEADER, voterA, voterB, learner]);
    const leader = within(row(LEADER));
    expect(leader.getByText(NAMES[LEADER] as string)).toBeTruthy();
    expect(leader.getByText("192.0.2.11:8444")).toBeTruthy();
    expect(leader.getByText("Voter")).toBeTruthy();
    expect(leader.getByTestId("member-leader")).toBeTruthy();
    expect(leader.getByTestId("member-health").dataset.state).toBe("leader");
    expect(leader.getByTestId("member-lag").textContent).toBe("–");
    expect(leader.getByTestId("member-contact").textContent).toBe("–");
    expect(row(LEADER).textContent).toContain("format 3");
    expect(row(LEADER).dataset.state).toBe("leader");

    const follower = within(row(voterA));
    expect(follower.getByTestId("member-health").dataset.state).toBe("caught_up");
    expect(follower.getByTestId("member-health").textContent).toBe("Caught up");
    expect(follower.getByTestId("member-lag").textContent).toBe("0");
    expect(follower.getByTestId("member-contact").textContent).toBe("40 ms");
    expect(follower.queryByTestId("member-leader")).toBeNull();

    const waiting = within(row(learner));
    expect(waiting.getByText("Learner")).toBeTruthy();
    expect(waiting.getByTestId("member-health").dataset.state).toBe("catching_up");
    expect(waiting.getByTestId("member-health").textContent).toBe("Catching up");
    expect(waiting.getByTestId("member-lag").textContent).toBe("4,200");
    expect(waiting.getByTestId("member-contact").textContent).toBe("300 ms");
    expect(screen.getByTestId("cluster-members").getAttribute("aria-label")).toBe("Members");
  });

  it("shows a member out of contact and one that reports nothing", async () => {
    patch(voterB, { last_contact_ms: 25_000, lag_entries: 9 });
    patch(learner, { last_contact_ms: null, lag_entries: null });
    await openLoaded();
    const lost = within(row(voterB));
    expect(lost.getByTestId("member-health").dataset.state).toBe("out_of_contact");
    expect(lost.getByTestId("member-health").textContent).toBe("Out of contact");
    expect(lost.getByTestId("member-contact").textContent).toBe("25 sec");
    const unknown = within(row(learner));
    expect(unknown.getByTestId("member-health").dataset.state).toBe("unknown");
    expect(unknown.getByTestId("member-lag").textContent).toBe("–");
  });

  it("says when the quorum is lost and when a membership change is in progress", async () => {
    mockCluster.setQuorum("isolated");
    clusterState().changing = true;
    await openLoaded();
    expect(screen.getByTestId("cluster-quorum").dataset.state).toBe("isolated");
    expect(screen.getByTestId("cluster-quorum").textContent).toContain("Isolated");
    expect(screen.getByTestId("cluster-quorum").textContent).toContain("since");
    expect(screen.getByTestId("cluster-changing").textContent).toContain("A membership change is in progress");
  });

  it("follows the cluster topic", async () => {
    stopBridge = bridgeMockEvents();
    await openLoaded();
    clusterState().members.delete(learner);
    clusterState().changing = true;
    commit("cluster", { tables: ["cluster.members"] });
    await waitFor(() => expect(nodesListed()).toEqual([LEADER, voterA, voterB]));
    expect(screen.getByTestId("cluster-changing")).toBeTruthy();
  });

  it("shows the refusal of the server instead of the page when the members cannot be read", async () => {
    server.use(
      http.get("/api/v1/cluster/members", () =>
        HttpResponse.json({ status: 403, code: "auth.forbidden", title: "Forbidden", detail: "" }, { status: 403 }),
      ),
    );
    openCluster();
    expect(await screen.findByTestId("error-notice")).toBeTruthy();
    expect(screen.queryByTestId("cluster-members")).toBeNull();
  });

  it("has no accessibility violations", async () => {
    const view = await openLoaded();
    expect(await axeViolations(view.container)).toEqual([]);
  });
});

describe("promoting a learner", () => {
  it("previews the change and refuses a learner that has not caught up unless forced", async () => {
    await openLoaded();
    fireEvent.click(screen.getByTestId(`member-promote-${learner}`));
    const dialog = await screen.findByTestId("dialog-promote");
    expect(dialog.getAttribute("aria-label")).toBe("Promote ctl-4.example.test to voter");
    expect(within(dialog).getByTestId("preview-voters").textContent).toBe("3 → 4");
    expect(within(dialog).getByTestId("preview-tolerated").textContent).toBe("1 (unchanged)");
    const forceable = within(dialog).getByTestId("preview-forceable");
    expect(within(forceable).getAllByRole("listitem").map((li) => li.dataset.blocker)).toEqual(["even_voters", "not_caught_up"]);
    expect(within(dialog).queryByTestId("preview-blockers")).toBeNull();
    expect((within(dialog).getByTestId("promote-confirm") as HTMLButtonElement).disabled).toBe(true);
    expect(await axeViolations(dialog)).toEqual([]);
  });

  it("promotes with force: the refusals become warnings and the body carries force", async () => {
    const posted = recordCalls("post", `/api/v1/cluster/members/${learner}/promote`);
    await openLoaded();
    fireEvent.click(screen.getByTestId(`member-promote-${learner}`));
    const dialog = await screen.findByTestId("dialog-promote");
    fireEvent.click(within(dialog).getByTestId("field-force"));
    expect(within(dialog).queryByTestId("preview-forceable")).toBeNull();
    const caveats = within(dialog).getByTestId("preview-caveats");
    expect(within(caveats).getAllByRole("listitem").map((li) => li.dataset.caveat)).toEqual(["forced", "even_after"]);
    const confirm = within(dialog).getByTestId("promote-confirm") as HTMLButtonElement;
    expect(confirm.disabled).toBe(false);
    expect(await axeViolations(dialog)).toEqual([]);

    fireEvent.click(confirm);
    await waitFor(() => expect(screen.queryByTestId("dialog-promote")).toBeNull());
    expect(posted).toEqual([{ force: true }]);
    expect(within(row(learner)).getByText("Voter")).toBeTruthy();
    expect(screen.getByTestId("cluster-voters").textContent).toBe("4 voters · Tolerates 1 failure");
    expect(toastTitles()).toContain("ctl-4.example.test is a voter now.");
    expect(within(row(learner)).queryByTestId(`member-promote-${learner}`)).toBeNull();
  });

  it("promotes a caught-up learner in place of a voter without any refusal", async () => {
    patch(learner, { lag_entries: 3, last_contact_ms: 50 });
    const posted = recordCalls("post", `/api/v1/cluster/members/${learner}/promote`);
    await openLoaded();
    fireEvent.click(screen.getByTestId(`member-promote-${learner}`));
    const dialog = await screen.findByTestId("dialog-promote");
    // Four voters would be an even number, which the rules refuse.
    expect(within(dialog).getByTestId("preview-forceable")).toBeTruthy();
    fireEvent.change(within(dialog).getByTestId("field-replace"), { target: { value: String(voterB) } });
    expect(within(dialog).getByTestId("preview-voters").textContent).toBe("3 (unchanged)");
    expect(within(dialog).queryByTestId("preview-forceable")).toBeNull();
    expect(within(dialog).queryByTestId("preview-blockers")).toBeNull();
    expect(within(within(dialog).getByTestId("preview-caveats")).getByRole("listitem").dataset.caveat).toBe("replaces");
    expect(within(dialog).queryByTestId("field-force")).toBeNull();
    fireEvent.click(within(dialog).getByTestId("promote-confirm"));
    await waitFor(() => expect(screen.queryByTestId("dialog-promote")).toBeNull());
    expect(posted).toEqual([{ replace: voterB }]);
    expect(nodesListed()).toEqual([LEADER, voterA, learner]);
  });

  it("offers every voter but the leader to replace", async () => {
    await openLoaded();
    fireEvent.click(screen.getByTestId(`member-promote-${learner}`));
    const select = (await screen.findByTestId("field-replace")) as HTMLSelectElement;
    expect(Array.from(select.options).map((o) => o.textContent)).toEqual(["Do not replace a voter", NAMES[voterA], NAMES[voterB]]);
  });

  it("blocks the promotion while another membership change runs", async () => {
    clusterState().changing = true;
    await openLoaded();
    fireEvent.click(screen.getByTestId(`member-promote-${learner}`));
    const dialog = await screen.findByTestId("dialog-promote");
    const blockers = within(dialog).getByTestId("preview-blockers");
    expect(blockers.textContent).toContain("Another membership change is in progress.");
    expect((within(dialog).getByTestId("promote-confirm") as HTMLButtonElement).disabled).toBe(true);
  });

  it("offers Promote for learners only", async () => {
    await openLoaded();
    expect(screen.queryByTestId(`member-promote-${LEADER}`)).toBeNull();
    expect(screen.queryByTestId(`member-promote-${voterA}`)).toBeNull();
    expect(screen.getByTestId(`member-promote-${learner}`).getAttribute("aria-label")).toBe("Promote ctl-4.example.test");
  });

  it("shows the refusal of the server in the dialog and keeps it open", async () => {
    server.use(
      http.post(`/api/v1/cluster/members/${learner}/promote`, () =>
        HttpResponse.json(
          { status: 409, code: "cluster.member.changing", title: "Conflict", detail: "another change", params: {} },
          { status: 409 },
        ),
      ),
    );
    await openLoaded();
    fireEvent.click(screen.getByTestId(`member-promote-${learner}`));
    const dialog = await screen.findByTestId("dialog-promote");
    fireEvent.click(within(dialog).getByTestId("field-force"));
    fireEvent.click(within(dialog).getByTestId("promote-confirm"));
    const notice = await within(dialog).findByTestId("error-notice");
    expect(notice.dataset.code).toBe("cluster.member.changing");
    expect(notice.textContent).toBe("Another membership change is in progress.");
    expect(screen.getByTestId("dialog-promote")).toBeTruthy();
    expect(within(row(learner)).getByText("Learner")).toBeTruthy();
  });

  it("links the job of the change from the toast", async () => {
    patch(learner, { lag_entries: 3, last_contact_ms: 50 });
    const view = await openLoaded();
    fireEvent.click(screen.getByTestId(`member-promote-${learner}`));
    const dialog = await screen.findByTestId("dialog-promote");
    fireEvent.change(within(dialog).getByTestId("field-replace"), { target: { value: String(voterB) } });
    fireEvent.click(within(dialog).getByTestId("promote-confirm"));
    const action = await screen.findByTestId("toast-action");
    expect(action.textContent).toBe("Open job");
    fireEvent.click(action);
    await waitFor(() => expect(view.location()).toMatch(/^\/jobs\/[0-9a-f-]{36}$/));
  });
});

describe("removing a member", () => {
  it("previews the removal of a learner: the voters stay, the certificates are revoked", async () => {
    const deleted = recordCalls("delete", `/api/v1/cluster/members/${learner}`);
    await openLoaded();
    fireEvent.click(screen.getByTestId(`member-remove-${learner}`));
    const dialog = await screen.findByTestId("dialog-remove");
    expect(dialog.getAttribute("aria-label")).toBe("Remove ctl-4.example.test?");
    expect(within(dialog).getByTestId("preview-voters").textContent).toBe("3 (unchanged)");
    expect(within(dialog).getByTestId("preview-tolerated").textContent).toBe("1 (unchanged)");
    expect(within(within(dialog).getByTestId("preview-caveats")).getAllByRole("listitem").map((li) => li.dataset.caveat)).toEqual(["revokes"]);
    expect(await axeViolations(dialog)).toEqual([]);

    fireEvent.click(within(dialog).getByTestId("remove-confirm"));
    await waitFor(() => expect(screen.queryByTestId("dialog-remove")).toBeNull());
    expect(deleted).toEqual([null]);
    expect(nodesListed()).toEqual([LEADER, voterA, voterB]);
    expect(toastTitles()).toContain("ctl-4.example.test was removed from the cluster.");
  });

  it("warns that removing a voter leaves an even number that tolerates no failure", async () => {
    await openLoaded();
    fireEvent.click(screen.getByTestId(`member-remove-${voterB}`));
    const dialog = await screen.findByTestId("dialog-remove");
    expect(within(dialog).getByTestId("preview-voters").textContent).toBe("3 → 2");
    expect(within(dialog).getByTestId("preview-tolerated").textContent).toBe("1 → 0");
    const caveats = within(within(dialog).getByTestId("preview-caveats")).getAllByRole("listitem");
    expect(caveats.map((li) => li.dataset.caveat)).toEqual(["even_after", "no_tolerance", "revokes"]);
    expect((within(dialog).getByTestId("remove-confirm") as HTMLButtonElement).disabled).toBe(false);
  });

  it("refuses to remove the last voter", async () => {
    clusterState().members.delete(voterA);
    clusterState().members.delete(voterB);
    await openLoaded();
    fireEvent.click(screen.getByTestId(`member-remove-${LEADER}`));
    const dialog = await screen.findByTestId("dialog-remove");
    expect(within(dialog).getByTestId("preview-blockers").textContent).toContain("The last voter cannot be removed.");
    const caveats = within(within(dialog).getByTestId("preview-caveats")).getAllByRole("listitem");
    expect(caveats.map((li) => li.dataset.caveat)).toEqual(["removes_leader", "removes_self", "revokes"]);
    expect((within(dialog).getByTestId("remove-confirm") as HTMLButtonElement).disabled).toBe(true);
  });

  it("shows the refusal of the server and leaves the member in the table", async () => {
    server.use(
      http.delete(`/api/v1/cluster/members/${voterA}`, () =>
        HttpResponse.json({ status: 409, code: "cluster.member.last_voter", title: "Conflict", detail: "", params: {} }, { status: 409 }),
      ),
    );
    await openLoaded();
    fireEvent.click(screen.getByTestId(`member-remove-${voterA}`));
    const dialog = await screen.findByTestId("dialog-remove");
    fireEvent.click(within(dialog).getByTestId("remove-confirm"));
    expect((await within(dialog).findByTestId("error-notice")).textContent).toBe("The change would remove the last voter.");
    expect(nodesListed()).toContain(voterA);
  });

  it("closes without removing on Cancel", async () => {
    const deleted = recordCalls("delete", `/api/v1/cluster/members/${learner}`);
    await openLoaded();
    fireEvent.click(screen.getByTestId(`member-remove-${learner}`));
    const dialog = await screen.findByTestId("dialog-remove");
    fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByTestId("dialog-remove")).toBeNull());
    expect(deleted).toEqual([]);
    expect(nodesListed()).toContain(learner);
  });
});

describe("stepping down", () => {
  it("offers it only to an administrator on the controller that leads", async () => {
    await openLoaded();
    expect(screen.getByTestId("cluster-step-down")).toBeTruthy();
  });

  it("does not offer it on a controller that follows", async () => {
    clusterState().node = voterA;
    await openLoaded();
    expect(screen.getByTestId("cluster-node").textContent).toBe(NAMES[voterA]);
    expect(screen.queryByTestId("cluster-step-down")).toBeNull();
  });

  it("does not offer it to a controller that is alone", async () => {
    for (const node of [voterA, voterB, learner]) clusterState().members.delete(node);
    await openLoaded();
    expect(screen.queryByTestId("cluster-step-down")).toBeNull();
  });

  it("names the successor, hands leadership over and shows the new leader", async () => {
    await openLoaded();
    fireEvent.click(screen.getByTestId("cluster-step-down"));
    const dialog = await screen.findByTestId("dialog-step-down");
    expect(within(dialog).getByTestId("step-down-successor").textContent).toBe(`Leadership passes to ${NAMES[voterA]}.`);
    expect(within(dialog).getByTestId("step-down-successor").dataset.node).toBe(String(voterA));
    expect(within(dialog).getByTestId("preview-voters").textContent).toBe("3 (unchanged)");
    expect(within(within(dialog).getByTestId("preview-caveats")).getByRole("listitem").dataset.caveat).toBe("reconnect");
    expect(await axeViolations(dialog)).toEqual([]);

    fireEvent.click(within(dialog).getByTestId("step-down-confirm"));
    await waitFor(() => expect(screen.queryByTestId("dialog-step-down")).toBeNull());
    await waitFor(() => expect(screen.getByTestId("cluster-leader").textContent).toBe(NAMES[voterA]));
    expect(screen.getByTestId("cluster-term").textContent).toBe("8");
    expect(row(voterA).dataset.state).toBe("leader");
    expect(toastTitles()).toContain("ctl-2.example.test leads now (term 8).");
    expect(screen.queryByTestId("cluster-step-down")).toBeNull();
  });

  it("refuses when no other voter has caught up", async () => {
    clusterState().members.delete(voterA);
    clusterState().members.delete(voterB);
    await openLoaded();
    fireEvent.click(screen.getByTestId("cluster-step-down"));
    const dialog = await screen.findByTestId("dialog-step-down");
    expect(within(dialog).getByTestId("preview-blockers").textContent).toContain("No other voter has caught up to take over.");
    expect(within(dialog).queryByTestId("step-down-successor")).toBeNull();
    expect((within(dialog).getByTestId("step-down-confirm") as HTMLButtonElement).disabled).toBe(true);
  });
});

describe("the digest check", () => {
  it("shows nothing until the person asks, then every member agrees", async () => {
    await openLoaded();
    const section = screen.getByTestId("cluster-digests");
    expect(within(section).queryByTestId("digests-result")).toBeNull();
    fireEvent.click(within(section).getByTestId("cluster-check-digests"));
    await within(section).findByTestId("digests-result");
    expect(within(section).getByTestId("digests-overall").dataset.state).toBe("agree");
    expect(within(section).getByTestId("digests-result").textContent).toMatch(/^All 4 members hold the same data at revision \d+\.$/);
    for (const node of [LEADER, voterA, voterB, learner]) {
      const digest = within(screen.getByTestId(`digest-row-${node}`));
      expect(screen.getByTestId(`digest-row-${node}`).dataset.state).toBe("agrees");
      expect(digest.getByTestId("digest-state").textContent).toBe("Agrees");
      expect(digest.getByTestId("digest-value").textContent).toMatch(/^[0-9a-f]{4}( [0-9a-f]{4}){3}$/);
    }
    expect(within(screen.getByTestId(`digest-row-${voterA}`)).getByText(NAMES[voterA] as string)).toBeTruthy();
    expect(await axeViolations(section)).toEqual([]);
  });

  it("shows the member that differs", async () => {
    mockCluster.setDigestMismatch(voterB);
    await openLoaded();
    fireEvent.click(screen.getByTestId("cluster-check-digests"));
    await screen.findByTestId("digests-result");
    expect(screen.getByTestId("digests-overall").dataset.state).toBe("differ");
    expect(screen.getByTestId("digests-result").textContent).toMatch(/^The members do not hold the same data at revision \d+\.$/);
    expect(screen.getByTestId(`digest-row-${voterB}`).dataset.state).toBe("differs");
    expect(within(screen.getByTestId(`digest-row-${voterB}`)).getByTestId("digest-state").textContent).toBe("Differs");
    expect(screen.getByTestId(`digest-row-${LEADER}`).dataset.state).toBe("agrees");
    expect(await axeViolations(screen.getByTestId("cluster-digests"))).toEqual([]);

    // Asking again after the member recovered replaces the answer.
    mockCluster.setDigestMismatch(null);
    fireEvent.click(screen.getByTestId("cluster-check-digests"));
    await waitFor(() => expect(screen.getByTestId("digests-overall").dataset.state).toBe("agree"));
  });

  it("shows a member that gave no digest", async () => {
    server.use(
      http.get("/api/v1/cluster/digests", () =>
        HttpResponse.json({
          revision: 12,
          agree: false,
          members: [
            { node: LEADER, sha256: "ab".repeat(32), revision: 12, tables: 41, entries: 2012 },
            { node: learner, error: "cluster.member.unreachable" },
          ],
        }),
      ),
    );
    await openLoaded();
    fireEvent.click(screen.getByTestId("cluster-check-digests"));
    await screen.findByTestId("digests-result");
    const missing = screen.getByTestId(`digest-row-${learner}`);
    expect(missing.dataset.state).toBe("missing");
    expect(within(missing).getByTestId("digest-state").textContent).toBe("No digest");
    expect(within(missing).getByTestId("digest-value").textContent).toBe("–");
  });

  it("shows the refusal of the server", async () => {
    server.use(
      http.get("/api/v1/cluster/digests", () =>
        HttpResponse.json({ status: 400, code: "sys.invalid_query", title: "Bad query", detail: "", params: {} }, { status: 400 }),
      ),
    );
    await openLoaded();
    fireEvent.click(screen.getByTestId("cluster-check-digests"));
    expect(await within(screen.getByTestId("cluster-digests")).findByTestId("error-notice")).toBeTruthy();
    expect(screen.queryByTestId("digests-result")).toBeNull();
  });
});

describe("adding a controller", () => {
  /** A token as the server answers it for a controller: the mock does not issue those yet. */
  async function answerWithControllerToken() {
    const bodies: unknown[] = [];
    const real = await api.post("/api/v1/nodes/enrolments", { body: { roles: ["probe"] }, idempotencyKey: null });
    server.use(
      http.post("/api/v1/nodes/enrolments", async ({ request }) => {
        bodies.push(await request.json());
        return HttpResponse.json({ ...real, enrolment: { ...real.enrolment, roles: ["controller"] } }, { status: 201 });
      }),
    );
    return bodies;
  }

  it("opens the token dialog with the controller role fixed and no role choice", async () => {
    const bodies = await answerWithControllerToken();
    await openLoaded();
    fireEvent.click(screen.getByTestId("cluster-add-controller"));
    const form = await screen.findByTestId("dialog-enrol");
    expect(form.textContent).toContain("Add a controller");
    expect(form.textContent).toContain("A join token lets one new controller enrol once.");
    expect(within(form).queryByTestId("field-role-probe")).toBeNull();
    expect(within(form).queryByTestId("field-role-dns")).toBeNull();
    expect(within(form).queryByRole("group")).toBeNull();
    // A controller token lives at most an hour.
    const lifetimes = Array.from((within(form).getByTestId("field-lifetime") as HTMLSelectElement).options).map((o) => o.value);
    expect(lifetimes).toEqual(["900", "3600"]);
    expect(await axeViolations(form)).toEqual([]);

    fireEvent.click(within(form).getByTestId("form-submit"));
    const shown = await screen.findByTestId("dialog-enrol-token");
    expect(bodies).toEqual([{ roles: ["controller"], name: null, vrf: null, expires_in_secs: 3600 }]);
    expect(within(shown).getByTestId("enrol-once")).toBeTruthy();
    expect(within(shown).getByTestId("enrol-token").textContent).toMatch(/^tnk1\./);
    expect(shown.textContent).toContain("The new controller joins as a learner.");
    expect(await axeViolations(shown)).toEqual([]);

    // The token is shown once: closing the dialog forgets it.
    fireEvent.click(within(shown).getByTestId("enrol-done"));
    await waitFor(() => expect(screen.queryByTestId("dialog-enrol-token")).toBeNull());
    expect(screen.queryByTestId("enrol-token")).toBeNull();
  });

  it("shows the refusal of the server in the dialog", async () => {
    server.use(
      http.post("/api/v1/nodes/enrolments", () =>
        HttpResponse.json(
          { status: 422, code: "cluster.enrolment.roles", title: "Unprocessable", detail: "", params: { role: "controller" } },
          { status: 422 },
        ),
      ),
    );
    await openLoaded();
    fireEvent.click(screen.getByTestId("cluster-add-controller"));
    const form = await screen.findByTestId("dialog-enrol");
    fireEvent.click(within(form).getByTestId("form-submit"));
    const alert = await within(form).findByRole("alert");
    expect(alert.textContent).toBe("A token cannot grant this role.");
  });

  it("gets the join command of a controller token from the mock", async () => {
    await openLoaded();
    fireEvent.click(screen.getByTestId("cluster-add-controller"));
    const form = await screen.findByTestId("dialog-enrol");
    fireEvent.click(within(form).getByTestId("form-submit"));
    const token = await screen.findByTestId("dialog-enrol-token");
    expect(token.textContent).toContain("tenko cluster join");
  });
});

describe("the page for an operator and a viewer", () => {
  it.each(["operator", "viewer"] as const)("shows a %s the cluster without the buttons that change it", async (role) => {
    await signInWithRole(role);
    const view = await openLoaded();
    expect(nodesListed()).toEqual([LEADER, voterA, voterB, learner]);
    expect(screen.queryByTestId(`member-promote-${learner}`)).toBeNull();
    expect(screen.queryByTestId(`member-remove-${learner}`)).toBeNull();
    expect(screen.queryByTestId("cluster-step-down")).toBeNull();
    expect(screen.queryByTestId("cluster-add-controller")).toBeNull();
    // Reading and the digest check stay.
    expect(screen.getByTestId("cluster-queue-link").getAttribute("href")).toBe("/cluster/queue");
    fireEvent.click(screen.getByTestId("cluster-check-digests"));
    await screen.findByTestId("digests-result");
    expect(await axeViolations(view.container)).toEqual([]);
  });
});

describe("the keyboard", () => {
  it("reaches the actions of the page and of every dialog, and Escape closes the dialogs", async () => {
    await openLoaded();

    const promote = screen.getByTestId(`member-promote-${learner}`);
    promote.focus();
    fireEvent.click(promote);
    let dialog = await screen.findByTestId("dialog-promote");
    expect(dialog.contains(document.activeElement)).toBe(true);
    fireEvent.keyDown(dialog, { key: "Escape" });
    await waitFor(() => expect(screen.queryByTestId("dialog-promote")).toBeNull());
    expect(document.activeElement).toBe(promote);

    const remove = screen.getByTestId(`member-remove-${learner}`);
    remove.focus();
    fireEvent.click(remove);
    dialog = await screen.findByTestId("dialog-remove");
    // The first control is Cancel, so Enter on a fresh dialog never removes anything.
    expect(document.activeElement?.textContent).toBe("Cancel");
    fireEvent.keyDown(dialog, { key: "Escape" });
    await waitFor(() => expect(screen.queryByTestId("dialog-remove")).toBeNull());
    expect(document.activeElement).toBe(remove);

    const step = screen.getByTestId("cluster-step-down");
    step.focus();
    fireEvent.click(step);
    dialog = await screen.findByTestId("dialog-step-down");
    fireEvent.keyDown(dialog, { key: "Escape" });
    await waitFor(() => expect(screen.queryByTestId("dialog-step-down")).toBeNull());
    expect(document.activeElement).toBe(step);

    pressWithKeyboard(screen.getByTestId("cluster-add-controller"));
    dialog = await screen.findByTestId("dialog-enrol");
    fireEvent.keyDown(dialog, { key: "Escape" });
    await waitFor(() => expect(screen.queryByTestId("dialog-enrol")).toBeNull());

    pressWithKeyboard(screen.getByTestId("cluster-check-digests"));
    await screen.findByTestId("digests-result");
    expect(screen.getByTestId("cluster-queue-link").tabIndex).toBeGreaterThanOrEqual(0);
  });

  it("keeps Tab inside a dialog", async () => {
    await openLoaded();
    fireEvent.click(screen.getByTestId(`member-remove-${learner}`));
    const dialog = await screen.findByTestId("dialog-remove");
    const buttons = within(dialog).getAllByRole("button");
    const last = buttons[buttons.length - 1] as HTMLElement;
    last.focus();
    fireEvent.keyDown(dialog, { key: "Tab" });
    expect(document.activeElement).toBe(buttons[0]);
    fireEvent.keyDown(dialog, { key: "Tab", shiftKey: true });
    expect(document.activeElement).toBe(last);
  });

  it("confirms a promotion with the keyboard", async () => {
    patch(learner, { lag_entries: 3, last_contact_ms: 50 });
    await openLoaded();
    pressWithKeyboard(screen.getByTestId(`member-promote-${learner}`));
    const dialog = await screen.findByTestId("dialog-promote");
    const select = within(dialog).getByTestId("field-replace");
    expect(select.tabIndex).toBeGreaterThanOrEqual(0);
    fireEvent.change(select, { target: { value: String(voterB) } });
    pressWithKeyboard(within(dialog).getByTestId("promote-confirm"));
    await waitFor(() => expect(screen.queryByTestId("dialog-promote")).toBeNull());
    expect(nodesListed()).toEqual([LEADER, voterA, learner]);
  });
});

describe("compatibility and the data format (WP3.11d)", () => {
  it("shows the protocol majors, the Raft wire version and the formats of a member in one cell", async () => {
    await openLoaded();
    const cell = screen.getByTestId(`member-compat-${LEADER}`);
    expect(within(cell).getByTestId("compat-majors").textContent).toBe("v1, v2");
    expect(within(cell).getByTestId("compat-wire").textContent).toBe("openraft-0.9/cbor-1");
    expect(within(cell).getByTestId("compat-formats").textContent).toBe("formats 2 to 3");
    expect(cell.querySelector("[title]")?.getAttribute("title")).toBe(
      "Protocol majors: v1, v2. Raft wire: openraft-0.9/cbor-1. Data formats it can open: formats 2 to 3.",
    );
  });

  it("shows a dash for what a member has not reported and the single format as it is", async () => {
    const learnerView = member(learner);
    learnerView.protocol_majors = [];
    learnerView.raft_wire = null;
    learnerView.formats = [];
    member(voterA).formats = [3];
    await openLoaded();
    const cell = screen.getByTestId(`member-compat-${learner}`);
    expect(within(cell).getByTestId("compat-majors").textContent).toBe("–");
    expect(within(cell).getByTestId("compat-wire").textContent).toBe("–");
    expect(within(cell).getByTestId("compat-formats").textContent).toBe("–");
    expect(within(screen.getByTestId(`member-compat-${voterA}`)).getByTestId("compat-formats").textContent).toBe("format 3");
  });

  it("says the data is in the newest format and shows no warning when nothing waits", async () => {
    await openLoaded();
    const panel = await screen.findByTestId("cluster-format");
    expect(panel.dataset.state).toBe("current");
    expect(within(panel).getByTestId("format-stored").textContent).toBe("3");
    expect(within(panel).getByTestId("format-binary").textContent).toBe("3");
    expect(within(panel).getByTestId("format-current")).toBeTruthy();
    expect(within(panel).queryByTestId("format-blockers")).toBeNull();
    expect(screen.queryByTestId("cluster-warning")).toBeNull();
  });

  it("shows no panel when the status carries no data format", async () => {
    server.use(
      http.get("/api/v1/system/status", () => HttpResponse.json({ warnings: [] })),
    );
    await openLoaded();
    expect(screen.queryByTestId("cluster-format")).toBeNull();
  });

  it("names the voters that block a pending migration, with the warning as the banner", async () => {
    mockCluster.setMigrationPending(true);
    await openLoaded();
    const panel = await screen.findByTestId("cluster-format");
    expect(panel.dataset.state).toBe("pending");
    expect(within(panel).getByTestId("format-stored").textContent).toBe("2");
    expect(within(panel).getByTestId("format-target").textContent).toBe("3");
    const blockers = within(panel).getAllByTestId("format-blocker");
    expect(blockers).toHaveLength(1);
    expect(blockers[0]?.dataset.node).toBe(String(voterB));
    expect(blockers[0]?.textContent).toContain("ctl-3.example.test");
    expect(blockers[0]?.textContent).toContain("knows format 2");
    expect(within(panel).getByTestId("format-advice").textContent).toContain("docs/upgrades.md, section 7.7");
    const warning = within(panel).getByTestId("cluster-warning");
    expect(warning.dataset.code).toBe("upgrade.migration_blocked");
    expect(warning.textContent).toBe("The data stays in format 2 until every voter can open format 3. Update controller 1102 first.");
  });

  it("says when a blocking voter has not reported its format", async () => {
    mockCluster.setMigrationPending(true);
    server.use(
      http.get("/api/v1/system/status", () =>
        HttpResponse.json({
          warnings: [],
          data_format: { stored: 2, binary: 3, pending: { target: 3, blocked_by: [{ node: voterA, data_format: null }] } },
        }),
      ),
    );
    await openLoaded();
    const blocker = await screen.findByTestId("format-blocker");
    expect(blocker.textContent).toContain("format not reported");
  });

  it("has no accessibility violations with a pending migration", async () => {
    mockCluster.setMigrationPending(true);
    const view = await openLoaded();
    await screen.findByTestId("cluster-format");
    expect(await axeViolations(view.container, { disable: ["region"] })).toEqual([]);
  });
});
