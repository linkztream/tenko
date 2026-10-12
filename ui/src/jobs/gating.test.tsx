// Display gating of the job actions (IAM-01): cancel and mark done are enabled for a global
// writer and for a scoped operator on a job whose targets all lie in its scope; everybody else
// sees the buttons disabled with the reason (`jobs.no_right`).
import { screen, waitFor } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { HOST_IDS } from "../api/mock/ipam/api";
import { createJob, MOCK_JOB_IDS, MOCK_MOVE_GROUP } from "../api/mock/job-store";
import { renderRoute } from "../app/testing/render";
import { signInAlex } from "../auth/account/testkit";
import { signInScopedOperator, signInWithRoles } from "../auth/scope-testkit";
import { setSessionForTest } from "../auth/session";
import { resetJobDetails } from "./data";
import JobDetail from "./JobDetail";
import JobsView from "./JobsView";

beforeEach(() => resetJobDetails());
afterEach(() => setSessionForTest(null));

/** A job with a manual step on a camera host, whose only address lies in 203.0.113.192/28. */
function insideJob(): string {
  return createJob({
    kind: "ipam.move",
    title: "ipam.move.title",
    targets: [{ kind: "host", id: HOST_IDS["cam-01"] as string }],
    timeoutSecs: 3600,
    steps: [
      { kind: "ipam.move.intent", automatic: true },
      {
        kind: "ipam.move.dhcp",
        automatic: false,
        manual: {
          instruction: "jobs.task.dhcp_reserve",
          args: { host: "cam-01", mac: "00:00:5e:00:53:c1", ip: "203.0.113.193", prefix: "203.0.113.192/28" },
        },
      },
    ],
  });
}

async function openJob(id: string) {
  renderRoute(JobDetail, { url: `/jobs/${id}`, path: "/jobs/:id", routes: { "/jobs": JobsView } });
  await screen.findByTestId("job-steps");
  await waitFor(() => expect(screen.queryAllByTestId("job-step-complete").length).toBeGreaterThan(0));
}

const cancel = () => screen.getByTestId("job-cancel") as HTMLButtonElement;
const complete = () => screen.getAllByTestId("job-step-complete")[0] as HTMLButtonElement;

function expectAllowed() {
  expect(cancel().disabled).toBe(false);
  expect(cancel().title).toBe("");
  expect(complete().disabled).toBe(false);
}

function expectRefused() {
  expect(cancel().disabled).toBe(true);
  expect(cancel().title).not.toBe("");
  expect(complete().disabled).toBe(true);
  expect(screen.getByText(cancel().title)).toBeTruthy();
}

describe("gating of the job actions", () => {
  it("enables an administrator on any job", async () => {
    await signInAlex();
    await openJob(MOCK_JOB_IDS.moveWaiting);
    expectAllowed();
  });

  it("enables a global operator", async () => {
    await signInWithRoles(["operator"]);
    await openJob(MOCK_JOB_IDS.moveWaiting);
    expectAllowed();
  });

  it("enables a scoped operator on a job whose targets are inside its scope", async () => {
    await signInScopedOperator();
    await openJob(insideJob());
    expectAllowed();
  });

  it("disables a scoped operator on a job with a target outside its scope", async () => {
    // The seed move job moves thermostat-1 into 198.51.100.0/24, where casey is a viewer.
    await signInScopedOperator();
    await openJob(MOCK_JOB_IDS.moveWaiting);
    expectRefused();
  });

  it("disables a scoped operator on a job with one target inside and one outside", async () => {
    await signInScopedOperator();
    const id = createJob({
      kind: "ipam.move",
      title: "ipam.move.title",
      targets: [
        { kind: "host", id: HOST_IDS["cam-01"] as string },
        { kind: "host", id: HOST_IDS["gw"] as string },
      ],
      timeoutSecs: 3600,
      steps: [
        { kind: "ipam.move.dhcp", automatic: false, manual: { instruction: "jobs.task.dhcp_reserve", args: { host: "cam-01", mac: "00:00:5e:00:53:c1", ip: "203.0.113.193", prefix: "203.0.113.192/28" } } },
      ],
    });
    await openJob(id);
    expectRefused();
  });

  it("disables a viewer, even on a job inside the area casey may write", async () => {
    await signInWithRoles(["viewer"]);
    await openJob(insideJob());
    expectRefused();
  });
});

describe("gating of the group checklist", () => {
  async function openGroup() {
    renderRoute(JobsView, { url: `/jobs?group=${encodeURIComponent(MOCK_MOVE_GROUP)}`, path: "/jobs" });
    await screen.findByTestId("page-jobs");
    return waitFor(() => {
      const buttons = screen.getAllByTestId("job-group-task-complete") as HTMLButtonElement[];
      expect(buttons.length).toBeGreaterThan(0);
      return buttons;
    });
  }

  it("enables an administrator", async () => {
    await signInAlex();
    const buttons = await openGroup();
    expect(buttons.every((b) => !b.disabled)).toBe(true);
  });

  it("disables a scoped operator on tasks of jobs outside its scope", async () => {
    await signInScopedOperator();
    const buttons = await openGroup();
    expect(buttons.every((b) => b.disabled && b.title !== "")).toBe(true);
  });

  it("disables a viewer", async () => {
    await signInWithRoles(["viewer"]);
    const buttons = await openGroup();
    expect(buttons.every((b) => b.disabled)).toBe(true);
  });
});
