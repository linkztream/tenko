// The queued changes (WP3.11a, WP3.9): the local queue of an isolated controller with its cancel,
// and the changes after the heal with re-apply (a dry run first, then the apply with the
// acknowledged warnings), discard, and dismiss for an applied change. It runs against the mock queue of
// src/api/mock/routes-cluster.ts; a server without the queue is played with 404 and 501.
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { CLUSTER_IDS, clusterState, mockCluster } from "../api/mock/cluster-store";
import { server } from "../api/mock/node";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { bridgeMockEvents } from "../audit/testkit";
import { signInAlex } from "../auth/account/testkit";
import { setSessionForTest } from "../auth/session";
import { queueChange } from "./api";
import { partition } from "./partition";
import QueueView, { conflictText, summaryText } from "./QueueView";

const ADDRESS_PATH = `/addresses/${CLUSTER_IDS.address}`;
const toastTitles = () => screen.queryAllByTestId("toast").map((el) => el.querySelector(".t")?.textContent);

let stopBridge: (() => void) | undefined;

beforeEach(async () => {
  await signInAlex();
});

afterEach(() => {
  stopBridge?.();
  stopBridge = undefined;
  partition.reset();
  setSessionForTest(null);
});

function openQueue() {
  return renderRoute(QueueView, {
    url: "/cluster/queue",
    path: "/cluster/queue",
    routes: { "/cluster": () => <div data-testid="cluster-stub" />, "/jobs/:id": () => <div data-testid="job-stub" /> },
  });
}

/** Isolates the controller and queues a change of an address and the creation of a prefix. */
async function isolateWithTwoQueued() {
  mockCluster.setQuorum("isolated");
  const address = await queueChange({ method: "PATCH", path: ADDRESS_PATH, body: { address: "192.0.2.50" } });
  const prefix = await queueChange({ method: "POST", path: "/prefixes", body: { cidr: "198.51.100.0/24" } });
  return { address, prefix };
}

/** The cluster heals with the first change applied and the second one in conflict. */
async function healWithConflict() {
  const queued = await isolateWithTwoQueued();
  mockCluster.heal({ conflicts: true });
  return queued;
}

const item = (id: string) => screen.getByTestId(`queue-item-${id}`);
const change = (id: string) => screen.getByTestId(`queued-change-${id}`);

/** The confirm button of the re-apply dialog once the dry run has answered. */
async function previewed(dialog: HTMLElement): Promise<HTMLButtonElement> {
  const confirm = (await within(dialog).findByTestId("plan-confirm")) as HTMLButtonElement;
  await waitFor(() => expect(confirm.disabled).toBe(false));
  return confirm;
}

function notFound(path: string, status: 404 | 501) {
  return http.get(path, () =>
    HttpResponse.json({ status, code: status === 404 ? "sys.not_found" : "sys.not_implemented", title: "No", detail: "" }, { status }),
  );
}

describe("the words of a queued change", () => {
  it("names the action and the object, with a fallback for what it does not know", () => {
    expect(summaryText({ action: "update", kind: "address", key: "192.0.2.50" })).toBe("Update address");
    expect(summaryText({ action: "create", kind: "prefix" })).toBe("Create prefix");
    expect(summaryText({ action: "delete", kind: "host" })).toBe("Delete host");
    expect(summaryText({ action: "bulk", kind: "vlan" })).toBe("Bulk change of VLAN");
    expect(summaryText({ action: "restore", kind: "interface" })).toBe("Restore interface");
    expect(summaryText({ action: "create", kind: "custom_field" })).toBe("Create custom_field");
    expect(summaryText(null)).toBe("Change");
  });

  it("explains a conflict in words, from the UI's texts, the server's detail or a general line", () => {
    expect(conflictText({ code: "queue.plan_changed", status: 409, detail: "" })).toBe("The data changed while the change was queued.");
    expect(conflictText({ code: "queue.expired", status: 409, detail: "" })).toBe("The change waited too long in the queue.");
    expect(conflictText({ code: "ipam.address.duplicate", status: 409, detail: "", params: { ip: "192.0.2.50" } })).toBe("192.0.2.50 already exists in this VRF.");
    expect(conflictText({ code: "ipam.something.new", status: 409, detail: "the host is gone" })).toBe("the host is gone");
    expect(conflictText({ code: "ipam.something.new", status: 409, detail: "" })).toBe("The change no longer fits the data.");
  });
});

describe("on this controller", () => {
  it("says so when nothing is queued", async () => {
    openQueue();
    expect((await screen.findByTestId("queue-local-empty")).textContent).toBe("Nothing is queued on this controller.");
    expect(screen.getByTestId("page-cluster-queue")).toBeTruthy();
    expect(screen.getByTestId("queue-local")).toBeTruthy();
    expect(screen.getByTestId("queue-changes")).toBeTruthy();
    expect(screen.getByTestId("queue-changes-empty").textContent).toContain("None of your queued changes");
    expect(screen.queryByTestId("queue-unavailable")).toBeNull();
  });

  it("lists the queued changes with their request, times and state", async () => {
    const { address, prefix } = await isolateWithTwoQueued();
    openQueue();
    await screen.findByTestId(`queue-item-${address.id}`);
    const first = within(item(address.id));
    expect(first.getByTestId("queue-item-summary").textContent).toBe("Update address");
    expect(item(address.id).textContent).toContain("192.0.2.50");
    expect(item(address.id).textContent).toContain(`PATCH ${ADDRESS_PATH}`);
    expect(first.getByTestId("queue-item-state").dataset.state).toBe("queued");
    expect(first.getByTestId("queue-item-state").textContent).toBe("Queued");
    expect(item(address.id).querySelectorAll("time")).toHaveLength(2);
    const second = within(item(prefix.id));
    expect(second.getByTestId("queue-item-summary").textContent).toBe("Create prefix");
    expect(item(prefix.id).textContent).toContain("198.51.100.0/24");
    expect(item(prefix.id).textContent).toContain("POST /prefixes");
    expect(screen.queryByTestId("queue-local-empty")).toBeNull();
  });

  it("asks first and keeps the change when the question is declined", async () => {
    const { address } = await isolateWithTwoQueued();
    openQueue();
    fireEvent.click(await screen.findByTestId(`queue-cancel-${address.id}`));
    const dialog = await screen.findByTestId("dialog-cancel-queued");
    expect(dialog.textContent).toContain("Update address is dropped from the queue and will not be applied.");
    expect(await axeViolations(dialog)).toEqual([]);
    fireEvent.click(within(dialog).getByTestId("confirm-cancel"));
    await waitFor(() => expect(screen.queryByTestId("dialog-cancel-queued")).toBeNull());
    expect(clusterState().queue).toHaveLength(2);
    expect(screen.getByTestId(`queue-item-${address.id}`)).toBeTruthy();
  });

  it("cancels a change after the question and drops its row", async () => {
    const { address, prefix } = await isolateWithTwoQueued();
    openQueue();
    fireEvent.click(await screen.findByTestId(`queue-cancel-${address.id}`));
    fireEvent.click(within(await screen.findByTestId("dialog-cancel-queued")).getByTestId("confirm-ok"));
    await waitFor(() => expect(screen.queryByTestId(`queue-item-${address.id}`)).toBeNull());
    expect(screen.getByTestId(`queue-item-${prefix.id}`)).toBeTruthy();
    expect(clusterState().queue.map((s) => s.item.id)).toEqual([prefix.id]);
    expect(toastTitles()).toContain("The queued change was cancelled.");
  });

  it("shows why a change could not be cancelled", async () => {
    const { address } = await isolateWithTwoQueued();
    server.use(
      http.delete(`/api/v1/queue/${address.id}`, () =>
        HttpResponse.json({ status: 404, code: "queue.not_found", title: "Not found", detail: "", params: {} }, { status: 404 }),
      ),
    );
    openQueue();
    fireEvent.click(await screen.findByTestId(`queue-cancel-${address.id}`));
    fireEvent.click(within(await screen.findByTestId("dialog-cancel-queued")).getByTestId("confirm-ok"));
    await waitFor(() => expect(toastTitles()).toContain("The queued change could not be cancelled"));
    expect(screen.getByTestId("toast").textContent).toContain("No queued change of yours has this id.");
  });
});

describe("after the heal", () => {
  it("lists the conflict first, with the problem code, and the applied change to dismiss", async () => {
    const { address, prefix } = await healWithConflict();
    openQueue();
    await screen.findByTestId(`queued-change-${address.id}`);
    expect(screen.getByTestId("queue-local-empty")).toBeTruthy();
    const rows = screen.getAllByTestId(/^queued-change-[0-9a-f-]{36}$/).map((r) => r.dataset.id);
    expect(rows).toEqual([prefix.id, address.id]);

    const conflict = within(change(prefix.id));
    expect(change(prefix.id).dataset.state).toBe("conflict");
    expect(conflict.getByTestId("queued-change-state").textContent).toBe("Needs a decision");
    expect(conflict.getByTestId("queued-change-conflict").dataset.code).toBe("queue.plan_changed");
    expect(conflict.getByTestId("queued-change-conflict").textContent).toContain("The data changed while the change was queued.");
    expect(conflict.getByTestId("queued-change-conflict").textContent).toContain("queue.plan_changed");
    expect(screen.getByTestId(`queued-reapply-${prefix.id}`).getAttribute("aria-label")).toBe("Re-apply: Create prefix");
    expect(screen.getByTestId(`queued-discard-${prefix.id}`)).toBeTruthy();

    const applied = within(change(address.id));
    expect(change(address.id).dataset.state).toBe("applied");
    expect(applied.getByTestId("queued-change-state").textContent).toBe("Applied");
    expect(applied.queryByTestId("queued-change-conflict")).toBeNull();
    expect(screen.queryByTestId(`queued-reapply-${address.id}`)).toBeNull();
    expect(screen.queryByTestId(`queued-discard-${address.id}`)).toBeNull();
    expect(screen.getByTestId(`queued-dismiss-${address.id}`).getAttribute("aria-label")).toBe("Dismiss: Update address");
  });

  it("shows a change that expired before the heal as one to decide on", async () => {
    mockCluster.setQuorum("isolated");
    const expired = await queueChange({ method: "DELETE", path: ADDRESS_PATH });
    const stored = clusterState().queue.find((s) => s.item.id === expired.id);
    if (stored) stored.item.state = "expired";
    mockCluster.heal({ conflicts: false });
    openQueue();
    const row = await screen.findByTestId(`queued-change-${expired.id}`);
    expect(row.dataset.state).toBe("expired");
    expect(within(row).getByTestId("queued-change-state").textContent).toBe("Expired");
    expect(within(row).getByTestId("queued-change-conflict").dataset.code).toBe("queue.expired");
    expect(screen.getByTestId(`queued-reapply-${expired.id}`)).toBeTruthy();
    expect(screen.getByTestId(`queued-discard-${expired.id}`)).toBeTruthy();
  });

  it("dismisses an applied change without asking", async () => {
    const { address } = await healWithConflict();
    openQueue();
    fireEvent.click(await screen.findByTestId(`queued-dismiss-${address.id}`));
    await waitFor(() => expect(screen.queryByTestId(`queued-change-${address.id}`)).toBeNull());
    expect(clusterState().changes.some((c) => c.change.id === address.id)).toBe(false);
    expect(toastTitles()).toContain("The applied change was removed from the list.");
  });

  it("refuses to re-apply an applied change", async () => {
    const { address } = await healWithConflict();
    const answer = await fetch(`/api/v1/queue/conflicts/${address.id}/reapply?dry_run=true`, { method: "POST" });
    expect(answer.status).toBe(409);
    expect(((await answer.json()) as { code: string }).code).toBe("queue.changed");
  });

  it("follows the heal live", async () => {
    stopBridge = bridgeMockEvents();
    const { address, prefix } = await isolateWithTwoQueued();
    openQueue();
    await screen.findByTestId(`queue-item-${address.id}`);
    mockCluster.heal({ conflicts: true });
    await screen.findByTestId(`queued-change-${prefix.id}`);
    expect(screen.queryByTestId(`queue-item-${address.id}`)).toBeNull();
    expect(screen.getByTestId("queue-local-empty")).toBeTruthy();
  });

  it("previews a re-apply, applies it without If-Match, drops the record and updates the banner count", async () => {
    const { prefix } = await healWithConflict();
    const calls: { dryRun: boolean; ifMatch: string | null; acknowledge: string[] }[] = [];
    server.use(
      http.post(`/api/v1/queue/conflicts/${prefix.id}/reapply`, ({ request }) => {
        const url = new URL(request.url);
        calls.push({ dryRun: url.searchParams.get("dry_run") === "true", ifMatch: request.headers.get("if-match"), acknowledge: url.searchParams.getAll("acknowledge") });
        return undefined;
      }),
    );
    partition.setConflicts(1);
    openQueue();
    fireEvent.click(await screen.findByTestId(`queued-reapply-${prefix.id}`));
    const dialog = await screen.findByTestId("dialog-reapply");
    const confirm = await previewed(dialog);
    expect(calls).toHaveLength(1);
    expect(calls[0]).toEqual({ dryRun: true, ifMatch: null, acknowledge: [] });
    expect(dialog.textContent).toContain("Create prefix is planned again against the current data.");
    expect(confirm.textContent).toBe("Apply");
    expect(confirm.disabled).toBe(false);
    expect(await axeViolations(dialog)).toEqual([]);

    fireEvent.click(confirm);
    await waitFor(() => expect(screen.queryByTestId("dialog-reapply")).toBeNull());
    expect(calls).toHaveLength(2);
    expect(calls[1]).toEqual({ dryRun: false, ifMatch: null, acknowledge: [] });
    expect(toastTitles()).toContain("The change was applied.");
    await waitFor(() => expect(screen.queryByTestId(`queued-change-${prefix.id}`)).toBeNull());
    await waitFor(() => expect(partition.conflicts()).toBe(0));
  });

  it("shows the warnings of the new plan and applies only with them acknowledged", async () => {
    const { prefix } = await healWithConflict();
    const applied: string[][] = [];
    server.use(
      http.post(`/api/v1/queue/conflicts/${prefix.id}/reapply`, ({ request }) => {
        const url = new URL(request.url);
        if (url.searchParams.get("dry_run") === "true") {
          return HttpResponse.json({
            dry_run: true,
            plan: { base_revision: 1, changes: [], results: [], summary: { counts: [], lines: [], mutations: 0, preconditions: 0, unacknowledged: [], warnings: {} }, warnings: [] },
            warnings: [{ code: "ipam.prefix.nibble_boundary", message: "The prefix is not on a nibble boundary.", requires_ack: true, params: { cidr: "198.51.100.0/24" } }],
          });
        }
        applied.push(url.searchParams.getAll("acknowledge"));
        return HttpResponse.json({ dry_run: false, warnings: [], job_id: "0190d1c2-0000-7000-8000-00000c100099", revision: 3 });
      }),
    );
    openQueue();
    fireEvent.click(await screen.findByTestId(`queued-reapply-${prefix.id}`));
    const dialog = await screen.findByTestId("dialog-reapply");
    const confirm = (await within(dialog).findByTestId("plan-confirm")) as HTMLButtonElement;
    const ack = await within(dialog).findByTestId("plan-ack");
    expect(ack.dataset.code).toBe("ipam.prefix.nibble_boundary");
    expect(confirm.disabled).toBe(true);
    fireEvent.click(ack);
    expect(confirm.disabled).toBe(false);
    fireEvent.click(confirm);
    await waitFor(() => expect(screen.queryByTestId("dialog-reapply")).toBeNull());
    expect(applied).toEqual([["ipam.prefix.nibble_boundary"]]);
  });

  it("opens the job of a re-applied change from the toast", async () => {
    const { prefix } = await healWithConflict();
    const view = openQueue();
    fireEvent.click(await screen.findByTestId(`queued-reapply-${prefix.id}`));
    fireEvent.click(await previewed(await screen.findByTestId("dialog-reapply")));
    const action = await screen.findByTestId("toast-action");
    fireEvent.click(action);
    await waitFor(() => expect(view.location()).toMatch(/^\/jobs\/[0-9a-f-]{36}$/));
  });

  it("shows the refusal of the apply in the dialog and keeps it open", async () => {
    const { prefix } = await healWithConflict();
    server.use(
      http.post(`/api/v1/queue/conflicts/${prefix.id}/reapply`, ({ request }) => {
        if (new URL(request.url).searchParams.get("dry_run") === "true") return undefined;
        return HttpResponse.json({ status: 409, code: "queue.changed", title: "Conflict", detail: "", params: {} }, { status: 409 });
      }),
    );
    openQueue();
    fireEvent.click(await screen.findByTestId(`queued-reapply-${prefix.id}`));
    const dialog = await screen.findByTestId("dialog-reapply");
    fireEvent.click(await previewed(dialog));
    expect((await within(dialog).findByTestId("error-notice")).textContent).toBe("The queued change was applied or changed meanwhile. Reload the list.");
    expect(screen.getByTestId("dialog-reapply")).toBeTruthy();
    expect(change(prefix.id).dataset.state).toBe("conflict");
  });

  it("asks before discarding, then drops the record without If-Match and updates the banner count", async () => {
    const { prefix } = await healWithConflict();
    const calls: (string | null)[] = [];
    server.use(
      http.delete(`/api/v1/queue/conflicts/${prefix.id}`, ({ request }) => {
        calls.push(request.headers.get("if-match"));
        return undefined;
      }),
    );
    partition.setConflicts(1);
    openQueue();
    fireEvent.click(await screen.findByTestId(`queued-discard-${prefix.id}`));
    const dialog = await screen.findByTestId("dialog-discard-queued");
    expect(dialog.textContent).toContain("Create prefix is dropped. Nothing is applied.");
    expect(await axeViolations(dialog)).toEqual([]);

    // Declining changes nothing.
    fireEvent.click(within(dialog).getByTestId("confirm-cancel"));
    await waitFor(() => expect(screen.queryByTestId("dialog-discard-queued")).toBeNull());
    expect(calls).toEqual([]);
    expect(change(prefix.id).dataset.state).toBe("conflict");

    fireEvent.click(screen.getByTestId(`queued-discard-${prefix.id}`));
    fireEvent.click(within(await screen.findByTestId("dialog-discard-queued")).getByTestId("confirm-ok"));
    await waitFor(() => expect(screen.queryByTestId(`queued-change-${prefix.id}`)).toBeNull());
    expect(calls).toEqual([null]);
    expect(toastTitles()).toContain("The queued change was discarded.");
    await waitFor(() => expect(partition.conflicts()).toBe(0));
  });

  it("has no accessibility violations", async () => {
    const { address } = await healWithConflict();
    const view = openQueue();
    await screen.findByTestId(`queued-change-${address.id}`);
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("has no accessibility violations with a local queue", async () => {
    const { address } = await isolateWithTwoQueued();
    const view = openQueue();
    await screen.findByTestId(`queue-item-${address.id}`);
    expect(await axeViolations(view.container)).toEqual([]);
  });
});

describe("a server without a queue", () => {
  it.each([404, 501] as const)("keeps to one calm note when the routes answer %i", async (status) => {
    server.use(notFound("/api/v1/queue", status), notFound("/api/v1/queue/conflicts", status));
    const view = openQueue();
    const note = await screen.findByTestId("queue-unavailable");
    expect(note.textContent).toContain("This controller keeps no queue of changes.");
    expect(screen.queryByTestId("error-notice")).toBeNull();
    expect(screen.queryByTestId("queue-local")).toBeNull();
    expect(screen.queryByTestId("queue-changes")).toBeNull();
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("shows other failures as errors", async () => {
    server.use(
      http.get("/api/v1/queue", () =>
        HttpResponse.json({ status: 403, code: "auth.forbidden", title: "Forbidden", detail: "" }, { status: 403 }),
      ),
    );
    openQueue();
    expect(await screen.findByTestId("error-notice")).toBeTruthy();
    expect(screen.queryByTestId("queue-unavailable")).toBeNull();
  });
});

describe("the keyboard", () => {
  it("reaches cancel, re-apply and discard, and Escape closes their dialogs", async () => {
    const { address, prefix } = await isolateWithTwoQueued();
    mockCluster.heal({ conflicts: true });
    // The heal drained the queue: queue again for the local list.
    mockCluster.setQuorum("isolated");
    const local = await queueChange({ method: "DELETE", path: ADDRESS_PATH });
    openQueue();

    const cancel = await screen.findByTestId(`queue-cancel-${local.id}`);
    cancel.focus();
    expect(document.activeElement).toBe(cancel);
    expect(cancel.tagName).toBe("BUTTON");
    fireEvent.click(cancel);
    let dialog = await screen.findByTestId("dialog-cancel-queued");
    // Escape declines the question.
    fireEvent.keyDown(dialog, { key: "Escape" });
    await waitFor(() => expect(screen.queryByTestId("dialog-cancel-queued")).toBeNull());
    expect(document.activeElement).toBe(cancel);

    const reapply = await screen.findByTestId(`queued-reapply-${prefix.id}`);
    reapply.focus();
    expect(reapply.tagName).toBe("BUTTON");
    fireEvent.click(reapply);
    dialog = await screen.findByTestId("dialog-reapply");
    await previewed(dialog);
    fireEvent.keyDown(dialog, { key: "Escape" });
    await waitFor(() => expect(screen.queryByTestId("dialog-reapply")).toBeNull());
    expect(document.activeElement).toBe(reapply);

    const discard = screen.getByTestId(`queued-discard-${prefix.id}`);
    discard.focus();
    expect(discard.tagName).toBe("BUTTON");
    fireEvent.click(discard);
    dialog = await screen.findByTestId("dialog-discard-queued");
    fireEvent.keyDown(dialog, { key: "Escape" });
    await waitFor(() => expect(screen.queryByTestId("dialog-discard-queued")).toBeNull());
    expect(document.activeElement).toBe(discard);

    // The dismiss button of the applied change is a button the keyboard reaches.
    const dismiss = screen.getByTestId(`queued-dismiss-${address.id}`);
    expect(dismiss.tagName).toBe("BUTTON");
    expect(dismiss.tabIndex).toBeGreaterThanOrEqual(0);
  });

  it("links back to the cluster page", async () => {
    openQueue();
    const back = await screen.findByRole("link", { name: "Cluster" });
    expect(back.getAttribute("href")).toBe("/cluster");
  });
});
