import { screen, waitFor, within } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { api } from "../api/client";
import { CONNECTOR_IDS, connectorsState } from "../api/mock/connectors-store";
import { server } from "../api/mock/node";
import { NODE_IDS, nodesState } from "../api/mock/nodes-store";
import { paths } from "../app/paths";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { bridgeMockEvents } from "../audit/testkit";
import { signInAlex } from "../auth/account/testkit";
import { setSessionForTest } from "../auth/session";
import { listProposals, rejectProposal } from "../discovery/api";
import { resetModules, setModulesForTest } from "../updates/modules";
import Dashboard from "./Dashboard";

let stopBridge: (() => void) | undefined;

beforeEach(async () => {
  resetModules();
  await signInAlex();
});

afterEach(() => {
  stopBridge?.();
  stopBridge = undefined;
  resetModules();
  setSessionForTest(null);
});

async function openDashboard() {
  const view = renderRoute(Dashboard, { url: "/" });
  await screen.findByTestId("page-dashboard");
  return view;
}

const tile = (id: string) => screen.getByTestId(id);
const valueOf = (id: string) => within(tile(id)).getByRole("link").textContent;
const hintOf = (id: string) => tile(id).querySelector("p.muted")?.textContent;

/** Waits until a tile shows its number: the tiles read their data after the page is up. */
async function shows(id: string, value: string) {
  await waitFor(() => expect(valueOf(id)).toBe(value), { timeout: 3000 });
}

function failing(path: string, status = 503) {
  server.use(
    http.get(path, () =>
      HttpResponse.json({ code: "sys.unavailable", status, title: "Service Unavailable", detail: "busy", params: {} }, { status, headers: { "content-type": "application/problem+json" } }),
    ),
  );
}

async function callApi(method: string, path: string): Promise<Response> {
  return fetch(path, { method });
}

describe("the tiles for discovery, connectors and nodes", () => {
  it("counts the open proposals, links to the inbox and counts the conflicts among them", async () => {
    await openDashboard();
    const proposals = await screen.findByTestId("dashboard-proposals");
    expect(within(proposals).getByRole("heading", { name: "Open proposals" })).toBeTruthy();
    await shows("dashboard-proposals", "6");
    const link = within(proposals).getByTestId("dashboard-proposals-link");
    expect(link.getAttribute("href")).toBe(paths.discovery());
    expect(link.getAttribute("href")).toBe("/discovery");
    expect(link.getAttribute("aria-label")).toBeNull();
    expect(hintOf("dashboard-proposals")).toBe("1 conflict");

    // The same numbers as the inbox has.
    const open = await listProposals({ state: ["open"] });
    expect(open).toHaveLength(6);
    expect(open.filter((p) => p.kind === "conflict")).toHaveLength(1);
  });

  it("counts the connectors that are healthy among the enabled ones and says how many need a look", async () => {
    await openDashboard();
    const connectors = await screen.findByTestId("dashboard-connectors");
    expect(within(connectors).getByRole("heading", { name: "Healthy connectors" })).toBeTruthy();
    await shows("dashboard-connectors", "1");
    expect(within(connectors).getByTestId("dashboard-connectors-link").getAttribute("href")).toBe("/connectors");
    expect(hintOf("dashboard-connectors")).toBe("of 2 enabled, 1 needs a look");
  });

  it("counts the nodes that are connected among the enrolled ones and says how many were refused", async () => {
    await openDashboard();
    const nodes = await screen.findByTestId("dashboard-nodes");
    expect(within(nodes).getByRole("heading", { name: "Nodes connected" })).toBeTruthy();
    await shows("dashboard-nodes", "1");
    expect(within(nodes).getByTestId("dashboard-nodes-link").getAttribute("href")).toBe("/nodes");
    expect(hintOf("dashboard-nodes")).toBe("of 2 enrolled, 1 refused");
  });

  it("has no accessibility violations", async () => {
    await openDashboard();
    await shows("dashboard-proposals", "6");
    await shows("dashboard-connectors", "1");
    await shows("dashboard-nodes", "1");
    expect(await axeViolations(screen.getByTestId("page-dashboard"))).toEqual([]);
  });

  it("shows the same tiles to an account that only reads", async () => {
    await signInAlex({
      prepare: (user) => {
        user.roles = ["viewer"];
      },
    });
    await openDashboard();
    await shows("dashboard-proposals", "6");
    await shows("dashboard-connectors", "1");
    await shows("dashboard-nodes", "1");
  });
});

describe("the tiles when there is little to count", () => {
  it("leaves out how many need a look when every enabled connector is healthy", async () => {
    connectorsState().instances.delete(CONNECTOR_IDS.controller);
    await openDashboard();
    await shows("dashboard-connectors", "1");
    expect(hintOf("dashboard-connectors")).toBe("of 1 enabled");
  });

  it("counts only the connectors that are enabled", async () => {
    const view = connectorsState().instances.get(CONNECTOR_IDS.inventory);
    if (!view) throw new Error("the seed has no inventory connector");
    view.enabled = false;
    await openDashboard();
    await shows("dashboard-connectors", "0");
    expect(hintOf("dashboard-connectors")).toBe("of 1 enabled, 1 needs a look");
  });

  it("shows zero for no connector at all", async () => {
    connectorsState().instances.clear();
    await openDashboard();
    await waitFor(() => expect(within(tile("dashboard-connectors")).getByRole("link").getAttribute("aria-label")).toBeNull());
    expect(valueOf("dashboard-connectors")).toBe("0");
    expect(hintOf("dashboard-connectors")).toBe("of 0 enabled");
  });

  it("shows zero connectors, and keeps the page, when the connectors cannot be read", async () => {
    failing("/api/v1/connectors");
    await openDashboard();
    await waitFor(() => expect(within(tile("dashboard-connectors")).getByRole("link").getAttribute("aria-label")).toBeNull());
    expect(valueOf("dashboard-connectors")).toBe("0");
    await shows("dashboard-nodes", "1");
  });

  it("counts no proposal as none and no conflict", async () => {
    const open = await listProposals({ state: ["open"] });
    for (const proposal of open) await rejectProposal(proposal, "");
    await openDashboard();
    await shows("dashboard-proposals", "0");
    expect(hintOf("dashboard-proposals")).toBe("no conflict");
  });

  it("keeps the page and the other tiles when the proposals cannot be read", async () => {
    failing("/api/v1/proposals");
    await openDashboard();
    await shows("dashboard-connectors", "1");
    await shows("dashboard-nodes", "1");
    expect(screen.getByTestId("dashboard-waiting")).toBeTruthy();
    const proposals = tile("dashboard-proposals");
    expect(within(proposals).getByTestId("dashboard-proposals-link")).toBeTruthy();
  });

  it("says that there is no cluster port when the status has no cluster", async () => {
    const status = await api.get("/api/v1/system/status");
    server.use(http.get("/api/v1/system/status", () => HttpResponse.json({ ...status, cluster: null })));
    await openDashboard();
    await waitFor(() => expect(hintOf("dashboard-nodes")).toBe("No cluster port"));
    expect(valueOf("dashboard-nodes")).not.toMatch(/\d/);
    expect(within(tile("dashboard-nodes")).getByTestId("dashboard-nodes-link").getAttribute("aria-label")).toBe("Open the nodes");
  });

  it("shows the nodes without a refusal once every node shares a protocol", async () => {
    nodesState().nodes.delete(NODE_IDS.lab);
    await openDashboard();
    await shows("dashboard-nodes", "1");
    expect(hintOf("dashboard-nodes")).toBe("of 1 enrolled");
  });
});

describe("the tiles and the modules", () => {
  it("has no tile for the proposals, and asks for none, when the discovery module is off", async () => {
    const asked: string[] = [];
    server.use(
      http.get("/api/v1/proposals", ({ request }) => {
        asked.push(request.url);
        return undefined;
      }),
    );
    setModulesForTest(["ipam", "dns", "dhcp"]);
    await openDashboard();
    await shows("dashboard-connectors", "1");
    await shows("dashboard-nodes", "1");
    expect(screen.queryByTestId("dashboard-proposals")).toBeNull();
    expect(screen.queryByTestId("dashboard-proposals-link")).toBeNull();
    expect(asked).toEqual([]);
    expect(await axeViolations(screen.getByTestId("page-dashboard"))).toEqual([]);
  });

  it("shows the tile for the proposals while the discovery module runs", async () => {
    setModulesForTest(["discovery"]);
    await openDashboard();
    await shows("dashboard-proposals", "6");
  });

  it("keeps the connector and node tiles when only the discovery module runs", async () => {
    setModulesForTest(["discovery"]);
    await openDashboard();
    await shows("dashboard-connectors", "1");
    await shows("dashboard-nodes", "1");
  });
});

describe("the tiles follow their topics", () => {
  it("counts a connector that is disabled elsewhere", async () => {
    stopBridge = bridgeMockEvents();
    await openDashboard();
    await shows("dashboard-connectors", "1");
    expect((await callApi("POST", `/api/v1/connectors/${CONNECTOR_IDS.inventory}/disable`)).status).toBe(200);
    await shows("dashboard-connectors", "0");
    expect(hintOf("dashboard-connectors")).toBe("of 1 enabled, 1 needs a look");
  });

  it("counts a connector that is created elsewhere", async () => {
    stopBridge = bridgeMockEvents();
    await openDashboard();
    await shows("dashboard-connectors", "1");
    const made = await fetch("/api/v1/connectors", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: "Annex inventory", plugin: "sample" }),
    });
    expect(made.status).toBe(201);
    await shows("dashboard-connectors", "2");
    expect(hintOf("dashboard-connectors")).toBe("of 3 enabled, 1 needs a look");
  });

  it("drops a proposal that is decided elsewhere, and the conflict with it", async () => {
    stopBridge = bridgeMockEvents();
    await openDashboard();
    await shows("dashboard-proposals", "6");
    const conflict = (await listProposals({ state: ["open"] })).find((p) => p.kind === "conflict");
    if (!conflict) throw new Error("the seed has no open conflict");
    await rejectProposal(conflict, "");
    await shows("dashboard-proposals", "5");
    expect(hintOf("dashboard-proposals")).toBe("no conflict");
  });

  it("counts a node that is revoked elsewhere", async () => {
    stopBridge = bridgeMockEvents();
    await openDashboard();
    await shows("dashboard-nodes", "1");
    expect(hintOf("dashboard-nodes")).toBe("of 2 enrolled, 1 refused");
    expect((await callApi("DELETE", `/api/v1/nodes/${NODE_IDS.lab}`)).status).toBe(204);
    await waitFor(() => expect(hintOf("dashboard-nodes")).toBe("of 1 enrolled"), { timeout: 3000 });
    expect(valueOf("dashboard-nodes")).toBe("1");
  });
});
