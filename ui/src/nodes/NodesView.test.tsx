import { cleanup, fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../api/client";
import { MOCK_CA_FINGERPRINT } from "../api/mock/fixtures";
import { server } from "../api/mock/node";
import { NODE_IDS, nodesState } from "../api/mock/nodes-store";
import { iso } from "../api/mock/util";
import { renderRoute } from "../app/testing/render";
import { axeViolations } from "../app/testing/axe";
import { bridgeMockEvents } from "../audit/testkit";
import { signInAlex } from "../auth/account/testkit";
import { setSessionForTest } from "../auth/session";
import { fingerprintPairs } from "./model";
import NodesView from "./NodesView";

const DMZ = NODE_IDS.dmz;
const LAB = NODE_IDS.lab;
const PENDING_TOKEN = NODE_IDS.token;

let stopBridge: (() => void) | undefined;

beforeEach(async () => {
  await signInAlex();
});

afterEach(() => {
  stopBridge?.();
  stopBridge = undefined;
  Reflect.deleteProperty(navigator, "clipboard");
  setSessionForTest(null);
});

/** Signs the seeded account in as an operator or a viewer instead of an administrator. */
async function signInWithRole(role: "operator" | "viewer") {
  await signInAlex({
    prepare: (user) => {
      user.roles = [role];
    },
  });
}

function openNodes(url = "/nodes") {
  return renderRoute(NodesView, { url, path: "/nodes/:id?" });
}

const rows = () => screen.queryAllByTestId("row");
const names = () => rows().map((r) => r.dataset.key);

function rowOf(name: string): HTMLElement {
  const row = rows().find((r) => r.dataset.key === name);
  if (!row) throw new Error(`no row for ${name}`);
  return row;
}

function cellOf(row: HTMLElement, column: string): HTMLElement {
  const cell = row.querySelector<HTMLElement>(`[data-col="${column}"]`);
  if (!cell) throw new Error(`no ${column} cell`);
  return cell;
}

async function listed(count: number) {
  await waitFor(() => expect(rows()).toHaveLength(count));
}

const tokens = () => screen.queryAllByTestId("enrolment");

function tokenOf(name: string): HTMLElement {
  const found = tokens().find((r) => r.textContent?.includes(name));
  if (!found) throw new Error(`no token for ${name}`);
  return found;
}

/** The page with its list and its token table loaded. */
async function openLoaded(url = "/nodes") {
  const view = openNodes(url);
  await listed(2);
  await screen.findAllByTestId("enrolment");
  return view;
}

function fill(testid: string, value: string) {
  fireEvent.input(screen.getByTestId(testid), { target: { value } });
}

function fieldError(testid: string): string | undefined {
  const field = screen.getByTestId(testid).closest(".field");
  return field?.querySelector<HTMLElement>("[data-testid='field-error']")?.textContent?.trim();
}

function fakeClipboard(options: { writable?: boolean } = {}) {
  const writeText = vi.fn((_text: string) =>
    options.writable === false ? Promise.reject(new DOMException("denied", "NotAllowedError")) : Promise.resolve(),
  );
  Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText } });
  return writeText;
}

const toastTitles = () => screen.queryAllByTestId("toast").map((t) => t.querySelector(".t")?.textContent);

/** The calls of the page to one endpoint, with their bodies; the mock still answers. */
function recordPosts(path: string) {
  const bodies: unknown[] = [];
  server.use(
    http.post(path, async ({ request }) => {
      bodies.push(await request.clone().json());
      return undefined;
    }),
  );
  return bodies;
}

async function call(method: string, path: string, json?: unknown): Promise<Response> {
  return fetch(path, {
    method,
    headers: json === undefined ? {} : { "content-type": "application/json" },
    body: json === undefined ? null : JSON.stringify(json),
  });
}

describe("the node list", () => {
  it("shows both nodes with roles, address, connection, version, protocol and certificate", async () => {
    openNodes();
    await listed(2);
    expect(names()).toEqual(["probe-dmz", "probe-lab"]);
    expect(screen.getByTestId("grid-nodes")).toBeTruthy();
    expect(screen.getByTestId("page-nodes")).toBeTruthy();
    expect(screen.getByTestId("page-nodes").textContent).toContain("2 nodes, 1 connected");

    const dmz = rowOf("probe-dmz");
    expect(dmz.dataset.id).toBe(String(DMZ));
    expect(cellOf(dmz, "name").textContent).toBe("probe-dmz");
    expect(within(cellOf(dmz, "name")).getByRole("link").getAttribute("href")).toBe(`/nodes/${DMZ}`);
    expect(cellOf(dmz, "roles").textContent).toBe("Probe");
    expect(cellOf(dmz, "address").textContent).toBe("192.0.2.20");
    expect(within(cellOf(dmz, "link")).getByTestId("node-link").dataset.state).toBe("connected");
    expect(cellOf(dmz, "link").textContent).toContain("Connected");
    expect(cellOf(dmz, "version").textContent).toBe("0.1.0-dev · protocol 1");
    expect(cellOf(dmz, "certificate").textContent).toMatch(/^32[45] days left$/);
    expect((cellOf(dmz, "certificate").firstElementChild as HTMLElement).dataset.due).toBe("false");

    const lab = rowOf("probe-lab");
    expect(lab.dataset.id).toBe(String(LAB));
    expect(cellOf(lab, "roles").textContent).toBe("Probe");
    expect(cellOf(lab, "address").textContent).toBe("203.0.113.20");
    expect(within(cellOf(lab, "link")).getByTestId("node-link").dataset.state).toBe("mismatch");
    expect(cellOf(lab, "link").textContent).toContain("Refused: protocol");
    expect(cellOf(lab, "version").textContent).toBe("0.2.0 · protocol 1");
    expect(lab.classList.contains("node-mismatch")).toBe(true);
    expect(dmz.classList.contains("node-mismatch")).toBe(false);
  });

  it("marks a certificate that is due for renewal with a glyph and the due attribute", async () => {
    openNodes();
    await listed(2);
    const due = cellOf(rowOf("probe-lab"), "certificate");
    expect(due.textContent?.trim()).toMatch(/^(19|20) days left$/);
    const marker = due.firstElementChild as HTMLElement;
    expect(marker.dataset.due).toBe("true");
    expect(marker.querySelector("svg")).toBeTruthy();
    expect(marker.classList.contains("due")).toBe(true);
    expect(cellOf(rowOf("probe-dmz"), "certificate").querySelector("svg")).toBeNull();
  });

  it("names the node whose handshake was refused, and what the controller speaks", async () => {
    openNodes();
    const notice = await screen.findByTestId("nodes-version-mismatch");
    await waitFor(() => expect(notice.textContent).toContain("probe-lab"));
    expect(notice.textContent).toBe(
      "1 node shares no protocol version with this controller (probe-lab); this controller speaks 1. Upgrade the older side.",
    );
    expect(notice.getAttribute("role")).toBe("alert");
  });

  it("shows no notice when every node shares a protocol major", async () => {
    nodesState().nodes.delete(LAB);
    openNodes();
    await listed(1);
    await screen.findByTestId("nodes-cluster");
    expect(screen.queryByTestId("nodes-version-mismatch")).toBeNull();
  });

  it("names where the cluster port listens and the versions of the connected nodes", async () => {
    openNodes();
    const line = await screen.findByTestId("nodes-cluster");
    expect(line.textContent).toBe("The cluster port listens on 0.0.0.0:8444 with protocol 1 · connected versions: 0.1.0-dev (1)");
  });

  it("says that the cluster port is not open yet", async () => {
    nodesState().listening = [];
    openNodes();
    const line = await screen.findByTestId("nodes-cluster");
    expect(line.textContent).toContain("The cluster port opens when the first enrolment token is created.");
  });

  it("says so when no node is enrolled", async () => {
    nodesState().nodes.clear();
    openNodes();
    expect((await screen.findByTestId("nodes-empty")).textContent).toContain("No node enrolled");
    expect(screen.getByTestId("page-nodes").textContent).toContain("No node enrolled");
  });

  it("has no accessibility violations", async () => {
    const view = await openLoaded();
    expect(await axeViolations(view.container)).toEqual([]);
  });
});

describe("a node in the panel", () => {
  it("opens with a click on its row and shows the connection and the certificate", async () => {
    const node = await api.get("/api/v1/nodes/{id}", { path: { id: DMZ } });
    const view = openNodes();
    await listed(2);
    fireEvent.click(cellOf(rowOf("probe-dmz"), "address"));
    const panel = await screen.findByTestId("node-panel");
    expect(view.location()).toBe(`/nodes/${DMZ}`);
    expect(panel.dataset.id).toBe(String(DMZ));
    await within(panel).findByRole("heading", { name: "probe-dmz" });
    expect(panel.textContent).toContain(`Node ${DMZ}`);
    expect(within(panel).getByTestId("node-link").dataset.state).toBe("connected");

    const connection = within(panel).getByTestId("node-connection");
    expect(connection.textContent).toContain("192.0.2.20:51234");
    expect(connection.textContent).toContain("Protocol");
    expect(within(connection).getByTestId("node-buffer").textContent).toBe("0 batches, 0 byte");

    const certificate = within(panel).getByTestId("node-certificate");
    expect(certificate.textContent).toContain(node.certificate.serial);
    expect(certificate.textContent).toMatch(/32[45] days left/);
    expect(certificate.textContent).not.toContain("Renewal is due");
    expect(within(panel).queryByTestId("node-mismatch")).toBeNull();
    // The list stays beside the panel and marks the open node.
    expect(rowOf("probe-dmz").classList.contains("current")).toBe(true);
    expect(rows()).toHaveLength(2);
  });

  it("links a probe to its scan configuration, and a node without the probe role to nothing", async () => {
    openNodes(`/nodes/${DMZ}`);
    const panel = await screen.findByTestId("node-panel");
    await within(panel).findByRole("heading", { name: "probe-dmz" });
    const link = within(panel).getByTestId("node-scan-config");
    expect(link.getAttribute("href")).toBe(`/nodes/${DMZ}/scan`);
    expect(link.textContent).toContain("Scan configuration");
    cleanup();

    const node = nodesState().nodes.get(LAB);
    if (!node) throw new Error("no lab node");
    node.roles = ["dns"];
    openNodes(`/nodes/${LAB}`);
    const other = await screen.findByTestId("node-panel");
    await within(other).findByRole("heading", { name: "probe-lab" });
    expect(within(other).queryByTestId("node-scan-config")).toBeNull();
  });

  it("opens the focused node with Enter", async () => {
    const view = openNodes();
    await listed(2);
    const grid = screen.getByRole("grid", { name: "Nodes" });
    fireEvent.focus(grid);
    // The focus starts on the first node; one key reaches the second.
    fireEvent.keyDown(grid, { key: "ArrowDown" });
    fireEvent.keyDown(grid, { key: "Enter" });
    await waitFor(() => expect(view.location()).toBe(`/nodes/${LAB}`));
    expect((await screen.findByTestId("node-panel")).dataset.id).toBe(String(LAB));
  });

  it("follows the link in the name cell to the node", async () => {
    const view = openNodes();
    await listed(2);
    fireEvent.click(within(cellOf(rowOf("probe-lab"), "name")).getByRole("link"));
    await waitFor(() => expect(view.location()).toBe(`/nodes/${LAB}`));
    await screen.findByTestId("node-panel");
  });

  it("opens from the address and explains a refused handshake", async () => {
    openNodes(`/nodes/${LAB}`);
    const panel = await screen.findByTestId("node-panel");
    await within(panel).findByRole("heading", { name: "probe-lab" });
    expect(within(panel).getByTestId("node-link").dataset.state).toBe("mismatch");
    const mismatch = within(panel).getByTestId("node-mismatch");
    expect(mismatch.textContent).toContain("version 0.2.0 offers protocol 2, this controller speaks 1. Upgrade the older side.");
    const connection = within(panel).getByTestId("node-connection");
    expect(connection.textContent).toContain("Not connected to this controller.");
    expect(within(connection).queryByTestId("node-buffer")).toBeNull();
    const certificate = within(panel).getByTestId("node-certificate");
    expect(certificate.textContent).toContain("Renewal is due");
    expect((within(certificate).getByText(/days left/) as HTMLElement).dataset.due).toBe("true");
    await waitFor(() => expect(rows()).toHaveLength(2));
    expect(rowOf("probe-lab").classList.contains("current")).toBe(false);
  });

  it("closes with the close button and with Escape", async () => {
    const view = openNodes(`/nodes/${DMZ}`);
    const panel = await screen.findByTestId("node-panel");
    await within(panel).findByRole("heading", { name: "probe-dmz" });
    fireEvent.click(within(panel).getByRole("button", { name: "Close" }));
    await waitFor(() => expect(screen.queryByTestId("node-panel")).toBeNull());
    expect(view.location()).toBe("/nodes");

    view.history.set({ value: `/nodes/${LAB}` });
    const again = await screen.findByTestId("node-panel");
    await within(again).findByRole("heading", { name: "probe-lab" });
    fireEvent.keyDown(again, { key: "Escape" });
    await waitFor(() => expect(screen.queryByTestId("node-panel")).toBeNull());
    expect(view.location()).toBe("/nodes");
  });

  it("says so when the node does not exist and offers to close the panel", async () => {
    const view = openNodes("/nodes/9999");
    const panel = await screen.findByTestId("node-panel");
    await waitFor(() => expect(panel.textContent).toContain("The node is not enrolled."));
    fireEvent.click(within(panel).getByRole("button", { name: "Close" }));
    await waitFor(() => expect(view.location()).toBe("/nodes"));
  });

  it("has no accessibility violations with the panel open", async () => {
    const view = openNodes(`/nodes/${LAB}`);
    const panel = await screen.findByTestId("node-panel");
    await within(panel).findByTestId("node-mismatch");
    await listed(2);
    await screen.findAllByTestId("enrolment");
    expect(await axeViolations(view.container)).toEqual([]);
  });
});

describe("revoking a node", () => {
  it("asks first and keeps the node when the question is declined", async () => {
    const view = openNodes(`/nodes/${LAB}`);
    const panel = await screen.findByTestId("node-panel");
    fireEvent.click(await within(panel).findByTestId("node-revoke"));
    const dialog = await screen.findByTestId("dialog-confirm");
    expect(dialog.getAttribute("aria-label")).toBe("Revoke probe-lab?");
    expect(dialog.textContent).toContain("Enrolling it again gives it a new id.");
    expect(within(dialog).getByTestId("confirm-ok").textContent).toBe("Revoke node");
    expect(await axeViolations(dialog)).toEqual([]);
    fireEvent.click(within(dialog).getByTestId("confirm-cancel"));
    await waitFor(() => expect(screen.queryByTestId("dialog-confirm")).toBeNull());
    expect(view.location()).toBe(`/nodes/${LAB}`);
    expect((await api.get("/api/v1/nodes")).items.map((n) => n.name)).toEqual(["probe-dmz", "probe-lab"]);
  });

  it("revokes the node, says so, drops it from the list and returns to the list", async () => {
    const view = openNodes(`/nodes/${LAB}`);
    await listed(2);
    const panel = await screen.findByTestId("node-panel");
    fireEvent.click(await within(panel).findByTestId("node-revoke"));
    fireEvent.click(await screen.findByTestId("confirm-ok"));

    await waitFor(() => expect(view.location()).toBe("/nodes"));
    await waitFor(() => expect(names()).toEqual(["probe-dmz"]));
    expect(screen.queryByTestId("node-panel")).toBeNull();
    expect(screen.queryByTestId("dialog-confirm")).toBeNull();
    expect(toastTitles()).toEqual(["Revoked probe-lab"]);
    expect(nodesState().nodes.has(LAB)).toBe(false);
    expect([...nodesState().revoked.values()]).toEqual([LAB]);
  });

  it("revokes the node with the live stream on, and goes straight back to the list", async () => {
    stopBridge = bridgeMockEvents();
    const view = openNodes(`/nodes/${LAB}`);
    await listed(2);
    const panel = await screen.findByTestId("node-panel");
    fireEvent.click(await within(panel).findByTestId("node-revoke"));
    fireEvent.click(await screen.findByTestId("confirm-ok"));
    await waitFor(() => expect(view.location()).toBe("/nodes"));
    await waitFor(() => expect(names()).toEqual(["probe-dmz"]), { timeout: 3000 });
    expect(toastTitles()).toEqual(["Revoked probe-lab"]);
    // The panel never shows the node as missing on its way out.
    expect(screen.queryByText("The node is not enrolled.")).toBeNull();
    await new Promise((resolve) => setTimeout(resolve, 400));
    expect(screen.queryByText("The node is not enrolled.")).toBeNull();
  });

  it("reports a node that was revoked elsewhere meanwhile", async () => {
    openNodes(`/nodes/${LAB}`);
    const panel = await screen.findByTestId("node-panel");
    const revoke = await within(panel).findByTestId("node-revoke");
    expect((await call("DELETE", `/api/v1/nodes/${LAB}`)).status).toBe(204);
    fireEvent.click(revoke);
    fireEvent.click(await screen.findByTestId("confirm-ok"));
    await waitFor(() => expect(toastTitles()).toEqual(["probe-lab was not revoked"]));
    const toast = screen.getByTestId("toast");
    expect(toast.dataset.key).toBe("bad");
    expect(toast.textContent).toContain("The node is not enrolled.");
  });

  it("is for administrators: an operator sees the node and no revoke button", async () => {
    await signInWithRole("operator");
    openNodes(`/nodes/${DMZ}`);
    const panel = await screen.findByTestId("node-panel");
    await within(panel).findByRole("heading", { name: "probe-dmz" });
    expect(within(panel).getByTestId("node-connection")).toBeTruthy();
    expect(within(panel).queryByTestId("node-revoke")).toBeNull();
    expect(panel.textContent).not.toContain("Revoke");
  });
});

describe("the scan configuration of this controller", () => {
  /** Answers the status as if the controller ran exactly `roles`. */
  async function running(roles: string[]) {
    const status = await api.get("/api/v1/system/status");
    server.use(http.get("/api/v1/system/status", () => HttpResponse.json({ ...status, node: { ...status.node, roles } })));
  }

  it("links the \"This controller\" section to the scan configuration while the probe role runs", async () => {
    await running(["controller", "dns", "probe"]);
    openNodes();
    const section = await screen.findByTestId("nodes-self");
    const link = await within(section).findByTestId("node-scan-config");
    expect(link.getAttribute("href")).toBe("/nodes/1/scan");
  });

  /** Answers the roles of this controller as if it stored `configured` and ran `running`. */
  async function ownRoles(configured: string[], running: string[]) {
    const roles = await api.get("/api/v1/nodes/{id}/roles", { path: { id: 1 } });
    server.use(http.get("/api/v1/nodes/1/roles", () => HttpResponse.json({ ...roles, configured, running, stored: true, revision: 7 })));
  }

  it("links to the scan configuration when the stored set has the probe role and the status does not list it", async () => {
    // A server of version 0.0.5 or older never listed the probe role in the status.
    await running(["controller", "dns"]);
    await ownRoles(["controller", "dns", "probe"], ["controller", "dns", "probe"]);
    openNodes();
    const section = await screen.findByTestId("nodes-self");
    const link = await within(section).findByRole("link", { name: "Scan configuration" });
    expect(link.getAttribute("href")).toBe("/nodes/1/scan");
    expect(within(section).queryByTestId("nodes-self-scan-off")).toBeNull();
  });

  it("links to it as soon as the probe role is stored, before the restart applies it", async () => {
    await running(["controller", "dns"]);
    await ownRoles(["controller", "dns", "probe"], ["controller", "dns"]);
    openNodes();
    const section = await screen.findByTestId("nodes-self");
    expect((await within(section).findByTestId("node-scan-config")).getAttribute("href")).toBe("/nodes/1/scan");
  });

  it("says how to get there while the controller has no probe role, and links once it is switched on", async () => {
    await running(["controller", "dns"]);
    openNodes();
    const section = await screen.findByTestId("nodes-self");
    // The mock controller starts with the probe role: switch it off first.
    await within(section).findByTestId("node-scan-config");
    const probe = () => within(section).getByTestId("node-role-probe") as HTMLInputElement;
    const change = async () => {
      fireEvent.click(probe());
      fireEvent.click(within(section).getByTestId("node-roles-save"));
      const dialog = await screen.findByTestId("node-roles-confirm");
      fireEvent.click(within(dialog).getByRole("button", { name: "Change and restart" }));
    };
    await change();
    // The probe still runs until the restart, which the roles editor follows.
    const hint = await within(section).findByTestId("nodes-self-scan-off", undefined, { timeout: 5000 });
    expect(hint.tagName).toBe("P");
    expect(hint.querySelector("a")).toBeNull();
    expect(hint.textContent).toContain("does not have the probe role");
    expect(within(section).queryByTestId("node-scan-panel")).toBeNull();

    await waitFor(() => expect(probe().checked).toBe(false));
    await change();
    expect((await within(section).findByTestId("node-scan-config")).getAttribute("href")).toBe("/nodes/1/scan");
    expect(within(section).queryByTestId("nodes-self-scan-off")).toBeNull();
  });
});

describe("the health rows of the node page", () => {
  const COMMAND = "sudo bash install.sh --prepare --roles controller,dns,probe";

  /** Answers the status with the warnings of a machine the installer did not prepare. */
  async function warned(warnings: { code: string; detail: string; params: Record<string, string> }[]) {
    const status = await api.get("/api/v1/system/status");
    server.use(http.get("/api/v1/system/status", () => HttpResponse.json({ ...status, warnings: [...status.warnings, ...warnings] })));
  }

  it("shows no health row while the machine is prepared", async () => {
    openNodes();
    await listed(2);
    expect(screen.queryByTestId("nodes-health-row")).toBeNull();
  });

  it("shows the privileges warning with the capability, the drop-in and the installer command", async () => {
    await warned([
      {
        code: "node.roles.privileges",
        detail: "the role(s) probe need raw sockets",
        params: { roles: "probe", dropins: "probe.conf", capability: "CAP_NET_RAW", command: "sudo bash install.sh --prepare" },
      },
    ]);
    openNodes();
    const row = await screen.findByTestId("nodes-health-row");
    expect(row.dataset.code).toBe("node.roles.privileges");
    expect(row.textContent).toContain("probe");
    expect(row.textContent).toContain("CAP_NET_RAW");
    expect(row.textContent).toContain("probe.conf");
    expect(row.textContent).toContain("sudo bash install.sh --prepare");
  });

  it("shows the warning about a machine the installer did not prepare", async () => {
    await warned([
      {
        code: "node.roles.unprepared",
        detail: "the machine is not prepared for dhcp",
        params: { roles: "dhcp", missing: "dhcp-direct.conf, 67/udp", command: COMMAND },
      },
    ]);
    openNodes();
    const row = await screen.findByTestId("nodes-health-row");
    expect(row.dataset.code).toBe("node.roles.unprepared");
    expect(row.textContent).toContain("did not prepare");
    expect(row.textContent).toContain("dhcp-direct.conf, 67/udp");
    expect(row.textContent).toContain(COMMAND);
  });

  // WP9.4: the findings of the router advertisement check of the dhcp role.
  const RA: { code: string; kind: string; params: Record<string, string>; text: string }[] = [
    {
      code: "dhcp.ra.flags_off",
      kind: "warn",
      params: { node: "1", interface: "eth1", routers: "fe80::2", scopes: "2001:db8:0:30::/64" },
      text: "The routers fe80::2 on eth1 of node 1 set neither the M nor the O flag, so the hosts on that link do not ask DHCPv6 and the scopes 2001:db8:0:30::/64 serve nobody.",
    },
    {
      code: "dhcp.ra.other_only",
      kind: "info",
      params: { node: "1", interface: "eth0", routers: "fe80::1", scopes: "2001:db8:0:10::/64" },
      text: "The routers fe80::1 on eth0 of node 1 set the O flag without M, so the hosts on that link ask DHCPv6 for options only.",
    },
    {
      code: "dhcp.ra.managed_without_scope",
      kind: "warn",
      params: { node: "1", interface: "eth2", routers: "fe80::9", prefixes: "2001:db8:0:50::/64" },
      text: "The routers fe80::9 on eth2 of node 1 set the M flag for 2001:db8:0:50::/64, but no enabled DHCPv6 scope covers that link",
    },
    {
      code: "dhcp.ra.unchecked",
      kind: "info",
      params: { node: "1", reason: "no CAP_NET_RAW" },
      text: "The router advertisement check cannot run on node 1: no CAP_NET_RAW.",
    },
  ];

  for (const { code, kind, params, text } of RA) {
    it(`shows ${code} as a ${kind} health row in words`, async () => {
      await warned([{ code, detail: `English detail of ${code}`, params }]);
      openNodes();
      const row = await screen.findByTestId("nodes-health-row");
      expect(row.dataset.code).toBe(code);
      expect(row.classList.contains(kind)).toBe(true);
      expect(row.textContent).toContain(text);
      expect(row.textContent).not.toContain("English detail");
    });
  }

  it("shows the router advertisement rows next to the preparation rows", async () => {
    await warned([
      { code: "dhcp.ra.flags_off", detail: "x", params: RA[0]!.params },
      { code: "node.roles.privileges", detail: "x", params: { roles: "probe", dropins: "probe.conf", capability: "CAP_NET_RAW", command: COMMAND } },
    ]);
    openNodes();
    await waitFor(() => expect(screen.getAllByTestId("nodes-health-row").map((r) => r.dataset.code)).toEqual(["dhcp.ra.flags_off", "node.roles.privileges"]));
  });

  it("falls back to the detail for a router advertisement code it has no words for", async () => {
    await warned([{ code: "dhcp.ra.future", detail: "a finding of a newer server", params: { node: "1" } }]);
    openNodes();
    const row = await screen.findByTestId("nodes-health-row");
    expect(row.textContent).toContain("a finding of a newer server");
    expect(row.classList.contains("info")).toBe(true);
  });
});

describe("when the server cannot answer", () => {
  const failing = (path: string) =>
    server.use(
      http.get(path, () =>
        HttpResponse.json({ code: "sys.unavailable", status: 503, title: "Service Unavailable", detail: "the store is busy", params: {} }, { status: 503, headers: { "content-type": "application/problem+json" } }),
      ),
    );

  it("shows the error of the token list instead of an empty one, and keeps the nodes", async () => {
    failing("/api/v1/nodes/enrolments");
    openNodes();
    await listed(2);
    const section = screen.getByTestId("nodes-tokens");
    const alert = await within(section).findByRole("alert");
    expect(alert.textContent?.length).toBeGreaterThan(0);
    expect(section.textContent).not.toContain("No token.");
    expect(tokens()).toHaveLength(0);
    expect(screen.getByTestId("nodes-enrol")).toBeTruthy();
  });

  it("shows the nodes without the cluster summary when the status cannot be read", async () => {
    failing("/api/v1/system/status");
    openNodes();
    await listed(2);
    await screen.findAllByTestId("enrolment");
    expect(screen.queryByTestId("nodes-cluster")).toBeNull();
    expect(screen.queryByTestId("nodes-version-mismatch")).toBeNull();
    expect(screen.getByTestId("page-nodes").textContent).not.toContain("connected");
  });

  it("shows the error of the list of nodes with a retry", async () => {
    failing("/api/v1/nodes");
    openNodes();
    const grid = await screen.findByTestId("grid-nodes");
    await waitFor(() => expect(grid.querySelector("[role='alert']")).toBeTruthy());
    expect(within(grid).getByRole("button", { name: "Try again" })).toBeTruthy();
    expect(rows()).toHaveLength(0);
  });
});

describe("the enrolment tokens", () => {
  it("lists the pending token with its roles and a delete button", async () => {
    openNodes();
    const token = (await screen.findAllByTestId("enrolment"))[0] as HTMLElement;
    expect(screen.getByTestId("nodes-tokens")).toBeTruthy();
    expect(tokens()).toHaveLength(1);
    expect(token.dataset.id).toBe(PENDING_TOKEN);
    expect(token.dataset.state).toBe("pending");
    expect(token.textContent).toContain("Waiting");
    expect(token.textContent).toContain("probe-garage");
    expect(token.textContent).toContain("Probe");
    expect(within(token).getByTestId("enrolment-delete").getAttribute("aria-label")).toBe("Delete the token probe-garage");
    // The token text is never part of the list.
    expect(token.textContent).not.toContain("tnk1.");
    expect(document.body.textContent).not.toContain("Z2FyYWdlLXByb2JlLXRva2VuLW9mLXRoZS1tb2NrLTA");
  });

  it("shows an expired token as expired", async () => {
    const stored = nodesState().enrolments.get(PENDING_TOKEN);
    if (!stored) throw new Error("the seed has no pending token");
    stored.view = { ...stored.view, created_at: iso(Date.now() - 3_600_000), expires_at: iso(Date.now() - 1000) };
    openNodes();
    const token = (await screen.findAllByTestId("enrolment"))[0] as HTMLElement;
    expect(token.dataset.state).toBe("expired");
    expect(token.textContent).toContain("Expired");
  });

  it("shows a used token with the node that enrolled with it", async () => {
    const made = (await (await call("POST", "/api/v1/nodes/enrolments", { name: "probe-annex", roles: ["probe"] })).json()) as { token: string };
    const csr = "-----BEGIN CERTIFICATE REQUEST-----\nZXhhbXBsZQ==\n-----END CERTIFICATE REQUEST-----\n";
    const enrolled = await call("POST", "/api/v1/nodes/enrol", { token: made.token, csr, version: "0.1.0-dev", majors: [1] });
    expect(enrolled.status).toBe(201);
    const { node } = (await enrolled.json()) as { node: { id: number } };

    openNodes();
    await listed(3);
    await waitFor(() => expect(tokens()).toHaveLength(2));
    const used = tokenOf("probe-annex");
    expect(used.dataset.state).toBe("used");
    expect(used.textContent).toContain("Used");
    const link = within(used).getByTestId("enrolment-node");
    expect(link.textContent).toBe("probe-annex");
    expect(link.getAttribute("href")).toBe(`/nodes/${node.id}`);
    expect(link.getAttribute("data-id")).toBe(String(node.id));
    expect(within(used).getByRole("link", { name: "probe-annex" })).toBe(link);
    // A token that nobody used has no node.
    expect(within(tokenOf("probe-garage")).queryByTestId("enrolment-node")).toBeNull();
    expect(tokenOf("probe-garage").dataset.state).toBe("pending");
  });

  it("says so when there is no token", async () => {
    nodesState().enrolments.clear();
    openNodes();
    await listed(2);
    await waitFor(() => expect(screen.getByTestId("nodes-tokens").textContent).toContain("No token."));
    expect(tokens()).toHaveLength(0);
  });

  it("deletes a token after asking, and says so", async () => {
    openNodes();
    await screen.findAllByTestId("enrolment");
    fireEvent.click(within(tokenOf("probe-garage")).getByTestId("enrolment-delete"));
    const dialog = await screen.findByTestId("dialog-confirm");
    expect(dialog.getAttribute("aria-label")).toBe("Delete the enrolment token?");
    expect(dialog.textContent).toContain("Nobody can enrol a node with it any more.");
    fireEvent.click(within(dialog).getByTestId("confirm-ok"));
    await waitFor(() => expect(tokens()).toHaveLength(0));
    expect(toastTitles()).toEqual(["Deleted the enrolment token"]);
    expect(screen.getByTestId("nodes-tokens").textContent).toContain("No token.");
    expect(nodesState().enrolments.size).toBe(0);
  });

  it("keeps the token when the question is declined", async () => {
    openNodes();
    await screen.findAllByTestId("enrolment");
    fireEvent.click(within(tokenOf("probe-garage")).getByTestId("enrolment-delete"));
    fireEvent.click(await screen.findByTestId("confirm-cancel"));
    await waitFor(() => expect(screen.queryByTestId("dialog-confirm")).toBeNull());
    expect(tokens()).toHaveLength(1);
    expect(nodesState().enrolments.size).toBe(1);
  });

  it("tells that only the list entry goes when the token is used up", async () => {
    const stored = nodesState().enrolments.get(PENDING_TOKEN);
    if (!stored) throw new Error("the seed has no pending token");
    stored.view = { ...stored.view, created_at: iso(Date.now() - 3_600_000), expires_at: iso(Date.now() - 1000) };
    openNodes();
    await screen.findAllByTestId("enrolment");
    fireEvent.click(within(tokenOf("probe-garage")).getByTestId("enrolment-delete"));
    expect((await screen.findByTestId("dialog-confirm")).textContent).toContain("It is used or expired; only the list entry goes.");
  });

  it("reports a token that is gone already", async () => {
    openNodes();
    await screen.findAllByTestId("enrolment");
    expect((await call("DELETE", `/api/v1/nodes/enrolments/${PENDING_TOKEN}`)).status).toBe(204);
    fireEvent.click(within(tokenOf("probe-garage")).getByTestId("enrolment-delete"));
    fireEvent.click(await screen.findByTestId("confirm-ok"));
    await waitFor(() => expect(toastTitles()).toEqual(["The token was not deleted"]));
    expect(screen.getByTestId("toast").dataset.key).toBe("bad");
    expect(screen.getByTestId("toast").textContent).toContain("The enrolment token does not exist.");
  });
});

describe("creating a token", () => {
  async function openDialog() {
    const view = await openLoaded();
    fireEvent.click(screen.getByTestId("nodes-enrol"));
    const form = await screen.findByTestId("dialog-enrol");
    return { view, form };
  }

  it("offers the roles, a name, a lifetime of one hour and no VRF choice with a single VRF", async () => {
    const { form } = await openDialog();
    expect(form.closest("[role='dialog']")?.getAttribute("aria-label")).toBe("New enrolment token");
    expect((screen.getByTestId("field-role-probe") as HTMLInputElement).checked).toBe(true);
    expect((screen.getByTestId("field-role-dns") as HTMLInputElement).checked).toBe(false);
    expect((screen.getByTestId("field-role-dhcp") as HTMLInputElement).checked).toBe(false);
    expect((screen.getByTestId("field-name") as HTMLInputElement).value).toBe("");
    const lifetime = screen.getByTestId("field-lifetime") as HTMLSelectElement;
    expect(lifetime.value).toBe("3600");
    expect(Array.from(lifetime.options).map((o) => o.textContent)).toEqual(["15 minutes", "1 hour", "1 day", "7 days"]);
    expect(screen.queryByTestId("field-vrf")).toBeNull();
    expect(await axeViolations(form)).toEqual([]);
  });

  it("creates the token and shows it once with the command, the token and the fingerprint", async () => {
    const posted = recordPosts("/api/v1/nodes/enrolments");
    const { form } = await openDialog();
    fireEvent.click(screen.getByTestId("field-role-dns"));
    fill("field-name", "  probe-office ");
    fireEvent.change(screen.getByTestId("field-lifetime"), { target: { value: "86400" } });
    fireEvent.click(within(form).getByTestId("form-submit"));

    const shown = await screen.findByTestId("dialog-enrol-token");
    expect(posted).toEqual([{ roles: ["probe", "dns"], name: "probe-office", vrf: null, expires_in_secs: 86400 }]);
    expect(screen.queryByTestId("dialog-enrol")).toBeNull();

    const token = within(shown).getByTestId("enrol-token").textContent ?? "";
    expect(token).toMatch(/^tnk1\.[0-9a-f]{32}\.[A-Za-z0-9_-]{43}$/);
    const command = within(shown).getByTestId("enrol-command").textContent ?? "";
    expect(command).toContain("tenko node enrol");
    expect(command).toContain(`--controller ${window.location.origin}`);
    expect(command).toContain("--token tnk1.");
    expect(command).toContain(`--token ${token}`);
    expect(command).toContain(`--ca-fingerprint ${MOCK_CA_FINGERPRINT}`);
    expect(within(shown).getByTestId("enrol-fingerprint").textContent).toBe(fingerprintPairs(MOCK_CA_FINGERPRINT));
    expect(within(shown).getByTestId("enrol-fingerprint").textContent).toMatch(/^([0-9A-F]{2}:){31}[0-9A-F]{2}$/);
    expect(within(shown).getByTestId("enrol-once").textContent).toContain("This is the only time the token is shown");
    expect(shown.textContent).toContain("Then start the node process with the roles Probe, DNS");
    expect(await axeViolations(shown)).toEqual([]);

    // The server has the token with the roles, the name and the lifetime that were asked for.
    const stored = (await api.get("/api/v1/nodes/enrolments")).items.find((e) => e.name === "probe-office");
    expect(stored?.roles).toEqual(["probe", "dns"]);
    expect(stored?.state).toBe("pending");
    expect(Date.parse(stored?.expires_at ?? "") - Date.parse(stored?.created_at ?? "")).toBe(86_400_000);
  });

  it("copies the command and the token with their buttons and says so", async () => {
    const writeText = fakeClipboard();
    const { form } = await openDialog();
    fill("field-name", "probe-office");
    fireEvent.click(within(form).getByTestId("form-submit"));
    const shown = await screen.findByTestId("dialog-enrol-token");
    const command = within(shown).getByTestId("enrol-command").textContent;
    const token = within(shown).getByTestId("enrol-token").textContent;

    fireEvent.click(within(shown).getByTestId("nodes-copy-command"));
    await waitFor(() => expect(toastTitles()).toHaveLength(1));
    expect(writeText).toHaveBeenLastCalledWith(command);
    expect(toastTitles()[0]).toContain("Copied the");
    expect(screen.getAllByTestId("toast")[0]?.dataset.key).toBe("ok");

    fireEvent.click(within(shown).getByTestId("nodes-copy-token"));
    await waitFor(() => expect(toastTitles()).toHaveLength(2));
    expect(writeText).toHaveBeenLastCalledWith(token);
    expect(writeText).toHaveBeenCalledTimes(2);
  });

  it("tells the person when the browser does not allow copying", async () => {
    const writeText = fakeClipboard({ writable: false });
    const { form } = await openDialog();
    fireEvent.click(within(form).getByTestId("form-submit"));
    const shown = await screen.findByTestId("dialog-enrol-token");
    fireEvent.click(within(shown).getByTestId("nodes-copy-token"));
    await waitFor(() => expect(toastTitles()).toEqual(["The browser did not allow copying; select the text and copy it."]));
    expect(writeText).toHaveBeenCalledTimes(1);
    expect(screen.getByTestId("toast").dataset.key).toBe("bad");
  });

  it("forgets the token when the dialog is closed and lists the new token without its text", async () => {
    fakeClipboard();
    const { form } = await openDialog();
    fill("field-name", "probe-office");
    fireEvent.click(within(form).getByTestId("form-submit"));
    const shown = await screen.findByTestId("dialog-enrol-token");
    const token = within(shown).getByTestId("enrol-token").textContent ?? "";
    const secret = token.split(".")[2] ?? "";
    expect(secret).toHaveLength(43);

    // The list behind the dialog has the new token already.
    await waitFor(() => expect(tokens()).toHaveLength(2));
    fireEvent.click(within(shown).getByTestId("enrol-done"));
    await waitFor(() => expect(screen.queryByTestId("dialog-enrol-token")).toBeNull());
    expect(screen.queryByTestId("enrol-token")).toBeNull();
    expect(screen.queryByTestId("enrol-command")).toBeNull();

    // Newest first.
    expect(tokens().map((r) => r.dataset.state)).toEqual(["pending", "pending"]);
    const fresh = tokens()[0] as HTMLElement;
    expect(fresh.textContent).toContain("probe-office");
    expect(fresh.textContent).toContain("Probe");
    expect(fresh.textContent).not.toContain("tnk1.");
    expect(document.body.innerHTML).not.toContain(secret);
    expect(document.body.textContent).not.toContain(token);
    // The page keeps the list of nodes as it was.
    expect(names()).toEqual(["probe-dmz", "probe-lab"]);
  });

  it("creates a token without a name and with the default lifetime", async () => {
    const posted = recordPosts("/api/v1/nodes/enrolments");
    const { form } = await openDialog();
    fireEvent.click(within(form).getByTestId("form-submit"));
    await screen.findByTestId("dialog-enrol-token");
    expect(posted).toEqual([{ roles: ["probe"], name: null, vrf: null, expires_in_secs: 3600 }]);
    await waitFor(() => expect(tokens()).toHaveLength(2));
    expect(tokens()[0]?.textContent).toContain("chosen by the node");
  });

  it("offers the VRF choice when there are several VRFs", async () => {
    const posted = recordPosts("/api/v1/nodes/enrolments");
    const vrfs = await api.get("/api/v1/vrfs");
    await api.post("/api/v1/vrfs", { body: { name: "guests", tenant: null } as never });
    const all = await api.get("/api/v1/vrfs");
    expect(all.items.length).toBeGreaterThan(vrfs.items.length);
    const { form } = await openDialog();
    const select = (await screen.findByTestId("field-vrf")) as HTMLSelectElement;
    const guests = all.items.find((v) => v.name === "guests");
    expect(Array.from(select.options).map((o) => o.textContent)).toContain("guests");
    expect(select.options[0]?.textContent).toBe("The default VRF");
    fireEvent.change(select, { target: { value: guests?.id } });
    fireEvent.click(within(form).getByTestId("form-submit"));
    await screen.findByTestId("dialog-enrol-token");
    expect(posted).toEqual([{ roles: ["probe"], name: null, vrf: guests?.id, expires_in_secs: 3600 }]);
  });

  it("refuses a bad name at the field and sends nothing", async () => {
    const posted = recordPosts("/api/v1/nodes/enrolments");
    const { form } = await openDialog();
    fill("field-name", "-bad name");
    fireEvent.click(within(form).getByTestId("form-submit"));
    await waitFor(() => expect(fieldError("field-name")).toBe("1 to 63 letters, digits, dots, hyphens and underscores, starting with a letter or digit."));
    expect(screen.getByTestId("field-name").getAttribute("aria-invalid")).toBe("true");
    expect(posted).toEqual([]);
    expect(screen.queryByTestId("dialog-enrol-token")).toBeNull();
    expect(tokens()).toHaveLength(1);
    expect(await axeViolations(form)).toEqual([]);

    // A good name goes through.
    fill("field-name", "probe-office.example.test");
    fireEvent.click(within(form).getByTestId("form-submit"));
    await screen.findByTestId("dialog-enrol-token");
    expect(posted).toHaveLength(1);
  });

  it("refuses a token without a role and sends nothing", async () => {
    const posted = recordPosts("/api/v1/nodes/enrolments");
    const { form } = await openDialog();
    fireEvent.click(screen.getByTestId("field-role-probe"));
    fireEvent.click(within(form).getByTestId("form-submit"));
    const alert = await within(form).findByRole("alert");
    expect(alert.textContent).toContain("Choose at least one role.");
    expect(posted).toEqual([]);
    fireEvent.click(screen.getByTestId("field-role-dhcp"));
    await waitFor(() => expect(within(form).queryByRole("alert")).toBeNull());
  });

  it("shows the refusal of the server in the dialog and keeps the form", async () => {
    const { form } = await openDialog();
    fill("field-name", "probe-dmz");
    fireEvent.click(within(form).getByTestId("form-submit"));
    const alert = await within(form).findByRole("alert");
    expect(alert.textContent).toBe("Another node has this name.");
    expect(screen.queryByTestId("dialog-enrol-token")).toBeNull();
    expect((screen.getByTestId("field-name") as HTMLInputElement).value).toBe("probe-dmz");
    expect(tokens()).toHaveLength(1);
    // The refusal goes away with a new try.
    fill("field-name", "probe-office");
    fireEvent.click(within(form).getByTestId("form-submit"));
    await screen.findByTestId("dialog-enrol-token");
  });

  it("closes with Cancel and with Escape without creating anything", async () => {
    const posted = recordPosts("/api/v1/nodes/enrolments");
    const { form } = await openDialog();
    fireEvent.click(within(form).getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByTestId("dialog-enrol")).toBeNull());
    fireEvent.click(screen.getByTestId("nodes-enrol"));
    fireEvent.keyDown(await screen.findByTestId("dialog-enrol"), { key: "Escape" });
    await waitFor(() => expect(screen.queryByTestId("dialog-enrol")).toBeNull());
    expect(posted).toEqual([]);
    expect(tokens()).toHaveLength(1);
  });
});

describe("the page for an operator and a viewer", () => {
  it.each(["operator", "viewer"] as const)("shows the nodes to a %s, without tokens and without the buttons to enrol and revoke", async (role) => {
    await signInWithRole(role);
    const view = openNodes();
    await listed(2);
    await screen.findByTestId("nodes-cluster");
    expect(names()).toEqual(["probe-dmz", "probe-lab"]);
    expect(screen.queryByTestId("nodes-tokens")).toBeNull();
    expect(screen.queryByTestId("nodes-enrol")).toBeNull();
    expect(screen.queryByTestId("enrolment")).toBeNull();
    expect(screen.getByTestId("nodes-version-mismatch").textContent).toContain("probe-lab");
    expect(await axeViolations(view.container)).toEqual([]);
  });
});

describe("live updates", () => {
  it("drops a node that is revoked through the API and clears the notice about its protocol", async () => {
    stopBridge = bridgeMockEvents();
    openNodes();
    await listed(2);
    await screen.findByTestId("nodes-version-mismatch");
    expect((await call("DELETE", `/api/v1/nodes/${LAB}`)).status).toBe(204);
    await waitFor(() => expect(names()).toEqual(["probe-dmz"]), { timeout: 3000 });
    await waitFor(() => expect(screen.queryByTestId("nodes-version-mismatch")).toBeNull(), { timeout: 3000 });
    expect(screen.getByTestId("page-nodes").textContent).toContain("1 node, 1 connected");
  });

  it("lists a token that is created through the API", async () => {
    stopBridge = bridgeMockEvents();
    openNodes();
    await screen.findAllByTestId("enrolment");
    expect((await call("POST", "/api/v1/nodes/enrolments", { name: "probe-annex", roles: ["probe", "dhcp"] })).status).toBe(201);
    await waitFor(() => expect(tokens()).toHaveLength(2), { timeout: 3000 });
    expect(tokens()[0]?.textContent).toContain("probe-annex");
    expect(tokens()[0]?.textContent).toContain("Probe, DHCP");
  });

  it("shows a node that enrols through the API and the token that it used", async () => {
    stopBridge = bridgeMockEvents();
    openNodes();
    await listed(2);
    await screen.findAllByTestId("enrolment");
    const csr = "-----BEGIN CERTIFICATE REQUEST-----\nZXhhbXBsZQ==\n-----END CERTIFICATE REQUEST-----\n";
    const made = (await (await call("POST", "/api/v1/nodes/enrolments", { name: "probe-annex" })).json()) as { token: string };
    expect((await call("POST", "/api/v1/nodes/enrol", { token: made.token, csr, majors: [1] })).status).toBe(201);
    await listed(3);
    await waitFor(() => expect(tokenOf("probe-annex").dataset.state).toBe("used"), { timeout: 3000 });
  });

  it("follows a node that is revoked while its panel is open", async () => {
    stopBridge = bridgeMockEvents();
    openNodes(`/nodes/${LAB}`);
    const panel = await screen.findByTestId("node-panel");
    await within(panel).findByRole("heading", { name: "probe-lab" });
    await listed(2);
    expect((await call("DELETE", `/api/v1/nodes/${LAB}`)).status).toBe(204);
    await waitFor(() => expect(names()).toEqual(["probe-dmz"]), { timeout: 3000 });
    await waitFor(() => expect(screen.getByTestId("node-panel").textContent).toContain("The node is not enrolled."), { timeout: 3000 });
    // The panel no longer claims the node is there, and lets the person close it.
    expect(within(screen.getByTestId("node-panel")).queryByTestId("node-revoke")).toBeNull();
    expect(within(screen.getByTestId("node-panel")).getByRole("button", { name: "Close" })).toBeTruthy();
  });
});
