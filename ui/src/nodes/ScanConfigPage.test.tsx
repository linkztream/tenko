import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { commit } from "../api/mock/db";
import { server } from "../api/mock/node";
import { NODE_IDS, nodesState } from "../api/mock/nodes-store";
import { probeConfigView, scansState } from "../api/mock/scans-store";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { bridgeMockEvents } from "../audit/testkit";
import { signInAlex } from "../auth/account/testkit";
import { setSessionForTest } from "../auth/session";
import { CONFIG_METHODS } from "../scans/model";
import ScanConfigPage from "./ScanConfigPage";

const DMZ = NODE_IDS.dmz;
const LAB = NODE_IDS.lab;

/** The page is rendered without the application shell, so its landmarks are missing. */
const NO_SHELL = { disable: ["region"] } as const;

let stopBridge: (() => void) | undefined;

beforeEach(async () => {
  await signInAlex();
});

afterEach(() => {
  stopBridge?.();
  stopBridge = undefined;
  setSessionForTest(null);
});

async function signInWithRole(role: "operator" | "viewer") {
  await signInAlex({
    prepare: (user) => {
      user.roles = [role];
    },
  });
}

function openPage(node: number | string = DMZ) {
  return renderRoute(ScanConfigPage, { url: `/nodes/${node}/scan`, path: "/nodes/:id/scan" });
}

/** The page with its first read done. */
async function openLoaded(node: number | string = DMZ) {
  const view = openPage(node);
  await screen.findByTestId("scan-config-form");
  return view;
}

const probe = (node = DMZ) => {
  const found = scansState().probes.get(node);
  if (!found) throw new Error(`no probe ${node}`);
  return found;
};
const field = (name: string) => screen.getByTestId(`field-${name}`) as HTMLInputElement & HTMLTextAreaElement & HTMLSelectElement;
const save = () => screen.getByTestId("scan-config-save") as HTMLButtonElement;
const text = (testid: string) => screen.getByTestId(testid).textContent ?? "";

function type(name: string, value: string) {
  fireEvent.input(field(name), { target: { value } });
}

function errorOf(name: string): string | undefined {
  const note = [...screen.queryAllByTestId("field-error")].find((e) => e.dataset.field === name || e.dataset.field?.startsWith(`${name}[`));
  return note?.textContent?.trim();
}

/** Records the bodies of the writes of the page and lets the mock answer. */
function recordPuts() {
  const bodies: { revision: string | null; body: unknown }[] = [];
  server.use(
    http.put("/api/v1/nodes/:id/scan-config", async ({ request }) => {
      bodies.push({ revision: request.headers.get("If-Match"), body: await request.clone().json() });
      return undefined;
    }),
  );
  return bodies;
}

/** A refusal the way the server words it. */
function refuse(status: number, code: string, errors: { field: string; code: string }[] = []) {
  server.use(
    http.put("/api/v1/nodes/:id/scan-config", () =>
      HttpResponse.json(
        { type: `about:blank#${code}`, status, code, title: code, detail: code, params: {}, errors },
        { status, headers: { "Content-Type": "application/problem+json" } },
      ),
    ),
  );
}

describe("the seeded configuration", () => {
  it("shows the node, the sync state, the applied scope, the kill switch and the form", async () => {
    await openLoaded();
    expect(screen.getByTestId("page-scan-config").dataset.node).toBe(String(DMZ));
    expect(screen.getByRole("heading", { level: 1 }).textContent).toContain("Scan configuration");
    expect(screen.getByRole("heading", { level: 1 }).textContent).toContain("probe-dmz");
    expect(screen.getByTestId("scan-config-back").getAttribute("href")).toBe(`/nodes/${DMZ}`);

    const sync = screen.getByTestId("scan-config-sync");
    expect(sync.dataset.sync).toBe("true");
    expect(sync.dataset.stored).toBe("true");
    expect(text("scan-sync-origin")).toBe("Set by an administrator");
    expect(text("scan-sync-revision")).toBe("2");

    const applied = screen.getByTestId("scan-config-applied");
    expect(within(applied).getByTestId("scan-applied-prefixes").textContent).toBe("203.0.113.128/26, 203.0.113.192/28");
    expect(within(applied).getByTestId("scan-applied-exclude").textContent).toBe("203.0.113.200");
    expect(within(applied).getByTestId("scan-applied-methods").textContent).toContain("ARP table");
    expect(within(applied).getByTestId("scan-applied-methods").textContent).not.toContain("SNMP");
    expect(within(applied).getByTestId("scan-applied-revision").textContent).toBe("2");

    const kill = screen.getByTestId("scan-kill-switch");
    expect(kill.dataset.state).toBe("running");
    expect(within(kill).getByTestId("scan-stop")).toBeTruthy();
    expect(within(kill).queryByTestId("scan-resume")).toBeNull();

    expect(field("prefixes").value).toBe("203.0.113.128/26\n203.0.113.192/28");
    expect(field("exclude").value).toBe("203.0.113.200");
    expect(field("concurrency").value).toBe("32");
    expect(field("rate").value).toBe("normal");
    expect(field("enabled").checked).toBe(true);
    expect(field("tcp_connect.ports").value).toBe("22, 53, 80, 443, 445, 3389, 8080");
    expect(save().disabled).toBe(true);
  });

  it("has a fieldset for every method, and marks the raw-socket ones", async () => {
    await openLoaded();
    for (const { key, raw } of CONFIG_METHODS) {
      const fieldset = screen.getByTestId(`method-${key}`);
      expect(fieldset.tagName).toBe("FIELDSET");
      expect(fieldset.dataset.raw).toBe(raw ? "true" : "false");
      expect(within(fieldset).queryByTestId(`method-${key}-raw`) !== null).toBe(raw);
      expect(within(fieldset).getByTestId(`field-${key}.enabled`)).toBeTruthy();
      expect(within(fieldset).getByTestId(`field-${key}.interval_secs`)).toBeTruthy();
    }
    expect(screen.getByTestId("method-lldp-raw").textContent).toContain("Needs raw sockets");
    expect(screen.getByTestId("method-dhcp_snoop-raw").textContent).toContain("Needs raw sockets");
    expect(screen.getByTestId("scan-group-methods").textContent).not.toContain("not implemented");
    for (const key of ["arp_sweep", "tcp_syn", "os_fingerprint"]) {
      expect(within(screen.getByTestId(`method-${key}`)).getByTestId(`field-${key}.timeout_ms`)).toBeTruthy();
    }
    for (const key of ["arp_sweep", "tcp_syn", "os_fingerprint", "lldp", "dhcp_snoop"]) {
      expect(within(screen.getByTestId(`method-${key}`)).getByTestId(`field-${key}.interface`)).toBeTruthy();
    }
    expect(field("lldp.listen_secs").value).toBe("35");
    expect(field("dhcp_snoop.listen_secs").value).toBe("120");
    expect(within(screen.getByTestId("method-lldp")).getByTestId("field-lldp.cdp")).toBeTruthy();
    expect(field("icmp.timeout_ms").value).toBe("1000");
    expect(within(screen.getByTestId("method-mdns")).getByTestId("field-mdns.group")).toBeTruthy();
    expect(within(screen.getByTestId("method-reverse_dns")).getByTestId("field-reverse_dns.servers")).toBeTruthy();
    expect(within(screen.getByTestId("method-snmp")).getByTestId("scan-devices-empty")).toBeTruthy();
  });

  it("shows a configuration the controllers do not hold yet as the defaults", async () => {
    probe().stored = false;
    probe().revision = null;
    probe().origin = null;
    probe().updatedAt = null;
    probe().updatedBy = null;
    await openLoaded();
    expect(screen.getByTestId("scan-config-sync").dataset.stored).toBe("false");
    expect(screen.getByTestId("scan-config-sync").textContent).toContain("runs on its own file");
  });

  it("warns about SNMP devices that lack a vault secret", async () => {
    probe().config.snmp.devices = [{ address: "192.0.2.2", port: 161, user: "tenko", auth: "sha256" }];
    server.use(
      http.get("/api/v1/nodes/:id/scan-config", () =>
        HttpResponse.json({ ...probeConfigView(probe()), lacking_secrets: ["192.0.2.2"] }, { headers: { ETag: '"2"' } }),
      ),
    );
    await openLoaded();
    expect(screen.getByTestId("scan-config-lacking").textContent).toContain("192.0.2.2");
    const row = screen.getByTestId("scan-device");
    expect(within(row).getByTestId("device-lacking")).toBeTruthy();
    expect((screen.getByTestId("device-user-0") as HTMLInputElement).value).toBe("tenko");
  });

  it("shows what the probe applies and the error of a configuration it could not apply", async () => {
    probe().inSync = false;
    probe().applied = { ...probe().applied!, error: "scan.config: unknown time zone", revision: 1 };
    server.use(http.get("/api/v1/nodes/:id/scan-config", () => HttpResponse.json(probeConfigView(probe()), { headers: { ETag: '"2"' } })));
    await openLoaded();
    expect(screen.getByTestId("scan-config-sync").dataset.sync).toBe("false");
    expect(screen.getByTestId("scan-applied-error").textContent).toContain("unknown time zone");
    expect(screen.getByTestId("scan-applied-revision").textContent).toBe("1");
  });
});

describe("saving", () => {
  it("saves an edit with the revision read, follows the new revision and is in sync after the next read", async () => {
    const puts = recordPuts();
    await openLoaded();
    type("concurrency", "16");
    expect(screen.getByTestId("scan-config-form").dataset.dirty).toBe("true");
    expect(save().disabled).toBe(false);
    fireEvent.click(save());

    await waitFor(() => expect(text("scan-sync-revision")).toBe("3"));
    expect(puts).toHaveLength(1);
    expect(puts[0]?.revision).toBe('"2"');
    expect((puts[0]?.body as { concurrency: number }).concurrency).toBe(16);
    expect(probe().config.concurrency).toBe(16);
    expect(probe().revision).toBe(3);
    await waitFor(() => expect(screen.getByTestId("scan-config-sync").dataset.sync).toBe("true"));
    await waitFor(() => expect(text("scan-applied-revision")).toBe("3"));
    expect(field("concurrency").value).toBe("16");
    expect(save().disabled).toBe(true);
    expect(screen.queryAllByTestId("toast").map((x) => x.textContent).join(" ")).toContain("Scan configuration saved");
  });

  it("sends the lists as lists and the SNMP devices without empty members", async () => {
    const puts = recordPuts();
    await openLoaded();
    type("prefixes", "203.0.113.128/26\n\n198.51.100.0/24 \n");
    type("tcp_connect.ports", "22, 443;8443");
    fireEvent.click(screen.getByTestId("device-add"));
    fireEvent.input(screen.getByTestId("device-address-0"), { target: { value: "192.0.2.2" } });
    fireEvent.input(screen.getByTestId("device-user-0"), { target: { value: "tenko" } });
    fireEvent.change(screen.getByTestId("device-auth-0"), { target: { value: "sha256" } });
    fireEvent.click(save());
    await waitFor(() => expect(puts).toHaveLength(1));
    const body = puts[0]?.body as {
      prefixes: string[];
      tcp_connect: { ports: number[] };
      snmp: { devices: Record<string, unknown>[] };
    };
    expect(body.prefixes).toEqual(["203.0.113.128/26", "198.51.100.0/24"]);
    expect(body.tcp_connect.ports).toEqual([22, 443, 8443]);
    expect(body.snmp.devices).toEqual([{ address: "192.0.2.2", port: 161, user: "tenko", auth: "sha256", context: "" }]);
    await waitFor(() => expect(probe().config.snmp.devices).toHaveLength(1));
  });

  it("sends the raw-socket method fields, an empty interface as null", async () => {
    const puts = recordPuts();
    await openLoaded();
    type("dhcp_snoop.interface", " eth1 ");
    type("dhcp_snoop.listen_secs", "60");
    type("tcp_syn.timeout_ms", "3000");
    type("lldp.interface", "");
    fireEvent.click(save());
    await waitFor(() => expect(puts).toHaveLength(1));
    const body = puts[0]?.body as {
      dhcp_snoop: { interface: string | null; listen_secs: number };
      tcp_syn: { timeout_ms: number; ports: (number | string)[] };
      lldp: { interface: string | null; cdp: boolean };
    };
    expect(body.dhcp_snoop).toMatchObject({ interface: "eth1", listen_secs: 60 });
    expect(body.tcp_syn.timeout_ms).toBe(3000);
    expect(body.tcp_syn.ports).toHaveLength(28);
    expect(body.lldp).toMatchObject({ interface: null, cdp: true });
  });

  it("refuses a bad prefix on the client, names the line and sends nothing", async () => {
    const puts = recordPuts();
    await openLoaded();
    type("prefixes", "203.0.113.128/26\nnot-a-prefix\n203.0.113.999/24");
    expect(errorOf("prefixes")).toBeUndefined();
    fireEvent.click(save());
    await waitFor(() => expect(errorOf("prefixes")).toContain("Not a valid prefix or address."));
    expect(errorOf("prefixes")).toContain("lines 2 and 3");
    expect(field("prefixes").getAttribute("aria-invalid")).toBe("true");
    expect(document.activeElement).toBe(field("prefixes"));
    expect(puts).toHaveLength(0);
    expect(probe().revision).toBe(2);
    // Fixing the line clears the error at once.
    type("prefixes", "203.0.113.128/26");
    expect(errorOf("prefixes")).toBeUndefined();
  });

  it("refuses numbers and ports that are out of range on the client", async () => {
    await openLoaded();
    type("concurrency", "0");
    type("tcp_connect.ports", "22, 70000, x");
    type("icmp.interval_secs", "");
    fireEvent.click(save());
    await waitFor(() => expect(errorOf("concurrency")).toBe("Enter a whole number within the allowed range."));
    expect(errorOf("tcp_connect.ports")).toContain("A port is a whole number from 1 to 65,535.");
    expect(errorOf("tcp_connect.ports")).toContain("entries 2 and 3");
    expect(errorOf("icmp.interval_secs")).toBe("Enter a whole number within the allowed range.");
  });

  it("maps the field errors of a server refusal to their fields and lists the ones it cannot place", async () => {
    await openLoaded();
    refuse(422, "node.config.invalid", [
      { field: "exclude[1]", code: "scans.config.cidr" },
      { field: "tcp_connect.ports[0]", code: "scans.config.port" },
      { field: "bogus", code: "scans.config.unknown" },
    ]);
    type("concurrency", "8");
    fireEvent.click(save());
    await waitFor(() => expect(errorOf("exclude")).toContain("Not a valid prefix or address."));
    expect(errorOf("exclude")).toContain("line 2");
    expect(errorOf("tcp_connect.ports")).toContain("A port is a whole number");
    const general = screen.getByTestId("scan-config-errors");
    expect(general.textContent).toContain("bogus");
    expect(general.textContent).toContain("The controllers do not know this setting.");
    // The draft is kept, and editing takes the server's errors away.
    expect(field("concurrency").value).toBe("8");
    type("concurrency", "9");
    expect(screen.queryByTestId("scan-config-errors")).toBeNull();
    expect(errorOf("exclude")).toBeUndefined();
  });

  it("shows other refusals as an error notice and keeps the draft", async () => {
    await openLoaded();
    refuse(503, "node.config.vault_unavailable");
    type("concurrency", "8");
    fireEvent.click(save());
    await waitFor(() => expect(screen.getByTestId("error-notice").dataset.code).toBe("node.config.vault_unavailable"));
    expect(field("concurrency").value).toBe("8");
  });

  it("says the configuration changed meanwhile after a 412 and reloads on request", async () => {
    await openLoaded();
    type("concurrency", "16");
    // Someone else saved a revision in the meantime; no event reaches the page.
    probe().config = { ...probe().config, concurrency: 64 };
    probe().revision = 3;
    fireEvent.click(save());
    const stale = await screen.findByTestId("scan-config-stale");
    expect(stale.textContent).toContain("changed meanwhile");
    expect(probe().config.concurrency).toBe(64);
    expect(field("concurrency").value).toBe("16");

    fireEvent.click(within(stale).getByTestId("scan-config-reload"));
    await waitFor(() => expect(screen.queryByTestId("scan-config-stale")).toBeNull());
    expect(field("concurrency").value).toBe("64");
    await waitFor(() => expect(text("scan-sync-revision")).toBe("3"));
    expect(save().disabled).toBe(true);
  });

  it("reverts the edits", async () => {
    await openLoaded();
    type("concurrency", "16");
    fireEvent.click(screen.getByTestId("scan-config-revert"));
    expect(field("concurrency").value).toBe("32");
    expect(save().disabled).toBe(true);
  });
});

describe("live changes", () => {
  it("takes a change from the server when nothing was edited", async () => {
    stopBridge = bridgeMockEvents();
    await openLoaded();
    probe().config = { ...probe().config, concurrency: 48 };
    probe().revision = 3;
    commit("discovery", { tables: ["scan.probe_config"] });
    await waitFor(() => expect(field("concurrency").value).toBe("48"));
    expect(text("scan-sync-revision")).toBe("3");
    expect(screen.queryByTestId("scan-config-remote")).toBeNull();
  });

  it("keeps unsaved edits and shows a note instead of overwriting them", async () => {
    stopBridge = bridgeMockEvents();
    await openLoaded();
    type("concurrency", "16");
    probe().config = { ...probe().config, concurrency: 48 };
    probe().revision = 3;
    commit("discovery", { tables: ["scan.probe_config"] });
    const note = await screen.findByTestId("scan-config-remote");
    expect(note.textContent).toContain("changed on the server");
    expect(field("concurrency").value).toBe("16");
    // The status cards follow the server at once.
    expect(text("scan-sync-revision")).toBe("3");

    fireEvent.click(within(note).getByTestId("scan-config-reload"));
    await waitFor(() => expect(screen.queryByTestId("scan-config-remote")).toBeNull());
    expect(field("concurrency").value).toBe("48");
  });

  it("does not disturb the edits when only the probe state changes", async () => {
    stopBridge = bridgeMockEvents();
    await openLoaded();
    type("concurrency", "16");
    probe().applied = { ...probe().applied!, methods: ["arp"] };
    commit("discovery", { tables: ["scan.scopes"] });
    await waitFor(() => expect(text("scan-applied-methods")).toBe("ARP table"));
    expect(field("concurrency").value).toBe("16");
    expect(screen.queryByTestId("scan-config-remote")).toBeNull();
  });
});

describe("the kill switch", () => {
  it("stops the probe with a reason and resumes it", async () => {
    await openLoaded();
    fireEvent.click(screen.getByTestId("scan-stop"));
    const dialog = await screen.findByTestId("dialog-stop-probe");
    fireEvent.input(within(dialog).getByTestId("field-reason"), { target: { value: " maintenance window " } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));

    await waitFor(() => expect(screen.getByTestId("scan-kill-switch").dataset.state).toBe("stopped"));
    expect(screen.queryByTestId("dialog-stop-probe")).toBeNull();
    expect(probe().killSwitch.stopped).toBe(true);
    expect(text("scan-ks-reason")).toBe("maintenance window");
    expect(screen.getByTestId("scan-ks-confirmed").dataset.confirmed).toBe("true");
    expect(screen.queryByTestId("scan-stop")).toBeNull();
    await waitFor(() => expect(text("scan-config-applied")).toContain("Methods"));

    fireEvent.click(screen.getByTestId("scan-resume"));
    await waitFor(() => expect(screen.getByTestId("scan-kill-switch").dataset.state).toBe("running"));
    expect(probe().killSwitch.stopped).toBe(false);
    expect(screen.getByTestId("scan-stop")).toBeTruthy();
    expect(screen.queryByTestId("scan-resume")).toBeNull();
  });

  it("stops without a reason when none is given", async () => {
    await openLoaded();
    fireEvent.click(screen.getByTestId("scan-stop"));
    const dialog = await screen.findByTestId("dialog-stop-probe");
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(screen.getByTestId("scan-kill-switch").dataset.state).toBe("stopped"));
    expect(text("scan-ks-reason")).toBe("stopped from the controllers");
  });

  it("shows a stop the probe has not confirmed", async () => {
    probe().killSwitch = { stopped: true, confirmed: false, reason: "offline test", at: new Date().toISOString(), by: null };
    await openLoaded();
    expect(screen.getByTestId("scan-ks-confirmed").dataset.confirmed).toBe("false");
    expect(text("scan-ks-confirmed")).toContain("Waiting for the probe");
  });

  it("closes the dialog with Escape and gives the focus back", async () => {
    await openLoaded();
    const opener = screen.getByTestId("scan-stop");
    opener.focus();
    fireEvent.click(opener);
    const dialog = await screen.findByTestId("dialog-stop-probe");
    await waitFor(() => expect(dialog.contains(document.activeElement)).toBe(true));
    expect(document.activeElement).toBe(within(dialog).getByTestId("field-reason"));
    fireEvent.keyDown(document.activeElement as HTMLElement, { key: "Escape" });
    await waitFor(() => expect(screen.queryByTestId("dialog-stop-probe")).toBeNull());
    expect(probe().killSwitch.stopped).toBe(false);
    expect(document.activeElement).toBe(opener);
  });

  it("keeps the focus inside the dialog when Tab leaves its last control", async () => {
    await openLoaded();
    fireEvent.click(screen.getByTestId("scan-stop"));
    const dialog = await screen.findByTestId("dialog-stop-probe");
    const submit = within(dialog).getByTestId("form-submit");
    submit.focus();
    fireEvent.keyDown(submit, { key: "Tab" });
    expect(document.activeElement).toBe(within(dialog).getByTestId("field-reason"));
    fireEvent.keyDown(within(dialog).getByTestId("field-reason"), { key: "Tab", shiftKey: true });
    expect(document.activeElement).toBe(submit);
  });

  it("refuses a reason that is too long", async () => {
    await openLoaded();
    fireEvent.click(screen.getByTestId("scan-stop"));
    const dialog = await screen.findByTestId("dialog-stop-probe");
    fireEvent.input(within(dialog).getByTestId("field-reason"), { target: { value: "x".repeat(201) } });
    expect(within(dialog).getByTestId("field-reason").getAttribute("aria-invalid")).toBe("true");
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    expect(probe().killSwitch.stopped).toBe(false);
  });
});

describe("who may change it", () => {
  it("lets a viewer read the configuration with every input disabled and no actions", async () => {
    await signInWithRole("viewer");
    await openLoaded();
    expect(screen.getByTestId("scan-config-readonly")).toBeTruthy();
    expect(screen.queryByTestId("scan-config-save")).toBeNull();
    expect(screen.queryByTestId("scan-stop")).toBeNull();
    expect(screen.queryByTestId("scan-resume")).toBeNull();
    expect(screen.queryByTestId("device-add")).toBeNull();
    const form = screen.getByTestId("scan-config-form");
    const inputs = form.querySelectorAll("input, select, textarea");
    expect(inputs.length).toBeGreaterThan(40);
    for (const input of inputs) expect(input.matches(":disabled")).toBe(true);
    expect(field("prefixes").value).toBe("203.0.113.128/26\n203.0.113.192/28");
  });

  it("treats an operator like a viewer here", async () => {
    await signInWithRole("operator");
    await openLoaded();
    expect(screen.queryByTestId("scan-config-save")).toBeNull();
    expect(field("concurrency").matches(":disabled")).toBe(true);
  });
});

describe("this controller's own probe role", () => {
  const OWN = 1;

  it("renders for the controller's id, which the node list does not contain, and leads back to the Nodes page", async () => {
    expect(nodesState().nodes.has(OWN)).toBe(false);
    await openLoaded(OWN);
    expect(screen.getByTestId("page-scan-config").dataset.node).toBe(String(OWN));
    expect(screen.getByRole("heading", { level: 1 }).textContent).toContain("ctl-1.example.test");
    expect(screen.getByTestId("scan-config-back").getAttribute("href")).toBe("/nodes");
    expect(field("prefixes").value).toBe("192.0.2.0/24\n2001:db8:0:10::/64");
    expect(screen.queryByTestId("scan-config-not-probe")).toBeNull();
    expect(screen.queryByTestId("error-notice")).toBeNull();
  });

  it("still shows the form when neither the probe list nor the node can be read", async () => {
    server.use(
      http.get("/api/v1/scans/probes", () => HttpResponse.json({ status: 503, code: "store.unavailable", title: "x", detail: "x" }, { status: 503, headers: { "Content-Type": "application/problem+json" } })),
    );
    await openLoaded(OWN);
    await waitFor(() => expect(screen.getByRole("heading", { level: 1 }).textContent).toContain("Node 1"));
    expect(screen.queryByTestId("scan-config-not-probe")).toBeNull();
  });
});

describe("a node that has no scan configuration", () => {
  it("shows a calm notice for a node without the probe role", async () => {
    const node = nodesState().nodes.get(LAB);
    if (!node) throw new Error("no lab node");
    node.roles = ["dns"];
    openPage(LAB);
    const notice = await screen.findByTestId("scan-config-not-probe");
    await waitFor(() => expect(notice.textContent).toContain("probe-lab does not have the probe role"));
    expect(notice.textContent).not.toContain("conflict");
    expect(screen.queryByTestId("scan-config-form")).toBeNull();
    expect(screen.queryByTestId("error-notice")).toBeNull();
    expect(screen.getByTestId("scan-config-back").getAttribute("href")).toBe(`/nodes/${LAB}`);
  });

  it("shows a calm notice for a node that does not exist", async () => {
    openPage(9999);
    const notice = await screen.findByTestId("scan-config-not-probe");
    expect(notice.textContent).toContain("No enrolled node has this id");
    expect(screen.queryByTestId("error-notice")).toBeNull();
  });

  it("shows a calm notice for an address that is no node id", async () => {
    openPage("abc");
    expect((await screen.findByTestId("scan-config-not-probe")).textContent).toContain("No enrolled node has this id");
  });
});

describe("the keyboard", () => {
  it("has a natural tab order: the scanner switch first, the save button last, no positive tabindex", async () => {
    await openLoaded();
    type("concurrency", "16");
    const form = screen.getByTestId("scan-config-form");
    const stops = [...form.querySelectorAll<HTMLElement>("a[href], button, input, select, textarea, [tabindex]")].filter((el) => !el.matches(":disabled"));
    expect(stops[0]).toBe(field("enabled"));
    expect(stops[stops.length - 1]).toBe(save());
    expect(stops.every((el) => !(el.tabIndex > 0))).toBe(true);
    const order = stops.map((el) => el.dataset.testid);
    expect(order.indexOf("field-prefixes")).toBeGreaterThan(order.indexOf("field-timezone"));
    expect(order.indexOf("field-arp.enabled")).toBeGreaterThan(order.indexOf("field-blackout"));
    expect(order.indexOf("field-arp.enabled")).toBeLessThan(order.indexOf("field-tcp_connect.ports"));
    expect(order.indexOf("field-tcp_connect.ports")).toBeLessThan(order.indexOf("field-snmp.retries"));
  });

  it("adds a device, moves the focus to it and removes it again", async () => {
    await openLoaded();
    fireEvent.click(screen.getByTestId("device-add"));
    await waitFor(() => expect(document.activeElement).toBe(screen.getByTestId("device-address-0")));
    expect(screen.getAllByTestId("scan-device")).toHaveLength(1);
    fireEvent.click(screen.getByTestId("device-add"));
    expect(screen.getAllByTestId("scan-device")).toHaveLength(2);
    fireEvent.click(screen.getByTestId("device-remove-0"));
    expect(screen.getAllByTestId("scan-device")).toHaveLength(1);
    // A blank device is refused on the client: it has no address.
    fireEvent.click(save());
    await waitFor(() => expect(screen.getAllByTestId("field-error").length).toBeGreaterThan(0));
    expect(screen.getAllByTestId("field-error")[0]?.dataset.field).toBe("snmp.devices[0].address");
    expect(document.activeElement).toBe(screen.getByTestId("device-address-0"));
  });
});

describe("accessibility", () => {
  it("has no axe violations on the page", async () => {
    const { container } = await openLoaded();
    expect(await axeViolations(container)).toEqual([]);
  });

  it("has no axe violations with SNMP devices, errors and the notes shown", async () => {
    probe().config.snmp.devices = [{ address: "192.0.2.2", port: 161, user: "tenko", auth: "sha256" }];
    const { container } = await openLoaded();
    type("prefixes", "bad");
    fireEvent.click(screen.getByTestId("device-add"));
    fireEvent.click(save());
    await waitFor(() => expect(screen.getAllByTestId("field-error").length).toBeGreaterThan(1));
    expect(await axeViolations(container)).toEqual([]);
  });

  it("has no axe violations for a viewer", async () => {
    await signInWithRole("viewer");
    const { container } = await openLoaded();
    expect(await axeViolations(container)).toEqual([]);
  });

  it("has no axe violations with the stop dialog open", async () => {
    await openLoaded();
    fireEvent.click(screen.getByTestId("scan-stop"));
    await screen.findByTestId("dialog-stop-probe");
    expect(await axeViolations(document.body, NO_SHELL)).toEqual([]);
  });

  it("has no axe violations on the notice of a node without the probe role", async () => {
    const node = nodesState().nodes.get(LAB);
    if (node) node.roles = ["dns"];
    const { container } = openPage(LAB);
    await screen.findByTestId("scan-config-not-probe");
    expect(await axeViolations(container)).toEqual([]);
  });
});
