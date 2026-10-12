import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api, ANY_REVISION } from "../api/client";
import { HOST_IDS, INTERFACE_IDS, IPAM_IDS, ipamState } from "../api/mock/ipam/api";
import { server } from "../api/mock/node";
import { SEED_SECRET_VALUES } from "../api/mock/secrets-store";
import type { Address, Host, HostInput } from "../api/types";
import { paths } from "../app/paths";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { signInAlex } from "../auth/account/testkit";
import { applied, confirmPlan, recordWrites } from "../ipam/testkit";
import { connectTargets } from "./Connect";
import HostView from "./HostView";

beforeEach(async () => {
  // The Connect control remembers its choices per host in the browser.
  localStorage.clear();
  await signInAlex();
});

const MODE_DIALOG = "dialog-host-mode";
/** The links to the two addresses of gw; they name the VRF, as an address needs it. */
const ADDRESS_LINKS = [paths.address("192.0.2.1", IPAM_IDS.vrf.default), paths.address("2001:db8:0:10::1", IPAM_IDS.vrf.default)];

function renderHost(name: string) {
  return renderRoute(HostView, { url: paths.host(name), path: "/ipam/hosts/:fqdn" });
}

/** Renders the page and waits until the host, its interfaces and its addresses are there. */
async function openHost(name: string, interfaces = 1): Promise<ReturnType<typeof renderHost>> {
  const view = renderHost(name);
  await screen.findByTestId("host-modes");
  await waitFor(() => expect(interfaceRows()).toHaveLength(interfaces));
  return view;
}

function interfaceRows(): HTMLElement[] {
  return within(screen.getByTestId("grid-host-interfaces")).queryAllByTestId("row");
}

function cell(row: HTMLElement, column: string): string {
  return row.querySelector(`[data-col='${column}']`)?.textContent ?? "";
}

/** The mode word in the heading of the page. */
function headingMode(): string | undefined {
  return screen.getByRole("heading", { level: 1 }).querySelector(".mode")?.textContent ?? undefined;
}

/** The entry of the mode list that is marked as the current one. */
function currentMode(): HTMLElement | null {
  return within(screen.getByTestId("host-modes")).queryAllByRole("listitem").find((li) => li.getAttribute("aria-current") === "true") ?? null;
}

function stored(name: string) {
  return ipamState().data.host.get(HOST_IDS[name] as string);
}

async function createHost(body: HostInput): Promise<Host> {
  const made = await api.post("/api/v1/hosts", { body });
  return made.item as Host;
}

async function interfaceIdOf(host: Host): Promise<string> {
  const list = await api.get("/api/v1/hosts/{id}/interfaces", { path: { id: host.id } });
  return (list.items[0] as { id: string }).id;
}

async function addAddress(ip: string, iface: string): Promise<void> {
  await api.post("/api/v1/addresses", { body: { ip, interface: iface } });
}

async function patchInterface(id: string, body: { mac?: string | null; duid?: string | null }): Promise<void> {
  await api.patch("/api/v1/interfaces/{id}", { path: { id }, body, ifMatch: ANY_REVISION });
}

const warning = () => screen.queryByTestId("host-identifier-warning");

describe("the host page", () => {
  it("shows the name, the mode with what it means, the interfaces and the addresses", async () => {
    await patchInterface(INTERFACE_IDS.gw as string, { duid: "00:01:00:01:aa:bb:cc:dd" });
    await openHost("gw");

    const title = screen.getByRole("heading", { level: 1 });
    expect(title.querySelector(".hostname")?.textContent).toBe("gw");
    expect(headingMode()).toBe("static");
    expect(title.querySelector(".flag.locked")).toBeNull();
    expect(within(screen.getByRole("navigation", { name: "Where this host belongs" })).getByRole("link", { name: "Hosts" }).getAttribute("href")).toBe("/ipam/hosts");

    // The current mode is marked and explained; the other modes are listed with theirs.
    const current = currentMode();
    expect(current?.textContent).toContain("static");
    expect(current?.textContent).toContain("Only DNS follows. The device itself is configured by hand.");
    expect(current?.textContent).toContain("current");
    const modes = within(screen.getByTestId("host-modes")).getAllByRole("listitem");
    expect(modes.map((li) => li.querySelector(".mode")?.textContent)).toEqual(["reserved", "static", "dynamic", "unmanaged"]);
    expect(modes[0]?.textContent).toContain("An address change moves the DHCP reservation and updates DNS.");
    expect(modes[3]?.textContent).toContain("Tenko never touches this host.");
    expect(screen.queryByText(/The host is locked/)).toBeNull();

    // The interface with its MAC address, its DUID and both addresses.
    const [eth0] = interfaceRows() as [HTMLElement];
    expect(cell(eth0, "name")).toBe("eth0");
    expect(cell(eth0, "mac")).toBe("00:00:5e:00:53:01");
    expect(cell(eth0, "duid")).toBe("00010001aabbccdd");
    const links = within(eth0).getAllByRole("link", { hidden: true });
    expect(links.map((a) => a.textContent)).toEqual(["192.0.2.1", "2001:db8:0:10::1"]);
    expect(links.map((a) => a.getAttribute("href"))).toEqual(ADDRESS_LINKS);

    // The addresses of the host, with their DNS name and status.
    const section = document.querySelector("[aria-labelledby='host-addresses-title']") as HTMLElement;
    const addresses = [...section.querySelectorAll("li")];
    expect(addresses.map((li) => li.dataset.key)).toEqual(["192.0.2.1", "2001:db8:0:10::1"]);
    for (const li of addresses) {
      expect(li.textContent).toContain("gw.example.test");
      expect(li.textContent).toContain("Active");
    }
    expect(within(section).getAllByRole("link").map((a) => a.getAttribute("href"))).toEqual(ADDRESS_LINKS);
  });

  it("shows the lock in the heading and says what it means", async () => {
    await openHost("nas");
    expect(headingMode()).toBe("reserved");
    expect(screen.getByRole("heading", { level: 1 }).querySelector(".flag.locked")?.textContent).toBe("Locked");
    expect(screen.getByText("The host is locked: no automation touches it, whatever its mode.")).toBeTruthy();
    const lock = screen.getByTestId("host-lock");
    expect(lock.getAttribute("aria-pressed")).toBe("true");
    expect(lock.textContent).toContain("Unlock");
  });

  it("tells when no host has the name", async () => {
    renderHost("no-such-host");
    expect(await screen.findByText("No host named no-such-host.")).toBeTruthy();
    expect(screen.queryByTestId("host-modes")).toBeNull();
  });
});

describe("scan now", () => {
  it("offers a scan of the host that names it", async () => {
    await openHost("gw");
    fireEvent.click(await screen.findByTestId("scan-now"));
    const dialog = await screen.findByTestId("dialog-scan-now");
    expect(dialog.textContent).toContain("gw");
    fireEvent.click(within(dialog).getByTestId("scan-now-cancel"));
    await waitFor(() => expect(screen.queryByTestId("dialog-scan-now")).toBeNull());
  });

  it("starts the scan with the host as its target", async () => {
    const targets: unknown[] = [];
    server.use(
      http.post("/api/v1/scans", async ({ request }) => {
        targets.push(((await request.clone().json()) as { target: unknown }).target);
        return undefined;
      }),
    );
    await openHost("gw");
    fireEvent.click(await screen.findByTestId("scan-now"));
    fireEvent.click(within(await screen.findByTestId("dialog-scan-now")).getByTestId("scan-now-start"));
    await waitFor(() => expect(targets).toEqual([{ kind: "host", value: HOST_IDS.gw }]));
  });

  it("is not offered to a viewer", async () => {
    await signInAlex({ prepare: (user) => void (user.roles = ["viewer"] as never) });
    await openHost("gw");
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(screen.queryByTestId("scan-now")).toBeNull();
  });
});

describe("the warning for a reserved host without MAC address or DUID (IPAM-18)", () => {
  it("is shown for a reserved host whose interface has neither", async () => {
    await createHost({ name: "kiosk.example.test", mode: "reserved", interfaces: [{ name: "eth0" }] });
    await openHost("kiosk.example.test");
    const text = warning();
    expect(text).not.toBeNull();
    expect(text?.textContent).toMatch(/Add the MAC address so the DHCP reservation can be made/);
    const notice = text?.closest("[role='status']") as HTMLElement;
    expect(notice.textContent).toContain("No reservation possible:");
  });

  it("is not shown for a reserved host with a MAC address", async () => {
    await openHost("thermostat-1");
    expect(headingMode()).toBe("reserved");
    expect(cell(interfaceRows()[0] as HTMLElement, "mac")).toBe("00:00:5e:00:53:29");
    expect(warning()).toBeNull();
  });

  it("appears when the MAC address of the reserved host's IPv4 interface is removed", async () => {
    await patchInterface(INTERFACE_IDS["thermostat-1"] as string, { mac: null });
    await openHost("thermostat-1");
    expect(warning()?.textContent).toMatch(/interface of its IPv4 address has no MAC address/);
  });

  it("is not shown for a static host without a MAC address", async () => {
    await createHost({ name: "bench.example.test", mode: "static", interfaces: [{ name: "eth0" }] });
    await openHost("bench.example.test");
    expect(headingMode()).toBe("static");
    expect(warning()).toBeNull();
  });

  it("asks for the DUID when only the IPv6 address lacks an identifier", async () => {
    const host = await createHost({ name: "kiosk.example.test", mode: "reserved", interfaces: [{ name: "eth0", mac: "00:00:5e:00:53:70" }] });
    await addAddress("2001:db8:0:10::70", await interfaceIdOf(host));
    await openHost("kiosk.example.test");
    expect(warning()?.textContent).toMatch(/interface of its IPv6 address has no DUID/);
  });

  it("names both when neither the IPv4 nor the IPv6 address has its identifier", async () => {
    const host = await createHost({ name: "kiosk.example.test", mode: "reserved", interfaces: [{ name: "eth0" }] });
    const iface = await interfaceIdOf(host);
    await addAddress("192.0.2.70", iface);
    await addAddress("2001:db8:0:10::70", iface);
    await openHost("kiosk.example.test");
    expect(warning()?.textContent).toMatch(/neither a MAC address for IPv4 nor a DUID for IPv6/);
  });
});

describe("changing the mode", () => {
  async function chooseMode(mode: string): Promise<void> {
    fireEvent.click(screen.getByTestId("host-mode"));
    const menu = await screen.findByTestId("mode-menu");
    const item = menu.querySelector<HTMLElement>(`[data-item='${mode}']`);
    if (!item) throw new Error(`no menu item for the mode ${mode}`);
    fireEvent.click(item);
  }

  it("goes through the plan dialog and shows the new mode afterwards", async () => {
    const writes = recordWrites();
    await openHost("thermostat-1");
    expect(headingMode()).toBe("reserved");
    await chooseMode("static");

    const dialog = await screen.findByTestId(MODE_DIALOG);
    expect(within(dialog).getByRole("heading", { name: "Set thermostat-1 to static" })).toBeTruthy();
    // The dialog says what the new mode does, and the preview wrote nothing.
    expect(within(dialog).getByText("Only DNS follows. The device itself is configured by hand.")).toBeTruthy();
    await within(dialog).findByTestId("plan-preview");
    expect(stored("thermostat-1")?.mode).toBe("reserved");
    expect(applied(writes())).toHaveLength(0);
    const preview = writes().find((w) => w.method === "PATCH");
    expect(preview?.url).toContain(`/hosts/${HOST_IDS["thermostat-1"]}`);
    expect(preview?.url).toContain("dry_run=true");
    expect(preview?.body).toEqual({ mode: "static" });

    await confirmPlan({ dialog: MODE_DIALOG });
    await waitFor(() => expect(screen.queryByTestId(MODE_DIALOG)).toBeNull());
    expect(applied(writes())).toHaveLength(1);
    expect(stored("thermostat-1")?.mode).toBe("static");
    await waitFor(() => expect(headingMode()).toBe("static"));
    expect(currentMode()?.textContent).toContain("static");
    expect(await screen.findByText("thermostat-1 is now static")).toBeTruthy();
  });

  it("opens the mode menu with Shift+M and does not offer the current mode", async () => {
    await openHost("thermostat-1");
    fireEvent.keyDown(document.body, { key: "M", shiftKey: true });
    const menu = await screen.findByTestId("mode-menu");
    const items = [...menu.querySelectorAll<HTMLElement>("[data-item]")];
    expect(items.map((i) => i.dataset.item)).toEqual(["reserved", "static", "dynamic", "unmanaged"]);
    const disabled = items.filter((i) => i.getAttribute("aria-disabled") === "true");
    expect(disabled.map((i) => i.dataset.item)).toEqual(["reserved"]);
    expect(items[0]?.getAttribute("aria-checked")).toBe("true");
  });

  it("keeps the mode when the dialog is cancelled", async () => {
    const writes = recordWrites();
    await openHost("thermostat-1");
    await chooseMode("dynamic");
    const dialog = await screen.findByTestId(MODE_DIALOG);
    await within(dialog).findByTestId("plan-preview");
    fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByTestId(MODE_DIALOG)).toBeNull());
    expect(applied(writes())).toHaveLength(0);
    expect(stored("thermostat-1")?.mode).toBe("reserved");
    expect(headingMode()).toBe("reserved");
  });
});

describe("the lock", () => {
  it("locks the host, offers Undo in the toast, and Undo unlocks it again", async () => {
    await openHost("thermostat-1");
    const button = screen.getByTestId("host-lock");
    expect(button.getAttribute("aria-pressed")).toBe("false");
    expect(button.textContent).toContain("Lock");
    fireEvent.click(button);

    const toast = (await screen.findByText("thermostat-1 is locked")).closest(".toast") as HTMLElement;
    expect(stored("thermostat-1")?.lock).toBe(true);
    await waitFor(() => expect(screen.getByTestId("host-lock").getAttribute("aria-pressed")).toBe("true"));
    expect(screen.getByTestId("host-lock").textContent).toContain("Unlock");
    expect(screen.getByRole("heading", { level: 1 }).querySelector(".flag.locked")).not.toBeNull();
    expect(screen.getByText("The host is locked: no automation touches it, whatever its mode.")).toBeTruthy();

    fireEvent.click(within(toast).getByRole("button", { name: "Undo" }));
    await waitFor(() => expect(stored("thermostat-1")?.lock).toBe(false));
    await waitFor(() => expect(screen.getByTestId("host-lock").getAttribute("aria-pressed")).toBe("false"));
    expect(screen.getByRole("heading", { level: 1 }).querySelector(".flag.locked")).toBeNull();
    expect(screen.queryByText("The host is locked: no automation touches it, whatever its mode.")).toBeNull();
    // The toast is gone once its action ran.
    await waitFor(() => expect(screen.queryByText("thermostat-1 is locked")).toBeNull());
  });

  it("unlocks a locked host and offers Undo that locks it again", async () => {
    await openHost("nas");
    fireEvent.click(screen.getByTestId("host-lock"));
    const toast = (await screen.findByText("nas is unlocked")).closest(".toast") as HTMLElement;
    await waitFor(() => expect(stored("nas")?.lock).toBe(false));
    fireEvent.click(within(toast).getByRole("button", { name: "Undo" }));
    await waitFor(() => expect(stored("nas")?.lock).toBe(true));
  });

  it("toggles the lock with the L key", async () => {
    await openHost("thermostat-1");
    fireEvent.keyDown(document.body, { key: "l" });
    expect(await screen.findByText("thermostat-1 is locked")).toBeTruthy();
    expect(stored("thermostat-1")?.lock).toBe(true);
  });
});

describe("remote access hand-off", () => {
  const OBJECT_URL = "blob:https://tenko.example.test/0001";
  const REMOTE_PATH = /^\/api\/v1\/hosts\/([^/]+)\/remote$/;
  let blobs: Blob[];
  let downloads: { name: string; href: string }[];
  let clicked: HTMLAnchorElement[];
  /** The requests for a connection file or link that reached the API, as the server saw them. */
  let remote: { host: string; query: Record<string, string> }[];

  beforeEach(() => {
    blobs = [];
    downloads = [];
    clicked = [];
    remote = [];
    Object.defineProperty(URL, "createObjectURL", {
      configurable: true,
      writable: true,
      value: (blob: Blob) => {
        blobs.push(blob);
        return OBJECT_URL;
      },
    });
    Object.defineProperty(URL, "revokeObjectURL", { configurable: true, writable: true, value: () => undefined });
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (this: HTMLAnchorElement) {
      clicked.push(this);
      downloads.push({ name: this.download, href: this.getAttribute("href") ?? "" });
    });
    server.events.on("request:start", ({ request }) => {
      const url = new URL(request.url);
      const match = REMOTE_PATH.exec(url.pathname);
      if (match) remote.push({ host: match[1] as string, query: Object.fromEntries(url.searchParams) });
    });
  });

  afterEach(() => {
    server.events.removeAllListeners();
    Reflect.deleteProperty(URL, "createObjectURL");
    Reflect.deleteProperty(URL, "revokeObjectURL");
  });

  const connect = () => screen.getByTestId("host-connect");
  const rows = () => within(connect()).getAllByTestId("remote-target");
  const keys = () => rows().map((row) => row.dataset.key);
  const buttons = (kind: "rdp" | "ssh") => within(connect()).getAllByTestId(`host-${kind}`) as HTMLButtonElement[];
  const button = (kind: "rdp" | "ssh", index = 0) => buttons(kind)[index] as HTMLButtonElement;
  /** The inputs of the connect panel by their label; they are `field-user`, `field-rdp_port` and `field-ssh_port`. */
  const FIELD_IDS = { User: "field-user", "RDP port": "field-rdp_port", "SSH port": "field-ssh_port" } as const;
  const field = (label: keyof typeof FIELD_IDS) => within(connect()).getByTestId(FIELD_IDS[label]) as HTMLInputElement;

  function setField(label: keyof typeof FIELD_IDS, value: string): void {
    fireEvent.input(field(label), { target: { value } });
  }

  /** Presses a button and waits for the file or the link to be handed over; returns the lines of a file. */
  async function hand(kind: "rdp" | "ssh", index = 0): Promise<string[]> {
    const before = downloads.length;
    fireEvent.click(button(kind, index));
    await waitFor(() => expect(downloads).toHaveLength(before + 1));
    // The buttons are enabled again once the hand-off is done.
    await waitFor(() => expect(button(kind, index).disabled).toBe(false));
    return kind === "rdp" ? (await (blobs.at(-1) as Blob).text()).split("\r\n") : [];
  }

  /** The id of a host of the mock, for the path of the request. */
  const idOf = (name: string) => HOST_IDS[name] as string;

  /** A host with one interface and the given addresses, none of them with a DNS name. */
  async function hostWith(name: string, ips: string[]): Promise<Host> {
    const host = await createHost({ name, mode: "static", interfaces: [{ name: "eth0" }] });
    const iface = await interfaceIdOf(host);
    for (const ip of ips) await addAddress(ip, iface);
    return host;
  }

  /** Answers the connection requests with a problem. */
  function refuseRemote(): void {
    server.use(
      http.get("/api/v1/hosts/:id/remote", () =>
        HttpResponse.json(
          { type: "about:blank", title: "Unknown address", status: 400, code: "remote.address_unknown", detail: "", params: {} },
          { status: 400, headers: { "content-type": "application/problem+json" } },
        ),
      ),
    );
  }

  describe("the rows", () => {
    it("has a row with the DNS name for a host with one address, and the usual ports", async () => {
      await openHost("pve1");
      expect(keys()).toEqual(["pve1.example.test"]);
      const [row] = rows() as [HTMLElement];
      expect(row.textContent).toContain("pve1.example.test");
      expect(row.textContent).toContain("192.0.2.10");
      expect(button("rdp").dataset.key).toBe("pve1.example.test");
      expect(button("ssh").dataset.key).toBe("pve1.example.test");
      expect(button("rdp").disabled).toBe(false);
      expect(button("ssh").disabled).toBe(false);
      expect(field("User").value).toBe("");
      expect(field("RDP port").value).toBe("3389");
      expect(field("SSH port").value).toBe("22");
      // The ids belong to the inputs that the labels name.
      for (const label of Object.keys(FIELD_IDS) as (keyof typeof FIELD_IDS)[]) {
        expect(within(connect()).getByLabelText(label)).toBe(field(label));
      }
      // Nothing is asked of the server until a button is pressed.
      expect(remote).toEqual([]);
    });

    it("has a row for each address of the host, IPv4 first, each with its IP address", async () => {
      await openHost("gw");
      // Both addresses of gw have the DNS name gw.example.test, which is what the server gets for either.
      expect(keys()).toEqual(["gw.example.test", "gw.example.test"]);
      const [v4, v6] = rows() as [HTMLElement, HTMLElement];
      expect(v4.textContent).toContain("192.0.2.1");
      expect(v6.textContent).toContain("2001:db8:0:10::1");
      expect(v6.textContent).not.toContain("192.0.2.1");
      expect(buttons("rdp")).toHaveLength(2);
      expect(buttons("ssh")).toHaveLength(2);
    });

    it("lists an IPv4 address before an IPv6 address whatever the order they were made in, by IP address when there is no DNS name", async () => {
      await hostWith("dual.example.test", ["2001:db8:0:10::71", "192.0.2.71"]);
      await openHost("dual.example.test");
      await waitFor(() => expect(keys()).toEqual(["192.0.2.71", "2001:db8:0:10::71"]));
      expect(buttons("rdp").map((b) => b.dataset.key)).toEqual(["192.0.2.71", "2001:db8:0:10::71"]);
      expect(buttons("ssh").map((b) => b.dataset.key)).toEqual(["192.0.2.71", "2001:db8:0:10::71"]);
    });

    it("has one row with the host name for a host without addresses, and asks for no address", async () => {
      const host = await createHost({ name: "kiosk.example.test", mode: "static", interfaces: [{ name: "eth0" }] });
      await openHost("kiosk.example.test");
      expect(keys()).toEqual(["kiosk.example.test"]);
      expect(button("rdp").dataset.key).toBe("kiosk.example.test");
      expect(button("ssh").dataset.key).toBe("kiosk.example.test");

      const lines = await hand("rdp");
      expect(remote).toEqual([{ host: host.id, query: { protocol: "rdp" } }]);
      expect(lines[0]).toBe("full address:s:kiosk.example.test:3389");
    });

    it("leaves out a deleted address, and a host whose addresses are all deleted falls back to its name", () => {
      const gw = stored("gw") as Host;
      const [v4, v6] = [...ipamState().data.address.values()].filter((a) => a.interface === INTERFACE_IDS.gw) as [Address, Address];
      const gone = (a: Address): Address => ({ ...a, meta: { ...a.meta, deleted: a.meta.updated } });
      expect(connectTargets(gw, [v6, v4]).map((target) => target.ip)).toEqual([v4.ip, v6.ip]);
      expect(connectTargets(gw, [v4, gone(v6)]).map((target) => target.ip)).toEqual([v4.ip]);
      expect(connectTargets(gw, [gone(v4), gone(v6)])).toEqual([{ label: "gw" }]);
    });
  });

  describe("the .rdp file", () => {
    it("is the file the server makes, with the user name of the bound credential, saved as <host>.rdp", async () => {
      await openHost("nas");
      expect(keys()).toEqual(["nas.example.test"]);
      const lines = await hand("rdp");

      expect(remote).toEqual([{ host: idOf("nas"), query: { protocol: "rdp", address: "nas.example.test" } }]);
      expect(downloads).toEqual([{ name: "nas.rdp", href: OBJECT_URL }]);
      expect(blobs).toHaveLength(1);
      expect(blobs[0]?.type).toBe("application/x-rdp");
      expect(lines[0]).toBe("full address:s:nas.example.test:3389");
      expect(lines[1]).toBe("username:s:admin");
      expect(lines.at(-1)).toBe("");
      // The file holds no password.
      expect(lines.join("\r\n")).not.toContain(SEED_SECRET_VALUES.nasAdmin);
    });

    it("saves the text of the answer as it is", async () => {
      server.use(
        http.get(
          "/api/v1/hosts/:id/remote",
          () =>
            new HttpResponse("full address:s:other.example.test:4000\r\nusername:s:kept\r\n", {
              headers: { "content-type": "application/x-rdp" },
            }),
        ),
      );
      await openHost("nas");
      const lines = await hand("rdp");
      expect(lines).toEqual(["full address:s:other.example.test:4000", "username:s:kept", ""]);
    });

    it("has no user name when the host has no credential", async () => {
      await openHost("pve1");
      const lines = await hand("rdp");
      expect(lines[0]).toBe("full address:s:pve1.example.test:3389");
      expect(lines.some((line) => line.startsWith("username:"))).toBe(false);
      expect(downloads).toEqual([{ name: "pve1.rdp", href: OBJECT_URL }]);
    });

    it("sends the user and a changed RDP port with the request, and the file follows them", async () => {
      await openHost("nas");
      setField("User", "ops");
      setField("RDP port", "3390");
      const lines = await hand("rdp");

      expect(remote).toEqual([
        { host: idOf("nas"), query: { protocol: "rdp", address: "nas.example.test", port: "3390", user: "ops" } },
      ]);
      expect(lines[0]).toBe("full address:s:nas.example.test:3390");
      expect(lines[1]).toBe("username:s:ops");
    });

    it("sends the user without the spaces around it, and sends no user for a blank field and no port for the default", async () => {
      await openHost("nas");
      setField("User", "  ops  ");
      setField("RDP port", "3390");
      await hand("rdp");
      expect(remote.at(-1)?.query).toEqual({ protocol: "rdp", address: "nas.example.test", port: "3390", user: "ops" });

      setField("User", "   ");
      setField("RDP port", "3389");
      const lines = await hand("rdp");
      expect(remote.at(-1)?.query).toEqual({ protocol: "rdp", address: "nas.example.test" });
      // The bound credential speaks again when the field is blank.
      expect(lines[1]).toBe("username:s:admin");
    });

    it("connects to the address of the row that was pressed, an IPv6 address in brackets", async () => {
      await hostWith("dual.example.test", ["192.0.2.71", "2001:db8:0:10::71"]);
      await openHost("dual.example.test");
      await waitFor(() => expect(rows()).toHaveLength(2));

      const v6 = await hand("rdp", 1);
      expect(remote.at(-1)?.query).toEqual({ protocol: "rdp", address: "2001:db8:0:10::71" });
      expect(v6[0]).toBe("full address:s:[2001:db8:0:10::71]:3389");

      const v4 = await hand("rdp", 0);
      expect(remote.at(-1)?.query).toEqual({ protocol: "rdp", address: "192.0.2.71" });
      expect(v4[0]).toBe("full address:s:192.0.2.71:3389");
      expect(downloads.map((d) => d.name)).toEqual(["dual.example.test.rdp", "dual.example.test.rdp"]);
    });

    it("lets a viewer have the file, but without a user name from the vault", async () => {
      await signInAlex({
        prepare: (u) => {
          u.roles = ["viewer"];
        },
      });
      await openHost("nas");
      const lines = await hand("rdp");
      expect(lines[0]).toBe("full address:s:nas.example.test:3389");
      expect(lines.some((line) => line.startsWith("username:"))).toBe(false);

      setField("User", "ops");
      expect((await hand("rdp"))[1]).toBe("username:s:ops");
    });
  });

  describe("the ssh link", () => {
    it("is opened through a temporary link whose address is the URI of the server", async () => {
      await openHost("nas");
      await hand("ssh");

      expect(remote).toEqual([{ host: idOf("nas"), query: { protocol: "ssh", address: "nas.example.test" } }]);
      // An anchor without a download attribute: the operating system opens the link.
      expect(downloads).toEqual([{ name: "", href: "ssh://admin@nas.example.test" }]);
      expect(clicked[0]?.rel).toBe("noopener");
      expect(clicked[0]?.hasAttribute("download")).toBe(false);
      expect(blobs).toEqual([]);
      // The anchor is gone again, and the page has no ssh link of its own.
      expect(document.querySelector("a[href^='ssh:']")).toBeNull();
    });

    it("sends the user and a changed SSH port, and opens what the server builds from them", async () => {
      await openHost("nas");
      setField("User", "root");
      setField("SSH port", "2222");
      await hand("ssh");

      expect(remote).toEqual([
        { host: idOf("nas"), query: { protocol: "ssh", address: "nas.example.test", port: "2222", user: "root" } },
      ]);
      expect(downloads).toEqual([{ name: "", href: "ssh://root@nas.example.test:2222" }]);
    });

    it("leaves the port out at 22 and has no user name for a host without a credential", async () => {
      await openHost("pve1");
      setField("SSH port", "22");
      await hand("ssh");
      expect(remote).toEqual([{ host: idOf("pve1"), query: { protocol: "ssh", address: "pve1.example.test" } }]);
      expect(downloads).toEqual([{ name: "", href: "ssh://pve1.example.test" }]);
    });

    it("connects to the address of the row that was pressed, an IPv6 address in brackets", async () => {
      await hostWith("dual.example.test", ["192.0.2.71", "2001:db8:0:10::71"]);
      await openHost("dual.example.test");
      await waitFor(() => expect(rows()).toHaveLength(2));

      await hand("ssh", 1);
      expect(remote.at(-1)?.query).toEqual({ protocol: "ssh", address: "2001:db8:0:10::71" });
      await hand("ssh", 0);
      expect(remote.at(-1)?.query).toEqual({ protocol: "ssh", address: "192.0.2.71" });
      expect(downloads.map((d) => d.href)).toEqual(["ssh://[2001:db8:0:10::71]", "ssh://192.0.2.71"]);
    });

    it("keeps the ports of the two protocols apart", async () => {
      await openHost("nas");
      setField("RDP port", "3390");
      await hand("ssh");
      expect(remote.at(-1)?.query).toEqual({ protocol: "ssh", address: "nas.example.test" });
      setField("SSH port", "2222");
      await hand("rdp");
      expect(remote.at(-1)?.query).toEqual({ protocol: "rdp", address: "nas.example.test", port: "3390" });
    });
  });

  describe("invalid ports", () => {
    it("disable the buttons of that protocol in every row, and only those", async () => {
      await openHost("gw");
      setField("RDP port", "70000");
      expect(field("RDP port").getAttribute("aria-invalid")).toBe("true");
      expect(field("SSH port").getAttribute("aria-invalid")).toBeNull();
      expect(buttons("rdp").map((b) => b.disabled)).toEqual([true, true]);
      expect(buttons("ssh").map((b) => b.disabled)).toEqual([false, false]);

      setField("SSH port", "0");
      expect(field("SSH port").getAttribute("aria-invalid")).toBe("true");
      expect(buttons("rdp").map((b) => b.disabled)).toEqual([true, true]);
      expect(buttons("ssh").map((b) => b.disabled)).toEqual([true, true]);

      // A valid port enables them again.
      setField("RDP port", "3389");
      setField("SSH port", "22");
      expect(field("RDP port").getAttribute("aria-invalid")).toBeNull();
      expect(field("SSH port").getAttribute("aria-invalid")).toBeNull();
      expect(buttons("rdp").map((b) => b.disabled)).toEqual([false, false]);
      expect(buttons("ssh").map((b) => b.disabled)).toEqual([false, false]);
    });

    it("are an empty field, a number below 1 or above 65535, and a number with a fraction; 1 and 65535 are valid", async () => {
      await openHost("pve1");
      for (const bad of ["", "-1", "0", "65536", "22.5"]) {
        setField("SSH port", bad);
        expect(button("ssh").disabled, `port "${bad}"`).toBe(true);
        expect(field("SSH port").getAttribute("aria-invalid"), `port "${bad}"`).toBe("true");
      }
      for (const good of ["1", "65535"]) {
        setField("SSH port", good);
        expect(button("ssh").disabled, `port "${good}"`).toBe(false);
        expect(field("SSH port").getAttribute("aria-invalid"), `port "${good}"`).toBeNull();
      }
    });

    it("send no request when a disabled button is pressed", async () => {
      await openHost("pve1");
      setField("RDP port", "70000");
      setField("SSH port", "0");
      fireEvent.click(button("rdp"));
      fireEvent.click(button("ssh"));
      await new Promise((resolve) => setTimeout(resolve, 50));
      expect(remote).toEqual([]);
      expect(downloads).toEqual([]);
      expect(blobs).toEqual([]);
    });
  });

  describe("what is remembered", () => {
    const kept = (name: string) => JSON.parse(localStorage.getItem(`tenko-connect:${idOf(name)}`) ?? "{}") as unknown;

    it("is the user and the two ports, per host, in this browser", async () => {
      const first = await openHost("pve1");
      setField("User", "admin");
      setField("RDP port", "3390");
      setField("SSH port", "2222");
      await hand("rdp");
      expect(kept("pve1")).toEqual({ rdpPort: 3390, sshPort: 2222, user: "admin" });
      first.unmount();

      const second = await openHost("pve1");
      expect(field("User").value).toBe("admin");
      expect(field("RDP port").value).toBe("3390");
      expect(field("SSH port").value).toBe("2222");
      // What was remembered goes into the next request.
      await hand("ssh");
      expect(remote.at(-1)?.query).toEqual({ protocol: "ssh", address: "pve1.example.test", port: "2222", user: "admin" });
      second.unmount();

      // Another host has its own choice, and nothing is stored for it.
      await openHost("gw");
      expect(field("User").value).toBe("");
      expect(field("RDP port").value).toBe("3389");
      expect(field("SSH port").value).toBe("22");
      expect(localStorage.getItem(`tenko-connect:${idOf("gw")}`)).toBeNull();
    });

    it("is stored when a button is pressed, whether or not the request succeeds", async () => {
      refuseRemote();
      await openHost("nas");
      setField("User", "ops");
      setField("SSH port", "2222");
      fireEvent.click(button("ssh"));
      await screen.findByText("The connection file could not be made");
      expect(kept("nas")).toEqual({ rdpPort: 3389, sshPort: 2222, user: "ops" });
    });

    it("starts from what an earlier visit stored, and from the defaults when that is not JSON", async () => {
      localStorage.setItem(`tenko-connect:${idOf("pve1")}`, JSON.stringify({ rdpPort: 3390, sshPort: 2222, user: "ops" }));
      localStorage.setItem(`tenko-connect:${idOf("gw")}`, "{not json");
      const view = await openHost("pve1");
      expect(field("User").value).toBe("ops");
      expect(field("RDP port").value).toBe("3390");
      expect(field("SSH port").value).toBe("2222");
      view.unmount();

      await openHost("gw");
      expect(field("User").value).toBe("");
      expect(field("RDP port").value).toBe("3389");
      expect(field("SSH port").value).toBe("22");
    });

    it("starts from the defaults when the stored value is the JSON text null", async () => {
      localStorage.setItem(`tenko-connect:${idOf("gw")}`, "null");
      await openHost("gw");
      expect(field("RDP port").value).toBe("3389");
      expect(field("SSH port").value).toBe("22");
    });
  });

  describe("a failing request", () => {
    it.each(["rdp", "ssh"] as const)("shows a toast with the reason for %s and hands nothing over", async (kind) => {
      refuseRemote();
      await openHost("nas");
      fireEvent.click(button(kind));

      const title = await screen.findByText("The connection file could not be made");
      const toast = title.closest(".toast") as HTMLElement;
      expect(toast.dataset.key).toBe("bad");
      expect(within(toast).getByText("The address does not belong to this host.")).toBeTruthy();
      expect(remote).toHaveLength(1);
      expect(downloads).toEqual([]);
      expect(blobs).toEqual([]);
      // The buttons work again, so the person can try once more.
      await waitFor(() => expect(button(kind).disabled).toBe(false));
    });

    it("shows the generic message when the server fails without a reason", async () => {
      server.use(
        http.get("/api/v1/hosts/:id/remote", () =>
          HttpResponse.json(
            { type: "about:blank", title: "", status: 500, code: "remote.no_translation", detail: "", params: {} },
            { status: 500, headers: { "content-type": "application/problem+json" } },
          ),
        ),
      );
      await openHost("nas");
      fireEvent.click(button("rdp"));
      const title = await screen.findByText("The connection file could not be made");
      expect(within(title.closest(".toast") as HTMLElement).getByText(/could not complete the request/)).toBeTruthy();
      expect(downloads).toEqual([]);
    });
  });

  describe("while a request is under way", () => {
    it("disables every button of every row, and enables them when the answer is in", async () => {
      let release: () => void = () => undefined;
      const gate = new Promise<void>((resolve) => {
        release = resolve;
      });
      server.use(
        http.get("/api/v1/hosts/:id/remote", async () => {
          await gate;
          return new HttpResponse("full address:s:gw.example.test:3389\r\n", { headers: { "content-type": "application/x-rdp" } });
        }),
      );
      await openHost("gw");
      fireEvent.click(button("rdp", 0));
      await waitFor(() => expect(buttons("rdp").every((b) => b.disabled)).toBe(true));
      expect(buttons("ssh").every((b) => b.disabled)).toBe(true);
      // A second press while the first is under way asks for nothing more.
      fireEvent.click(button("rdp", 1));
      fireEvent.click(button("ssh", 0));
      await waitFor(() => expect(remote).toHaveLength(1));

      release();
      await waitFor(() => expect(downloads).toHaveLength(1));
      await waitFor(() => expect(buttons("rdp").some((b) => b.disabled)).toBe(false));
      expect(buttons("ssh").some((b) => b.disabled)).toBe(false);
      expect(remote).toHaveLength(1);
    });
  });
});

describe("the connect section", () => {
  const section = () => document.querySelector("[aria-labelledby='host-connect-title']") as HTMLElement;

  it("holds the remote access rows and then the credentials of the host", async () => {
    await openHost("nas");
    const credentials = await screen.findByTestId("host-credentials");
    expect([...section().children].map((el) => el.tagName)).toEqual(["H2", "DIV", "DIV"]);
    expect(section().children[1]).toBe(screen.getByTestId("host-connect"));
    expect(section().lastElementChild).toBe(credentials);
    await within(credentials).findByTestId("credential");
    expect(within(credentials).getAllByTestId("credential").map((row) => row.dataset.key)).toEqual(["nas admin"]);
    expect(within(screen.getByTestId("host-connect")).getAllByTestId("remote-target")).toHaveLength(1);
  });

  it("holds the remote access rows alone for a viewer, who gets no credentials section", async () => {
    await signInAlex({
      prepare: (u) => {
        u.roles = ["viewer"];
      },
    });
    await openHost("nas");
    await waitFor(() => expect(screen.queryByTestId("host-credentials")).toBeNull());
    expect([...section().children].map((el) => el.tagName)).toEqual(["H2", "DIV"]);
    expect(section().lastElementChild).toBe(screen.getByTestId("host-connect"));
    expect(within(screen.getByTestId("host-connect")).getAllByTestId("remote-target")).toHaveLength(1);
  });

  it("has no accessibility violations with the rows and the credentials", async () => {
    await openHost("nas");
    await within(screen.getByTestId("host-credentials")).findByTestId("credential");
    expect(await axeViolations(section())).toEqual([]);
  });
});

describe("accessibility", () => {
  it("has no violations on the loaded page", async () => {
    await openHost("gw");
    expect(await axeViolations(screen.getByTestId("page-host"))).toEqual([]);
  });

  it("has no violations on the page of a reserved host with the warning", async () => {
    await createHost({ name: "kiosk.example.test", mode: "reserved", interfaces: [{ name: "eth0" }] });
    await openHost("kiosk.example.test");
    expect(warning()).not.toBeNull();
    expect(await axeViolations(screen.getByTestId("page-host"))).toEqual([]);
  });
});
