import { fireEvent, render, screen, waitFor, within } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api, ANY_REVISION } from "../api/client";
import { HOST_IDS, INTERFACE_IDS, IPAM_IDS, ipamState } from "../api/mock/ipam/api";
import type { Host, HostInput } from "../api/types";
import { paths } from "../app/paths";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { signInAlex } from "../auth/account/testkit";
import { applied, confirmPlan, recordWrites } from "../ipam/testkit";
import { CredentialSlot } from "./credentials";
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
  let blobs: Blob[];
  let downloads: { name: string; href: string }[];

  beforeEach(() => {
    blobs = [];
    downloads = [];
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
      downloads.push({ name: this.download, href: this.getAttribute("href") ?? "" });
    });
  });

  afterEach(() => {
    Reflect.deleteProperty(URL, "createObjectURL");
    Reflect.deleteProperty(URL, "revokeObjectURL");
  });

  const textOf = (blob: Blob) => blob.text();

  const connect = () => screen.getByTestId("host-connect");
  const field = (label: string) => within(connect()).getByLabelText(label) as HTMLInputElement | HTMLSelectElement;

  function setField(label: string, value: string): void {
    const input = field(label);
    if (input instanceof HTMLSelectElement) fireEvent.change(input, { target: { value } });
    else fireEvent.input(input, { target: { value } });
  }

  it("offers RDP and SSH for a host with an address, with the usual ports", async () => {
    await openHost("pve1");
    const targets = [...(field("Connect to") as HTMLSelectElement).options].map((o) => o.value);
    // The DNS name comes first, then the addresses, then the host name.
    expect(targets).toEqual(["pve1.example.test", "192.0.2.10", "pve1"]);
    expect((field("RDP port") as HTMLInputElement).value).toBe("3389");
    expect((field("SSH port") as HTMLInputElement).value).toBe("22");
    const rdp = screen.getByTestId("host-rdp") as HTMLButtonElement;
    expect(rdp.disabled).toBe(false);
    expect(rdp.textContent).toContain("Remote desktop (.rdp)");
    expect(screen.getByTestId("host-ssh").getAttribute("href")).toBe("ssh://pve1.example.test");
  });

  it("hands over an .rdp file with the chosen address, port and user", async () => {
    await openHost("pve1");
    setField("Connect to", "192.0.2.10");
    setField("User", "admin");
    setField("RDP port", "3390");
    fireEvent.click(screen.getByTestId("host-rdp"));

    expect(downloads).toEqual([{ name: "pve1.rdp", href: OBJECT_URL }]);
    expect(blobs).toHaveLength(1);
    expect(blobs[0]?.type).toBe("application/x-rdp");
    const lines = (await textOf(blobs[0] as Blob)).split("\r\n");
    expect(lines[0]).toBe("full address:s:192.0.2.10:3390");
    expect(lines[1]).toBe("username:s:admin");
    expect(lines.at(-1)).toBe("");
  });

  it("brackets an IPv6 address in the .rdp file and the ssh link", async () => {
    await openHost("gw");
    setField("Connect to", "2001:db8:0:10::1");
    fireEvent.click(screen.getByTestId("host-rdp"));
    expect((await textOf(blobs[0] as Blob)).split("\r\n")[0]).toBe("full address:s:[2001:db8:0:10::1]:3389");
    expect(screen.getByTestId("host-ssh").getAttribute("href")).toBe("ssh://[2001:db8:0:10::1]");
  });

  it("builds the ssh link from the chosen address, port and user", async () => {
    await openHost("pve1");
    setField("Connect to", "192.0.2.10");
    expect(screen.getByTestId("host-ssh").getAttribute("href")).toBe("ssh://192.0.2.10");
    setField("SSH port", "2222");
    expect(screen.getByTestId("host-ssh").getAttribute("href")).toBe("ssh://192.0.2.10:2222");
    setField("User", "root");
    expect(screen.getByTestId("host-ssh").getAttribute("href")).toBe("ssh://root@192.0.2.10:2222");
    // Following the link downloads nothing: the operating system opens it.
    expect(downloads).toEqual([]);
  });

  it("refuses an invalid port: no .rdp button, no ssh link", async () => {
    await openHost("pve1");
    setField("RDP port", "70000");
    setField("SSH port", "0");
    expect(field("RDP port").getAttribute("aria-invalid")).toBe("true");
    expect(field("SSH port").getAttribute("aria-invalid")).toBe("true");
    expect((screen.getByTestId("host-rdp") as HTMLButtonElement).disabled).toBe(true);
    expect(screen.queryByTestId("host-ssh")).toBeNull();
    fireEvent.click(screen.getByTestId("host-rdp"));
    expect(blobs).toEqual([]);
  });

  it("remembers the choice for the host in this browser", async () => {
    const first = await openHost("pve1");
    setField("Connect to", "192.0.2.10");
    setField("User", "admin");
    setField("RDP port", "3390");
    fireEvent.click(screen.getByTestId("host-rdp"));
    expect(JSON.parse(localStorage.getItem(`tenko-connect:${HOST_IDS.pve1}`) ?? "{}")).toEqual({
      rdpPort: 3390,
      sshPort: 22,
      user: "admin",
      target: "192.0.2.10",
    });
    first.unmount();

    const second = await openHost("pve1");
    expect((field("Connect to") as HTMLSelectElement).value).toBe("192.0.2.10");
    expect((field("User") as HTMLInputElement).value).toBe("admin");
    expect((field("RDP port") as HTMLInputElement).value).toBe("3390");
    second.unmount();

    // Another host has its own choice.
    await openHost("gw");
    expect((field("Connect to") as HTMLSelectElement).value).toBe("gw.example.test");
    expect((field("User") as HTMLInputElement).value).toBe("");
    expect((field("RDP port") as HTMLInputElement).value).toBe("3389");
  });
});

describe("the credential slot", () => {
  it("renders nothing on its own", () => {
    const host = stored("gw") as Host;
    const { container } = render(() => <CredentialSlot host={host} />);
    expect(container.innerHTML).toBe("");
  });

  it("adds nothing to the connect section of the page", async () => {
    await openHost("gw");
    const section = document.querySelector("[aria-labelledby='host-connect-title']") as HTMLElement;
    expect(section).not.toBeNull();
    expect([...section.children].map((el) => el.tagName)).toEqual(["H2", "DIV"]);
    expect(section.lastElementChild).toBe(screen.getByTestId("host-connect"));
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
