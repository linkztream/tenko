// The Connect panel of the host page reads the `services` facts of the probe: which buttons and
// links it offers, what a disabled button says, the ports the fields start with and the line of
// open ports (docs/scanning.md, section 3).
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { beforeEach, describe, expect, it } from "vitest";
import { api } from "../api/client";
import { putServices } from "../api/mock/reconcile-store";
import type { Host } from "../api/types";
import { paths } from "../app/paths";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { signInAlex } from "../auth/account/testkit";
import { formatDateTime } from "../i18n";
import HostView from "./HostView";

beforeEach(async () => {
  localStorage.clear();
  await signInAlex();
});

/** A host with one interface and the given addresses, none of them with a DNS name. */
async function hostAt(name: string, ips: string[]): Promise<Host> {
  const made = await api.post("/api/v1/hosts", { body: { name, mode: "static", interfaces: [{ name: "eth0" }] } });
  const host = made.item as Host;
  const list = await api.get("/api/v1/hosts/{id}/interfaces", { path: { id: host.id } });
  const iface = (list.items[0] as { id: string }).id;
  for (const ip of ips) await api.post("/api/v1/addresses", { body: { ip, interface: iface } });
  return host;
}

/** Opens the page of a host and waits until the panel has read the open ports. */
async function open(name: string): Promise<HTMLElement> {
  renderRoute(HostView, { url: paths.host(name), path: "/ipam/hosts/:fqdn" });
  await screen.findByTestId("host-modes");
  await waitFor(() => expect(screen.queryByTestId("connect-loading")).toBeNull());
  return screen.getByTestId("host-connect");
}

const rdp = (panel: HTMLElement, index = 0) => within(panel).getAllByTestId("host-rdp")[index] as HTMLButtonElement;
const ssh = (panel: HTMLElement, index = 0) => within(panel).getAllByTestId("host-ssh")[index] as HTMLButtonElement;
const field = (panel: HTMLElement, id: "rdp_port" | "ssh_port") => within(panel).getByTestId(`field-${id}`) as HTMLInputElement;
const primary = (panel: HTMLElement) => within(panel).queryByTestId("web-primary") as HTMLAnchorElement | null;

describe("a host no scan has reached", () => {
  it("says so in one line with a link to the nodes, and offers neither a button nor a link", async () => {
    await hostAt("quiet.example.test", ["192.0.2.80"]);
    const panel = await open("quiet.example.test");
    const line = within(panel).getByTestId("connect-no-scan");
    expect(line.textContent).toContain("No port scan has reached this host yet.");
    expect(within(line).getByTestId("connect-scan-link").getAttribute("href")).toBe(paths.nodes());
    expect(within(panel).queryAllByTestId("host-rdp")).toEqual([]);
    expect(within(panel).queryAllByTestId("host-ssh")).toEqual([]);
    expect(within(panel).queryByTestId("connect-web")).toBeNull();
    expect(within(panel).queryByTestId("connect-ports")).toBeNull();
    // The fields stay, with the usual ports.
    expect(field(panel, "rdp_port").value).toBe("3389");
    expect(field(panel, "ssh_port").value).toBe("22");
    expect(within(panel).getByTestId("field-user")).toBeTruthy();
  });

  it("counts a fact that has expired as no fact", async () => {
    await hostAt("stale.example.test", ["192.0.2.81"]);
    putServices("192.0.2.81", [22, 3389], { expired: true });
    const panel = await open("stale.example.test");
    expect(within(panel).getByTestId("connect-no-scan")).toBeTruthy();
    expect(within(panel).queryAllByTestId("host-rdp")).toEqual([]);
  });
});

describe("a host with a services fact", () => {
  it("shows both buttons disabled, with the time of the last scan, when the fact has neither port", async () => {
    await hostAt("closed.example.test", ["192.0.2.82"]);
    const fact = putServices("192.0.2.82", [8000, 5900]);
    const panel = await open("closed.example.test");
    expect(within(panel).queryByTestId("connect-no-scan")).toBeNull();
    for (const [button, port] of [[rdp(panel), 3389], [ssh(panel), 22]] as const) {
      expect(button.disabled).toBe(true);
      expect(button.title).toContain(`Port ${port} was not seen open`);
      expect(button.title).toContain(formatDateTime(fact.last_seen));
    }
    expect(primary(panel)).toBeNull();
  });

  it("enables RDP alone when 3389 is open", async () => {
    await hostAt("win.example.test", ["192.0.2.83"]);
    putServices("192.0.2.83", [135, 3389]);
    const panel = await open("win.example.test");
    expect(rdp(panel).disabled).toBe(false);
    expect(rdp(panel).title).toBe("");
    expect(ssh(panel).disabled).toBe(true);
    expect(field(panel, "rdp_port").value).toBe("3389");
    expect(field(panel, "ssh_port").value).toBe("22");
  });

  it("starts the SSH port at 2222 when that is open and 22 is not, and the button follows", async () => {
    await hostAt("alt.example.test", ["192.0.2.84"]);
    putServices("192.0.2.84", [2222]);
    const panel = await open("alt.example.test");
    expect(field(panel, "ssh_port").value).toBe("2222");
    expect(ssh(panel).disabled).toBe(false);
    expect(rdp(panel).disabled).toBe(true);
    // Typing the closed usual port disables the button, as the field decides.
    fireEvent.input(field(panel, "ssh_port"), { target: { value: "22" } });
    expect(ssh(panel).disabled).toBe(true);
    expect(ssh(panel).title).toContain("Port 22 was not seen open");
  });

  it("keeps 22 when both are open, and keeps a port the operator remembered", async () => {
    const host = await hostAt("both.example.test", ["192.0.2.85"]);
    putServices("192.0.2.85", [22, 2222, 3389]);
    localStorage.setItem(`tenko-connect:${host.id}`, JSON.stringify({ sshPort: 2222 }));
    const panel = await open("both.example.test");
    expect(field(panel, "ssh_port").value).toBe("2222");
    expect(field(panel, "rdp_port").value).toBe("3389");
  });

  it("lists the open ports with the TLS mark and the time of the last scan", async () => {
    await hostAt("ports.example.test", ["192.0.2.86"]);
    const fact = putServices("192.0.2.86", [22, 443, 8006], { tls: [443] });
    const panel = await open("ports.example.test");
    const line = within(panel).getByTestId("connect-ports");
    expect(line.textContent).toMatch(/^Open at the last scan, .+: 22, 443 TLS, 8006$/);
    expect(line.title).toBe(formatDateTime(fact.last_seen));
    expect([...line.querySelectorAll("[data-port]")].map((el) => [el.getAttribute("data-port"), el.getAttribute("data-tls")])).toEqual([
      ["22", null],
      ["443", "true"],
      ["8006", null],
    ]);
  });

  it("says that nothing was open when the fact lists no port", async () => {
    await hostAt("none.example.test", ["192.0.2.87"]);
    putServices("192.0.2.87", []);
    const panel = await open("none.example.test");
    expect(within(panel).getByTestId("connect-ports").textContent).toMatch(/^No open port at the last scan, /);
    expect(rdp(panel).disabled).toBe(true);
  });

  it("marks an address no scan has reached in the row of a host with two addresses", async () => {
    await hostAt("two.example.test", ["192.0.2.88", "2001:db8:0:10::88"]);
    putServices("192.0.2.88", [22]);
    const panel = await open("two.example.test");
    const [v4, v6] = within(panel).getAllByTestId("remote-target") as [HTMLElement, HTMLElement];
    expect(within(v4).getByTestId("host-ssh")).toBeTruthy();
    expect(within(v6).queryByTestId("host-ssh")).toBeNull();
    expect(within(v6).getByTestId("connect-unscanned").textContent).toBe("Not scanned");
  });
});

describe("the web interface", () => {
  it("links HTTPS in a new tab without an opener when 443 is open, and offers no HTTP link", async () => {
    await hostAt("secure.example.test", ["192.0.2.90"]);
    putServices("192.0.2.90", [22, 443], { tls: [443] });
    const panel = await open("secure.example.test");
    const link = primary(panel) as HTMLAnchorElement;
    expect(link.getAttribute("href")).toBe("https://192.0.2.90/");
    expect(link.target).toBe("_blank");
    expect(link.rel).toBe("noopener noreferrer");
    expect(link.textContent).toBe("Web interface");
    expect(within(panel).queryByTestId("web-http")).toBeNull();
    expect(within(panel).queryByTestId("web-address")).toBeNull();
    expect(within(panel).queryByTestId("connect-web-more")).toBeNull();
  });

  it("links HTTP when only 80 is open", async () => {
    await hostAt("plain.example.test", ["192.0.2.91"]);
    putServices("192.0.2.91", [80]);
    const panel = await open("plain.example.test");
    const link = primary(panel) as HTMLAnchorElement;
    expect(link.getAttribute("href")).toBe("http://192.0.2.91/");
    expect(link.dataset.scheme).toBe("http");
    expect(within(panel).queryByTestId("web-http")).toBeNull();
  });

  it("makes HTTPS the button and HTTP a small link when both are open", async () => {
    await hostAt("web.example.test", ["192.0.2.92"]);
    putServices("192.0.2.92", [80, 443]);
    const panel = await open("web.example.test");
    expect((primary(panel) as HTMLAnchorElement).getAttribute("href")).toBe("https://192.0.2.92/");
    const http = within(panel).getByTestId("web-http") as HTMLAnchorElement;
    expect(http.getAttribute("href")).toBe("http://192.0.2.92/");
    expect(http.classList.contains("btn")).toBe(false);
    expect(http.target).toBe("_blank");
    expect(http.rel).toBe("noopener noreferrer");
  });

  it("lists the other web ports found open under More, each labelled by its port, and no guess beyond the fact", async () => {
    await hostAt("pve.example.test", ["192.0.2.93"]);
    putServices("192.0.2.93", [22, 8006, 8123, 8080, 9000], { tls: [8080] });
    const panel = await open("pve.example.test");
    // Neither 80 nor 443 is open: no primary button, only the list.
    expect(primary(panel)).toBeNull();
    const more = within(panel).getByTestId("connect-web-more");
    const links = within(more).getAllByTestId("web-more") as HTMLAnchorElement[];
    expect(links.map((a) => a.textContent)).toEqual(["8080", "8006", "8123"]);
    expect(links.map((a) => a.getAttribute("href"))).toEqual(["https://192.0.2.93:8080/", "https://192.0.2.93:8006/", "http://192.0.2.93:8123/"]);
    expect(links.every((a) => a.target === "_blank" && a.rel === "noopener noreferrer")).toBe(true);
  });

  it("shows More beside the primary button", async () => {
    await hostAt("both-web.example.test", ["192.0.2.94"]);
    putServices("192.0.2.94", [443, 8443]);
    const panel = await open("both-web.example.test");
    expect((primary(panel) as HTMLAnchorElement).getAttribute("href")).toBe("https://192.0.2.94/");
    expect(within(panel).getAllByTestId("web-more").map((a) => a.getAttribute("href"))).toEqual(["https://192.0.2.94:8443/"]);
  });

  it("uses the DNS name in the link and keeps the address as a fallback link", async () => {
    // pve1 of the mock has the DNS name pve1.example.test on 192.0.2.10.
    putServices("192.0.2.10", [22, 80, 443, 8006], { tls: [443] });
    const panel = await open("pve1");
    expect((primary(panel) as HTMLAnchorElement).getAttribute("href")).toBe("https://pve1.example.test/");
    expect(within(panel).getByTestId("web-http").getAttribute("href")).toBe("http://pve1.example.test/");
    expect(within(panel).getByTestId("web-address").getAttribute("href")).toBe("https://192.0.2.10/");
    expect(within(panel).getByTestId("web-more").getAttribute("href")).toBe("https://pve1.example.test:8006/");
  });

  it("opens the address whose 443 answered TLS, and writes an IPv6 address in brackets", async () => {
    await hostAt("dual-web.example.test", ["192.0.2.95", "2001:db8:0:10::95"]);
    putServices("192.0.2.95", [443]);
    putServices("2001:db8:0:10::95", [443], { tls: [443] });
    const panel = await open("dual-web.example.test");
    expect((primary(panel) as HTMLAnchorElement).getAttribute("href")).toBe("https://[2001:db8:0:10::95]/");
  });

  it("takes the first address, IPv4 first, when none answered TLS", async () => {
    await hostAt("dual-plain.example.test", ["2001:db8:0:10::96", "192.0.2.96"]);
    putServices("192.0.2.96", [443]);
    putServices("2001:db8:0:10::96", [443]);
    const panel = await open("dual-plain.example.test");
    expect((primary(panel) as HTMLAnchorElement).getAttribute("href")).toBe("https://192.0.2.96/");
  });

  it("is left out of a host without a web port", async () => {
    await hostAt("ssh-only.example.test", ["192.0.2.97"]);
    putServices("192.0.2.97", [22]);
    const panel = await open("ssh-only.example.test");
    expect(within(panel).queryByTestId("connect-web")).toBeNull();
    expect(within(panel).queryByTestId("connect-web-more")).toBeNull();
  });
});

describe("the panel", () => {
  it("has no accessibility violations with buttons, links and the line of ports", async () => {
    putServices("192.0.2.10", [22, 80, 443, 8006], { tls: [443] });
    const panel = await open("pve1");
    expect(await axeViolations(panel)).toEqual([]);
  });

  it("has no accessibility violations when no scan has reached the host", async () => {
    await hostAt("axe.example.test", ["192.0.2.98"]);
    const panel = await open("axe.example.test");
    expect(await axeViolations(panel)).toEqual([]);
  });
});
