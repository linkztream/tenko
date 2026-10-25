// The leases with DHCPv6 beside DHCPv4 (WP9.4): the family filter in the URL and in the request, the
// DUID filter, a DHCPv6 row with its DUID and IAID, the kind column, the link from a lease to the
// client's lease of the other family (both ways, and none for a client without a MAC address), the
// name of a DHCPv6 lease, the release of a DHCPv6 lease, no reserve action for it, the status
// strip with both families, the live strip of a DHCPv6 scope with a pool too big to count, Swedish.
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DHCP_IDS } from "../../api/mock/dhcp-model";
import { server } from "../../api/mock/node";
import { dhcpLeaseState } from "../../api/mock/routes-dhcp-leases";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { signInAlex } from "../../auth/account/testkit";
import { setSessionForTest } from "../../auth/session";
import { setLocale } from "../../i18n";
import { cell, recordWrites, row, rowAction, rowActions, rows } from "../testkit";
import LeasesPage from "./LeasesPage";

beforeEach(async () => {
  await signInAlex();
});

afterEach(async () => {
  vi.restoreAllMocks();
  setSessionForTest(null);
  await setLocale("en");
});

const GRID = "dhcp-leases";
const V6 = ["2001:db8:0:10::100", "2001:db8:0:10::101", "2001:db8:0:10::102", "2001:db8:0:10::103"];
const open = (url = "/dhcp/leases") => renderRoute(LeasesPage, { url, path: "/dhcp/leases" });
const loaded = () => waitFor(() => expect(rows(GRID).length).toBeGreaterThan(0));
const keys = () => rows(GRID).map((r) => r.dataset.key ?? "");

function leaseReads(spy: { mock: { calls: unknown[][] } }): URL[] {
  return spy.mock.calls.map(([url]) => new URL(String(url), "http://localhost")).filter((url) => url.pathname === "/api/v1/dhcp/leases");
}

/** The lease the mock holds at `addr`, to arrange it. */
function held(addr: string) {
  const found = dhcpLeaseState().leases.find((l) => l.addr === addr);
  if (!found) throw new Error(`no lease at ${addr}`);
  return found;
}

describe("the family filter", () => {
  it("lists both families, DHCPv4 first, each row with its family", async () => {
    const view = open();
    await loaded();
    expect(keys().slice(12)).toEqual(V6);
    expect(within(row(GRID, "192.0.2.100")).getByTestId("lease-family").textContent).toBe("DHCPv4");
    expect(within(row(GRID, V6[0]!)).getByTestId("lease-family").textContent).toBe("DHCPv6");
    expect(within(row(GRID, V6[0]!)).getByTestId("lease-family").dataset.key).toBe("v6");
    expect((screen.getByTestId("filter-family") as HTMLSelectElement).value).toBe("");
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("sends the family as a query parameter and keeps it in the URL", async () => {
    const spy = vi.spyOn(globalThis, "fetch");
    const view = open();
    await loaded();
    expect(leaseReads(spy).at(-1)!.searchParams.get("family")).toBeNull();

    fireEvent.change(screen.getByTestId("filter-family"), { target: { value: "v6" } });
    await waitFor(() => expect(leaseReads(spy).at(-1)!.searchParams.get("family")).toBe("v6"));
    await waitFor(() => expect(keys()).toEqual(V6));
    expect(view.location()).toContain("family=v6");

    fireEvent.change(screen.getByTestId("filter-family"), { target: { value: "v4" } });
    await waitFor(() => expect(leaseReads(spy).at(-1)!.searchParams.get("family")).toBe("v4"));
    await waitFor(() => expect(rows(GRID)).toHaveLength(12));
    expect(keys().every((k) => !k.includes(":"))).toBe(true);

    fireEvent.change(screen.getByTestId("filter-family"), { target: { value: "" } });
    await waitFor(() => expect(leaseReads(spy).at(-1)!.searchParams.get("family")).toBeNull());
    expect(view.location()).not.toContain("family");
  });

  it("takes the family from the link", async () => {
    const spy = vi.spyOn(globalThis, "fetch");
    open("/dhcp/leases?family=v6");
    await waitFor(() => expect(keys()).toEqual(V6));
    expect((screen.getByTestId("filter-family") as HTMLSelectElement).value).toBe("v6");
    expect(leaseReads(spy).at(-1)!.searchParams.get("family")).toBe("v6");
    expect(screen.getByTestId("leases-reset")).toBeTruthy();
  });

  it("ignores a family that is none", async () => {
    const spy = vi.spyOn(globalThis, "fetch");
    open("/dhcp/leases?family=v5");
    await loaded();
    expect(leaseReads(spy).at(-1)!.searchParams.get("family")).toBeNull();
    expect(rows(GRID)).toHaveLength(16);
  });

  it("resets the family with the other filters", async () => {
    const view = open("/dhcp/leases?family=v6");
    await waitFor(() => expect(keys()).toEqual(V6));
    fireEvent.click(screen.getByTestId("leases-reset"));
    await waitFor(() => expect(rows(GRID)).toHaveLength(16));
    expect(view.location()).not.toContain("family");
  });
});

describe("the DUID filter", () => {
  it("sends the DUID as typed and shows the leases of that client", async () => {
    const spy = vi.spyOn(globalThis, "fetch");
    const view = open();
    await loaded();
    fireEvent.change(screen.getByTestId("filter-duid"), { target: { value: "00:03:00:01:00:00:5e:00:53:10" } });
    await waitFor(() => expect(leaseReads(spy).at(-1)!.searchParams.get("duid")).toBe("00:03:00:01:00:00:5e:00:53:10"));
    await waitFor(() => expect(keys()).toEqual([V6[0]]));
    expect(view.location()).toContain("duid=");
  });

  it("points at a text that is no DUID and shows what the server answers", async () => {
    open("/dhcp/leases?duid=xyz");
    expect((await screen.findByTestId("field-error")).dataset.field).toBe("duid");
    expect(screen.getByTestId("field-error").textContent).toBe("That is not a DUID: use hexadecimal digits in pairs, with or without colons.");
    expect(await screen.findByTestId("error-notice")).toBeTruthy();
  });

  it("takes an odd number of digits for none", async () => {
    open("/dhcp/leases?duid=000");
    expect((await screen.findByTestId("field-error")).dataset.field).toBe("duid");
  });
});

describe("a DHCPv6 row", () => {
  it("shows the MAC address of its DUID, the DUID, the IAID, the kind, the FQDN and the relay link address", async () => {
    open();
    await loaded();
    const r = row(GRID, V6[0]!);
    expect(cell(r, "mac").textContent).toBe("00:00:5e:00:53:10");
    const duid = within(r).getByTestId("lease-duid");
    expect(duid.textContent).toBe("00:03:00:01:00:00:5e:00:53:10");
    expect(duid.getAttribute("title")).toBe("00:03:00:01:00:00:5e:00:53:10");
    expect(within(r).getByTestId("lease-iaid").textContent).toBe("IAID 1");
    expect(within(r).getByTestId("lease-kind").textContent).toBe("Address");
    expect(within(r).getByTestId("lease-kind").dataset.key).toBe("address");
    expect(cell(r, "name").textContent).toBe("pc-1.example.net");
    expect(cell(r, "relay").textContent).toBe("2001:db8:0:10::1");
    await waitFor(() => expect(cell(r, "scope").textContent).toBe("2001:db8:0:10::/64"));
    expect(within(r).getByTestId("lease-state").dataset.key).toBe("active");
    // A DHCPv4 row has no DUID, and its kind is an address too.
    const v4 = row(GRID, "192.0.2.100");
    expect(within(v4).queryByTestId("lease-duid")).toBeNull();
    expect(within(v4).getByTestId("lease-kind").textContent).toBe("Address");
  });

  it("cuts a long DUID in the middle and keeps the whole of it in the title", async () => {
    held(V6[1]!).duid = "0004" + "00112233445566778899aabbccddeeff";
    open();
    await loaded();
    const duid = within(row(GRID, V6[1]!)).getByTestId("lease-duid");
    expect(duid.textContent).toBe("00:04:00:11:22:33…cc:dd:ee:ff");
    expect(duid.getAttribute("title")).toBe("00:04:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff");
  });

  it("shows no MAC address for a DUID that holds none, and no peer", async () => {
    open();
    await loaded();
    const r = row(GRID, V6[1]!);
    expect(cell(r, "mac").textContent).toBe("");
    expect(within(r).getByTestId("lease-duid").textContent).toBe("00:02:00:00:00:09:0c:0c:0c:0c:01");
    expect(within(r).queryByTestId("lease-peer")).toBeNull();
  });

  it("shows a delegated prefix with its length and the word Prefix", async () => {
    const lease = held(V6[2]!);
    lease.kind = "pd";
    lease.addr = "2001:db8:1::";
    lease.prefix_len = 56;
    open();
    await loaded();
    const r = row(GRID, "2001:db8:1::");
    expect(within(r).getByTestId("lease-kind").textContent).toBe("Prefix");
    expect(within(r).getByTestId("lease-kind").dataset.key).toBe("prefix");
    expect(within(r).getByTestId("lease-history-link").textContent).toBe("2001:db8:1::/56");
    // The history link still names the address of the row.
    expect(within(r).getByTestId("lease-history-link").getAttribute("href")).toContain("2001%3Adb8%3A1%3A%3A");
  });

  it("links an address to its history", async () => {
    open();
    await loaded();
    const href = within(row(GRID, V6[0]!)).getByTestId("lease-history-link").getAttribute("href")!;
    expect(new URL(href, "http://localhost").searchParams.get("addr")).toBe(V6[0]);
  });
});

describe("the lease of the same client in the other family", () => {
  const peerHrefOf = (r: HTMLElement) => new URL(within(r).getByTestId("lease-peer-link").getAttribute("href")!, "http://localhost");

  it("links a DHCPv6 lease to the DHCPv4 lease of the client", async () => {
    open();
    await loaded();
    const r = row(GRID, V6[0]!);
    const peer = within(r).getByTestId("lease-peer");
    expect(peer.dataset.family).toBe("v4");
    expect(peer.textContent).toBe("Also DHCPv4: 192.0.2.100");
    expect(within(r).getByTestId("lease-peer-link").textContent).toBe("192.0.2.100");
    expect(peerHrefOf(r).pathname).toBe("/dhcp/leases");
    expect(peerHrefOf(r).searchParams.get("addr")).toBe("192.0.2.100");
  });

  it("links a DHCPv4 lease to the DHCPv6 lease of the client", async () => {
    open();
    await loaded();
    const r = row(GRID, "192.0.2.100");
    expect(within(r).getByTestId("lease-peer").textContent).toBe("Also DHCPv6: 2001:db8:0:10::100");
    expect(peerHrefOf(r).searchParams.get("addr")).toBe(V6[0]);
    expect(within(row(GRID, "192.0.2.102")).getByTestId("lease-peer-link").textContent).toBe(V6[2]);
    // The client of 192.0.2.101 has no DHCPv6 lease.
    expect(within(row(GRID, "192.0.2.101")).queryByTestId("lease-peer")).toBeNull();
  });

  it("follows the link to the list narrowed to the address", async () => {
    const view = open();
    await loaded();
    fireEvent.click(within(row(GRID, V6[0]!)).getByTestId("lease-peer-link"));
    await waitFor(() => expect(keys()).toEqual(["192.0.2.100"]));
    expect(new URL(view.location(), "http://localhost").searchParams.get("addr")).toBe("192.0.2.100");
    expect((screen.getByTestId("filter-addr") as HTMLInputElement).value).toBe("192.0.2.100");
  });

  it("says when the other lease is not active", async () => {
    const lease = held(V6[0]!);
    lease.state = "expired";
    lease.ends = new Date(Date.now() - 3_600_000).toISOString();
    open();
    await loaded();
    const peer = within(row(GRID, "192.0.2.100")).getByTestId("lease-peer");
    expect(peer.dataset.state).toBe("expired");
    expect(peer.textContent).toBe("Also DHCPv6: 2001:db8:0:10::100 (Expired)");
  });

  it("takes the active lease of the other family before one that ends later", async () => {
    // A second, expired DHCPv6 lease of the same client that ends later than the active one.
    const copy = { ...held(V6[0]!), addr: "2001:db8:0:10::1ff", state: "expired" as const, ends: new Date(Date.now() + 86_400_000).toISOString() };
    dhcpLeaseState().leases.push(copy);
    open();
    await loaded();
    expect(within(row(GRID, "192.0.2.100")).getByTestId("lease-peer-link").textContent).toBe(V6[0]);
  });

  it("is a column that can be read as text", async () => {
    open();
    await loaded();
    expect(cell(row(GRID, "192.0.2.102"), "peer").textContent).toBe("Also DHCPv6: 2001:db8:0:10::102");
  });
});

describe("the row menu of a DHCPv6 lease", () => {
  it("offers the history and the release, and no reservation", async () => {
    open();
    await loaded();
    expect(await rowActions(row(GRID, V6[0]!))).toEqual(["history", "release"]);
    // A DHCPv4 lease that is not reserved keeps its reserve action.
    expect(await rowActions(row(GRID, "192.0.2.100"))).toContain("reserve");
  });

  it("releases a DHCPv6 lease with the address in the path, the VRF and the reason", async () => {
    const writes = recordWrites();
    open();
    await loaded();
    await rowAction(row(GRID, V6[0]!), "release");
    const dialog = await screen.findByTestId("dialog-lease-release");
    expect(dialog.textContent).toContain(V6[0]);
    expect(within(dialog).getByTestId("release-body").textContent).toBe(`The lease of ${V6[0]} held by 00:00:5e:00:53:10 ends now. The client can ask for an address again.`);
    fireEvent.input(within(dialog).getByTestId("field-reason"), { target: { value: "Replaced" } });
    fireEvent.click(within(dialog).getByTestId("confirm-ok"));
    await waitFor(() => expect(within(row(GRID, V6[0]!)).getByTestId("lease-state").dataset.key).toBe("released"));
    const sent = writes().find((w) => w.method === "POST");
    expect(decodeURIComponent(sent?.url ?? "")).toContain(`/api/v1/dhcp/leases/${V6[0]}/release`);
    expect(sent?.body).toEqual({ vrf: held(V6[0]!).vrf, reason: "Replaced" });
    // The other family's lease is untouched.
    expect(within(row(GRID, "192.0.2.100")).getByTestId("lease-state").dataset.key).toBe("active");
  });

  it("names a client without a MAC address by its DUID in the release dialog", async () => {
    open();
    await loaded();
    await rowAction(row(GRID, V6[1]!), "release");
    const dialog = await screen.findByTestId("dialog-lease-release");
    expect(within(dialog).getByTestId("release-body").textContent).toBe(
      `The lease of ${V6[1]} held by the client with the DUID 00:02:00:00:00:09:0c:0c:0c:0c:01 ends now. The client can ask for an address again.`,
    );
  });
});

describe("the status strip with both families", () => {
  it("counts the listeners, the scopes and the active leases of each family", async () => {
    open();
    const strip = await screen.findByTestId("dhcp-strip");
    await waitFor(() => expect(within(strip).getByTestId("strip-scopes").textContent).toBe("1 DHCPv4 and 1 DHCPv6 scopes"));
    expect(within(strip).getByTestId("strip-listeners").textContent).toBe("1 DHCPv4 and 0 DHCPv6 listeners");
    const active = within(strip)
      .getAllByTestId("strip-leases")
      .find((el) => el.dataset.key === "active")!;
    expect(active.textContent).toBe("9 DHCPv4 and 3 DHCPv6 active leases");
    expect(active.dataset.v4).toBe("9");
    expect(active.dataset.v6).toBe("3");
    // A state both families have is one count with the split in its title.
    const expired = within(strip)
      .getAllByTestId("strip-leases")
      .find((el) => el.dataset.key === "expired")!;
    expect(expired.textContent).toBe("Expired 2");
    expect(expired.querySelector("[title]")?.getAttribute("title")).toBe("1 DHCPv4 and 1 DHCPv6");
  });
});

describe("the live strip of a DHCPv6 scope", () => {
  it("names the scope and says the size of a pool too big to count as a power of two", async () => {
    server.use(
      http.get("/api/v1/dhcp/scopes/:prefix/utilization", ({ params }) =>
        HttpResponse.json({ prefix: params.prefix, family: "v6", pool_size: 18446744073709552000, pool_bits: 64, leased: 3, reserved: 0, abandoned: 0, free: 18446744073709552000, utilization: 0, at: new Date().toISOString() }),
      ),
    );
    open(`/dhcp/leases?scope=${DHCP_IDS.lanV6}`);
    await waitFor(() => expect(keys()).toEqual(V6));
    const bar = await screen.findByTestId("leases-utilization");
    const fact = (key: string) => within(bar).getAllByTestId("util-fact").find((el) => el.dataset.key === key)?.textContent ?? "";
    await waitFor(() => expect(fact("pool_size")).toContain("2^64"));
    expect(fact("free")).toContain("2^64");
    // The raw number never shows.
    expect(bar.textContent).not.toMatch(/18[,\s.]?446/);
    await waitFor(() => expect(screen.getByTestId("leases-scope-name").textContent).toBe("2001:db8:0:10::/64"));
  });
});

describe("the words", () => {
  it("speaks Swedish", async () => {
    await setLocale("sv");
    open();
    await loaded();
    expect(screen.getByLabelText("Adressfamilj")).toBeTruthy();
    expect(screen.getByLabelText("DUID")).toBeTruthy();
    const r = row(GRID, V6[0]!);
    expect(within(r).getByTestId("lease-kind").textContent).toBe("Adress");
    expect(within(r).getByTestId("lease-peer").textContent).toBe("Även DHCPv4: 192.0.2.100");
    expect(within(r).getByTestId("lease-family").textContent).toBe("DHCPv6");
    const strip = await screen.findByTestId("dhcp-strip");
    await waitFor(() => expect(within(strip).getByTestId("strip-scopes").textContent).toBe("1 DHCPv4- och 1 DHCPv6-omfång"));
  });
});
