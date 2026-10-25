// The lease history with DHCPv6 beside DHCPv4 (WP9.4): both families merged newest first, a family
// column, the MAC address from `mac` (a DUID-LL or DUID-LLT names one, a DUID-EN none), the DUID of
// a DHCPv6 row, the family and DUID filters in the URL and in the request, an IPv6 address in the
// address filter, a delegated prefix with its length (WP9.2), the MAC address of a client found by its
// link-layer address, Swedish.
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { dhcpLeaseState } from "../../api/mock/routes-dhcp-leases";
import { renderRoute } from "../../app/testing/render";
import { signInAlex } from "../../auth/account/testkit";
import { setSessionForTest } from "../../auth/session";
import { setLocale } from "../../i18n";
import { cell, rows } from "../testkit";
import HistoryPage from "./HistoryPage";

beforeEach(async () => {
  await signInAlex();
});

afterEach(async () => {
  vi.restoreAllMocks();
  setSessionForTest(null);
  await setLocale("en");
});

const GRID = "dhcp-history";
const V6_100 = "2001:db8:0:10::100";
const V6_101 = "2001:db8:0:10::101";
/** The delegated prefix 2001:db8:1:110::/60 of the client of ::100. */
const PD = "2001:db8:1:110::";
const open = (url = "/dhcp/history") => renderRoute(HistoryPage, { url, path: "/dhcp/history" });
const loaded = () => waitFor(() => expect(rows(GRID).length).toBeGreaterThan(0));
const keys = () => rows(GRID).map((r) => r.dataset.key ?? "");
const rowOf = (key: string) => {
  const found = rows(GRID).find((r) => r.dataset.key === key);
  if (!found) throw new Error(`no row ${key}: ${keys().join(", ")}`);
  return found;
};

function historyReads(spy: { mock: { calls: unknown[][] } }): URL[] {
  return spy.mock.calls.map(([url]) => new URL(String(url), "http://localhost")).filter((url) => url.pathname === "/api/v1/dhcp/history");
}

describe("the history of both families", () => {
  it("merges the events newest first, each with its family", async () => {
    open();
    await loaded();
    const families = rows(GRID).map((r) => within(r).getByTestId("event-family").dataset.key);
    expect(families).toContain("v4");
    expect(families).toContain("v6");
    // The DHCPv6 events lie between the DHCPv4 renewals (newest) and the DHCPv4 grants (oldest).
    const first = keys().findIndex((k) => k.startsWith("2001:"));
    const lastV4Renewal = keys().findLastIndex((k) => k.endsWith(" renewed") && !k.startsWith("2001:"));
    expect(lastV4Renewal).toBeLessThan(first);
    expect(within(rowOf(`${V6_100} granted`)).getByTestId("event-family").textContent).toBe("DHCPv6");
    expect(within(rowOf("192.0.2.100 granted")).getByTestId("event-family").textContent).toBe("DHCPv4");
  });

  it("shows the MAC address and the DUID of a DHCPv6 event, and no name", async () => {
    open();
    await loaded();
    const r = rowOf(`${V6_100} granted`);
    expect(cell(r, "mac").textContent).toBe("00:00:5e:00:53:10");
    const duid = within(r).getByTestId("event-duid");
    expect(duid.textContent).toBe("00:03:00:01:00:00:5e:00:53:10");
    expect(duid.getAttribute("title")).toBe("00:03:00:01:00:00:5e:00:53:10");
    expect(cell(r, "name").textContent).toBe("");
    expect(within(r).getByTestId("event-kind").dataset.key).toBe("granted");
  });

  it("shows a DHCPv6 event of a DUID without a MAC address with the DUID alone", async () => {
    open();
    await loaded();
    const r = rowOf(`${V6_101} granted`);
    expect(cell(r, "mac").textContent).toBe("");
    expect(within(r).getByTestId("event-duid").textContent).toBe("00:02:00:00:00:09:0c:0c:0c:0c:01");
  });

  it("shows the MAC address a DHCPv4 event carries and no DUID", async () => {
    open();
    await loaded();
    const r = rowOf("192.0.2.103 renewed");
    expect(cell(r, "mac").textContent).toBe("00:00:5e:00:53:13");
    expect(within(r).queryByTestId("event-duid")).toBeNull();
    expect(cell(r, "name").textContent).toBe("host-4");
  });

  it("links an IPv6 address to the leases", async () => {
    open();
    await loaded();
    const href = within(rowOf(`${V6_100} granted`)).getByTestId("event-lease-link").getAttribute("href")!;
    expect(new URL(href, "http://localhost").searchParams.get("addr")).toBe(V6_100);
  });
});

describe("the family filter", () => {
  it("sends the family and keeps it in the URL", async () => {
    const spy = vi.spyOn(globalThis, "fetch");
    const view = open();
    await loaded();
    expect(historyReads(spy).at(-1)!.searchParams.get("family")).toBeNull();

    fireEvent.change(screen.getByTestId("filter-family"), { target: { value: "v6" } });
    await waitFor(() => expect(historyReads(spy).at(-1)!.searchParams.get("family")).toBe("v6"));
    await waitFor(() => expect(keys().every((k) => k.startsWith("2001:"))).toBe(true));
    expect(rows(GRID).length).toBeGreaterThan(0);
    expect(view.location()).toContain("family=v6");

    fireEvent.change(screen.getByTestId("filter-family"), { target: { value: "v4" } });
    await waitFor(() => expect(historyReads(spy).at(-1)!.searchParams.get("family")).toBe("v4"));
    await waitFor(() => expect(keys().some((k) => k.startsWith("2001:"))).toBe(false));
    expect(rows(GRID).length).toBeGreaterThan(0);

    fireEvent.change(screen.getByTestId("filter-family"), { target: { value: "" } });
    await waitFor(() => expect(historyReads(spy).at(-1)!.searchParams.get("family")).toBeNull());
    expect(view.location()).not.toContain("family");
  });

  it("takes the family from the link", async () => {
    open("/dhcp/history?family=v6");
    await waitFor(() => expect(keys().length).toBeGreaterThan(0));
    expect(keys().every((k) => k.startsWith("2001:"))).toBe(true);
    expect((screen.getByTestId("filter-family") as HTMLSelectElement).value).toBe("v6");
    expect(screen.getByTestId("history-reset")).toBeTruthy();
  });
});

describe("the DUID filter", () => {
  it("sends the DUID as typed and shows the events of that client only", async () => {
    const spy = vi.spyOn(globalThis, "fetch");
    const view = open();
    await loaded();
    fireEvent.change(screen.getByTestId("filter-duid"), { target: { value: "00:02:00:00:00:09:0c:0c:0c:0c:01" } });
    await waitFor(() => expect(historyReads(spy).at(-1)!.searchParams.get("duid")).toBe("00:02:00:00:00:09:0c:0c:0c:0c:01"));
    await waitFor(() => expect(keys()).toEqual([`${V6_101} granted`]));
    expect(view.location()).toContain("duid=");
  });

  it("points at a text that is no DUID", async () => {
    open("/dhcp/history?duid=zz");
    expect((await screen.findByTestId("field-error")).dataset.field).toBe("duid");
  });
});

describe("the address filter with an IPv6 address", () => {
  it("shows the history of one IPv6 address", async () => {
    const spy = vi.spyOn(globalThis, "fetch");
    open(`/dhcp/history?addr=${encodeURIComponent(V6_100)}`);
    await waitFor(() => expect(keys().sort()).toEqual([`${V6_100} granted`, `${V6_100} renewed`]));
    expect(historyReads(spy).at(-1)!.searchParams.get("addr")).toBe(V6_100);
    expect((screen.getByTestId("filter-addr") as HTMLInputElement).value).toBe(V6_100);
  });
});

describe("a delegated prefix", () => {
  it("shows the prefix with its length where an address shows only the address", async () => {
    open();
    await loaded();
    const r = rowOf(`${PD} granted`);
    expect(within(r).getByTestId("event-lease-link").textContent).toBe("2001:db8:1:110::/60");
    expect(within(r).getByTestId("event-family").dataset.key).toBe("v6");
    expect(cell(r, "mac").textContent).toBe("00:00:5e:00:53:10");
    // The address of the same client keeps the plain address.
    expect(within(rowOf(`${V6_100} granted`)).getByTestId("event-lease-link").textContent).toBe(V6_100);
  });

  it("links to the leases by the first address, which the lease list reads as the prefix too", async () => {
    open();
    await loaded();
    const href = within(rowOf(`${PD} granted`)).getByTestId("event-lease-link").getAttribute("href")!;
    expect(new URL(href, "http://localhost").searchParams.get("addr")).toBe(PD);
  });

  it("shows the history of the prefix by its first address", async () => {
    open(`/dhcp/history?addr=${encodeURIComponent(PD)}`);
    await waitFor(() => expect(keys()).toEqual([`${PD} granted`]));
    expect((screen.getByTestId("filter-addr") as HTMLInputElement).value).toBe(PD);
  });
});

describe("the MAC address of a DHCPv6 client behind a relay", () => {
  it("finds the events of a DUID-EN client by the link-layer address of its lease", async () => {
    const lease = dhcpLeaseState().leases.find((l) => l.addr === V6_101)!;
    lease.link_layer = "00005e005377";
    lease.link_layer_type = 1;
    dhcpLeaseState().events.push({
      addr: V6_101,
      at: new Date().toISOString(),
      duid: lease.duid,
      ends: lease.ends,
      family: "v6",
      iaid: 1,
      kind: "renewed",
      mac: "00:00:5e:00:53:77",
      node: 1,
      prefix_len: 128,
      scope: lease.scope,
      state: "active",
      vrf: lease.vrf,
    });
    const spy = vi.spyOn(globalThis, "fetch");
    open();
    await loaded();
    fireEvent.change(screen.getByTestId("filter-mac"), { target: { value: "00:00:5e:00:53:77" } });
    await waitFor(() => expect(historyReads(spy).at(-1)!.searchParams.get("mac")).toBe("00:00:5e:00:53:77"));
    await waitFor(() => expect(keys()).toEqual([`${V6_101} renewed`]));
    expect(cell(rowOf(`${V6_101} renewed`), "mac").textContent).toBe("00:00:5e:00:53:77");
  });
});

describe("the words", () => {
  it("speaks Swedish", async () => {
    await setLocale("sv");
    open();
    await loaded();
    expect(screen.getByLabelText("Adressfamilj", { selector: "select" })).toBeTruthy();
    expect(screen.getByLabelText("DUID", { selector: "input" })).toBeTruthy();
    expect(within(rowOf(`${V6_100} granted`)).getByTestId("event-family").textContent).toBe("DHCPv6");
  });
});
