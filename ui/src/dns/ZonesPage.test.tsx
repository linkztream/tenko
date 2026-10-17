// The zone list: the zones with their kind, serving state, counts, serial and origin mix; the
// search; create and delete with the local checks and the server's refusals; the gating by
// role; the notices for a server without the DNS service (501) and a switched-off module.
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { DNS_IDS } from "../api/mock/dns-model";
import { dnsState } from "../api/mock/routes-dns";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { signInAlex } from "../auth/account/testkit";
import { signInWithRoles } from "../auth/scope-testkit";
import { setSessionForTest } from "../auth/session";
import { setLocale } from "../i18n";
import { cell, dnsNotBuilt, dnsSwitchedOff, recordWrites, row, rowAction, rows } from "./testkit";
import ZonesPage from "./ZonesPage";

beforeEach(async () => {
  await signInAlex();
});

afterEach(async () => {
  setSessionForTest(null);
  await setLocale("en");
});

function open(url = "/dns") {
  return renderRoute(ZonesPage, { url, path: "/dns", routes: { "/dns/zones/:id": () => <div data-testid="zone-opened" /> } });
}

async function loaded() {
  await waitFor(() => expect(rows("dns-zones")).toHaveLength(4));
}

describe("the zone list", () => {
  it("lists the zones with kind, serving state, RRsets, serial and origins", async () => {
    const view = open();
    await loaded();
    expect(rows("dns-zones").map((r) => r.dataset.key)).toEqual(["2.0.192.in-addr.arpa", "example.test", "corp.example.test", "lab.example.test"]);
    const example = row("dns-zones", "example.test");
    expect(within(example).getByTestId("zone-kind").dataset.kind).toBe("primary");
    expect(within(example).queryByTestId("zone-not-served")).toBeNull();
    expect(cell(example, "rrsets").textContent).toBe("13");
    expect(cell(example, "serial").textContent).toBe("2026101701");
    expect(within(example).getByTestId("zone-origins").dataset.key).toBe("ipam,manual");
    expect(within(row("dns-zones", "2.0.192.in-addr.arpa")).getByTestId("zone-reverse")).toBeTruthy();
    expect(within(row("dns-zones", "lab.example.test")).getByTestId("zone-not-served")).toBeTruthy();
    expect(within(row("dns-zones", "corp.example.test")).getByTestId("zone-not-served")).toBeTruthy();
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("asks for the origin mix when the server does not report it", async () => {
    for (const zone of dnsState().zones) delete (zone as { origins?: unknown }).origins;
    open();
    await loaded();
    await waitFor(() => expect(within(row("dns-zones", "example.test")).getByTestId("zone-origins").dataset.key).toBe("manual,ipam"));
    expect(within(row("dns-zones", "lab.example.test")).getByTestId("zone-origins").dataset.key).toBe("manual");
  });

  it("searches the names", async () => {
    open();
    await loaded();
    fireEvent.input(screen.getByTestId("filter-input"), { target: { value: "arpa" } });
    await waitFor(() => expect(rows("dns-zones").map((r) => r.dataset.key)).toEqual(["2.0.192.in-addr.arpa"]));
    fireEvent.input(screen.getByTestId("filter-input"), { target: { value: "nothing-matches" } });
    expect(await screen.findByText("No rows match the filter.")).toBeTruthy();
  });

  it("opens a zone", async () => {
    const view = open();
    await loaded();
    fireEvent.dblClick(cell(row("dns-zones", "example.test"), "name"));
    await waitFor(() => expect(view.location()).toBe(`/dns/zones/${DNS_IDS.zone.example}`));
  });

  it("speaks Swedish", async () => {
    await setLocale("sv");
    open();
    await loaded();
    expect(screen.getByRole("heading", { level: 1 }).textContent).toContain("Zoner");
    expect(within(row("dns-zones", "lab.example.test")).getByTestId("zone-not-served").textContent).toBe("Tillhandahålls inte än");
  });
});

describe("creating a zone", () => {
  it("creates a primary zone with its SOA names and opens it", async () => {
    const writes = recordWrites();
    const view = open();
    await loaded();
    fireEvent.click(screen.getByTestId("dns-zone-create"));
    const dialog = await screen.findByTestId("dialog-zone-form");
    fireEvent.input(within(dialog).getByTestId("field-name"), { target: { value: "Home.Example.Test." } });
    expect((within(dialog).getByTestId("field-soa.mname") as HTMLInputElement).value).toBe("ns1.home.example.test");
    fireEvent.input(within(dialog).getByTestId("field-name_servers"), { target: { value: "ns1.home.example.test, ns2.home.example.test" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(view.location()).toMatch(/^\/dns\/zones\//));
    const sent = writes().find((w) => w.method === "POST");
    expect(sent?.body).toMatchObject({
      name: "home.example.test",
      kind: "primary",
      serial: "date_counter",
      soa: { mname: "ns1.home.example.test", rname: "hostmaster.home.example.test", ttl: 3600 },
      name_servers: ["ns1.home.example.test", "ns2.home.example.test"],
    });
    expect(sent?.body).not.toHaveProperty("update");
    const zone = dnsState().zones.find((z) => z.name === "home.example.test");
    expect(dnsState().rrsets.get(zone?.id ?? "")?.map((s) => s.type)).toEqual(["SOA", "NS"]);
    expect(await screen.findByText("Zone home.example.test created")).toBeTruthy();
  });

  it("checks the name before it sends and shows the server's refusal on the field", async () => {
    const writes = recordWrites();
    open();
    await loaded();
    fireEvent.click(screen.getByTestId("dns-zone-create"));
    const dialog = await screen.findByTestId("dialog-zone-form");
    fireEvent.input(within(dialog).getByTestId("field-name"), { target: { value: "bad name" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    const error = await within(dialog).findByTestId("field-error");
    expect(error.dataset.field).toBe("name");
    expect(writes()).toHaveLength(0);
    fireEvent.input(within(dialog).getByTestId("field-name"), { target: { value: "example.test" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(within(dialog).getByTestId("field-error").textContent).toBe("A zone of this name exists already."));
  });

  it("asks a secondary zone for its primary servers", async () => {
    open();
    await loaded();
    fireEvent.click(screen.getByTestId("dns-zone-create"));
    const dialog = await screen.findByTestId("dialog-zone-form");
    fireEvent.input(within(dialog).getByTestId("field-name"), { target: { value: "peer.example.test" } });
    fireEvent.change(within(dialog).getByTestId("field-kind"), { target: { value: "secondary" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    expect((await within(dialog).findByTestId("field-error")).dataset.field).toBe("source");
    fireEvent.input(within(dialog).getByTestId("field-source"), { target: { value: "198.51.100.53" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(dnsState().zones.find((z) => z.name === "peer.example.test")?.source?.primaries).toEqual([{ address: "198.51.100.53" }]));
  });
});

describe("deleting a zone", () => {
  it("deletes a zone after the confirmation", async () => {
    open();
    await loaded();
    await rowAction(row("dns-zones", "corp.example.test"), "delete");
    const dialog = await screen.findByTestId("dialog-zone-delete");
    fireEvent.click(within(dialog).getByTestId("confirm-ok"));
    await waitFor(() => expect(rows("dns-zones")).toHaveLength(3));
    expect(dnsState().zones.some((z) => z.name === "corp.example.test")).toBe(false);
  });
});

describe("who sees what", () => {
  it("offers a viewer no create and no delete", async () => {
    await signInWithRoles(["viewer"]);
    open();
    await loaded();
    expect(screen.queryByTestId("dns-zone-create")).toBeNull();
    fireEvent.click(within(row("dns-zones", "example.test")).getByRole("button", { name: /^Actions for/ }));
    const menu = await screen.findByTestId("row-menu");
    expect(within(menu).queryAllByTestId("menu-item").map((i) => i.dataset.key)).toEqual(["open"]);
  });

  it("says the DNS service is not built yet when the server answers 501", async () => {
    dnsNotBuilt();
    const view = open();
    expect(await screen.findByTestId("dns-not-built")).toBeTruthy();
    expect(screen.queryByTestId("dns-zone-create")).toBeNull();
    expect(screen.queryByTestId("grid-dns-zones")).toBeNull();
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("says the module is switched off and links to the settings", async () => {
    dnsSwitchedOff();
    open();
    const notice = await screen.findByTestId("dns-off");
    expect(within(notice).getByTestId("dns-modules-link").getAttribute("href")).toBe("/settings");
  });
});
