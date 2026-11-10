// The Owners tab of a primary zone: the owners of its names in a table with filters, the notice
// of a zone that keeps none, Release with its explanation, Reassign with the row's revision,
// "Assign a name", the refusals of the server, Swedish, and what a viewer sees.
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { components } from "../api/generated/schema";
import { DNS_IDS } from "../api/mock/dns-model";
import { dnsState } from "../api/mock/routes-dns";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { signInAlex } from "../auth/account/testkit";
import { signInWithRoles } from "../auth/scope-testkit";
import { setSessionForTest } from "../auth/session";
import { setLocale } from "../i18n";
import { row, rowAction, rowActions, rows, recordWrites } from "./testkit";
import ZonePage from "./ZonePage";

type Owner = components["schemas"]["NameOwnerItem"];

const PRIMARY = DNS_IDS.zone.example;
const SECONDARY = DNS_IDS.zone.lab;
const HOLD = "2026-12-01T00:00:00Z";

beforeEach(async () => {
  await signInAlex();
});

afterEach(async () => {
  vi.restoreAllMocks();
  setSessionForTest(null);
  await setLocale("en");
});

const owner = (name: string, principal: string, extra: Partial<Owner> = {}): Owner => ({
  scope: "default",
  name: `${name}.example.test`,
  principal,
  since: "2026-10-01T08:00:00Z",
  how: "created",
  revision: 7,
  ...extra,
});

/** Gives the zone Kerberos settings and the owners, as a server with secure updates would hold them. */
function givenOwners(items: Owner[], kerberos = true) {
  const zone = dnsState().zones.find((z) => z.id === PRIMARY) as { update?: components["schemas"]["DnsUpdatePolicy"] } | undefined;
  if (zone && kerberos) zone.update = { kerberos: { realms: ["CORP.EXAMPLE.TEST"], ownership: "windows", owner_hold_days: 14, privileged: [] } };
  dnsState().owners.set(PRIMARY, items);
}

const SEED = (): Owner[] => [
  owner("pc07", "PC07$@CORP.EXAMPLE.TEST", { sid: "S-1-5-21-1000-2000-3000-1105" }),
  owner("pc08", "PC08$@CORP.EXAMPLE.TEST", { how: "assigned", hold_until: HOLD }),
  owner("print.lab", "PRINT$@CORP.EXAMPLE.TEST", { how: "claimed" }),
];

async function open(zone: string = PRIMARY) {
  const view = renderRoute(ZonePage, { url: `/dns/zones/${zone}/owners`, path: "/dns/zones/:id/:tab?", routes: { "/dns": () => <div data-testid="zones-page" /> } });
  await screen.findByTestId("zone-name");
  return view;
}

describe("the owners of a zone", () => {
  it("lists them with the principal, the SID, how, since and the hold", async () => {
    givenOwners(SEED());
    const view = await open();
    await waitFor(() => expect(rows("dns-owners")).toHaveLength(3));
    const r = row("dns-owners", "pc07");
    expect(r.textContent).toContain("PC07$@CORP.EXAMPLE.TEST");
    expect(r.textContent).toContain("S-1-5-21-1000-2000-3000-1105");
    expect(within(r).getByTestId("owner-how").dataset.kind).toBe("created");
    expect(within(row("dns-owners", "pc08")).getByTestId("owner-hold").textContent).toContain("Held until");
    expect(within(row("dns-owners", "print.lab")).getByTestId("owner-how").dataset.kind).toBe("claimed");
    // In DNS order: the labels compared from the root down, so print.lab comes before pc07.
    expect(rows("dns-owners").map((x) => x.dataset.key)).toEqual(["print.lab", "pc07", "pc08"]);
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("filters by the name and its subtree, and by the owner", async () => {
    givenOwners(SEED());
    await open();
    await waitFor(() => expect(rows("dns-owners")).toHaveLength(3));
    fireEvent.input(screen.getByTestId("filter-name"), { target: { value: "lab" } });
    await waitFor(() => expect(rows("dns-owners").map((x) => x.dataset.key)).toEqual(["print.lab"]));
    fireEvent.input(screen.getByTestId("filter-name"), { target: { value: "" } });
    fireEvent.input(screen.getByTestId("filter-owner"), { target: { value: "pc08" } });
    await waitFor(() => expect(rows("dns-owners").map((x) => x.dataset.key)).toEqual(["pc08"]));
    fireEvent.input(screen.getByTestId("filter-owner"), { target: { value: "nobody" } });
    expect(await screen.findByText("No rows match the filter.", {}, { timeout: 3000 })).toBeTruthy();
  });

  it("says that a zone without Kerberos settings keeps no owners", async () => {
    givenOwners([], false);
    await open();
    expect((await screen.findByTestId("owners-off")).textContent).toContain("keeps no owners");
    expect(screen.queryByTestId("grid-dns-owners")).toBeNull();
    expect(screen.queryByTestId("owner-assign")).toBeNull();
  });

  it("is not a tab of a secondary zone", async () => {
    await open(SECONDARY);
    expect(screen.queryByTestId("zone-tab-owners")).toBeNull();
  });

  it("shows the tab of a primary zone", async () => {
    givenOwners(SEED());
    await open(PRIMARY);
    fireEvent.click(await screen.findByTestId("zone-tab-owners"));
    expect(await screen.findByTestId("zone-owners")).toBeTruthy();
  });
});

describe("release", () => {
  it("explains what happens and removes the owner", async () => {
    givenOwners(SEED());
    const writes = recordWrites();
    await open();
    await waitFor(() => expect(rows("dns-owners")).toHaveLength(3));
    await rowAction(row("dns-owners", "pc07"), "release");
    const dialog = await screen.findByTestId("dialog-owner-release");
    expect(dialog.textContent).toContain("PC07$@CORP.EXAMPLE.TEST stops owning pc07.");
    expect(dialog.textContent).toContain("claimable again");
    expect(dialog.textContent).toContain("HOST$");
    expect(dialog.textContent).toContain("use Reassign");
    fireEvent.click(within(dialog).getByTestId("confirm-ok"));
    await waitFor(() => expect(rows("dns-owners").map((x) => x.dataset.key)).toEqual(["print.lab", "pc08"]));
    const sent = writes().filter((w) => w.method === "DELETE");
    expect(sent).toHaveLength(1);
    expect(sent[0]?.url).toContain(`/dns/zones/${PRIMARY}/owners/pc07.example.test`);
    expect(dnsState().owners.get(PRIMARY)?.map((o) => o.name)).toEqual(["pc08.example.test", "print.lab.example.test"]);
  });

  it("reports the records that became claimable", async () => {
    givenOwners(SEED());
    dnsState().rrsets.get(PRIMARY)?.push({
      scope: "default",
      name: "pc07.example.test",
      type: "A",
      ttl: 1200,
      records: [{ type: "A", address: "192.0.2.77" }],
      origin: "ad",
      key: null,
      updated: { at: "2026-10-01T08:00:00Z", by: { kind: "user", id: "x", name: "x" } as never },
    });
    await open();
    await waitFor(() => expect(rows("dns-owners")).toHaveLength(3));
    await rowAction(row("dns-owners", "pc07"), "release");
    fireEvent.click(within(await screen.findByTestId("dialog-owner-release")).getByTestId("confirm-ok"));
    expect(await screen.findByText("pc07 released, 1 RRset claimable")).toBeTruthy();
  });

  it("shows the refusal when the owner is already gone", async () => {
    givenOwners(SEED());
    await open();
    await waitFor(() => expect(rows("dns-owners")).toHaveLength(3));
    dnsState().owners.set(PRIMARY, []);
    await rowAction(row("dns-owners", "pc07"), "release");
    fireEvent.click(within(await screen.findByTestId("dialog-owner-release")).getByTestId("confirm-ok"));
    expect((await screen.findByTestId("owner-release-error")).textContent).toContain("has no owner");
  });
});

describe("reassign and assign", () => {
  it("sends the new principal with the revision of the row", async () => {
    givenOwners(SEED());
    const spy = vi.spyOn(globalThis, "fetch");
    await open();
    await waitFor(() => expect(rows("dns-owners")).toHaveLength(3));
    await rowAction(row("dns-owners", "pc07"), "reassign");
    const dialog = await screen.findByTestId("dialog-owner-assign");
    expect(within(dialog).getByTestId("owner-current").textContent).toBe("PC07$@CORP.EXAMPLE.TEST");
    expect(within(dialog).queryByTestId("field-name")).toBeNull();
    fireEvent.input(within(dialog).getByTestId("field-principal"), { target: { value: "PC09$@CORP.EXAMPLE.TEST" } });
    fireEvent.input(within(dialog).getByTestId("field-sid"), { target: { value: "s-1-5-21-1000-2000-3000-1109" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(screen.queryByTestId("dialog-owner-assign")).toBeNull());
    const put = spy.mock.calls.find(([, init]) => init?.method === "PUT");
    expect(String(put?.[0])).toContain("/owners/pc07.example.test");
    expect(new Headers(put?.[1]?.headers).get("If-Match")).toBe('"7"');
    expect(JSON.parse(String(put?.[1]?.body))).toEqual({ principal: "PC09$@CORP.EXAMPLE.TEST", sid: "S-1-5-21-1000-2000-3000-1109" });
    await waitFor(() => expect(row("dns-owners", "pc07").textContent).toContain("PC09$@CORP.EXAMPLE.TEST"));
    expect(within(row("dns-owners", "pc07")).getByTestId("owner-how").dataset.kind).toBe("assigned");
  });

  it("assigns a name that has no records and holds it", async () => {
    givenOwners(SEED());
    await open();
    await waitFor(() => expect(rows("dns-owners")).toHaveLength(3));
    fireEvent.click(screen.getByTestId("owner-assign"));
    const dialog = await screen.findByTestId("dialog-owner-assign");
    expect(dialog.textContent).toContain("is held for this principal");
    fireEvent.input(within(dialog).getByTestId("field-name"), { target: { value: "new-pc" } });
    fireEvent.input(within(dialog).getByTestId("field-principal"), { target: { value: "NEW-PC$@corp.example.test" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(rows("dns-owners").map((x) => x.dataset.key)).toContain("new-pc"));
    expect(within(row("dns-owners", "new-pc")).getByTestId("owner-hold")).toBeTruthy();
  });

  it("checks the principal and the SID before it sends", async () => {
    givenOwners(SEED());
    const writes = recordWrites();
    await open();
    fireEvent.click(await screen.findByTestId("owner-assign"));
    const dialog = await screen.findByTestId("dialog-owner-assign");
    fireEvent.input(within(dialog).getByTestId("field-principal"), { target: { value: "PC09" } });
    fireEvent.input(within(dialog).getByTestId("field-sid"), { target: { value: "nope" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(within(dialog).getAllByTestId("field-error").map((e) => e.dataset.field).sort()).toEqual(["name", "principal", "sid"]));
    expect(writes().filter((w) => w.method === "PUT")).toHaveLength(0);
  });

  it("shows a name that keeps no owner as a refusal", async () => {
    givenOwners(SEED());
    await open();
    fireEvent.click(await screen.findByTestId("owner-assign"));
    const dialog = await screen.findByTestId("dialog-owner-assign");
    fireEvent.input(within(dialog).getByTestId("field-name"), { target: { value: "_ldap" } });
    fireEvent.input(within(dialog).getByTestId("field-principal"), { target: { value: "DC1$@CORP.EXAMPLE.TEST" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    expect((await within(dialog).findByTestId("error-notice")).textContent).toContain("keeps no owner");
    // The wildcard and the apex are as protected as the locator names.
    for (const name of ["*", "@", "_msdcs"]) {
      fireEvent.input(within(dialog).getByTestId("field-name"), { target: { value: name } });
      fireEvent.click(within(dialog).getByTestId("form-submit"));
      await waitFor(() => expect(within(dialog).getByTestId("error-notice").textContent).toContain("keeps no owner"));
    }
  });

  it("names the field when the principal is not of a realm of the zone", async () => {
    givenOwners(SEED());
    await open();
    fireEvent.click(await screen.findByTestId("owner-assign"));
    const dialog = await screen.findByTestId("dialog-owner-assign");
    fireEvent.input(within(dialog).getByTestId("field-name"), { target: { value: "pc10" } });
    fireEvent.input(within(dialog).getByTestId("field-principal"), { target: { value: "PC10$@OTHER.EXAMPLE.TEST" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(within(dialog).getByTestId("field-error").dataset.field).toBe("principal"));
  });

  it("shows the refusal of a zone that lost its Kerberos settings", async () => {
    givenOwners(SEED());
    await open();
    await waitFor(() => expect(rows("dns-owners")).toHaveLength(3));
    (dnsState().zones.find((z) => z.id === PRIMARY) as { update?: unknown }).update = {};
    fireEvent.click(screen.getByTestId("owner-assign"));
    const dialog = await screen.findByTestId("dialog-owner-assign");
    fireEvent.input(within(dialog).getByTestId("field-name"), { target: { value: "pc11" } });
    fireEvent.input(within(dialog).getByTestId("field-principal"), { target: { value: "PC11$@CORP.EXAMPLE.TEST" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    expect((await within(dialog).findByTestId("error-notice")).textContent).toContain("keeps no owners");
  });
});

describe("who may change the owners", () => {
  it("offers a viewer the table and no action", async () => {
    await signInWithRoles(["viewer"]);
    givenOwners(SEED());
    await open();
    await waitFor(() => expect(rows("dns-owners")).toHaveLength(3));
    expect(screen.queryByTestId("owner-assign")).toBeNull();
    expect(await rowActions(row("dns-owners", "pc07"))).toEqual([]);
  });

  it("speaks Swedish", async () => {
    await setLocale("sv");
    givenOwners(SEED());
    await open();
    await waitFor(() => expect(rows("dns-owners")).toHaveLength(3));
    expect(screen.getByTestId("zone-tab-owners").textContent).toBe("Ägare");
    expect(screen.getByTestId("owner-assign").textContent).toContain("Tilldela ett namn");
    expect(row("dns-owners", "pc08").textContent).toContain("Reserverad till");
    fireEvent.click(screen.getByTestId("owner-assign"));
    expect((await screen.findByTestId("dialog-owner-assign")).textContent).toContain("Tilldela ett namn");
  });
});
