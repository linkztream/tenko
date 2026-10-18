// WP6.1: the zone transfers on the settings tab and the read-only records of a secondary zone:
// the access list chips, the NOTIFY rows, TSIG, XoT and the catalog flag saved in one PATCH, the
// primaries and the transfer state of a secondary zone with "Transfer now", what a viewer and a
// server without the route see, and the records tab of a secondary zone.
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { DNS_IDS } from "../api/mock/dns-model";
import { server } from "../api/mock/node";
import { dnsState } from "../api/mock/routes-dns";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { signInAlex } from "../auth/account/testkit";
import { signInWithRoles } from "../auth/scope-testkit";
import { setSessionForTest } from "../auth/session";
import { setLocale } from "../i18n";
import { cell, recordWrites, row, rowActions, rows } from "./testkit";
import ZonePage from "./ZonePage";

const PRIMARY = DNS_IDS.zone.example;
const SECONDARY = DNS_IDS.zone.lab;

beforeEach(async () => {
  await signInAlex();
});

afterEach(async () => {
  setSessionForTest(null);
  await setLocale("en");
});

function open(zone: string, tab = "settings") {
  return renderRoute(ZonePage, { url: `/dns/zones/${zone}/${tab}`, path: "/dns/zones/:id/:tab?", routes: { "/dns": () => <div data-testid="zones-page" /> } });
}

async function settings(zone: string) {
  const view = open(zone);
  const form = await screen.findByTestId("zone-settings");
  await waitFor(() => expect(within(form).getByTestId("zone-transfer")).toBeTruthy());
  // The name servers of the apex arrive with a read of their own; a save before that would refuse an empty list.
  if (zone !== SECONDARY) await waitFor(() => expect((within(form).getByTestId("field-name_servers") as HTMLInputElement).value).not.toBe(""));
  return { view, form };
}

const patches = (writes: ReturnType<typeof recordWrites>) => writes().filter((w) => w.method === "PATCH");
const input = (form: HTMLElement, id: string) => within(form).getByTestId(id) as HTMLInputElement;

describe("the transfer section of a primary zone", () => {
  it("shows the access lists by name, the NOTIFY targets and the switches", async () => {
    const { view, form } = await settings(PRIMARY);
    const section = within(form).getByTestId("zone-transfer");
    await waitFor(() => expect(within(section).getAllByTestId("transfer-allow").map((c) => c.textContent)).toEqual(["transfer-peers"]));
    expect(within(section).getByTestId("transfer-notify-none")).toBeTruthy();
    expect(input(section, "field-require_tsig").checked).toBe(true);
    expect(input(section, "field-xot").checked).toBe(false);
    expect(input(section, "field-catalog").checked).toBe(false);
    expect(within(section).getByText(/Tenko lists the primary zones that allow transfers/)).toBeTruthy();
    expect(within(form).queryByTestId("zone-transfer-status")).toBeNull();
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("sends one PATCH with the transfer policy and the catalog flag", async () => {
    const writes = recordWrites();
    const { form } = await settings(PRIMARY);
    const add = input(form, "field-allow-add");
    await waitFor(() => expect(Array.from((add as unknown as HTMLSelectElement).options).map((o) => o.textContent)).toContain("internal"));
    fireEvent.change(add, { target: { value: DNS_IDS.acl.internal } });
    await waitFor(() => expect(within(form).getAllByTestId("transfer-allow").map((c) => c.dataset.key)).toEqual([DNS_IDS.acl.peers, DNS_IDS.acl.internal]));
    fireEvent.click(within(form).getByTestId("transfer-notify-add"));
    fireEvent.input(input(form, "field-notify.0.address"), { target: { value: "192.0.2.54" } });
    fireEvent.input(input(form, "field-notify.0.port"), { target: { value: "5353" } });
    fireEvent.input(input(form, "field-notify.0.key"), { target: { value: "xfr.example.test" } });
    fireEvent.click(input(form, "field-xot"));
    fireEvent.click(input(form, "field-catalog"));
    fireEvent.click(within(form).getByTestId("form-submit"));
    expect(await screen.findByText("Settings of example.test saved")).toBeTruthy();
    const sent = patches(writes);
    expect(sent).toHaveLength(1);
    expect(sent[0]?.body).toMatchObject({
      transfer: {
        allow: [DNS_IDS.acl.peers, DNS_IDS.acl.internal],
        notify: [{ address: "192.0.2.54", port: 5353, key: "xfr.example.test" }],
        require_tsig: true,
        xot: true,
      },
      catalog: true,
    });
    expect(sent[0]?.body).not.toHaveProperty("source");
    const zone = dnsState().zones.find((z) => z.id === PRIMARY);
    expect(zone?.transfer?.notify).toEqual([{ address: "192.0.2.54", port: 5353, key: "xfr.example.test" }]);
    expect(zone?.catalog).toBe(true);
  });

  it("leaves transfer and catalog out of the PATCH when they did not change", async () => {
    const writes = recordWrites();
    const { form } = await settings(PRIMARY);
    fireEvent.input(input(form, "field-description"), { target: { value: "The home zone, renamed" } });
    fireEvent.click(within(form).getByTestId("form-submit"));
    expect(await screen.findByText("Settings of example.test saved")).toBeTruthy();
    const body = patches(writes)[0]?.body ?? {};
    expect(body).toHaveProperty("description", "The home zone, renamed");
    expect(body).not.toHaveProperty("transfer");
    expect(body).not.toHaveProperty("catalog");
  });

  it("removes an access list chip and sends the shorter list", async () => {
    const writes = recordWrites();
    const { form } = await settings(PRIMARY);
    await waitFor(() => expect(within(form).getByTestId("transfer-allow").textContent).toBe("transfer-peers"));
    fireEvent.click(within(form).getByRole("button", { name: "Remove the access list transfer-peers" }));
    expect(within(form).getByTestId("transfer-allow-none")).toBeTruthy();
    fireEvent.click(within(form).getByTestId("form-submit"));
    expect(await screen.findByText("Settings of example.test saved")).toBeTruthy();
    expect(patches(writes)[0]?.body).toMatchObject({ transfer: { allow: [] } });
  });

  it("shows the id of an access list that does not exist any more", async () => {
    const zone = dnsState().zones.find((z) => z.id === PRIMARY);
    if (zone?.transfer) zone.transfer.allow = ["0190d1c2-0000-7000-8000-00000000dead"];
    const { form } = await settings(PRIMARY);
    await waitFor(() => expect(within(form).getByTestId("transfer-allow").textContent).toBe("0190d1c2-0000-7000-8000-00000000dead"));
  });

  it("checks the NOTIFY rows before it sends anything", async () => {
    const writes = recordWrites();
    const { form } = await settings(PRIMARY);
    fireEvent.click(within(form).getByTestId("transfer-notify-add"));
    fireEvent.input(input(form, "field-notify.0.address"), { target: { value: "ns.example.test" } });
    fireEvent.input(input(form, "field-notify.0.port"), { target: { value: "70000" } });
    fireEvent.click(within(form).getByTestId("form-submit"));
    await waitFor(() => expect(within(form).getAllByTestId("field-error").map((e) => e.dataset.field).sort()).toEqual(["notify.0.address", "notify.0.port"]));
    expect(patches(writes)).toHaveLength(0);
    fireEvent.input(input(form, "field-notify.0.address"), { target: { value: "2001:db8::54" } });
    fireEvent.input(input(form, "field-notify.0.port"), { target: { value: "" } });
    fireEvent.click(within(form).getByTestId("form-submit"));
    expect(await screen.findByText("Settings of example.test saved")).toBeTruthy();
    expect(patches(writes)[0]?.body).toMatchObject({ transfer: { notify: [{ address: "2001:db8::54", port: 53 }] } });
  });

  it("offers no transfers for a stub zone", async () => {
    open(DNS_IDS.zone.corp);
    const form = await screen.findByTestId("zone-settings");
    await waitFor(() => expect(within(form).getByTestId("zone-source")).toBeTruthy());
    expect(within(form).queryByTestId("zone-transfer")).toBeNull();
    expect(within(form).getByTestId("field-source")).toBeTruthy();
  });
});

describe("a secondary zone", () => {
  it("shows the primaries as rows, the transfer state and the SOA and name servers read-only", async () => {
    const { view, form } = await settings(SECONDARY);
    expect(within(form).getByTestId("zone-from-primary")).toBeTruthy();
    expect(input(form, "field-primaries.0.address").value).toBe("198.51.100.53");
    expect(input(form, "field-primaries.0.port").value).toBe("53");
    expect(input(form, "field-primaries.0.key").value).toBe("xfr.example.test");
    for (const id of ["field-soa.mname", "field-soa.rname", "field-soa.refresh", "field-name_servers", "field-serial"]) {
      expect(input(form, id).disabled).toBe(true);
    }
    expect(within(form).queryByTestId("field-source")).toBeNull();
    const status = await within(form).findByTestId("zone-transfer-status");
    await waitFor(() => expect(within(status).getByTestId("transfer-serial").dataset.key).toBe("7"));
    const primary = within(status).getByTestId("transfer-primary");
    expect(primary.dataset.key).toBe("198.51.100.53:53");
    expect(within(primary).getByTestId("transfer-last-success").querySelector("time")).toBeTruthy();
    expect(within(primary).getByTestId("transfer-last-error").dataset.code).toBe("");
    expect(within(status).getByTestId("transfer-running").dataset.state).toBe("idle");
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("names the code and the meaning of a failed transfer", async () => {
    server.use(
      http.get("/api/v1/dns/zones/:id/transfer", () =>
        HttpResponse.json({
          zone: SECONDARY,
          serial: 7,
          primaries: [{ address: "198.51.100.53:53", last_error: "dns.transfer.tsig" }],
          running: false,
        }),
      ),
    );
    const { form } = await settings(SECONDARY);
    const error = await within(form).findByTestId("transfer-last-error");
    expect(error.dataset.code).toBe("dns.transfer.tsig");
    expect(error.textContent).toBe("dns.transfer.tsig The TSIG signature was not accepted.");
  });

  it("queues a transfer with Transfer now and then shows the new serial", async () => {
    const writes = recordWrites();
    const { form } = await settings(SECONDARY);
    await waitFor(() => expect(within(form).getByTestId("transfer-serial").dataset.key).toBe("7"));
    fireEvent.click(within(form).getByTestId("transfer-now"));
    expect(await screen.findByText("Transfer of lab.example.test queued")).toBeTruthy();
    expect(writes().filter((w) => w.method === "POST" && w.url.endsWith(`/zones/${SECONDARY}/transfer`))).toHaveLength(1);
    expect(within(form).getByTestId("transfer-running").dataset.state).toBe("running");
    await waitFor(() => expect(within(form).getByTestId("transfer-running").dataset.state).toBe("idle"), { timeout: 4000 });
    expect(within(form).getByTestId("transfer-serial").dataset.key).toBe("8");
  });

  it("saves the primaries as source and never sends the SOA, the serial or the name servers", async () => {
    const writes = recordWrites();
    const { form } = await settings(SECONDARY);
    fireEvent.click(within(form).getByTestId("transfer-primary-add"));
    fireEvent.input(input(form, "field-primaries.1.address"), { target: { value: "203.0.113.53" } });
    fireEvent.input(input(form, "field-primaries.1.port"), { target: { value: "853" } });
    fireEvent.input(input(form, "field-primaries.1.tls_name"), { target: { value: "ns.example.test" } });
    fireEvent.click(input(form, "field-primaries.1.xot"));
    fireEvent.click(within(form).getByTestId("form-submit"));
    expect(await screen.findByText("Settings of lab.example.test saved")).toBeTruthy();
    const sent = patches(writes);
    expect(sent).toHaveLength(1);
    expect(sent[0]?.body).toEqual({
      description: null,
      source: {
        primaries: [
          { address: "198.51.100.53", port: 53, key: "xfr.example.test", xot: false },
          { address: "203.0.113.53", port: 853, xot: true, tls_name: "ns.example.test" },
        ],
      },
    });
    expect(writes().filter((w) => w.url.includes("/records/batch"))).toHaveLength(0);
  });

  it("needs at least one primary", async () => {
    const writes = recordWrites();
    const { form } = await settings(SECONDARY);
    fireEvent.click(within(form).getByTestId("transfer-primary-remove"));
    fireEvent.click(within(form).getByTestId("form-submit"));
    await waitFor(() => expect(within(form).getAllByTestId("field-error").map((e) => e.dataset.field)).toEqual(["primaries"]));
    expect(patches(writes)).toHaveLength(0);
  });

  it("says so quietly when the server has no transfer route", async () => {
    server.use(
      http.get("/api/v1/dns/zones/:id/transfer", () =>
        HttpResponse.json({ type: "about:blank", status: 501, code: "sys.not_implemented", title: "Not Implemented", detail: "", params: {} }, { status: 501 }),
      ),
    );
    const { form } = await settings(SECONDARY);
    expect(await within(form).findByTestId("zone-transfer-unavailable")).toBeTruthy();
    expect(within(form).queryByTestId("error-notice")).toBeNull();
    expect(within(form).queryByTestId("transfer-now")).toBeNull();
  });
});

describe("without write access", () => {
  it("disables every control of a primary zone", async () => {
    await signInWithRoles(["viewer"]);
    const { form } = await settings(PRIMARY);
    await waitFor(() => expect(within(form).getByTestId("transfer-allow")).toBeTruthy());
    for (const id of ["field-allow-add", "field-require_tsig", "field-xot", "field-catalog", "field-soa.mname", "field-description"]) {
      expect(input(form, id).disabled).toBe(true);
    }
    expect((within(form).getByTestId("transfer-allow-remove") as HTMLButtonElement).disabled).toBe(true);
    expect(within(form).queryByTestId("transfer-notify-add")).toBeNull();
    expect(within(form).queryByTestId("form-submit")).toBeNull();
  });

  it("shows the state of a secondary zone without Transfer now", async () => {
    await signInWithRoles(["viewer"]);
    const { form } = await settings(SECONDARY);
    await waitFor(() => expect(within(form).getByTestId("transfer-serial").dataset.key).toBe("7"));
    expect(within(form).queryByTestId("transfer-now")).toBeNull();
    expect(within(form).queryByTestId("transfer-primary-add")).toBeNull();
    expect(input(form, "field-primaries.0.address").disabled).toBe(true);
  });
});

describe("the records of a secondary zone", () => {
  it("are read-only and say where they come from", async () => {
    open(SECONDARY, "records");
    expect(await screen.findByTestId("zone-records-readonly")).toBeTruthy();
    await waitFor(() => expect(rows("dns-records").length).toBe(1));
    expect(screen.queryByTestId("dns-rrset-add")).toBeNull();
    expect(screen.queryByTestId("dns-batch-toggle")).toBeNull();
    fireEvent.dblClick(cell(row("dns-records", "@/SOA/0"), "ttl"));
    expect(screen.queryByTestId("cell-editor")).toBeNull();
  });

  it("keep an RRset of origin transfer read-only for everyone, with no take-over", async () => {
    const set = dnsState().rrsets.get(PRIMARY)?.find((s) => s.name === "www.example.test" && s.type === "A");
    if (set) set.origin = "transfer";
    open(PRIMARY, "records");
    await waitFor(() => expect(rows("dns-records").length).toBe(14));
    const www = () => row("dns-records", "www/A/0");
    expect(within(www()).getByTestId("rrset-origin").dataset.kind).toBe("transfer");
    expect(within(www()).getByTestId("rrset-origin").textContent).toBe("Zone transfer");
    fireEvent.dblClick(cell(www(), "data"));
    expect(within(cell(www(), "data")).queryByTestId("cell-editor")).toBeNull();
    expect(await rowActions(www())).toEqual([]);
  });
});
