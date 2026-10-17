// The zone page: the record grid grouped by RRset, inline edits of TTL and data, the RRsets
// IPAM keeps (read-only until taken over), adding and deleting RRsets, the batch with its dry
// run and diff, the settings tab (SOA, apex NS, serial policy), the history tab, the export,
// and the notice of a server without the DNS service.
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DNS_IDS } from "../api/mock/dns-model";
import { server } from "../api/mock/node";
import { dnsState } from "../api/mock/routes-dns";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { signInAlex } from "../auth/account/testkit";
import { signInWithRoles } from "../auth/scope-testkit";
import { setSessionForTest } from "../auth/session";
import { setLocale } from "../i18n";
import { cell, dnsNotBuilt, recordWrites, row, rowAction, rowActions, rows } from "./testkit";
import ZonePage from "./ZonePage";

const ZONE = DNS_IDS.zone.example;

beforeEach(async () => {
  await signInAlex();
});

afterEach(async () => {
  setSessionForTest(null);
  await setLocale("en");
});

function open(tab = "") {
  return renderRoute(ZonePage, { url: `/dns/zones/${ZONE}${tab ? `/${tab}` : ""}`, path: "/dns/zones/:id/:tab?", routes: { "/dns": () => <div data-testid="zones-page" /> } });
}

async function loaded() {
  await waitFor(() => expect(rows("dns-records").length).toBe(14));
}

const sets = () => dnsState().rrsets.get(ZONE) ?? [];
const setOf = (name: string, type: string) => sets().find((s) => s.name === name && s.type === type);
const batches = (writes: ReturnType<typeof recordWrites>) => writes().filter((w) => w.url.includes("/records/batch"));

describe("the record grid", () => {
  it("shows the zone and its records grouped by RRset", async () => {
    const view = open();
    expect(await screen.findByTestId("zone-name")).toBeTruthy();
    expect(screen.getByTestId("zone-name").textContent).toBe("example.test");
    expect(screen.getByTestId("zone-header-serial").dataset.key).toBe("2026101701");
    await loaded();
    const first = row("dns-records", "www/A/0");
    const second = row("dns-records", "www/A/1");
    expect(cell(first, "name").textContent).toBe("www");
    expect(cell(second, "name").textContent).toBe("");
    expect(cell(second, "data").textContent).toBe("192.0.2.81");
    expect(within(row("dns-records", "nas/A/0")).getByTestId("rrset-origin").dataset.kind).toBe("ipam");
    expect(cell(row("dns-records", "@/MX/0"), "data").textContent).toBe("10 mail.example.test");
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("filters by the start of the name", async () => {
    open();
    await loaded();
    fireEvent.input(screen.getByTestId("filter-input"), { target: { value: "n" } });
    await waitFor(() => expect(rows("dns-records").map((r) => r.dataset.key)).toEqual(["nas/A/0", "ns1/A/0"]));
  });

  it("saves a new TTL of an RRset in place", async () => {
    const writes = recordWrites();
    open();
    await loaded();
    fireEvent.dblClick(cell(row("dns-records", "www/A/0"), "ttl"));
    const editor = (await within(cell(row("dns-records", "www/A/0"), "ttl")).findByTestId("cell-editor")) as HTMLInputElement;
    fireEvent.input(editor, { target: { value: "600" } });
    fireEvent.keyDown(editor, { key: "Enter" });
    await waitFor(() => expect(setOf("www.example.test", "A")?.ttl).toBe(600));
    const sent = batches(writes);
    expect(sent).toHaveLength(1);
    expect(sent[0]?.url).not.toContain("dry_run");
    expect(sent[0]?.body).toEqual({
      changes: [{ op: "set", name: "www.example.test", type: "A", ttl: 600, records: [{ type: "A", address: "192.0.2.80" }, { type: "A", address: "192.0.2.81" }] }],
    });
    expect(await screen.findByText(/1 RRset changed, serial/)).toBeTruthy();
  });

  it("checks record data before it saves", async () => {
    open();
    await loaded();
    fireEvent.dblClick(cell(row("dns-records", "www/A/1"), "data"));
    const editor = (await within(cell(row("dns-records", "www/A/1"), "data")).findByTestId("cell-editor")) as HTMLInputElement;
    fireEvent.input(editor, { target: { value: "2001:db8::1" } });
    fireEvent.keyDown(editor, { key: "Enter" });
    expect(await screen.findByText("Not an IPv4 address.")).toBeTruthy();
    fireEvent.input(editor, { target: { value: "192.0.2.82" } });
    fireEvent.keyDown(editor, { key: "Enter" });
    await waitFor(() => expect(setOf("www.example.test", "A")?.records).toEqual([{ type: "A", address: "192.0.2.80" }, { type: "A", address: "192.0.2.82" }]));
  });

  it("keeps the RRsets of IPAM read-only until the person takes one over", async () => {
    const writes = recordWrites();
    open();
    await loaded();
    const nas = () => row("dns-records", "nas/A/0");
    fireEvent.dblClick(cell(nas(), "data"));
    expect(within(cell(nas(), "data")).queryByTestId("cell-editor")).toBeNull();
    expect(await rowActions(nas())).toEqual(["takeover"]);
    await rowAction(nas(), "takeover");
    fireEvent.click(within(await screen.findByTestId("dialog-take-over")).getByTestId("confirm-ok"));
    expect(await within(nas()).findByTestId("rrset-taken-over")).toBeTruthy();
    fireEvent.dblClick(cell(nas(), "data"));
    const editor = (await within(cell(nas(), "data")).findByTestId("cell-editor")) as HTMLInputElement;
    fireEvent.input(editor, { target: { value: "192.0.2.111" } });
    fireEvent.keyDown(editor, { key: "Enter" });
    await waitFor(() => expect(setOf("nas.example.test", "A")?.origin).toBe("manual"));
    expect(batches(writes)[0]?.body).toMatchObject({ changes: [{ op: "set", name: "nas.example.test", take_over: true }] });
  });

  it("shows the refusal of the server when an RRset of another origin is changed", async () => {
    open();
    await loaded();
    // Another writer took the RRset while the page was open.
    const www = setOf("www.example.test", "A");
    if (www) www.origin = "dynamic";
    fireEvent.dblClick(cell(row("dns-records", "www/A/0"), "ttl"));
    const editor = (await within(cell(row("dns-records", "www/A/0"), "ttl")).findByTestId("cell-editor")) as HTMLInputElement;
    fireEvent.input(editor, { target: { value: "60" } });
    fireEvent.keyDown(editor, { key: "Enter" });
    expect(await screen.findByText("www.example.test A is kept by another writer. Take it over first to change it here.")).toBeTruthy();
  });

  it("adds an RRset through the dialog, line by line", async () => {
    const writes = recordWrites();
    open();
    await loaded();
    fireEvent.click(screen.getByTestId("dns-rrset-add"));
    const dialog = await screen.findByTestId("dialog-rrset-form");
    fireEvent.input(within(dialog).getByTestId("field-name"), { target: { value: "printer" } });
    fireEvent.input(within(dialog).getByTestId("field-data"), { target: { value: "192.0.2.30\nnot-an-address" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    expect((await within(dialog).findByTestId("field-error")).textContent).toBe("Line 2: Not an IPv4 address.");
    expect(batches(writes)).toHaveLength(0);
    fireEvent.input(within(dialog).getByTestId("field-data"), { target: { value: "192.0.2.30\n\n192.0.2.31" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(screen.queryByTestId("dialog-rrset-form")).toBeNull());
    expect(batches(writes)[0]?.body).toEqual({
      changes: [{ op: "add", name: "printer.example.test", type: "A", ttl: 3600, records: [{ type: "A", address: "192.0.2.30" }, { type: "A", address: "192.0.2.31" }] }],
    });
    await waitFor(() => expect(rows("dns-records").map((r) => r.dataset.key)).toContain("printer/A/1"));
  });

  it("deletes an RRset after the confirmation", async () => {
    open();
    await loaded();
    await rowAction(row("dns-records", "ftp/CNAME/0"), "delete");
    fireEvent.click(within(await screen.findByTestId("dialog-rrset-delete")).getByTestId("confirm-ok"));
    await waitFor(() => expect(setOf("ftp.example.test", "CNAME")).toBeUndefined());
    await waitFor(() => expect(rows("dns-records").map((r) => r.dataset.key)).not.toContain("ftp/CNAME/0"));
  });

  it("offers a viewer no change at all", async () => {
    await signInWithRoles(["viewer"]);
    open();
    await loaded();
    expect(screen.queryByTestId("dns-rrset-add")).toBeNull();
    expect(screen.queryByTestId("dns-batch-toggle")).toBeNull();
    expect(screen.queryByTestId("dns-zone-delete")).toBeNull();
    fireEvent.dblClick(cell(row("dns-records", "www/A/0"), "ttl"));
    expect(within(cell(row("dns-records", "www/A/0"), "ttl")).queryByTestId("cell-editor")).toBeNull();
  });
});

describe("the batch", () => {
  it("collects changes, shows the diff of a dry run and applies them", async () => {
    const writes = recordWrites();
    open();
    await loaded();
    const serial = dnsState().zones.find((z) => z.id === ZONE)?.soa_serial;
    fireEvent.click(screen.getByTestId("dns-batch-toggle"));
    fireEvent.dblClick(cell(row("dns-records", "mail/A/0"), "ttl"));
    const editor = (await within(cell(row("dns-records", "mail/A/0"), "ttl")).findByTestId("cell-editor")) as HTMLInputElement;
    fireEvent.input(editor, { target: { value: "300" } });
    fireEvent.keyDown(editor, { key: "Enter" });
    await rowAction(row("dns-records", "ftp/CNAME/0"), "delete");
    fireEvent.click(within(await screen.findByTestId("dialog-rrset-delete")).getByTestId("confirm-ok"));
    await waitFor(() => expect(screen.getByTestId("dns-batch").dataset.count).toBe("2"));
    expect(within(row("dns-records", "mail/A/0")).getByTestId("rrset-pending")).toBeTruthy();
    // Nothing is sent while the batch collects.
    expect(batches(writes)).toHaveLength(0);
    fireEvent.click(screen.getByTestId("dns-batch-review"));
    const diff = await screen.findByTestId("dialog-batch-diff");
    expect(batches(writes)[0]?.url).toContain("dry_run=true");
    const changes = within(diff).getAllByTestId("plan-change");
    expect(changes.map((c) => [c.dataset.key, c.dataset.kind])).toEqual([
      ["ftp.example.test/CNAME", "delete"],
      ["mail.example.test/A", "change"],
    ]);
    expect(setOf("mail.example.test", "A")?.ttl).toBe(3600);
    fireEvent.click(within(diff).getByTestId("plan-confirm"));
    await waitFor(() => expect(screen.queryByTestId("dialog-batch-diff")).toBeNull());
    expect(setOf("mail.example.test", "A")?.ttl).toBe(300);
    expect(setOf("ftp.example.test", "CNAME")).toBeUndefined();
    expect(dnsState().zones.find((z) => z.id === ZONE)?.soa_serial).toBeGreaterThan(serial ?? 0);
    expect(screen.getByTestId("dns-batch").dataset.count).toBe("0");
    expect(await screen.findByText(/2 RRsets changed, serial/)).toBeTruthy();
  });

  it("drops a waiting change and keeps the dry run error in the diff dialog", async () => {
    open();
    await loaded();
    fireEvent.click(screen.getByTestId("dns-batch-toggle"));
    fireEvent.click(screen.getByTestId("dns-rrset-add"));
    const dialog = await screen.findByTestId("dialog-rrset-form");
    fireEvent.input(within(dialog).getByTestId("field-name"), { target: { value: "www" } });
    fireEvent.change(within(dialog).getByTestId("field-type"), { target: { value: "CNAME" } });
    fireEvent.input(within(dialog).getByTestId("field-data"), { target: { value: "ftp" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(screen.getByTestId("dns-batch").dataset.count).toBe("1"));
    fireEvent.click(screen.getByTestId("dns-batch-review"));
    const diff = await screen.findByTestId("dialog-batch-diff");
    expect((await within(diff).findByTestId("error-notice")).dataset.code).toBe("dns.record.conflict");
    expect((within(diff).getByTestId("plan-confirm") as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(within(diff).getByTestId("plan-cancel"));
    fireEvent.click(screen.getByTestId("batch-item-drop"));
    expect(screen.getByTestId("dns-batch").dataset.count).toBe("0");
  });
});

describe("the settings tab", () => {
  it("saves the SOA values, the serial policy and the name servers", async () => {
    const writes = recordWrites();
    open("settings");
    const form = await screen.findByTestId("zone-settings");
    await waitFor(() => expect((within(form).getByTestId("field-name_servers") as HTMLInputElement).value).toBe("ns1.example.test"));
    fireEvent.input(within(form).getByTestId("field-soa.refresh"), { target: { value: "7200" } });
    fireEvent.change(within(form).getByTestId("field-serial"), { target: { value: "counter" } });
    fireEvent.input(within(form).getByTestId("field-name_servers"), { target: { value: "ns1, ns2.example.test" } });
    fireEvent.click(within(form).getByTestId("form-submit"));
    expect(await screen.findByText("Settings of example.test saved")).toBeTruthy();
    const zone = dnsState().zones.find((z) => z.id === ZONE);
    expect(zone?.soa.refresh).toBe(7200);
    expect(zone?.serial).toBe("counter");
    expect(setOf("example.test", "NS")?.records).toEqual([
      { type: "NS", host: "ns1.example.test" },
      { type: "NS", host: "ns2.example.test" },
    ]);
    const patch = writes().find((w) => w.method === "PATCH");
    expect(patch?.body).not.toHaveProperty("update");
  });

  it("refuses an empty name server list and a TTL that is no number", async () => {
    open("settings");
    const form = await screen.findByTestId("zone-settings");
    await waitFor(() => expect((within(form).getByTestId("field-name_servers") as HTMLInputElement).value).not.toBe(""));
    fireEvent.input(within(form).getByTestId("field-name_servers"), { target: { value: "" } });
    fireEvent.input(within(form).getByTestId("field-soa.ttl"), { target: { value: "an hour" } });
    fireEvent.click(within(form).getByTestId("form-submit"));
    await waitFor(() => expect(within(form).getAllByTestId("field-error").map((e) => e.dataset.field).sort()).toEqual(["name_servers", "soa.ttl"]));
  });
});

describe("the history tab", () => {
  it("shows the serial and the changes of the zone from the audit log", async () => {
    open();
    await loaded();
    fireEvent.dblClick(cell(row("dns-records", "www/A/0"), "ttl"));
    const editor = (await within(cell(row("dns-records", "www/A/0"), "ttl")).findByTestId("cell-editor")) as HTMLInputElement;
    fireEvent.input(editor, { target: { value: "900" } });
    fireEvent.keyDown(editor, { key: "Enter" });
    await waitFor(() => expect(setOf("www.example.test", "A")?.ttl).toBe(900));
    fireEvent.click(screen.getByTestId("zone-tab-history"));
    const history = await screen.findByTestId("zone-history");
    const serial = String(dnsState().zones.find((z) => z.id === ZONE)?.soa_serial);
    await waitFor(() => expect(within(history).getByTestId("zone-serial").textContent).toBe(serial));
    await waitFor(() => expect(within(history).getAllByTestId("history-entry").map((e) => e.dataset.kind)).toContain("dns.record.change"));
  });

  it("says why there are no changes for an account that does not read the audit log", async () => {
    server.use(
      http.get("/api/v1/audit", () =>
        HttpResponse.json({ type: "about:blank", status: 403, code: "auth.forbidden", title: "Forbidden", detail: "", params: {} }, { status: 403 }),
      ),
    );
    open("history");
    expect(await screen.findByTestId("zone-history-refused")).toBeTruthy();
  });
});

describe("the export", () => {
  it("downloads the zone file", async () => {
    const created = vi.fn((blob: Blob) => {
      void blob;
      return "blob:zone";
    });
    const urls = vi.spyOn(URL, "createObjectURL").mockImplementation(created as never);
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);
    open();
    await loaded();
    fireEvent.click(screen.getByTestId("dns-zone-export"));
    await waitFor(() => expect(click).toHaveBeenCalledTimes(1));
    const blob = created.mock.calls[0]?.[0] as Blob;
    expect(await blob.text()).toMatch(/^\$ORIGIN example\.test\.\n\$TTL 3600\n/);
    urls.mockRestore();
    click.mockRestore();
  });
});

describe("a server without the DNS service", () => {
  it("says the service is not built yet", async () => {
    dnsNotBuilt();
    const view = open();
    expect(await screen.findByTestId("dns-not-built")).toBeTruthy();
    expect(screen.queryByTestId("grid-dns-records")).toBeNull();
    expect(await axeViolations(view.container)).toEqual([]);
  });
});
