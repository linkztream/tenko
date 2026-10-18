// The query log page: the newest queries of the node with their columns, the filters and their
// local checks, paging by cursor, the clients as pseudonyms or withheld, the kill switch for
// administrators, the empty states, the notices for a log that is off, a node without the role,
// a server without the DNS service and a switched-off module, the audit of every read, Swedish.
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { audit } from "../../api/mock/audit-store";
import { server } from "../../api/mock/node";
import { dnsLogState } from "../../api/mock/routes-dns";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { signInAlex } from "../../auth/account/testkit";
import { signInWithRoles } from "../../auth/scope-testkit";
import { setSessionForTest } from "../../auth/session";
import { setLocale } from "../../i18n";
import { dnsNotBuilt } from "../testkit";
import LogPage from "./LogPage";

beforeEach(async () => {
  await signInAlex();
});

afterEach(async () => {
  setSessionForTest(null);
  await setLocale("en");
});

function open() {
  return renderRoute(LogPage, { url: "/dns/log", path: "/dns/log" });
}

function lines(): HTMLElement[] {
  return screen.queryAllByTestId("dns-log-row");
}

function names(): string[] {
  return lines().map((row) => row.dataset.key ?? "");
}

function col(row: HTMLElement, id: string): string {
  return row.querySelector<HTMLElement>(`[data-col="${id}"]`)?.textContent ?? "";
}

async function loaded(count = 50) {
  await waitFor(() => expect(lines()).toHaveLength(count));
}

function filter(field: string, value: string) {
  const form = screen.getByTestId("dns-log-filters");
  const control = within(form).getByTestId(`field-${field}`);
  if (control.tagName === "SELECT") fireEvent.change(control, { target: { value } });
  else fireEvent.input(control, { target: { value } });
}

/** The `datetime-local` value of a UTC time in the test's own time zone. */
function local(iso: string): string {
  const at = new Date(iso);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${at.getFullYear()}-${pad(at.getMonth() + 1)}-${pad(at.getDate())}T${pad(at.getHours())}:${pad(at.getMinutes())}`;
}

function apply() {
  fireEvent.click(within(screen.getByTestId("dns-log-filters")).getByTestId("form-submit"));
}

describe("the query log page", () => {
  it("shows the newest queries of the node with their columns and the log's figures", async () => {
    const view = open();
    await loaded();
    const first = lines()[0]!;
    expect(first.dataset.key).toBe("time.example.org");
    expect(col(first, "type")).toBe("A");
    expect(col(first, "rcode")).toBe("SERVFAIL");
    expect(col(first, "transport")).toBe("DNS over HTTPS");
    expect(col(first, "latency")).toMatch(/ ms$/);
    const client = within(first).getByTestId("dns-log-client");
    expect(client.dataset.kind).toBe("pseudonym");
    expect(client.textContent).toMatch(/^p:[0-9a-f]{16}$/);
    expect(screen.getAllByTestId("dns-log-cached").length).toBeGreaterThan(0);
    const figures = screen.getByTestId("dns-log-figures");
    expect(figures.dataset).toMatchObject({ state: "on", client: "pseudonym", written: "60", dropped: "0" });
    expect(figures.textContent).toContain("pseudonymised");
    expect((screen.getByTestId("field-node") as HTMLSelectElement).value).toBe("1");
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("pages to older queries by cursor and back", async () => {
    open();
    await loaded();
    expect((screen.getByTestId("dns-log-newer") as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(screen.getByTestId("dns-log-older"));
    await loaded(10);
    expect(screen.getByTestId("dns-log-paging").dataset.page).toBe("2");
    expect(names().at(-1)).toBe("www.example.test");
    expect((screen.getByTestId("dns-log-older") as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(screen.getByTestId("dns-log-newer"));
    await loaded();
    expect(names()[0]).toBe("time.example.org");
  });

  it("filters by name, RCODE, client and time, and clears the filters", async () => {
    open();
    await loaded();
    filter("qname", "example.test");
    filter("rcode", "3");
    apply();
    await waitFor(() => expect(new Set(names())).toEqual(new Set(["missing.example.test"])));
    expect(lines()).toHaveLength(10);

    filter("rcode", "");
    filter("qname", "lab.example.test");
    apply();
    await waitFor(() => expect(new Set(names())).toEqual(new Set(["printer.lab.example.test"])));
    expect(lines()).toHaveLength(10);

    const pseudonym = within(lines()[0]!).getByTestId("dns-log-client").textContent ?? "";
    filter("qname", "");
    filter("client", pseudonym);
    apply();
    await waitFor(() => expect(lines()).toHaveLength(20));
    expect(lines().every((row) => within(row).getByTestId("dns-log-client").textContent === pseudonym)).toBe(true);

    filter("client", "");
    filter("from", local("2026-10-17T11:59:00Z"));
    filter("until", local("2026-10-17T11:59:00Z"));
    apply();
    const empty = await screen.findByTestId("dns-log-empty");
    expect(empty.dataset.filtered).toBe("true");
    filter("from", local("2026-10-17T12:00:00Z"));
    filter("until", local("2026-10-17T12:00:00Z"));
    apply();
    await loaded();

    fireEvent.click(screen.getByTestId("dns-log-reset"));
    await loaded();
    expect((within(screen.getByTestId("dns-log-filters")).getByTestId("field-qname") as HTMLInputElement).value).toBe("");
  });

  it("checks the filters before it asks", async () => {
    open();
    await loaded();
    filter("client", "somebody");
    filter("from", "2026-10-17T12:30");
    filter("until", "2026-10-17T12:00");
    apply();
    const errors = await screen.findAllByTestId("field-error");
    expect(errors.map((e) => e.dataset.field)).toEqual(["client", "until"]);
    expect(lines()).toHaveLength(50);
  });

  it("says when no query matches", async () => {
    open();
    await loaded();
    filter("qname", "nowhere.example.test");
    apply();
    const empty = await screen.findByTestId("dns-log-empty");
    expect(empty.dataset.filtered).toBe("true");
    expect(lines()).toHaveLength(0);
  });

  it("audits every read through the API", async () => {
    open();
    await loaded();
    filter("rcode", "2");
    apply();
    await loaded(10);
    const reads = audit.records.filter((r) => r.draft.action === "dns.log.read");
    expect(reads.length).toBeGreaterThanOrEqual(2);
    expect(reads.at(-1)?.draft.details?.context).toMatchObject({ "filter.rcode": "2", from_cursor: "newest" });
  });

  it("withholds addresses from a viewer and shows them to an administrator", async () => {
    dnsLogState().client = "address";
    const admin = open();
    await loaded();
    expect(within(lines()[0]!).getByTestId("dns-log-client").dataset.kind).toBe("address");
    admin.unmount();

    await signInWithRoles(["viewer"]);
    dnsLogState().client = "address";
    open();
    await loaded();
    expect(screen.queryAllByTestId("dns-log-client")).toHaveLength(0);
    expect(col(lines()[0]!, "client")).toBe("Not shown");
    expect(screen.queryByTestId("dns-log-stop")).toBeNull();
  });

  it("stops and starts the log for an administrator", async () => {
    open();
    await loaded();
    fireEvent.click(screen.getByTestId("dns-log-stop"));
    expect(await screen.findByTestId("dns-log-stopped")).toBeTruthy();
    expect(dnsLogState().mode).toBe("stopped");
    expect(screen.getByTestId("dns-log-figures").dataset.state).toBe("stopped");
    fireEvent.click(screen.getByTestId("dns-log-start"));
    await waitFor(() => expect(screen.queryByTestId("dns-log-stopped")).toBeNull());
    expect(dnsLogState().mode).toBe("on");
    expect(audit.records.filter((r) => r.draft.action === "dns.log.stop" || r.draft.action === "dns.log.start").map((r) => r.draft.action)).toEqual(["dns.log.stop", "dns.log.start"]);
  });

  it("shows where the log is set when it is off", async () => {
    dnsLogState().mode = "off";
    open();
    const off = await screen.findByTestId("dns-log-off");
    expect(within(off).getByTestId("dns-log-settings-link").getAttribute("href")).toBe("/settings/security");
    expect(screen.queryByTestId("dns-log-filters")).toBeNull();
    expect(screen.queryByTestId("dns-log-stop")).toBeNull();
  });

  it("says when the node does not run the DNS role", async () => {
    server.use(
      http.get("/api/v1/nodes/:id/dns", () =>
        HttpResponse.json(
          { type: "about:blank", status: 409, code: "dns.node.not_dns", title: "Not a DNS node", detail: "node 1 does not run the dns role", params: { node: "1" } },
          { status: 409, headers: { "content-type": "application/problem+json" } },
        ),
      ),
    );
    open();
    expect(await screen.findByTestId("dns-log-not-dns")).toBeTruthy();
  });

  it("says when the server has no DNS service or the module is off", async () => {
    dnsNotBuilt();
    const first = open();
    expect(await screen.findByTestId("dns-not-built")).toBeTruthy();
    first.unmount();
    server.use(
      http.get("/api/v1/nodes/:id/dns", () =>
        HttpResponse.json(
          { type: "about:blank", status: 404, code: "sys.route_not_found", title: "Not Found", detail: "no such route", params: {} },
          { status: 404, headers: { "content-type": "application/problem+json" } },
        ),
      ),
    );
    open();
    expect(await screen.findByTestId("dns-off")).toBeTruthy();
  });

  it("speaks Swedish", async () => {
    await setLocale("sv");
    open();
    await loaded();
    expect(screen.getByRole("heading", { level: 1 }).textContent).toContain("Frågelogg");
    expect(col(lines()[0]!, "transport")).toBe("DNS över HTTPS");
    expect(within(screen.getByTestId("dns-log-filters")).getByTestId("form-submit").textContent).toBe("Visa");
  });
});
