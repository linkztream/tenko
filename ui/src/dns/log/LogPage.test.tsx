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

// WP10.1: how the answer was found and the queries the resolver sent for it.
describe("the resolution columns", () => {
  it("shows how each answer was found and its sub-queries, and nothing for a line that has neither", async () => {
    open();
    await loaded();
    const [newest, recursed] = lines();
    // The newest seeded query was forwarded; the one before was recursed with sub-queries.
    expect(col(newest!, "resolution")).toBe("Forwarded");
    expect(col(newest!, "subqueries")).toBe("");
    expect(col(recursed!, "resolution")).toBe("Recursed");
    expect(col(recursed!, "subqueries")).toBe("5");
    expect(lines().some((row) => col(row, "resolution") === "Cache")).toBe(true);
    expect(screen.getByRole("columnheader", { name: "Resolution" })).toBeTruthy();
    expect(screen.getByRole("columnheader", { name: "Sub-queries" })).toBeTruthy();
  });

  it("shows a line written before the resolution was logged without a tag, and an unknown word as written", async () => {
    const entries = dnsLogState().entries;
    const oldest = entries[0]!;
    delete oldest.resolution;
    delete oldest.subqueries;
    entries[entries.length - 1]!.resolution = "mystery";
    open();
    await loaded();
    expect(col(lines()[0]!, "resolution")).toBe("mystery");
    fireEvent.click(screen.getByTestId("dns-log-older"));
    await loaded(10);
    expect(col(lines().at(-1)!, "resolution")).toBe("");
  });

  it("speaks Swedish", async () => {
    await setLocale("sv");
    open();
    await loaded();
    expect(col(lines()[1]!, "resolution")).toBe("Rekurserad");
    expect(screen.getByRole("columnheader", { name: "Delfrågor" })).toBeTruthy();
  });
});
// WP10.1: end.

// WP10.4: the validation state and the extended error of each line, and the filter on the page.
function validatedLines() {
  const line = (qname: string, extra: Record<string, unknown>) => ({
    at: "2026-10-17T12:00:00.000Z",
    transport: "udp",
    qname,
    type: "A",
    rcode: 0,
    cached: false,
    duration_micros: 1_500,
    client: "p:3f2a9c0d81b7e645",
    ...extra,
  });
  return [
    line("secure.example.test", { validation: "secure" }),
    line("insecure.example.test", { validation: "insecure" }),
    line("bogus.example.test", { validation: "bogus", ede: 6, rcode: 2 }),
    line("indeterminate.example.test", { validation: "indeterminate" }),
    line("unvalidated.example.test", { validation: "unvalidated" }),
    line("secure2.example.test", { validation: "secure" }),
    line("old.example.test", {}),
    line("odd.example.test", { validation: "from_the_future", ede: 99 }),
    line("stale.example.test", { validation: "secure", ede: 3 }),
  ];
}

function serveValidatedLines(without?: string) {
  server.use(
    http.get("/api/v1/nodes/:id/dns/log", () =>
      HttpResponse.json({ items: validatedLines().filter((l) => l.qname !== without), next_cursor: null, revision: 1 }),
    ),
  );
}

describe("the validation columns", () => {
  it("shows the validation state and the extended error of each line, and nothing for a line without", async () => {
    serveValidatedLines();
    const view = open();
    await loaded(9);
    expect(screen.getByRole("columnheader", { name: "Validation" })).toBeTruthy();
    expect(screen.getByRole("columnheader", { name: "Extended error" })).toBeTruthy();
    const row = (qname: string) => lines().find((r) => r.dataset.key === qname)!;
    const tag = (qname: string) => within(row(qname)).queryByTestId("dns-log-validation");
    expect(tag("secure.example.test")?.dataset.state).toBe("secure");
    expect(tag("secure.example.test")?.textContent).toBe("Secure");
    expect(tag("insecure.example.test")?.textContent).toBe("Insecure");
    expect(tag("indeterminate.example.test")?.textContent).toBe("Indeterminate");
    expect(tag("unvalidated.example.test")?.textContent).toBe("Not validated");
    expect(tag("bogus.example.test")?.className).toContain("conflict");
    expect(tag("secure.example.test")?.className).not.toContain("conflict");
    expect(col(row("old.example.test"), "validation")).toBe("");
    expect(col(row("old.example.test"), "ede")).toBe("");
    // A state this version does not know is shown as written.
    expect(tag("odd.example.test")?.dataset.state).toBe("from_the_future");
    expect(tag("odd.example.test")?.textContent).toBe("from_the_future");
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("names the extended error by the registry and shows a code it does not know as the number", async () => {
    serveValidatedLines();
    open();
    await loaded(9);
    const ede = screen.getAllByTestId("dns-log-ede");
    expect(ede.map((e) => e.dataset.code)).toEqual(["6", "99", "3"]);
    expect(ede[0]?.textContent).toBe("6 DNSSEC Bogus");
    expect(ede[0]?.getAttribute("title")).toBe("DNSSEC Bogus");
    expect(ede[1]?.textContent).toBe("99");
    expect(ede[1]?.getAttribute("title")).toBeNull();
    expect(ede[2]?.textContent).toBe("3 Stale Answer");
  });

  it("narrows the page shown to a validation state at once, and back to every line", async () => {
    serveValidatedLines();
    open();
    await loaded(9);
    expect(screen.getByTestId("field-validation").getAttribute("aria-describedby")).toBe("dns-log-validation-help");
    expect([...(screen.getByTestId("field-validation") as HTMLSelectElement).options].map((o) => o.value)).toEqual([
      "",
      "secure",
      "insecure",
      "bogus",
      "indeterminate",
      "unvalidated",
    ]);
    filter("validation", "secure");
    await waitFor(() => expect(names()).toEqual(["secure.example.test", "secure2.example.test", "stale.example.test"]));
    filter("validation", "bogus");
    await waitFor(() => expect(names()).toEqual(["bogus.example.test"]));
    filter("validation", "");
    await waitFor(() => expect(lines()).toHaveLength(9));
  });

  it("says no query on the page has the state when none does, and keeps the paging", async () => {
    serveValidatedLines("bogus.example.test");
    open();
    await loaded(8);
    filter("validation", "bogus");
    const empty = await screen.findByTestId("dns-log-empty-validation");
    expect(empty.textContent).toBe("No query on this page has that validation state.");
    expect(screen.queryByTestId("dns-log-table")).toBeNull();
    expect(screen.queryByTestId("dns-log-empty")).toBeNull();
    expect(screen.getByTestId("dns-log-paging")).toBeTruthy();
    filter("validation", "");
    await loaded(8);
    expect(screen.queryByTestId("dns-log-empty-validation")).toBeNull();
  });

  it("shows the mock node's validation states and finds nothing for a state it never logged", async () => {
    open();
    await loaded();
    const states = screen.queryAllByTestId("dns-log-validation").map((tag) => tag.dataset.state);
    expect(states.length).toBeGreaterThan(0);
    expect(states.every((state) => state === "secure" || state === "insecure" || state === "bogus")).toBe(true);
    expect(screen.queryAllByTestId("dns-log-ede").every((tag) => tag.dataset.code === "6")).toBe(true);
    filter("validation", "indeterminate");
    expect(await screen.findByTestId("dns-log-empty-validation")).toBeTruthy();
  });

  it("speaks Swedish", async () => {
    await setLocale("sv");
    serveValidatedLines();
    open();
    await loaded(9);
    expect(screen.getByRole("columnheader", { name: "Validering" })).toBeTruthy();
    expect(screen.getByRole("columnheader", { name: "Utökat fel" })).toBeTruthy();
    const bogus = lines().find((r) => r.dataset.key === "bogus.example.test")!;
    expect(within(bogus).getByTestId("dns-log-validation").textContent).toBe("Ogiltig");
    const unvalidated = lines().find((r) => r.dataset.key === "unvalidated.example.test")!;
    expect(within(unvalidated).getByTestId("dns-log-validation").textContent).toBe("Ej validerad");
    expect(screen.getByText("Valfritt tillstånd")).toBeTruthy();
    filter("validation", "indeterminate");
    await waitFor(() => expect(names()).toEqual(["indeterminate.example.test"]));
  });
});
