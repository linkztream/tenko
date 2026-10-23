// The infrastructure cache section of the DNS settings page (WP10.4): nothing is read until
// asked, the zone cuts in the canonical order of their names with their servers, addresses,
// round-trip times and capabilities, the suffix filter and its check, paging by cursor, the flush
// of a suffix and of everything after a confirmation (audited; a read is not), a node whose
// resolver is off, a failed read, Swedish, and no accessibility violations.
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { audit } from "../../api/mock/audit-store";
import type { InfraCut } from "../../api/mock/dns-recursion-model";
import { server } from "../../api/mock/node";
import { dnsRecursionState } from "../../api/mock/routes-dns";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { resetToasts, signInAlex } from "../../auth/account/testkit";
import { setSessionForTest } from "../../auth/session";
import { setLocale } from "../../i18n";
import DnsSettingsPage from "./DnsSettingsPage";

beforeEach(async () => {
  await signInAlex();
});

afterEach(async () => {
  vi.restoreAllMocks();
  resetToasts();
  setSessionForTest(null);
  await setLocale("en");
});

function open() {
  return renderRoute(DnsSettingsPage, { url: "/settings/dns", path: "/settings/dns" });
}

async function section(): Promise<HTMLElement> {
  return screen.findByTestId("dns-infra");
}

const cuts = () => screen.queryAllByTestId("dns-infra-cut");
const zones = () => cuts().map((c) => c.dataset.key);

function suffix(text: string) {
  fireEvent.input(screen.getByTestId("field-infra-suffix"), { target: { value: text } });
}

function show() {
  fireEvent.submit(screen.getByTestId("dns-infra-form"));
}

/** The requests for the zone cuts sent so far. */
function reads(spy: ReturnType<typeof vi.spyOn>): string[] {
  return spy.mock.calls.map(([url]: [unknown]) => String(url)).filter((url: string) => url.includes("/dns/infra") && !url.includes("flush"));
}

function infraAudit() {
  return audit.records.filter((r) => r.draft.action.startsWith("dns.infra"));
}

const PROBLEM = { type: "about:blank", params: {} };

describe("the infrastructure cache section", () => {
  it("reads nothing until asked, then lists the zone cuts in the canonical order of their names", async () => {
    const spy = vi.spyOn(globalThis, "fetch");
    open();
    const infra = await section();
    expect(within(infra).getByRole("heading", { level: 2 }).textContent).toBe("Infrastructure cache");
    expect(screen.queryByTestId("dns-infra-cuts")).toBeNull();
    expect(screen.queryByTestId("dns-infra-paging")).toBeNull();
    expect(reads(spy)).toHaveLength(0);
    expect(screen.getByTestId("dns-infra-show").textContent).toBe("Show the zone cuts");
    show();
    await waitFor(() => expect(cuts()).toHaveLength(4));
    expect(zones()).toEqual(["example.org", "test", "example.test", "sub.example.test"]);
    expect(reads(spy)).toHaveLength(1);
    expect(screen.getByTestId("dns-infra-show").textContent).toBe("Read again");
    // The cache holds no client data: reading it is not audited.
    expect(infraAudit()).toHaveLength(0);
  });

  it("shows the addresses of a cut with the server, where they were learned, the times and the capabilities", async () => {
    open();
    await section();
    show();
    await waitFor(() => expect(cuts()).toHaveLength(4));
    const test = cuts()[1]!;
    expect(within(test).getByRole("heading", { level: 3 }).textContent).toContain("test");
    expect(within(test).getByTestId("dns-infra-ds").textContent).toBe("Not known yet");
    expect(within(test).getByRole("heading", { level: 3 }).textContent).toContain("60 min");
    const [address] = within(test).getAllByTestId("dns-infra-address");
    expect(address?.dataset.key).toBe("192.0.2.53");
    expect(address?.dataset.server).toBe("a.nic.test");
    expect(within(address!).getAllByRole("cell").map((c) => c.textContent)).toEqual(["a.nic.test", "192.0.2.53", "Glue", "21.5 ms", "64 ms", "0", "EDNS"]);
    expect(within(address!).getAllByTestId("dns-infra-capability").map((c) => c.dataset.key)).toEqual(["edns"]);
  });

  it("shows what is wrong with an address and what is not known of a cut", async () => {
    const [seed] = dnsRecursionState().cuts;
    const address = seed!.servers[0]!.addresses[0]!;
    const custom: InfraCut[] = [
      {
        zone: "bad.example.test",
        ds: "bogus",
        ttl: 90,
        servers: [
          {
            name: "ns1.bad.example.test",
            addresses: [
              { ...address, address: "192.0.2.20", origin: "authoritative", srtt_ms: null, p99_ms: null, edns: false, tcp_only: true, lower_case: true, failures: 12 },
              { ...address, address: "2001:db8::20", origin: "learned_elsewhere", lame: true, down: true, edns: null },
            ],
          },
          { name: "ns2.bad.example.test", addresses: [] },
        ],
      },
      { zone: "bare.example.test", ds: "weird", ttl: 7_200, servers: [{ name: "ns1.bare.example.test", addresses: [] }, { name: "ns2.bare.example.test", addresses: [] }] },
      { zone: "signed.example.test", ds: "secure", ttl: 30, servers: [] },
      { zone: "plain.example.test", ds: "insecure", ttl: 5_000, servers: [] },
    ];
    dnsRecursionState().cuts = custom;
    open();
    await section();
    show();
    await waitFor(() => expect(cuts()).toHaveLength(4));
    const bad = cuts().find((c) => c.dataset.key === "bad.example.test")!;
    expect(bad.dataset.ds).toBe("bogus");
    expect(within(bad).getByTestId("dns-infra-ds").textContent).toBe("Bogus");
    expect(within(bad).getByTestId("dns-infra-ds").className).toContain("discrepancy");
    expect(within(bad).getByRole("heading", { level: 3 }).textContent).toContain("90 s");
    const [first, second] = within(bad).getAllByTestId("dns-infra-address");
    expect(within(first!).getAllByRole("cell").map((c) => c.textContent)).toEqual(["ns1.bad.example.test", "192.0.2.20", "Authoritative answer", "Not asked", "", "12", "No EDNSTCP onlyLower case only"]);
    expect(within(first!).getAllByTestId("dns-infra-capability").map((c) => c.dataset.key)).toEqual(["no_edns", "tcp_only", "lower_case"]);
    // An origin this version does not know is shown as written; lame and unreachable stand out.
    expect(within(second!).getAllByRole("cell")[2]?.textContent).toBe("learned_elsewhere");
    const flagged = within(second!).getAllByTestId("dns-infra-capability");
    expect(flagged.map((c) => c.dataset.key)).toEqual(["lame", "down"]);
    expect(flagged.every((c) => c.className.includes("discrepancy"))).toBe(true);
    // Zone cuts without an address say how many servers they know; a state not known reads as not known.
    const bare = cuts().find((c) => c.dataset.key === "bare.example.test")!;
    expect(within(bare).getByTestId("dns-infra-ds").textContent).toBe("Not known yet");
    expect(bare.textContent).toContain("2 name servers, no address known yet");
    expect(within(bare).queryByRole("table")).toBeNull();
    expect(within(cuts().find((c) => c.dataset.key === "signed.example.test")!).getByTestId("dns-infra-ds").textContent).toBe("Signed");
    expect(within(cuts().find((c) => c.dataset.key === "plain.example.test")!).getByTestId("dns-infra-ds").textContent).toBe("Unsigned");
    expect(within(cuts().find((c) => c.dataset.key === "plain.example.test")!).getByRole("heading", { level: 3 }).textContent).toContain("83 min");
  });

  it("narrows the listing to a suffix and checks it first", async () => {
    const spy = vi.spyOn(globalThis, "fetch");
    open();
    await section();
    suffix("not a name");
    show();
    expect((await screen.findByTestId("field-error")).dataset.field).toBe("infra-suffix");
    expect(screen.getByTestId("field-error").textContent).toBe("Enter a DNS name, such as example.test.");
    expect(reads(spy)).toHaveLength(0);
    suffix("Example.Test.");
    show();
    await waitFor(() => expect(zones()).toEqual(["example.test", "sub.example.test"]));
    expect(screen.queryByTestId("field-error")).toBeNull();
    expect(reads(spy).at(-1)).toContain("suffix=example.test");
    suffix("nothing.example.test");
    show();
    expect((await screen.findByTestId("dns-infra-empty")).textContent).toContain("No zone cut at or below nothing.example.test.");
  });

  it("says the cache is empty when there is no zone cut at all", async () => {
    dnsRecursionState().cuts = [];
    open();
    await section();
    show();
    expect((await screen.findByTestId("dns-infra-empty")).textContent).toBe("The infrastructure cache is empty.");
    expect(cuts()).toHaveLength(0);
  });

  it("pages through the cursor, 50 zone cuts to a page", async () => {
    const template = dnsRecursionState().cuts[0]!;
    dnsRecursionState().cuts = Array.from({ length: 64 }, (_, n) => ({ ...template, zone: `h${String(n).padStart(3, "0")}.example.test` }));
    open();
    await section();
    show();
    await waitFor(() => expect(cuts()).toHaveLength(50));
    expect(screen.getByTestId("dns-infra-paging").dataset.page).toBe("1");
    expect((screen.getByTestId("dns-infra-previous") as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(screen.getByTestId("dns-infra-next"));
    await waitFor(() => expect(cuts()).toHaveLength(14));
    expect(zones()[0]).toBe("h050.example.test");
    expect(screen.getByTestId("dns-infra-paging").dataset.page).toBe("2");
    expect((screen.getByTestId("dns-infra-next") as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(screen.getByTestId("dns-infra-previous"));
    await waitFor(() => expect(cuts()).toHaveLength(50));
    expect(zones()[0]).toBe("h000.example.test");
    expect(screen.getByTestId("dns-infra-paging").dataset.page).toBe("1");
  });

  it("flushes the zone cuts at or below the suffix after a confirmation and reads again", async () => {
    open();
    await section();
    suffix("example.test");
    expect(screen.getByTestId("dns-infra-flush").textContent).toBe("Flush example.test");
    show();
    await waitFor(() => expect(zones()).toEqual(["example.test", "sub.example.test"]));
    fireEvent.click(screen.getByTestId("dns-infra-flush"));
    const dialog = await screen.findByTestId("dns-infra-flush-dialog");
    expect(dialog.textContent).toContain("Flush the zone cuts at or below example.test?");
    expect(await axeViolations(dialog)).toEqual([]);
    fireEvent.click(within(dialog).getByTestId("confirm-cancel"));
    await waitFor(() => expect(screen.queryByTestId("dns-infra-flush-dialog")).toBeNull());
    expect(dnsRecursionState().cuts).toHaveLength(4);
    fireEvent.click(screen.getByTestId("dns-infra-flush"));
    fireEvent.click(within(await screen.findByTestId("dns-infra-flush-dialog")).getByTestId("confirm-ok"));
    expect((await screen.findByTestId("dns-infra-empty")).textContent).toContain("No zone cut at or below example.test.");
    expect((await screen.findByTestId("toast")).textContent).toContain("2 entries at or below example.test removed");
    expect(dnsRecursionState().cuts.map((c) => c.zone)).toEqual(["test", "example.org"]);
    const flushes = infraAudit();
    expect(flushes.map((r) => r.draft.action)).toEqual(["dns.infra.flush"]);
    expect(flushes[0]?.draft.details?.context).toMatchObject({ suffix: "example.test" });
  });

  it("flushes everything when no suffix is typed, also before anything was shown", async () => {
    open();
    await section();
    expect(screen.getByTestId("dns-infra-flush").textContent).toBe("Flush everything");
    fireEvent.click(screen.getByTestId("dns-infra-flush"));
    const dialog = await screen.findByTestId("dns-infra-flush-dialog");
    expect(dialog.textContent).toContain("Flush the infrastructure cache?");
    expect(dialog.textContent).toContain("Every zone cut and server address is forgotten");
    fireEvent.click(within(dialog).getByTestId("confirm-ok"));
    expect((await screen.findByTestId("toast")).textContent).toContain("4 entries removed; the root is primed again");
    await waitFor(() => expect(screen.queryByTestId("dns-infra-flush-dialog")).toBeNull());
    expect(dnsRecursionState().cuts).toHaveLength(0);
    // Nothing was shown, so nothing is listed now either.
    expect(screen.queryByTestId("dns-infra-empty")).toBeNull();
    expect(infraAudit()[0]?.draft.details?.context).not.toHaveProperty("suffix");
  });

  it("empties the listing shown when everything is flushed", async () => {
    open();
    await section();
    show();
    await waitFor(() => expect(cuts()).toHaveLength(4));
    fireEvent.click(screen.getByTestId("dns-infra-flush"));
    fireEvent.click(within(await screen.findByTestId("dns-infra-flush-dialog")).getByTestId("confirm-ok"));
    expect((await screen.findByTestId("dns-infra-empty")).textContent).toBe("The infrastructure cache is empty.");
  });

  it("checks the suffix before it asks for a confirmation", async () => {
    open();
    await section();
    suffix("a..b");
    fireEvent.click(screen.getByTestId("dns-infra-flush"));
    expect((await screen.findByTestId("field-error")).dataset.field).toBe("infra-suffix");
    expect(screen.queryByTestId("dns-infra-flush-dialog")).toBeNull();
  });

  it("says why a flush failed", async () => {
    server.use(
      http.post("/api/v1/nodes/:id/dns/infra/flush", () =>
        HttpResponse.json(
          { ...PROBLEM, status: 500, code: "sys.internal", title: "Internal Server Error", detail: "the store failed" },
          { status: 500, headers: { "content-type": "application/problem+json" } },
        ),
      ),
    );
    open();
    await section();
    fireEvent.click(screen.getByTestId("dns-infra-flush"));
    fireEvent.click(within(await screen.findByTestId("dns-infra-flush-dialog")).getByTestId("confirm-ok"));
    expect((await screen.findByTestId("toast")).textContent).toContain("The infrastructure cache could not be flushed");
    expect(dnsRecursionState().cuts).toHaveLength(4);
  });

  it("says the resolver of a node is off, and lists no zone cut", async () => {
    dnsRecursionState().enabled = false;
    open();
    const infra = await section();
    show();
    const off = await within(infra).findByTestId("dns-infra-off");
    expect(off.textContent).toContain("The resolver of this node is off");
    expect(off.textContent).toContain("[dns.recursion] enabled");
    expect(screen.queryByTestId("dns-infra-cuts")).toBeNull();
    expect(screen.queryByTestId("dns-infra-paging")).toBeNull();
    expect(within(infra).queryByRole("alert")).toBeNull();
  });

  it("shows another failure of the read as an error", async () => {
    server.use(
      http.get("/api/v1/nodes/:id/dns/infra", () =>
        HttpResponse.json(
          { ...PROBLEM, status: 500, code: "sys.internal", title: "Internal Server Error", detail: "the store failed" },
          { status: 500, headers: { "content-type": "application/problem+json" } },
        ),
      ),
    );
    open();
    const infra = await section();
    show();
    expect(await within(infra).findByRole("alert")).toBeTruthy();
    expect(screen.queryByTestId("dns-infra-cuts")).toBeNull();
    expect(screen.queryByTestId("dns-infra-off")).toBeNull();
  });

  it("speaks Swedish", async () => {
    await setLocale("sv");
    open();
    const infra = await section();
    expect(within(infra).getByRole("heading", { level: 2 }).textContent).toBe("Infrastrukturcache");
    show();
    await waitFor(() => expect(cuts()).toHaveLength(4));
    expect(within(cuts()[1]!).getByTestId("dns-infra-ds").textContent).toBe("Inte känd än");
    expect(within(cuts()[1]!).getAllByRole("cell")[2]?.textContent).toBe("Glue");
    expect(screen.getByTestId("dns-infra-flush").textContent).toBe("Töm allt");
    fireEvent.click(screen.getByTestId("dns-infra-flush"));
    expect((await screen.findByTestId("dns-infra-flush-dialog")).textContent).toContain("Tömma infrastrukturcachen?");
  });

  it("has no accessibility violations", async () => {
    const { container } = open();
    await section();
    show();
    await waitFor(() => expect(cuts()).toHaveLength(4));
    expect(await axeViolations(container)).toEqual([]);
  });
});
