// The recursion page of WP10.0: the title, that the recursive resolver comes with a later
// release, the trust anchors read as an empty state while the server answers 501 (no error, no
// toast), the list once the server answers, other failures as errors, in English and Swedish,
// without accessibility violations.
// WP10.1 adds the status block: the resolver of the node with its hints, priming, root servers,
// infrastructure cache and counters, the "Prime now" button (not for a viewer), the warning for
// what the node reports as wrong, the resolver that is off, the server without a node, a failed
// read, and Swedish.
import { fireEvent, screen, waitFor } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { recursionStatus } from "../../api/mock/dns-recursion-model";
import { server } from "../../api/mock/node";
import { dnsRecursionState } from "../../api/mock/routes-dns";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { resetToasts, signInAlex } from "../../auth/account/testkit";
import { signInWithRoles } from "../../auth/scope-testkit";
import { setSessionForTest } from "../../auth/session";
import { setLocale } from "../../i18n";
import { recordWrites } from "../testkit";
import RecursionPage from "./RecursionPage";

beforeEach(async () => {
  await signInAlex();
});

afterEach(async () => {
  resetToasts();
  setSessionForTest(null);
  await setLocale("en");
});

const open = () => renderRoute(RecursionPage, { url: "/dns/recursion", path: "/dns/recursion" });

const PROBLEM = { type: "about:blank", params: {} };

describe("the recursion page", () => {
  it("says the resolver comes later and shows the trust anchors as unavailable while the server answers 501", async () => {
    const view = open();
    expect(screen.getByTestId("page-dns-recursion")).toBeTruthy();
    expect(screen.getByRole("heading", { level: 1 }).textContent).toBe("Recursion");
    expect(screen.getByTestId("dns-recursion-coming").textContent).toContain("comes with a later release");
    const empty = await screen.findByTestId("dns-recursion-anchors-unavailable");
    expect(empty.textContent).toBe("The trust anchors are not available yet.");
    expect(screen.queryByRole("alert")).toBeNull();
    expect(screen.queryByTestId("toast")).toBeNull();
    const tab = screen.getAllByTestId("dns-nav-link").find((link) => link.dataset.key === "recursion");
    expect(tab?.getAttribute("aria-current")).toBe("page");
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("counts the zones that have a trust anchor once the server lists them", async () => {
    server.use(
      http.get("/api/v1/dns/trust-anchors", () =>
        HttpResponse.json({ items: [{ zone: ".", keys: [], revision: 1 }, { zone: "example.test", keys: [], revision: 2 }], revision: 2, next_cursor: null }),
      ),
    );
    open();
    const count = await screen.findByTestId("dns-recursion-anchors-count");
    expect(count.textContent).toBe("2 zones have a trust anchor.");
    expect(count.dataset.state).toBe("listed");
  });

  it("says there are none when the server lists none", async () => {
    server.use(http.get("/api/v1/dns/trust-anchors", () => HttpResponse.json({ items: [], revision: 1, next_cursor: null })));
    open();
    expect((await screen.findByTestId("dns-recursion-anchors-count")).dataset.state).toBe("none");
  });

  it("shows another failure of the read as an error", async () => {
    server.use(
      http.get("/api/v1/dns/trust-anchors", () =>
        HttpResponse.json(
          { ...PROBLEM, status: 500, code: "sys.internal", title: "Internal Server Error", detail: "the store failed" },
          { status: 500, headers: { "content-type": "application/problem+json" } },
        ),
      ),
    );
    open();
    await waitFor(() => expect(screen.getByTestId("dns-recursion-anchors").textContent).toContain("internal error"));
    expect(screen.queryByTestId("dns-recursion-anchors-unavailable")).toBeNull();
  });

  it("speaks Swedish", async () => {
    await setLocale("sv");
    open();
    expect(screen.getByRole("heading", { level: 1 }).textContent).toBe("Rekursion");
    expect(screen.getByText("Kommer i en senare version")).toBeTruthy();
    expect((await screen.findByTestId("dns-recursion-anchors-unavailable")).textContent).toBe("Förtroendeankarna är inte tillgängliga än.");
  });
});

// WP10.1: the status block.
const status = () => screen.getByTestId("dns-recursion-status");
const counter = (key: string) => screen.getAllByTestId("dns-recursion-counter").find((el) => el.dataset.key === key);

describe("the status block", () => {
  it("shows the resolver, its hints, the last priming, the root servers, the infrastructure cache and the counters", async () => {
    const view = open();
    expect((await screen.findByTestId("dns-recursion-running")).textContent).toBe("Running");
    expect(screen.getByTestId("dns-recursion-hints").textContent).toBe("Shipped with Tenko");
    expect(screen.getByTestId("dns-recursion-hints-date").textContent).toBe("2026-01-31");
    const priming = screen.getByTestId("dns-recursion-priming");
    expect(priming.dataset.outcome).toBe("ok");
    expect(priming.textContent).toContain("Succeeded");
    expect(priming.textContent).toContain("took 42.5 ms");
    expect(screen.getByTestId("dns-recursion-expires").textContent).toContain("in 6 days");

    const roots = screen.getAllByTestId("dns-recursion-root");
    expect(roots.map((row) => row.dataset.key)).toEqual(["192.0.2.1", "192.0.2.2", "2001:db8::3"]);
    expect(roots[0]?.querySelector("td[data-col=srtt]")?.textContent).toBe("12.5 ms");

    expect(screen.getByTestId("dns-recursion-infra-zones").textContent).toBe("4 of 10,000");
    expect(screen.getByTestId("dns-recursion-infra-servers").textContent).toBe("4 of 50,000");
    expect(screen.getByTestId("dns-recursion-infra-names").textContent).toBe("4");

    expect(counter("answered")?.textContent).toBe("1,204");
    expect(counter("servfail")?.textContent).toBe("17");
    for (const key of ["budget", "timeout", "local", "failure_cache_hits", "subqueries", "unwanted"]) expect(counter(key)).toBeTruthy();
    expect(screen.queryByTestId("dns-recursion-problems")).toBeNull();
    expect(screen.queryByTestId("dns-recursion-off")).toBeNull();
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("primes the resolver now and reads the status again", async () => {
    const sent = recordWrites();
    dnsRecursionState().primedAt = "2026-10-01T00:00:00Z";
    open();
    const before = (await screen.findByTestId("dns-recursion-priming")).textContent;
    fireEvent.click(screen.getByTestId("dns-recursion-prime"));
    expect((await screen.findByTestId("toast")).textContent).toContain("Priming requested");
    await waitFor(() => expect(screen.getByTestId("dns-recursion-priming").textContent).not.toBe(before));
    expect(sent().map((call) => `${call.method} ${new URL(call.url, "http://x").pathname}`)).toEqual(["POST /api/v1/nodes/1/dns/recursion/prime"]);
    expect(dnsRecursionState().primings).toBe(2);
  });

  it("says why the priming could not be requested", async () => {
    server.use(
      http.post("/api/v1/nodes/:id/dns/recursion/prime", () =>
        HttpResponse.json(
          { ...PROBLEM, status: 409, code: "dns.recursion.disabled", title: "Recursion disabled", detail: "the recursive resolver of node 1 is off" },
          { status: 409, headers: { "content-type": "application/problem+json" } },
        ),
      ),
    );
    open();
    fireEvent.click(await screen.findByTestId("dns-recursion-prime"));
    expect((await screen.findByTestId("toast")).textContent).toContain("The priming could not be requested");
    expect((screen.getByTestId("dns-recursion-prime") as HTMLButtonElement).disabled).toBe(false);
  });

  it("warns when no root server answered", async () => {
    dnsRecursionState().primingOk = false;
    open();
    const warning = await screen.findByTestId("dns-recursion-problems");
    expect(warning.textContent).toContain("No root server answered the priming query");
    expect(screen.getByTestId("dns-recursion-problem").dataset.code).toBe("priming_failed");
    expect(screen.getByTestId("dns-recursion-priming").dataset.outcome).toBe("failed");
  });

  it("shows a code it does not know as the node wrote it", async () => {
    const body = recursionStatus(dnsRecursionState());
    server.use(
      http.get("/api/v1/nodes/:id/dns/recursion", () =>
        HttpResponse.json({ ...body, hints_source: "/etc/tenko/root.hints", last_priming: undefined, root_expires_secs: undefined, problems: ["clock"] }),
      ),
    );
    open();
    expect((await screen.findByTestId("dns-recursion-problem")).textContent).toBe("clock");
    expect(screen.getByTestId("dns-recursion-hints").textContent).toBe("/etc/tenko/root.hints");
    expect(screen.getByTestId("dns-recursion-priming").dataset.outcome).toBe("never");
    expect(screen.queryByTestId("dns-recursion-expires")).toBeNull();
  });

  it("says the resolver is off and offers no priming", async () => {
    dnsRecursionState().enabled = false;
    open();
    const off = await screen.findByTestId("dns-recursion-off");
    expect(off.textContent).toContain("Recursion is off");
    expect(off.textContent).toContain("[dns.recursion]");
    expect(screen.queryByTestId("dns-recursion-prime")).toBeNull();
    expect(screen.queryByTestId("dns-recursion-running")).toBeNull();
    expect(screen.queryByTestId("dns-recursion-counters")).toBeNull();
  });

  it("lets a viewer read the status but not prime", async () => {
    await signInWithRoles(["viewer"]);
    open();
    expect(await screen.findByTestId("dns-recursion-running")).toBeTruthy();
    expect(screen.queryByTestId("dns-recursion-prime")).toBeNull();
  });

  it("says when the server has no node", async () => {
    server.use(http.get("/api/v1/system/status", () => HttpResponse.json({ node: { id: null, roles: ["controller"] } })));
    open();
    expect(await screen.findByTestId("dns-recursion-no-node")).toBeTruthy();
    expect(screen.queryByTestId("dns-recursion-facts")).toBeNull();
  });

  it("shows a failed read as the error it is", async () => {
    server.use(
      http.get("/api/v1/nodes/:id/dns/recursion", () =>
        HttpResponse.json(
          { ...PROBLEM, status: 500, code: "sys.internal", title: "Internal Server Error", detail: "the store failed" },
          { status: 500, headers: { "content-type": "application/problem+json" } },
        ),
      ),
    );
    open();
    await waitFor(() => expect(status().textContent).toContain("internal error"));
    expect(screen.queryByTestId("dns-recursion-running")).toBeNull();
  });

  it("speaks Swedish", async () => {
    await setLocale("sv");
    open();
    expect((await screen.findByTestId("dns-recursion-running")).textContent).toBe("Körs");
    expect(screen.getByTestId("dns-recursion-hints").textContent).toBe("Medföljer Tenko");
    expect(screen.getByTestId("dns-recursion-infra-zones").textContent).toMatch(/^4 av 10\s000$/);
    expect(screen.getByTestId("dns-recursion-prime").textContent).toBe("Prima nu");
    expect(screen.getByTestId("dns-recursion-priming").textContent).toContain("Lyckades");
  });
});
// WP10.1: end.
