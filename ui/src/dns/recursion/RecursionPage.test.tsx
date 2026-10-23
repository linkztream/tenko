// The recursion page (WP10.4): the title and the tab of the DNS area, the status block, the
// trust anchors and the negative trust anchors under it (their own tests are in
// AnchorsSection.test.tsx and NtaSection.test.tsx), a failed read of the anchors shown as an
// error, English and Swedish, without accessibility violations.
// WP10.1 added the status block: the resolver of the node with its hints, priming, root servers,
// infrastructure cache and counters, the "Prime now" button (not for a viewer), the warning for
// what the node reports as wrong, the resolver that is off, the server without a node, a failed
// read, and Swedish. WP10.4 adds the validation card: the four outcomes the validator counted
// and the anchor keys the node validates with.
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
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
  it("shows the title, the tab and the status, the trust anchors and the negative trust anchors", async () => {
    const view = open();
    expect(screen.getByTestId("page-dns-recursion")).toBeTruthy();
    expect(screen.getByRole("heading", { level: 1 }).textContent).toMatch(/^Recursion/);
    const tab = screen.getAllByTestId("dns-nav-link").find((link) => link.dataset.key === "recursion");
    expect(tab?.getAttribute("aria-current")).toBe("page");
    expect(await screen.findByTestId("dns-recursion-running")).toBeTruthy();
    expect(screen.getByTestId("dns-recursion-validation")).toBeTruthy();
    const anchors = screen.getByTestId("dns-recursion-anchors");
    expect(within(anchors).getByRole("heading", { level: 2 }).textContent).toBe("Trust anchors");
    await waitFor(() => expect(screen.getAllByTestId("dns-anchor")).toHaveLength(2));
    const ntas = screen.getByTestId("dns-recursion-ntas");
    expect(within(ntas).getByRole("heading", { level: 2 }).textContent).toBe("Negative trust anchors");
    expect(await screen.findByTestId("dns-nta-none")).toBeTruthy();
    // It is no placeholder any more: nothing says the resolver comes later.
    expect(screen.queryByTestId("dns-recursion-coming")).toBeNull();
    expect(screen.queryByTestId("dns-recursion-anchors-unavailable")).toBeNull();
    expect(screen.queryByRole("alert")).toBeNull();
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("counts the anchors the server lists", async () => {
    open();
    const list = await screen.findByTestId("dns-recursion-anchors-count");
    expect(list.dataset.state).toBe("listed");
    expect(list.dataset.count).toBe("2");
  });

  it("says there are none when the server lists none", async () => {
    server.use(http.get("/api/v1/dns/trust-anchors", () => HttpResponse.json({ items: [], revision: 1, next_cursor: null })));
    open();
    const none = await screen.findByTestId("dns-recursion-anchors-count");
    expect(none.dataset.state).toBe("none");
    expect(none.textContent).toBe("There are no trust anchors.");
  });

  it("shows a failure of the read of the anchors as an error", async () => {
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
    expect(screen.queryByTestId("dns-recursion-anchors-count")).toBeNull();
    // The anchors cannot be added to while they cannot be read; the rest of the page stays.
    expect(screen.queryByTestId("dns-anchor-add")).toBeNull();
    expect(await screen.findByTestId("dns-recursion-running")).toBeTruthy();
  });

  it("speaks Swedish", async () => {
    await setLocale("sv");
    open();
    expect(screen.getByRole("heading", { level: 1 }).textContent).toMatch(/^Rekursion/);
    expect(await screen.findByText("Förtroendeankare")).toBeTruthy();
    expect(screen.getByText("Negativa förtroendeankare")).toBeTruthy();
    expect((await screen.findByTestId("dns-nta-none")).textContent).toContain("Inget negativt förtroendeankare");
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

// WP10.4: the validation card.
const counted = (key: string) => screen.getAllByTestId("dns-recursion-validation-count").find((el) => el.dataset.key === key);

function validatingStatus() {
  const body = recursionStatus(dnsRecursionState());
  return {
    ...body,
    counters: { ...body.counters, secure: 12_034, insecure: 1_870, bogus: 7, indeterminate: 0 },
    trust_anchors: [
      { zone: ".", key_tag: 20326, state: "valid" },
      { zone: ".", key_tag: 38696, state: "valid" },
      { zone: ".", key_tag: 47000, state: "add_pend" },
      { zone: "corp.example.test", key_tag: 3613, state: "revoked" },
    ],
  };
}

describe("the validation card", () => {
  it("shows the four outcomes the validator counted, in their order", async () => {
    server.use(http.get("/api/v1/nodes/:id/dns/recursion", () => HttpResponse.json(validatingStatus())));
    const view = open();
    const card = await screen.findByTestId("dns-recursion-validation");
    expect(within(card).getByRole("heading", { level: 3 }).textContent).toBe("Validation");
    expect(screen.getAllByTestId("dns-recursion-validation-count").map((el) => el.dataset.key)).toEqual(["secure", "insecure", "bogus", "indeterminate"]);
    expect(counted("secure")?.textContent).toBe("12,034");
    expect(counted("secure")?.dataset.value).toBe("12034");
    expect(counted("insecure")?.textContent).toBe("1,870");
    expect(counted("bogus")?.textContent).toBe("7");
    expect(counted("indeterminate")?.textContent).toBe("0");
    expect(within(card).getByText("Secure")).toBeTruthy();
    expect(within(card).getByText("Indeterminate")).toBeTruthy();
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("lists the anchor keys the node validates with, each with its zone, tag and state", async () => {
    server.use(http.get("/api/v1/nodes/:id/dns/recursion", () => HttpResponse.json(validatingStatus())));
    open();
    const keys = await screen.findAllByTestId("dns-recursion-key");
    expect(keys.map((el) => [el.dataset.key, el.dataset.state])).toEqual([
      ["20326", "valid"],
      ["38696", "valid"],
      ["47000", "add_pend"],
      ["3613", "revoked"],
    ]);
    expect(keys.map((el) => el.textContent)).toEqual([". 20326 Valid", ". 38696 Valid", ". 47000 Add pending", "corp.example.test 3613 Revoked"]);
    expect(screen.getByTestId("dns-recursion-validation-keys").dataset.count).toBe("4");
  });

  it("says no key was reported when the node reports none", async () => {
    open();
    await screen.findByTestId("dns-recursion-validation");
    expect(screen.queryAllByTestId("dns-recursion-key")).toHaveLength(0);
    const keys = screen.getByTestId("dns-recursion-validation-keys");
    expect(keys.dataset.count).toBe("0");
    expect(keys.textContent).toBe("None reported");
    for (const key of ["secure", "insecure", "bogus", "indeterminate"]) expect(counted(key)?.textContent).toBe("0");
  });

  it("is not shown while the resolver is off", async () => {
    dnsRecursionState().enabled = false;
    open();
    await screen.findByTestId("dns-recursion-off");
    expect(screen.queryByTestId("dns-recursion-validation")).toBeNull();
  });

  it("speaks Swedish", async () => {
    await setLocale("sv");
    server.use(http.get("/api/v1/nodes/:id/dns/recursion", () => HttpResponse.json(validatingStatus())));
    open();
    const card = await screen.findByTestId("dns-recursion-validation");
    expect(within(card).getByRole("heading", { level: 3 }).textContent).toBe("Validering");
    expect(within(card).getByText("Säker")).toBeTruthy();
    expect(within(card).getByText("Obestämd")).toBeTruthy();
    expect(screen.getAllByTestId("dns-recursion-key")[2]?.textContent).toBe(". 47000 Tillägg väntar");
  });
});
// WP10.4: end.
