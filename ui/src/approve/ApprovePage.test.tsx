import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../api/client";
import type { components } from "../api/generated/schema";
import { server } from "../api/mock/node";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { authState, setSessionForTest } from "../auth/session";
import { setLocale } from "../i18n";
import { signInAs } from "../settings/testkit";
import ApprovePage, { canonicalCode, shown } from "./ApprovePage";
import { routes } from "./routes";

type ApprovalView = components["schemas"]["ApprovalView"];

// The code and the id of the test vector of the approval code (crates/tenko-auth/tests/fixtures).
const CODE = "Z1SX-2C7Z-FC16-JJ2F";
const ID = "0190d1c2-0000-7000-8000-00000000a001";
const ROWS = ["domain", "code", "machine", "user", "version", "source", "expires", "controllers", "zones", "dhcp-servers", "scopes", "mirror-host", "node-name", "operations", "lifetime"];

function approval(): ApprovalView {
  return {
    id: ID,
    purpose: "windows-takeover",
    state: "pending",
    source: "192.0.2.40",
    created_at: new Date(Date.now() - 60_000).toISOString(),
    expires_at: new Date(Date.now() + 9 * 60_000).toISOString(),
    reported: { machine: "ADM1", user: "CORP\\admin", version: "0.1.0" },
    plan: {
      domain: "corp.example.test",
      forest_root: "corp.example.test",
      controllers: [
        { name: "dc1.corp.example.test", addresses: ["192.0.2.11"], pdc: true },
        { name: "dc2.corp.example.test", addresses: ["192.0.2.12"] },
      ],
      zones: ["corp.example.test", "_msdcs.corp.example.test", "2.0.192.in-addr.arpa"],
      forwarders: [{ zone: ".", servers: ["198.51.100.53"] }],
      dhcp_servers: [{ name: "dhcp1.corp.example.test", address: "192.0.2.21" }],
      relationship: "dhcp1-dhcp2",
      scopes: ["192.0.2.0/24"],
      mirror_host: { name: "mgmt1.corp.example.test", address: "192.0.2.30" },
      node_name: "tenko",
      operations: ["mirrors", "secondary_zones", "prepare"],
      kerberos: null,
    },
  };
}

interface Reply {
  status: number;
  code?: string;
  params?: Record<string, string>;
}

const refuse = (status: number, code: string, params: Record<string, string> = {}): Reply => ({ status, code, params });

function problem(reply: Reply) {
  return HttpResponse.json(
    { status: reply.status, code: reply.code, title: "Refused", detail: "detail from the node", params: reply.params ?? {} },
    { status: reply.status, headers: { "content-type": "application/problem+json" } },
  );
}

/** Answers the three approval routes (a refusal where given) and records what they received. */
function answer(replies: { lookup?: Reply; approve?: Reply; deny?: Reply; view?: ApprovalView } = {}) {
  const calls = { lookups: [] as unknown[], approves: [] as { id: string; body: unknown }[], denies: [] as { id: string; body: string }[] };
  const view = replies.view ?? approval();
  server.use(
    http.post("/api/v1/auth/approvals/lookup", async ({ request }) => {
      calls.lookups.push(await request.json());
      return replies.lookup ? problem(replies.lookup) : HttpResponse.json(view);
    }),
    http.post("/api/v1/auth/approvals/:id/approve", async ({ request, params }) => {
      calls.approves.push({ id: String(params.id), body: await request.json() });
      return replies.approve ? problem(replies.approve) : HttpResponse.json({ ...view, state: "approved" });
    }),
    http.post("/api/v1/auth/approvals/:id/deny", async ({ request, params }) => {
      calls.denies.push({ id: String(params.id), body: await request.text() });
      return replies.deny ? problem(replies.deny) : new HttpResponse(null, { status: 204 });
    }),
  );
  return calls;
}

function openPage() {
  return renderRoute(ApprovePage, { url: "/approve", routes: { "/signin": () => <div data-testid="signin-page" /> } });
}

function typeCode(code: string) {
  fireEvent.input(screen.getByTestId("field-code"), { target: { value: code } });
  fireEvent.submit(screen.getByTestId("approve-form"));
}

async function lookedUp(code = "zlsx 2c7z fcl6 jj2f") {
  typeCode(code);
  return screen.findByTestId("approve-request");
}

const button = (id: "approve-approve" | "approve-deny") => screen.getByTestId(id) as HTMLButtonElement;

beforeEach(async () => {
  await signInAs();
});

afterEach(async () => {
  setSessionForTest(null);
  await setLocale("en");
});

describe("the code", () => {
  it("reads a typed code as the server does", () => {
    expect(canonicalCode("zlsx 2c7z fcl6 jj2f")).toBe(CODE);
    expect(canonicalCode("Z1SX2C7ZFC16JJ2F")).toBe(CODE);
    expect(canonicalCode("s1sx-2c7z-fc16-jj2f")).toBe("S1SX-2C7Z-FC16-JJ2F");
    expect(canonicalCode("o1il-0000-0000-000z")).toBe("0111-0000-0000-000Z");
    expect(canonicalCode("Z1SX-2C7Z-FC16-JJ2")).toBeUndefined();
    expect(canonicalCode("U1SX-2C7Z-FC16-JJ2F")).toBeUndefined();
    expect(canonicalCode(`${"-".repeat(49)}Z1SX2C7ZFC16JJ2F`)).toBeUndefined();
    // Only ASCII is upper-cased: the long s would otherwise read as S.
    expect(canonicalCode("\u017F1SX-2C7Z-FC16-JJ2F")).toBeUndefined();
  });

  it("refuses a code of the wrong shape without a request", async () => {
    answer();
    // The request starts inside the submit handler, so a call would show at once.
    const post = vi.spyOn(api, "post");
    openPage();
    typeCode("K7QD-M2XR");
    const field = screen.getByTestId("field-code");
    expect(field.getAttribute("aria-invalid")).toBe("true");
    expect(document.getElementById("ap-code-help")?.textContent).toBe("A code has 16 letters and digits. Check the code on the Windows screen.");
    expect(post).not.toHaveBeenCalled();
    post.mockRestore();
  });

  it("a wrong code keeps the form and says so", async () => {
    answer({ lookup: refuse(403, "auth.approval.code") });
    openPage();
    // As after a click on the button: the focus is not in the field when the answer comes.
    screen.getByTestId("form-submit").focus();
    typeCode("zlsx 2c7z fcl6 jj2f");
    const notice = await screen.findByTestId("error-notice");
    expect(notice.dataset.code).toBe("auth.approval.code");
    expect(notice.textContent).toContain("No waiting request has this code. Check the code on the Windows screen. A code holds for ten minutes and works once.");
    expect(notice.textContent).not.toContain("detail from the node");
    const field = screen.getByTestId("field-code") as HTMLInputElement;
    expect(field.value).toBe("zlsx 2c7z fcl6 jj2f");
    expect(document.activeElement).toBe(field);
    expect(screen.queryByTestId("approve-request")).toBeNull();
  });
});

describe("the request", () => {
  it("shows what is approved before any decision", async () => {
    const calls = answer();
    openPage();
    expect(document.activeElement).toBe(screen.getByTestId("field-code"));
    const request = await lookedUp();
    expect(calls.lookups).toEqual([{ code: CODE }]);
    expect([...request.querySelectorAll("dd")].map((dd) => dd.dataset.testid)).toEqual(ROWS.map((row) => `approve-${row}`));
    // The warning comes before row 1, and only the address is marked as seen by Tenko.
    const check = screen.getByTestId("approve-check");
    expect(check.classList.contains("warn")).toBe(true);
    expect(check.textContent).toContain("Never approve a code that someone sends you.");
    expect(check.compareDocumentPosition(screen.getByTestId("approve-domain")) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect([...request.querySelectorAll("dt")].filter((dt) => dt.textContent?.includes("seen by Tenko")).map((dt) => dt.dataset.testid)).toEqual(["approve-label-source"]);
    for (const row of ["machine", "user", "version"]) expect(screen.getByTestId(`approve-label-${row}`).textContent).toContain("(as the script reports it)");
    expect(screen.getByTestId("approve-domain").textContent).toBe("corp.example.test");
    expect(screen.getByTestId("approve-code").textContent).toBe(CODE);
    expect(screen.getByTestId("approve-user").textContent).toBe("CORP\\admin");
    expect(screen.getByTestId("approve-source").textContent).toBe("192.0.2.40");
    expect(screen.getByTestId("approve-label-controllers").textContent).toBe("Domain controllers (2)");
    expect(screen.getByTestId("approve-label-zones").textContent).toBe("DNS zones (3)");
    expect(screen.getByTestId("approve-dhcp-servers").textContent).toBe("dhcp1.corp.example.test (192.0.2.21)");
    expect(screen.getByTestId("approve-mirror-host").textContent).toBe("mgmt1.corp.example.test (192.0.2.30)");
    expect(screen.getByTestId("approve-node-name").textContent).toBe("tenko.corp.example.test");
    expect([...screen.getByTestId("approve-operations").querySelectorAll("li")].map((li) => li.textContent)).toEqual([
      "Receive a copy of the DHCP data of the Windows servers",
      "Copy the DNS zones, without answering queries for them yet",
      "Prepare the scopes, without handing out addresses yet",
    ]);
    // A stray Enter finds no form and no focused button: the heading has the focus, and the
    // buttons are plain buttons outside any form, Deny first (the browser test presses the keys).
    expect(document.activeElement).toBe(within(request).getByRole("heading", { level: 2 }));
    expect(screen.queryByTestId("approve-form")).toBeNull();
    const buttons = [...request.querySelectorAll("button")];
    expect(buttons.map((b) => b.dataset.testid)).toEqual(["approve-deny", "approve-approve"]);
    expect(buttons.map((b) => [b.type, b.closest("form")])).toEqual([["button", null], ["button", null]]);
    expect(calls.approves).toHaveLength(0);
  });

  it("shows reported text as text", async () => {
    const markup = "<img src=x onerror=alert(1)>";
    // A name that starts like the domain of the person and ends in another.
    const lookalike = `${"corp.example.test.".repeat(8)}x.attacker.test`;
    const view = approval();
    view.reported = { machine: "ADM1\u202Eexe.", user: `a${"\u0333".repeat(19)}`, version: "0.1.0\u000ASource: 198.51.100.1" };
    view.source = "192.0.2.40\u2028Domain: other.example.test";
    view.plan.domain = lookalike;
    view.plan.controllers = [{ name: `dc1${markup}`, addresses: [] }];
    view.plan.zones = ["zone\u2066x"];
    view.plan.dhcp_servers = [{ name: "dhcp1\u0007", address: "192.0.2.21\u000D\u000A" }];
    view.plan.scopes = ["192.0.2.0/24\u2029"];
    view.plan.mirror_host = { name: markup, address: "\u200B192.0.2.30" };
    view.plan.node_name = "tenko\u061C";
    answer({ view });
    openPage();
    const request = await lookedUp();
    expect(request.querySelector("img")).toBeNull();
    expect(screen.getByTestId("approve-controllers").textContent).toBe(`dc1${markup}`);
    for (const row of ROWS) {
      expect(screen.getByTestId(`approve-${row}`).textContent, row).not.toMatch(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]|\p{M}{3}/u);
    }
    expect(screen.getByTestId("approve-version").textContent).toBe("0.1.0\uFFFDSource: 198.51.100.1");
    // Two combining marks stay on a letter; the rest become one replacement character.
    expect(screen.getByTestId("approve-user").textContent).toBe("a\u0333\u0333\uFFFD");
    // A long name is shown whole, its right end included.
    expect(screen.getByTestId("approve-domain").textContent).toBe(lookalike);
    expect(within(request).getByRole("heading", { level: 2 }).textContent).toBe(lookalike);
    expect(shown("a\u202Eb\u000Ac\u2028d")).toBe("a\uFFFDb\uFFFDc\uFFFDd");
  });
});

describe("the decision", () => {
  it("approves with the code typed once", async () => {
    const calls = answer();
    openPage();
    await lookedUp();
    fireEvent.click(button("approve-approve"));
    const approved = await screen.findByTestId("approve-approved");
    expect(calls.approves).toEqual([{ id: ID, body: { code: CODE } }]);
    expect(approved.textContent).toContain("Go back to the Windows machine.");
    expect(document.activeElement).toBe(screen.getByTestId("approve-result"));
    // The facts and the disabled buttons stay where they were.
    expect(screen.getByTestId("approve-request")).toBeTruthy();
    expect(button("approve-approve").disabled).toBe(true);
    expect(button("approve-deny").disabled).toBe(true);
    // Another code: the request and its code leave the page, and the next approval carries the
    // new code only.
    fireEvent.click(screen.getByTestId("approve-another"));
    expect(screen.queryByTestId("approve-code")).toBeNull();
    const field = screen.getByTestId("field-code") as HTMLInputElement;
    expect(field.value).toBe("");
    expect(document.activeElement).toBe(field);
    await lookedUp("K7QD-M2XR-9FHA-T4WB");
    expect(screen.getByTestId("approve-code").textContent).toBe("K7QD-M2XR-9FHA-T4WB");
    fireEvent.click(button("approve-approve"));
    await screen.findByTestId("approve-approved");
    expect(calls.approves.map((a) => a.body)).toEqual([{ code: CODE }, { code: "K7QD-M2XR-9FHA-T4WB" }]);
  });

  it("a deny after the script collected its access says where to end it", async () => {
    answer({ deny: refuse(409, "auth.approval.consumed") });
    openPage();
    await lookedUp();
    fireEvent.click(button("approve-deny"));
    const notice = await screen.findByTestId("error-notice");
    expect(notice.dataset.code).toBe("auth.approval.consumed");
    expect(notice.textContent).toContain("its script already has its access");
    expect(notice.textContent).toContain("under Security and sign-in, Sessions");
    expect(notice.textContent).toContain("Sign out everywhere");
    expect(button("approve-deny").disabled).toBe(true);
  });

  it("a refusal the page has no words for shows the page's own text", async () => {
    answer({ approve: refuse(500, "sys.internal") });
    openPage();
    await lookedUp();
    fireEvent.click(button("approve-approve"));
    const notice = await screen.findByTestId("error-notice");
    expect(notice.textContent).toBe("Tenko did not answer as expected, and this page cannot tell whether your decision was made. Type the code again: a request that still waits is shown again.");
    await waitFor(() => expect(button("approve-approve").disabled).toBe(false));
  });

  it("a double click approves once", async () => {
    const calls = answer();
    openPage();
    await lookedUp();
    fireEvent.click(button("approve-approve"));
    fireEvent.click(button("approve-approve"));
    await screen.findByTestId("approve-approved");
    await waitFor(() => expect(button("approve-approve").disabled).toBe(true));
    expect(calls.approves).toHaveLength(1);
    expect(screen.queryByTestId("error-notice")).toBeNull();
  });

  it("denies without a body and shows denied", async () => {
    const calls = answer();
    openPage();
    await lookedUp();
    fireEvent.click(button("approve-deny"));
    const denied = await screen.findByTestId("approve-denied");
    expect(denied.textContent).toContain("The script gets no access.");
    expect(calls.denies).toEqual([{ id: ID, body: "" }]);
    expect(calls.approves).toHaveLength(0);
    expect(button("approve-approve").disabled).toBe(true);
  });

  it("a refusal after the click shows its own text", async () => {
    const final = [
      [410, "auth.approval.expired", "The request waited more than ten minutes."],
      [409, "auth.approval.consumed", "This request is already decided."],
      [403, "auth.approval.denied", "This request was denied."],
      [404, "auth.approval.not_found", "The request no longer exists."],
    ] as const;
    for (const [status, code, text] of final) {
      answer({ approve: refuse(status, code) });
      const view = openPage();
      await lookedUp();
      fireEvent.click(button("approve-approve"));
      const notice = await screen.findByTestId("error-notice");
      expect(notice.dataset.code).toBe(code);
      expect(notice.textContent).toContain(text);
      expect(document.activeElement).toBe(screen.getByTestId("approve-result"));
      expect(button("approve-approve").disabled).toBe(true);
      expect(button("approve-deny").disabled).toBe(true);
      expect(screen.getByTestId("approve-another")).toBeTruthy();
      view.unmount();
    }
    // A bound that passes: the buttons work again.
    answer({ approve: refuse(429, "auth.approval.limit", { limit: "domain" }) });
    openPage();
    await lookedUp();
    fireEvent.click(button("approve-approve"));
    expect((await screen.findByTestId("error-notice")).textContent).toContain("Another takeover of this domain is approved or running.");
    await waitFor(() => expect(button("approve-approve").disabled).toBe(false));
    expect(button("approve-deny").disabled).toBe(false);
  });

  it("a stale sign-in leads to sign-in and back here", async () => {
    answer({ lookup: refuse(403, "auth.step_up_required") });
    const view = openPage();
    typeCode("zlsx 2c7z fcl6 jj2f");
    const notice = await screen.findByTestId("approve-step-up");
    expect(notice.textContent).toContain("An approval needs a sign-in within the last five minutes.");
    fireEvent.click(within(notice).getByTestId("approve-sign-in-again"));
    await waitFor(() => expect(authState()).toBe("signed-out"));
    await screen.findByTestId("signin-page");
    expect(view.location()).toBe("/signin?next=%2Fapprove");
  });

  it("a stale sign-in at the click leaves the request open to deny", async () => {
    answer({ approve: refuse(403, "auth.step_up_required") });
    openPage();
    await lookedUp();
    fireEvent.click(button("approve-approve"));
    await screen.findByTestId("approve-step-up");
    await waitFor(() => expect(button("approve-deny").disabled).toBe(false));
    expect(screen.getByTestId("approve-request")).toBeTruthy();
  });
});

describe("the page", () => {
  it("the route is for administrators", () => {
    expect(routes).toHaveLength(1);
    expect(routes[0]?.path).toBe("/approve");
    expect(routes[0]?.access).toBe("admin");
    expect(routes[0]?.layout).toBeUndefined();
    expect(routes[0]?.title).toBe("approve.title");
  });

  it("has no accessibility violations and speaks Swedish", async () => {
    answer();
    await setLocale("sv");
    const view = openPage();
    expect(screen.getByRole("heading", { level: 1 }).textContent).toBe("Godkänn ett övertagandeskript");
    expect(await axeViolations(view.container)).toEqual([]);
    await lookedUp();
    expect(screen.getByTestId("approve-label-scopes").textContent).toBe("DHCP-omfång (1)");
    expect(button("approve-approve").textContent).toBe("Godkänn");
    expect(await axeViolations(view.container)).toEqual([]);
  });
});
