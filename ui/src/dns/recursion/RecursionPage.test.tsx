// The recursion page of WP10.0: the title, that the recursive resolver comes with a later
// release, the trust anchors read as an empty state while the server answers 501 (no error, no
// toast), the list once the server answers, other failures as errors, in English and Swedish,
// without accessibility violations.
import { screen, waitFor } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { server } from "../../api/mock/node";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { signInAlex } from "../../auth/account/testkit";
import { setSessionForTest } from "../../auth/session";
import { setLocale } from "../../i18n";
import RecursionPage from "./RecursionPage";

beforeEach(async () => {
  await signInAlex();
});

afterEach(async () => {
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
