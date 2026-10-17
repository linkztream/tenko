// The page of the DNS paths no view claims yet (views, forwarders, block lists): it says they
// come in a later slice and leads to the zones, in English and Swedish, without accessibility
// violations.
import { screen } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { signInAlex } from "../auth/account/testkit";
import { setSessionForTest } from "../auth/session";
import { setLocale } from "../i18n";
import DnsPage from "./DnsPage";

beforeEach(async () => {
  await signInAlex();
});

afterEach(async () => {
  setSessionForTest(null);
  await setLocale("en");
});

describe("the DNS page of later views", () => {
  it("says the view comes later and leads to the zones", async () => {
    for (const url of ["/dns/views", "/dns/forwarders", "/dns/lists"]) {
      const view = renderRoute(DnsPage, { url, path: "/dns/*rest" });
      expect(screen.getByTestId("page-dns-later")).toBeTruthy();
      expect(screen.getByRole("heading", { level: 1 }).textContent).toBe("DNS");
      expect(screen.getByTestId("dns-coming").textContent).toContain("Coming in a later slice");
      expect(screen.getByTestId("dns-coming-zones").getAttribute("href")).toBe("/dns");
      expect(await axeViolations(view.container)).toEqual([]);
      view.unmount();
    }
  });

  it("speaks Swedish", async () => {
    await setLocale("sv");
    renderRoute(DnsPage, { url: "/dns/views", path: "/dns/*rest" });
    expect(screen.getByText("Kommer i en senare etapp")).toBeTruthy();
  });
});
