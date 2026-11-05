// The Kerberos page of the DNS area (WP13.0): the title and the tab, the notice that the
// account's wizard and status come with later packages, the way back to the zones, in English
// and Swedish, without accessibility violations.
import { screen } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { signInAlex } from "../../auth/account/testkit";
import { setSessionForTest } from "../../auth/session";
import { setLocale } from "../../i18n";
import KerberosPage from "./KerberosPage";
import { KERBEROS_PATH } from "./paths";

beforeEach(async () => {
  await signInAlex();
});

afterEach(async () => {
  setSessionForTest(null);
  await setLocale("en");
});

const open = () => renderRoute(KerberosPage, { url: KERBEROS_PATH, path: KERBEROS_PATH });

describe("the Kerberos page", () => {
  it("shows the title, the tab and the notice, and leads to the zones", async () => {
    const view = open();
    expect(screen.getByTestId("page-dns-kerberos")).toBeTruthy();
    expect(screen.getByRole("heading", { level: 1 }).textContent).toMatch(/^Kerberos/);
    const tab = screen.getAllByTestId("dns-nav-link").find((link) => link.dataset.key === "kerberos");
    expect(tab?.getAttribute("href")).toBe("/dns/kerberos");
    expect(tab?.getAttribute("aria-current")).toBe("page");
    expect(screen.getByTestId("dns-kerberos-coming").textContent).toContain("Coming in a later package");
    expect(screen.getByTestId("dns-kerberos-zones").getAttribute("href")).toBe("/dns");
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("speaks Swedish", async () => {
    await setLocale("sv");
    open();
    expect(screen.getByText("Kommer i ett senare paket")).toBeTruthy();
  });
});
