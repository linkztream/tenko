import { fireEvent, screen, waitFor } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, describe, expect, it } from "vitest";
import { server } from "../../api/mock/node";
import { MOCK_TOTP_CODE } from "../../api/mock/fixtures";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { setLocale } from "../../i18n";
import Account from "./Account";
import { signInAlex } from "./testkit";

function show(url: string) {
  return renderRoute(Account, { url, path: "/account/:section?" });
}

const link = (name: string) => screen.getByRole("link", { name });

afterEach(async () => {
  await setLocale("en");
});

describe("the account pages", () => {
  it("has a head and a sub-navigation with the three pages", async () => {
    await signInAlex();
    show("/account");
    expect(screen.getByRole("heading", { level: 1 }).textContent).toContain("Security and sign-in");
    const nav = screen.getByRole("navigation", { name: "Account sections" });
    expect(Array.from(nav.querySelectorAll("a")).map((a) => a.textContent)).toEqual([
      "Sign-in methods",
      "Sessions",
      "Personal tokens",
    ]);
    expect(Array.from(nav.querySelectorAll("a")).map((a) => a.getAttribute("href"))).toEqual([
      "/account/security",
      "/account/sessions",
      "/account/tokens",
    ]);
  });

  it("shows the sign-in methods without a section and for an unknown one", async () => {
    await signInAlex();
    const first = show("/account");
    expect(await screen.findByText("Laptop passkey")).toBeTruthy();
    expect(link("Sign-in methods").classList.contains("active")).toBe(true);
    expect(link("Sessions").classList.contains("active")).toBe(false);
    first.unmount();

    show("/account/nothing-here");
    expect(await screen.findByText("Laptop passkey")).toBeTruthy();
    expect(link("Sign-in methods").classList.contains("active")).toBe(true);
  });

  it("shows the sessions and the tokens under their own addresses", async () => {
    await signInAlex();
    const sessions = show("/account/sessions");
    expect(await screen.findByText("Firefox on Android")).toBeTruthy();
    expect(link("Sessions").classList.contains("active")).toBe(true);
    sessions.unmount();

    show("/account/tokens");
    expect(await screen.findByText("nightly export")).toBeTruthy();
    expect(link("Personal tokens").classList.contains("active")).toBe(true);
    expect(link("Sign-in methods").classList.contains("active")).toBe(false);
  });

  it("moves between the pages with the links", async () => {
    await signInAlex();
    const view = show("/account/security");
    await screen.findByText("Laptop passkey");
    fireEvent.click(link("Sessions"));
    expect(await screen.findByText("Firefox on Android")).toBeTruthy();
    expect(view.location()).toContain("/account/sessions");
    fireEvent.click(link("Personal tokens"));
    expect(await screen.findByText("nightly export")).toBeTruthy();
    expect(screen.queryByText("Firefox on Android")).toBeNull();
    expect(view.location()).toContain("/account/tokens");
  });

  it("follows the language of the account", async () => {
    await signInAlex();
    await setLocale("sv");
    show("/account/sessions");
    expect(screen.getByRole("heading", { level: 1 }).textContent).toContain("Säkerhet och inloggning");
    expect(await screen.findByText("Var du är inloggad")).toBeTruthy();
    expect(screen.getByRole("link", { name: "Personliga token" })).toBeTruthy();
    expect(await screen.findByText("Firefox på Android")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Logga ut från alla andra enheter" })).toBeTruthy();
  });

  it("has no accessibility violations on any page", async () => {
    await signInAlex();
    for (const url of ["/account/security", "/account/sessions", "/account/tokens"]) {
      const view = show(url);
      await waitFor(() => expect(view.container.querySelector("table, .factor")).not.toBeNull());
      await new Promise((resolve) => setTimeout(resolve, 50));
      expect(await axeViolations(view.container)).toEqual([]);
      view.unmount();
    }
  });
});

describe("after a method was added", () => {
  it("tells the person to sign in again when the server says the session must", async () => {
    await signInAlex({ prepare: (u) => (u.totp = false) });
    server.use(
      http.post("/api/v1/auth/totp/enroll/finish", () => HttpResponse.json({ reauthenticate: true })),
    );
    show("/account/security");
    fireEvent.click(await screen.findByRole("button", { name: "Set up an authenticator app" }));
    fireEvent.input(await screen.findByLabelText("Code from the app"), { target: { value: MOCK_TOTP_CODE } });
    fireEvent.click(screen.getByRole("button", { name: "Verify" }));
    expect(await screen.findByText(/Sign out and sign in again with the new method to reach it/)).toBeTruthy();
  });
});
