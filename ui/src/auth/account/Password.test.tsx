import { fireEvent, screen, waitFor } from "@solidjs/testing-library";
import { afterEach, describe, expect, it, vi } from "vitest";
import { db } from "../../api/mock/db";
import { MOCK_PASSWORDS } from "../../api/mock/fixtures";
import { server } from "../../api/mock/node";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { session, setSessionForTest } from "../session";
import Account from "./Account";
import { alex, signInAlex } from "./testkit";

const STRONG = "tulip-garden-77-lantern";
const WAIT = { timeout: 3000 };

function show() {
  return renderRoute(Account, { url: "/account/security", path: "/account/:section?" });
}

const field = (name: string) => screen.getByLabelText(name) as HTMLInputElement;
const type = (name: string, value: string) => fireEvent.input(field(name), { target: { value } });
const items = () => Array.from(document.querySelectorAll<HTMLLIElement>(".pw-checks li"));
const itemFor = (text: string | RegExp) => {
  const found = items().find((li) => (typeof text === "string" ? li.textContent?.includes(text) : text.test(li.textContent ?? "")));
  if (!found) throw new Error(`no checklist line for ${String(text)}`);
  return found;
};

afterEach(() => {
  server.events.removeAllListeners();
  vi.restoreAllMocks();
});

describe("change of the password or PIN", () => {
  it("shows the rule of the profile before anything is typed", async () => {
    await signInAlex();
    show();
    expect(await screen.findByText("At least 12 characters")).toBeTruthy();
    expect(items().every((li) => li.classList.contains("idle"))).toBe(true);
  });

  it("checks the new password live and rejects a breached one", async () => {
    await signInAlex();
    show();
    type("New PIN or password", "letmein-please-123");
    await waitFor(() => expect(itemFor("breaches").classList.contains("bad")).toBe(true), WAIT);
    expect(itemFor("breaches").textContent).toContain("This password appears in known data breaches. Choose another.");
    expect(itemFor("At least 12 characters").classList.contains("ok")).toBe(true);
    type("Repeat the new PIN or password", "letmein-please-123");
    expect(screen.getByRole("button", { name: "Change PIN or password" }).hasAttribute("disabled")).toBe(true);
  });

  it("marks a password that is too short and one that is repeated or sequential", async () => {
    await signInAlex();
    show();
    type("New PIN or password", "abcdef");
    await waitFor(() => expect(itemFor("At least 12 characters").classList.contains("bad")).toBe(true), WAIT);
    expect(itemFor("repeated or sequential").classList.contains("bad")).toBe(true);
    expect(itemFor("At least 12 characters").textContent).toContain("Not met");
  });

  it("marks a password that contains the user name", async () => {
    await signInAlex();
    show();
    type("New PIN or password", "alex-is-the-best-1");
    await waitFor(() => expect(itemFor("user name").classList.contains("bad")).toBe(true), WAIT);
  });

  it("accepts a good password: every line is met", async () => {
    await signInAlex();
    show();
    type("New PIN or password", STRONG);
    await waitFor(() => expect(items().filter((li) => li.classList.contains("ok"))).toHaveLength(4), WAIT);
    expect(itemFor("Not found in known data breaches").textContent).toContain("Met");
  });

  it("asks the server once for a burst of keystrokes, 300 ms after the last one", async () => {
    await signInAlex();
    const asked: string[] = [];
    server.events.on("request:start", ({ request }) => {
      if (request.method === "POST" && new URL(request.url).pathname === "/api/v1/auth/password/check") {
        void request
          .clone()
          .json()
          .then((body: { password: string }) => asked.push(body.password));
      }
    });
    show();
    await screen.findByText("At least 12 characters");
    type("New PIN or password", "t");
    type("New PIN or password", "tu");
    type("New PIN or password", "tul");
    await new Promise((resolve) => setTimeout(resolve, 150));
    expect(asked.filter((p) => p !== "")).toEqual([]);
    await waitFor(() => expect(asked.filter((p) => p !== "")).toEqual(["tul"]), WAIT);
  });

  it("flags two entries that differ", async () => {
    await signInAlex();
    show();
    type("New PIN or password", STRONG);
    type("Repeat the new PIN or password", `${STRONG}x`);
    expect(await screen.findByText("The two entries differ.")).toBeTruthy();
    expect(field("Repeat the new PIN or password").getAttribute("aria-invalid")).toBe("true");
    expect(screen.getByRole("button", { name: "Change PIN or password" }).hasAttribute("disabled")).toBe(true);
  });

  it("says the current password is wrong", async () => {
    await signInAlex();
    show();
    type("Current PIN or password", "not-my-password");
    type("New PIN or password", STRONG);
    type("Repeat the new PIN or password", STRONG);
    await waitFor(() => expect(screen.getByRole("button", { name: "Change PIN or password" }).hasAttribute("disabled")).toBe(false), WAIT);
    fireEvent.click(screen.getByRole("button", { name: "Change PIN or password" }));
    expect(await screen.findByText("The current password is wrong.")).toBeTruthy();
    expect(field("Current PIN or password").getAttribute("aria-invalid")).toBe("true");
    expect(alex().password).toBe(MOCK_PASSWORDS.alex);
  });

  it("changes the password, names how many other sessions were signed out and clears the warning", async () => {
    await signInAlex({ prepare: (u) => (u.password_change_required = true) });
    show();
    expect(session()?.flags.password_change_required).toBe(true);
    expect(screen.getByText(/You must choose a new password or PIN/)).toBeTruthy();
    expect(db.sessions).toHaveLength(3);

    type("Current PIN or password", MOCK_PASSWORDS.alex);
    type("New PIN or password", STRONG);
    type("Repeat the new PIN or password", STRONG);
    const submit = screen.getByRole("button", { name: "Change PIN or password" });
    await waitFor(() => expect(submit.hasAttribute("disabled")).toBe(false), WAIT);
    fireEvent.click(submit);

    expect(await screen.findByText("PIN or password changed")).toBeTruthy();
    expect(screen.getByText("2 other sessions were signed out.")).toBeTruthy();
    expect(alex().password).toBe(STRONG);
    expect(db.sessions).toHaveLength(1);
    expect(field("New PIN or password").value).toBe("");
    // The session is read again, so the warning goes away.
    await waitFor(() => expect(session()?.flags.password_change_required).toBe(false), WAIT);
    expect(screen.queryByText(/You must choose a new password or PIN/)).toBeNull();
  });

  it("says when no other session was signed out", async () => {
    await signInAlex();
    db.sessions = db.sessions.filter((s) => s.id === db.currentSessionId);
    show();
    type("Current PIN or password", MOCK_PASSWORDS.alex);
    type("New PIN or password", STRONG);
    type("Repeat the new PIN or password", STRONG);
    const submit = screen.getByRole("button", { name: "Change PIN or password" });
    await waitFor(() => expect(submit.hasAttribute("disabled")).toBe(false), WAIT);
    fireEvent.click(submit);
    expect(await screen.findByText("No other sessions were signed out.")).toBeTruthy();
  });

  it("shows the new password only when asked to", async () => {
    await signInAlex();
    show();
    expect(field("New PIN or password").type).toBe("password");
    fireEvent.click(screen.getByRole("button", { name: "Show the new password" }));
    expect(field("New PIN or password").type).toBe("text");
    expect(field("Repeat the new PIN or password").type).toBe("text");
  });

  it("leaves the break-glass account without a form", async () => {
    await signInAlex();
    const s = session();
    if (!s) throw new Error("no session");
    setSessionForTest({ ...s, flags: { ...s.flags, break_glass: true } });
    show();
    expect(screen.getByText("The break-glass account signs in with its hardware security key only.")).toBeTruthy();
    expect(screen.queryByLabelText("Current PIN or password")).toBeNull();
  });

  it("has no accessibility violations, empty or with the checklist filled in", async () => {
    await signInAlex();
    const { container } = show();
    await screen.findByText("At least 12 characters");
    expect(await axeViolations(container)).toEqual([]);
    type("New PIN or password", "letmein-please-123");
    await waitFor(() => expect(itemFor("breaches").classList.contains("bad")).toBe(true), WAIT);
    expect(await axeViolations(container)).toEqual([]);
  });
});
