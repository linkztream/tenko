import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { describe, expect, it } from "vitest";
import { db } from "../../api/mock/db";
import { OTHER_SESSIONS } from "../../api/mock/fixtures";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { authState } from "../session";
import Account from "./Account";
import { signInAlex } from "./testkit";

// The view is rendered without the shell's <main>, which holds all page content in the app.
const NO_SHELL = { disable: ["region"] } as const;

function show() {
  return renderRoute(Account, { url: "/account/sessions", path: "/account/:section?" });
}

/** The row of the table whose first cell reads `client`. */
function rowOf(client: string): HTMLTableRowElement {
  const row = screen
    .getAllByRole("row")
    .find((r) => r.querySelector("td .acct-client")?.textContent === client);
  if (!row) throw new Error(`no session row for ${client}`);
  return row as HTMLTableRowElement;
}

describe("sessions", () => {
  it("lists the sessions of the account and marks this one", async () => {
    await signInAlex();
    show();
    await screen.findByText("Firefox on Android");
    // A header row and three sessions.
    expect(screen.getAllByRole("row")).toHaveLength(4);
    expect(screen.getAllByText("This session")).toHaveLength(1);
    const columns = screen.getAllByRole("columnheader").map((c) => c.textContent);
    expect(columns).toEqual(expect.arrayContaining(["Client", "Address", "Signed in", "Last activity", "Expires", "Sign-in method"]));
  });

  it("reads the user agent as browser and system and keeps the raw string in the title", async () => {
    await signInAlex();
    show();
    await screen.findByText("Firefox on Android");
    const row = rowOf("Firefox on Android");
    const client = row.querySelector(".acct-client");
    expect(client?.getAttribute("title")).toBe(OTHER_SESSIONS[0].user_agent);
    // The source address is in the data font.
    expect(row.querySelector(".addr")?.textContent).toBe("198.51.100.7");
    expect(within(row).getByText("Password")).toBeTruthy();
  });

  it("shows when each session started, was last active and ends", async () => {
    await signInAlex();
    show();
    await screen.findByText("Firefox on Android");
    const row = rowOf("Firefox on Android");
    const cells = within(row).getAllByRole("cell");
    // client, address, signed in, last activity, expires, method, actions
    expect(cells).toHaveLength(7);
    expect(cells[3]?.textContent).toMatch(/12 minutes ago/);
    expect(cells[2]?.textContent).not.toBe("");
    expect(cells[4]?.textContent).not.toBe("");
  });

  it("names a command-line tool", async () => {
    await signInAlex();
    const other = db.sessions.find((s) => s.id !== db.currentSessionId);
    if (!other) throw new Error("no other session");
    other.user_agent = "curl/8.5.0";
    show();
    expect(await screen.findByText("curl")).toBeTruthy();
  });

  it("offers Sign out for this session and Revoke for the others", async () => {
    await signInAlex();
    show();
    await screen.findByText("Firefox on Android");
    const current = screen.getByText("This session").closest("tr");
    if (!current) throw new Error("no row");
    expect(within(current).getByRole("button", { name: "Sign out" })).toBeTruthy();
    expect(within(current).queryByRole("button", { name: /Revoke/ })).toBeNull();
    expect(screen.getAllByRole("button", { name: /^Revoke the session from / })).toHaveLength(2);
  });

  it("revokes another session and takes it off the list", async () => {
    await signInAlex();
    show();
    fireEvent.click(await screen.findByRole("button", { name: "Revoke the session from Firefox on Android" }));
    await waitFor(() => expect(screen.queryByText("Firefox on Android")).toBeNull());
    expect(db.sessions).toHaveLength(2);
    expect(screen.getByText("Session revoked")).toBeTruthy();
    expect(screen.getAllByRole("row")).toHaveLength(3);
  });

  it("signs out of this session from its own row", async () => {
    await signInAlex();
    show();
    const current = (await screen.findByText("This session")).closest("tr");
    if (!current) throw new Error("no row");
    fireEvent.click(within(current).getByRole("button", { name: "Sign out" }));
    await waitFor(() => expect(authState()).toBe("signed-out"));
    expect(db.currentSessionId).toBeNull();
  });

  it("names the count on the button that signs out everywhere else", async () => {
    await signInAlex();
    show();
    await screen.findByText("Firefox on Android");
    fireEvent.click(screen.getByRole("button", { name: "Sign out everywhere else" }));
    const dialog = await screen.findByRole("dialog", { name: "Sign out everywhere else?" });
    expect(dialog.textContent).toContain("The 2 other sessions of this account end at once.");
    expect(dialog.textContent).toContain("This session stays signed in.");
    // Nothing has happened yet.
    expect(db.sessions).toHaveLength(3);
    fireEvent.click(within(dialog).getByRole("button", { name: "Sign out 2 other sessions" }));
    await waitFor(() => expect(db.sessions).toHaveLength(1));
    await waitFor(() => expect(screen.getAllByRole("row")).toHaveLength(2));
    expect(screen.getByText("2 sessions signed out")).toBeTruthy();
    expect(screen.getByText("You have no other open sessions.")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Sign out everywhere else" }).hasAttribute("disabled")).toBe(true);
    // This session stays.
    expect(db.currentSessionId).not.toBeNull();
    expect(authState()).toBe("signed-in");
  });

  it("uses the singular for one other session", async () => {
    await signInAlex();
    show();
    fireEvent.click(await screen.findByRole("button", { name: "Revoke the session from Firefox on Android" }));
    await waitFor(() => expect(db.sessions).toHaveLength(2));
    await waitFor(() => expect(screen.queryByText("Firefox on Android")).toBeNull());
    fireEvent.click(screen.getByRole("button", { name: "Sign out everywhere else" }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByRole("button", { name: "Sign out 1 other session" })).toBeTruthy();
    expect(dialog.textContent).toContain("The 1 other session of this account ends at once.");
  });

  it("has nothing to sign out when this is the only session", async () => {
    await signInAlex();
    db.sessions = db.sessions.filter((s) => s.id === db.currentSessionId);
    show();
    await screen.findByText("This session");
    expect(screen.getByRole("button", { name: "Sign out everywhere else" }).hasAttribute("disabled")).toBe(true);
  });

  it("has no accessibility violations on the page or in the confirmation", async () => {
    await signInAlex();
    const { container } = show();
    await screen.findByText("Firefox on Android");
    expect(await axeViolations(container)).toEqual([]);
    fireEvent.click(screen.getByRole("button", { name: "Sign out everywhere else" }));
    await screen.findByRole("dialog");
    expect(await axeViolations(document.body, NO_SHELL)).toEqual([]);
  });
});
