import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { describe, expect, it } from "vitest";
import { db } from "../../api/mock/db";
import { SEED_TOKEN } from "../../api/mock/fixtures";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { session, setSessionForTest } from "../session";
import Account from "./Account";
import { signInAlex } from "./testkit";

// The view is rendered without the shell's <main>, which holds all page content in the app.
const NO_SHELL = { disable: ["region"] } as const;

function show() {
  return renderRoute(Account, { url: "/account/tokens", path: "/account/:section?" });
}

async function useProfile(profile: "home" | "standard" | "hardened" | "lab") {
  const s = session();
  if (!s) throw new Error("no session");
  setSessionForTest({ ...s, profile });
}

/** Opens the creation dialog and fills in the name. */
async function openCreate(name: string) {
  fireEvent.click(await screen.findByRole("button", { name: "Create token" }));
  const dialog = await screen.findByRole("dialog", { name: "Create a personal token" });
  fireEvent.input(within(dialog).getByLabelText("Name"), { target: { value: name } });
  return dialog;
}

const lifetimeOptions = (dialog: HTMLElement) =>
  within(dialog)
    .getAllByRole("option")
    .map((o) => o.textContent);

describe("personal tokens", () => {
  it("lists the tokens with the prefix, when they were made, expire and were used", async () => {
    await signInAlex();
    show();
    expect(await screen.findByText(SEED_TOKEN.name)).toBeTruthy();
    const row = screen.getByText(SEED_TOKEN.name).closest("tr");
    if (!row) throw new Error("no row");
    const prefix = row.querySelector(".mono");
    expect(prefix?.textContent).toBe(SEED_TOKEN.prefix);
    expect(within(row).getByText("3 hours ago")).toBeTruthy();
    // The secret is not on the page: only the start of it.
    expect(row.textContent).not.toMatch(/tko_[A-Za-z0-9_-]{12,}/);
    expect(screen.getAllByRole("columnheader").map((c) => c.textContent)).toEqual(
      expect.arrayContaining(["Name", "Starts with", "Created", "Expires", "Last used"]),
    );
  });

  it("says never for a token that does not expire and has not been used", async () => {
    await signInAlex();
    db.tokens.push({
      user_id: db.sessions[0]?.user_id ?? "",
      info: { id: "t-2", name: "ci", prefix: "tko_ab12", created_at: new Date().toISOString() },
    });
    show();
    const row = (await screen.findByText("ci")).closest("tr");
    if (!row) throw new Error("no row");
    expect(within(row).getAllByText("Never")).toHaveLength(2);
  });

  it("marks a token past its expiry", async () => {
    await signInAlex();
    db.tokens.push({
      user_id: db.sessions[0]?.user_id ?? "",
      info: {
        id: "t-3",
        name: "old job",
        prefix: "tko_cd34",
        created_at: new Date(Date.now() - 100 * 86_400_000).toISOString(),
        expires_at: new Date(Date.now() - 86_400_000).toISOString(),
      },
    });
    show();
    const row = (await screen.findByText("old job")).closest("tr");
    if (!row) throw new Error("no row");
    expect(within(row).getByText("Expired")).toBeTruthy();
  });

  it("creates a token, shows it once and then only its prefix", async () => {
    await signInAlex();
    show();
    const form = await openCreate("backup job");
    expect(db.tokens).toHaveLength(1);
    fireEvent.click(within(form).getByRole("button", { name: "Create" }));

    const dialog = await screen.findByRole("dialog", { name: "Your new token" });
    const secret = dialog.querySelector("code.secret")?.textContent ?? "";
    expect(secret).toMatch(/^tko_/);
    expect(secret.length).toBeGreaterThan(16);
    expect(dialog.textContent).toContain("Copy backup job now");
    expect(db.tokens).toHaveLength(2);

    // It cannot be closed before the person says it is stored, not even with Esc.
    const close = within(dialog).getByRole("button", { name: "Close" });
    expect(close.hasAttribute("disabled")).toBe(true);
    fireEvent.keyDown(dialog, { key: "Escape" });
    expect(screen.queryByRole("dialog", { name: "Your new token" })).not.toBeNull();
    fireEvent.click(within(dialog).getByLabelText("I have stored the token"));
    expect(close.hasAttribute("disabled")).toBe(false);
    fireEvent.click(close);
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());

    // Only the prefix remains.
    const row = (await screen.findByText("backup job")).closest("tr");
    if (!row) throw new Error("no row");
    expect(row.querySelector(".mono")?.textContent).toBe(secret.slice(0, 8));
    expect(document.body.textContent).not.toContain(secret);
    // 90 days is the default under the Standard profile, so the token expires.
    expect(within(row).getAllByRole("cell")[3]?.textContent).not.toBe("Never");
  });

  it("copies the token", async () => {
    await signInAlex();
    const copied: string[] = [];
    Object.defineProperty(navigator, "clipboard", {
      value: {
        writeText: async (text: string) => {
          copied.push(text);
        },
      },
      configurable: true,
    });
    show();
    const form = await openCreate("copy me");
    fireEvent.click(within(form).getByRole("button", { name: "Create" }));
    const dialog = await screen.findByRole("dialog", { name: "Your new token" });
    fireEvent.click(within(dialog).getByRole("button", { name: "Copy" }));
    await waitFor(() => expect(copied).toHaveLength(1));
    expect(copied[0]).toBe(dialog.querySelector("code.secret")?.textContent);
  });

  it("needs a name", async () => {
    await signInAlex();
    show();
    const form = await openCreate("   ");
    fireEvent.click(within(form).getByRole("button", { name: "Create" }));
    expect(screen.queryByRole("dialog", { name: "Your new token" })).toBeNull();
    expect(db.tokens).toHaveLength(1);
    expect(document.activeElement).toBe(within(form).getByLabelText("Name"));
  });

  it("offers the lifetimes the profile allows (TGL-05)", async () => {
    await signInAlex();
    for (const [profile, expected] of [
      ["standard", ["30 days", "90 days"]],
      ["hardened", ["30 days"]],
      ["home", ["30 days", "90 days", "365 days"]],
      ["lab", ["30 days", "90 days", "365 days", "No expiry"]],
    ] as const) {
      await useProfile(profile);
      const view = show();
      const dialog = await openCreate("x");
      expect(lifetimeOptions(dialog)).toEqual(expected);
      view.unmount();
    }
  });

  it("starts at 90 days where that is allowed and at the maximum where it is less", async () => {
    await signInAlex();
    show();
    let dialog = await openCreate("x");
    expect((within(dialog).getByLabelText("Lifetime") as HTMLSelectElement).value).toBe("90");
    expect(within(dialog).getByText("The Standard profile allows tokens to live at most 90 days.")).toBeTruthy();
    fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    await useProfile("hardened");
    dialog = await openCreate("x");
    expect((within(dialog).getByLabelText("Lifetime") as HTMLSelectElement).value).toBe("30");
  });

  it("shows the server's message when it disagrees about the maximum", async () => {
    // The page thinks this is the Lab profile; the server applies Standard (90 days).
    await signInAlex();
    await useProfile("lab");
    show();
    const dialog = await openCreate("too long");
    expect(within(dialog).getByText("The Lab profile sets no maximum.")).toBeTruthy();
    fireEvent.change(within(dialog).getByLabelText("Lifetime"), { target: { value: "365" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    const alert = await within(dialog).findByRole("alert");
    expect(alert.textContent).toBe("Tokens may live at most 90 days in this profile.");
    // The form stays, nothing was created.
    expect(screen.queryByRole("dialog", { name: "Your new token" })).toBeNull();
    expect(db.tokens).toHaveLength(1);
  });

  it("asks before revoking a token", async () => {
    await signInAlex();
    show();
    fireEvent.click(await screen.findByRole("button", { name: `Revoke ${SEED_TOKEN.name}` }));
    const dialog = await screen.findByRole("dialog", { name: `Revoke ${SEED_TOKEN.name}?` });
    expect(db.tokens).toHaveLength(1);
    fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(db.tokens).toHaveLength(1);

    fireEvent.click(screen.getByRole("button", { name: `Revoke ${SEED_TOKEN.name}` }));
    const again = await screen.findByRole("dialog");
    fireEvent.click(within(again).getByRole("button", { name: "Revoke" }));
    await waitFor(() => expect(db.tokens).toHaveLength(0));
    expect(await screen.findByText("You have no personal tokens.")).toBeTruthy();
    expect(screen.getByText(`${SEED_TOKEN.name} revoked`)).toBeTruthy();
  });

  it("has no accessibility violations on the page and in its dialogs", async () => {
    await signInAlex();
    const { container } = show();
    await screen.findByText(SEED_TOKEN.name);
    expect(await axeViolations(container)).toEqual([]);

    const form = await openCreate("axe");
    expect(await axeViolations(document.body, NO_SHELL)).toEqual([]);
    fireEvent.click(within(form).getByRole("button", { name: "Create" }));
    await screen.findByRole("dialog", { name: "Your new token" });
    expect(await axeViolations(document.body, NO_SHELL)).toEqual([]);
  });

  it("has no accessibility violations in the revoke confirmation", async () => {
    await signInAlex();
    show();
    fireEvent.click(await screen.findByRole("button", { name: `Revoke ${SEED_TOKEN.name}` }));
    await screen.findByRole("dialog");
    expect(await axeViolations(document.body, NO_SHELL)).toEqual([]);
  });
});
