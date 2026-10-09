import { afterEach, describe, expect, it } from "vitest";
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { db } from "../api/mock/db";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { session, setSessionForTest } from "../auth/session";
import SecurityPage from "./SecurityPage";
import { SETTINGS_PATH, signInAs } from "./testkit";
import { TOGGLES } from "./toggles";

afterEach(() => setSessionForTest(null));

async function openPage() {
  const view = renderRoute(SecurityPage, { url: "/settings/security", path: SETTINGS_PATH });
  await screen.findByRole("table", { name: "Security settings and their values" });
  return view;
}

function row(id: string): HTMLElement {
  const el = document.querySelector<HTMLElement>(`tr[data-toggle="${id}"]`);
  if (!el) throw new Error(`no row for ${id}`);
  return el;
}

async function openEditor(name: string) {
  fireEvent.click(screen.getByRole("button", { name: `Edit ${name}` }));
  return screen.findByRole("dialog", { name: `Edit ${name}` });
}

describe("the security page", () => {
  it("lists TGL-01 to TGL-07 and TGL-23 in order with the current and the profile value", async () => {
    await signInAs();
    await openPage();
    const ids = Array.from(document.querySelectorAll("tbody tr[data-toggle]")).map((r) => r.getAttribute("data-toggle"));
    expect(ids).toEqual(TOGGLES.map((d) => d.id));
    expect(ids).toHaveLength(8);
    // The Standard profile: administrators need MFA, passwords are at least 12 characters.
    expect(within(row("TGL-02")).getAllByText("Required for administrators")).toHaveLength(2);
    expect(within(row("TGL-01")).getAllByText("Standard: at least 12 characters")).toHaveLength(2);
    expect(within(row("TGL-01")).getByText("TGL-01").className).toContain("mono");
    // Everything follows the profile: no deviation, no reset button, no banner.
    expect(screen.getByText("Every setting follows the profile.")).toBeTruthy();
    expect(screen.queryByRole("button", { name: /Reset to profile/ })).toBeNull();
    expect(screen.getByText(/of 23 settings are available/)).toBeTruthy();
  });

  it("shows the profile with its description and how many settings differ", async () => {
    await signInAs();
    await openPage();
    expect(screen.getByText("Business AD environment. The default for organizations.")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Change profile" })).toBeTruthy();
  });

  it("is loud in the Lab profile", async () => {
    await signInAs("lab");
    await openPage();
    expect(screen.getByText("The Lab profile is active")).toBeTruthy();
    expect(screen.getByText("Permissive")).toBeTruthy();
    // Lab sets lockout and the breached-password check off: weaker than Home, but not a deviation.
    expect(within(row("TGL-07")).getByText("Weaker than Home")).toBeTruthy();
    expect(within(row("TGL-06")).getByText("Weaker than Home")).toBeTruthy();
    expect(within(row("TGL-07")).queryByText("Differs from the profile")).toBeNull();
    expect(within(row("TGL-07")).queryByRole("button", { name: /Reset to profile/ })).toBeNull();
  });

  it("marks a setting that is weaker than Home, and a reset to the profile clears it and the banner", async () => {
    await signInAs("weak");
    await openPage();
    const lockout = row("TGL-07");
    expect(within(lockout).getByText("Weaker than Home")).toBeTruthy();
    expect(within(lockout).getByText("Differs from the profile")).toBeTruthy();
    expect(screen.getByText(/This setting is weaker than the Home profile: Lockout\./)).toBeTruthy();
    expect(session()?.banner.weaker_than_home).toBe(true);
    // The other six follow the profile.
    expect(within(row("TGL-01")).getByText("Follows the profile")).toBeTruthy();

    fireEvent.click(within(lockout).getByRole("button", { name: "Reset to profile: Lockout" }));

    await waitFor(() => expect(within(row("TGL-07")).queryByText("Weaker than Home")).toBeNull());
    expect(within(row("TGL-07")).queryByText("Differs from the profile")).toBeNull();
    expect(within(row("TGL-07")).getByText("Follows the profile")).toBeTruthy();
    // The shell banner follows the answer without a new session request.
    expect(session()?.banner.weaker_than_home).toBe(false);
    expect(db.settings.lockout).toBe("progressive_delay");
    expect(await screen.findByText("Reset Lockout to the profile")).toBeTruthy();
    expect(screen.queryByText(/is weaker than the Home profile/)).toBeNull();
  });

  it("shows the consequence of a weaker value before saving, saves it and raises the banner", async () => {
    await signInAs();
    await openPage();
    expect(session()?.banner.weaker_than_home).toBe(false);
    const dialog = await openEditor("Lockout");
    expect(within(dialog).getByText(/Nothing changes yet/)).toBeTruthy();
    expect((within(dialog).getByRole("button", { name: "Save setting" }) as HTMLButtonElement).disabled).toBe(true);

    fireEvent.change(within(dialog).getByLabelText("Lockout"), { target: { value: "off" } });
    expect(await within(dialog).findByText("Weaker than Home: the warning banner will show for everyone.")).toBeTruthy();
    expect(within(dialog).getByText(/Differs from the Standard profile/)).toBeTruthy();
    fireEvent.click(within(dialog).getByRole("button", { name: "Save setting" }));

    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(db.settings.lockout).toBe("off");
    expect(session()?.banner.weaker_than_home).toBe(true);
    expect(within(row("TGL-07")).getByText("Weaker than Home")).toBeTruthy();
    expect(within(row("TGL-07")).getByText("Differs from the profile")).toBeTruthy();
    expect(await screen.findByText("Saved Lockout")).toBeTruthy();
  });

  it("says when a change lifts the last weaker setting that the banner stands on", async () => {
    await signInAs("weak");
    await openPage();
    const dialog = await openEditor("Lockout");
    fireEvent.change(within(dialog).getByLabelText("Lockout"), { target: { value: "progressive_delay" } });
    expect(await within(dialog).findByText("No longer weaker than Home. The warning banner will clear.")).toBeTruthy();
    expect(within(dialog).getByText(/Matches the Home profile/)).toBeTruthy();
  });

  it("edits the session lifetimes and refuses an idle time that exceeds the absolute time", async () => {
    await signInAs();
    await openPage();
    const dialog = await openEditor("Session lifetime (absolute / idle)");
    const idle = within(dialog).getByLabelText("Idle lifetime");
    const absolute = within(dialog).getByLabelText("Absolute lifetime");
    expect((absolute as HTMLInputElement).value).toBe("12");

    fireEvent.input(idle, { target: { value: "13" } });
    expect(
      await within(dialog).findByText("The idle lifetime cannot be longer than the absolute lifetime."),
    ).toBeTruthy();
    expect(idle.getAttribute("aria-invalid")).toBe("true");
    expect((within(dialog).getByRole("button", { name: "Save setting" }) as HTMLButtonElement).disabled).toBe(true);

    // 13 hours idle fits inside one day.
    fireEvent.input(absolute, { target: { value: "1" } });
    fireEvent.change(within(dialog).getByLabelText("Unit of Absolute lifetime"), { target: { value: "days" } });
    await waitFor(() => expect(idle.getAttribute("aria-invalid")).toBeNull());
    fireEvent.click(within(dialog).getByRole("button", { name: "Save setting" }));

    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(db.settings.session).toEqual({ absolute_secs: 86_400, idle_secs: 13 * 3_600 });
    // The Standard profile has 12 h / 1 h: longer sessions are weaker than Home? No, Home is 30 d / 7 d.
    expect(within(row("TGL-04")).getByText("Differs from the profile")).toBeTruthy();
    expect(within(row("TGL-04")).queryByText("Weaker than Home")).toBeNull();
  });

  it("edits a custom password policy and checks the numbers", async () => {
    await signInAs();
    await openPage();
    const dialog = await openEditor("Password policy preset");
    fireEvent.change(within(dialog).getByLabelText("Preset"), { target: { value: "custom" } });
    const min = await within(dialog).findByLabelText("Minimum length");
    fireEvent.input(min, { target: { value: "3" } });
    expect(await within(dialog).findByText("Enter a whole number from 4 to 256.")).toBeTruthy();
    fireEvent.input(min, { target: { value: "14" } });
    fireEvent.input(within(dialog).getByLabelText("Required pattern (optional)"), { target: { value: "[" } });
    expect(await within(dialog).findByText("This is not a valid regular expression.")).toBeTruthy();
    expect((within(dialog).getByRole("button", { name: "Save setting" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.input(within(dialog).getByLabelText("Required pattern (optional)"), { target: { value: "" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Save setting" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(db.settings.password_policy).toEqual({ preset: "custom", min_length: 14 });
    expect(within(row("TGL-01")).getByText("Custom: at least 14 characters")).toBeTruthy();
  });

  it("sets the token maximum to none and to a number of days", async () => {
    await signInAs();
    await openPage();
    let dialog = await openEditor("API token maximum lifetime");
    fireEvent.click(within(dialog).getByRole("radio", { name: /No maximum/ }));
    expect(await within(dialog).findByText("Weaker than Home: the warning banner will show for everyone.")).toBeTruthy();
    fireEvent.click(within(dialog).getByRole("button", { name: "Save setting" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(db.settings.token_max_days).toBeNull();
    expect(within(row("TGL-05")).getAllByText("No maximum")).toHaveLength(1);

    dialog = await openEditor("API token maximum lifetime");
    fireEvent.click(within(dialog).getByRole("radio", { name: /Limit to a number of days/ }));
    const days = await within(dialog).findByLabelText("Maximum lifetime in days");
    fireEvent.input(days, { target: { value: "0" } });
    expect(await within(dialog).findByText("Enter a whole number from 1 to 36,500.")).toBeTruthy();
    fireEvent.input(days, { target: { value: "45" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Save setting" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(db.settings.token_max_days).toBe(45);
  });

  it("turns the passkey requirement on", async () => {
    await signInAs();
    await openPage();
    const dialog = await openEditor("Passkey required for administrators");
    fireEvent.click(within(dialog).getByRole("switch"));
    fireEvent.click(within(dialog).getByRole("button", { name: "Save setting" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(db.settings.passkey_for_admins).toBe(true);
    expect(within(row("TGL-03")).getByText("Differs from the profile")).toBeTruthy();
  });

  it("previews a profile switch, lists the settings that change, and applies it on confirmation", async () => {
    await signInAs();
    await openPage();
    fireEvent.click(screen.getByRole("button", { name: "Change profile" }));
    const dialog = await screen.findByRole("dialog", { name: "Change security profile" });
    // Nothing differs from Standard yet: resetting to the current profile changes nothing.
    expect(within(dialog).getByText("No setting changes.")).toBeTruthy();

    fireEvent.click(within(dialog).getByRole("radio", { name: /Hardened/ }));
    expect(
      await within(dialog).findByText("Switching to Hardened resets every setting to the Hardened values."),
    ).toBeTruthy();
    expect(within(dialog).getByText("8 settings change:")).toBeTruthy();
    const table = within(dialog).getByRole("table", { name: "Settings that change" });
    expect(within(table).getByText("Password policy preset")).toBeTruthy();
    expect(within(table).getByText("Lockout")).toBeTruthy();
    expect(within(table).getByText("Updates")).toBeTruthy();
    // The database has not changed before the confirmation.
    expect(db.settings.profile).toBe("standard");

    fireEvent.click(within(dialog).getByRole("button", { name: "Switch to Hardened" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(db.settings.profile).toBe("hardened");
    expect(db.settings.passkey_for_admins).toBe(true);
    expect(await screen.findByText("Switched to Hardened")).toBeTruthy();
    expect(within(row("TGL-03")).getAllByText("Yes")).toHaveLength(2);
  });

  it("needs an acknowledgement for Lab and shows what Lab turns off", async () => {
    await signInAs();
    await openPage();
    fireEvent.click(screen.getByRole("button", { name: "Change profile" }));
    const dialog = await screen.findByRole("dialog", { name: "Change security profile" });
    fireEvent.click(within(dialog).getByRole("radio", { name: /Lab/ }));
    const confirm = await within(dialog).findByRole("button", { name: "Switch to Lab" });
    expect((confirm as HTMLButtonElement).disabled).toBe(true);
    expect(within(dialog).getAllByText("The Lab profile is active")).toHaveLength(1);
    // The new values that are weaker than Home carry the marker in the preview.
    expect(within(dialog).getAllByText("Weaker than Home").length).toBeGreaterThan(0);

    fireEvent.click(within(dialog).getByRole("checkbox"));
    expect((confirm as HTMLButtonElement).disabled).toBe(false);
    fireEvent.click(confirm);
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(db.settings.profile).toBe("lab");
    expect(session()?.banner.lab).toBe(true);
    expect(await screen.findByText("The Lab profile is active")).toBeTruthy();
  });

  it("resets every deviation by switching to the current profile", async () => {
    await signInAs("weak");
    await openPage();
    fireEvent.click(screen.getByRole("button", { name: "Change profile" }));
    const dialog = await screen.findByRole("dialog", { name: "Change security profile" });
    expect(
      within(dialog).getByText("Resetting to Home puts every setting back to the Home values."),
    ).toBeTruthy();
    expect(within(dialog).getByText("1 setting changes:")).toBeTruthy();
    fireEvent.click(within(dialog).getByRole("button", { name: "Reset to Home" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(db.settings.lockout).toBe("progressive_delay");
    expect(session()?.banner.weaker_than_home).toBe(false);
  });

  it("shows the precondition message when the settings changed in the meantime, and works after the reload", async () => {
    await signInAs();
    await openPage();
    const dialog = await openEditor("MFA requirement");
    // Someone else saved the settings after this page read them.
    db.settingsRevision += 5;
    fireEvent.change(within(dialog).getByLabelText("MFA requirement"), { target: { value: "everyone" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Save setting" }));
    const alert = await within(dialog).findByRole("alert");
    expect(alert.textContent).toContain("Someone else changed this in the meantime. Reload and try again.");
    expect(db.settings.mfa).toBe("administrators");
    expect(within(dialog).getByText("The latest version has been loaded. Check it and try again.")).toBeTruthy();

    // The page reads the settings again, so the next try carries the new revision. Wait for
    // the reload to finish (the row shows the reloaded data) before trying once more.
    await new Promise((r) => setTimeout(r, 50));
    fireEvent.click(within(dialog).getByRole("button", { name: "Save setting" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(db.settings.mfa).toBe("everyone");
  });

  it("shows why a PIN is refused while the vault holds secrets", async () => {
    await signInAs();
    db.vaultHasOperatorSecrets = true;
    await openPage();
    expect(screen.getByText("The vault holds secrets")).toBeTruthy();
    const dialog = await openEditor("Password policy preset");
    fireEvent.change(within(dialog).getByLabelText("Preset"), { target: { value: "pin" } });
    expect(
      await within(dialog).findByText(
        "A PIN alone is not allowed while the vault holds secrets. Add a passkey or choose a password preset.",
      ),
    ).toBeTruthy();
    expect((within(dialog).getByRole("button", { name: "Save setting" }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("shows the server's refusal of a PIN when the vault gained secrets after the page loaded", async () => {
    await signInAs();
    await openPage();
    expect(screen.queryByText("The vault holds secrets")).toBeNull();
    const dialog = await openEditor("Password policy preset");
    fireEvent.change(within(dialog).getByLabelText("Preset"), { target: { value: "pin" } });
    db.vaultHasOperatorSecrets = true;
    fireEvent.click(within(dialog).getByRole("button", { name: "Save setting" }));
    const alert = await within(dialog).findByRole("alert");
    expect(alert.textContent).toBe(
      "A PIN alone is not allowed while the vault holds secrets. Add a passkey or choose a password preset.",
    );
    expect(db.settings.password_policy.preset).toBe("standard");
  });

  it("refuses a switch to a profile that sets the PIN while the vault holds secrets", async () => {
    await signInAs();
    db.vaultHasOperatorSecrets = true;
    await openPage();
    fireEvent.click(screen.getByRole("button", { name: "Change profile" }));
    const dialog = await screen.findByRole("dialog", { name: "Change security profile" });
    fireEvent.click(within(dialog).getByRole("radio", { name: /Home/ }));
    expect(
      await within(dialog).findByText(/A PIN alone is not allowed while the vault holds secrets/),
    ).toBeTruthy();
    expect((within(dialog).getByRole("button", { name: "Switch to Home" }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("explains a failed load and offers a retry", async () => {
    await signInAs();
    // An operator may read the settings, a viewer may not.
    const alex = db.users.find((u) => u.name === "alex");
    if (alex) alex.roles = ["viewer"];
    setSessionForTest(null);
    renderRoute(SecurityPage, { url: "/settings/security", path: SETTINGS_PATH });
    expect(await screen.findByRole("alert")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Try again" })).toBeTruthy();
  });

  it("has no accessibility violations: the page, an editor and the profile dialog", async () => {
    await signInAs("weak");
    const view = await openPage();
    expect(await axeViolations(view.container)).toEqual([]);

    const editor = await openEditor("Session lifetime (absolute / idle)");
    expect(await axeViolations(editor)).toEqual([]);
    fireEvent.click(within(editor).getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());

    fireEvent.click(screen.getByRole("button", { name: "Change profile" }));
    const dialog = await screen.findByRole("dialog", { name: "Change security profile" });
    fireEvent.click(within(dialog).getByRole("radio", { name: /Lab/ }));
    await within(dialog).findByRole("button", { name: "Switch to Lab" });
    expect(await axeViolations(dialog)).toEqual([]);
  });
});

describe("TGL-23: the update check and who may install", () => {
  it("lists the toggle with the value of the profile and no deviation", async () => {
    await signInAs();
    await openPage();
    const updates = row("TGL-23");
    expect(within(updates).getAllByText("Daily check on, install after a fresh sign-in")).toHaveLength(2);
    expect(within(updates).getByText("Follows the profile")).toBeTruthy();
    expect(within(updates).queryByRole("button", { name: /Reset to profile/ })).toBeNull();
  });

  it("shows the default of each profile in the profile dialog", async () => {
    await signInAs("lab");
    await openPage();
    // Lab installs from the web interface; Standard asks for a fresh sign-in first.
    expect(within(row("TGL-23")).getAllByText("Daily check on, install from the web interface")).toHaveLength(2);
    fireEvent.click(screen.getByRole("button", { name: "Change profile" }));
    const dialog = await screen.findByRole("dialog", { name: "Change security profile" });
    fireEvent.click(within(dialog).getByRole("radio", { name: /Hardened/ }));
    const table = await within(dialog).findByRole("table", { name: "Settings that change" });
    const changed = within(table).getByText("Updates").closest("tr") as HTMLElement;
    expect(within(changed).getByText("Daily check on, install from the web interface")).toBeTruthy();
    expect(within(changed).getByText("Daily check on, install from an uploaded file only")).toBeTruthy();
  });

  it("edits the install mode, explains each option and marks the deviation", async () => {
    await signInAs();
    await openPage();
    const dialog = await openEditor("Updates");
    expect(within(dialog).getByRole("switch", { name: /Check for new versions every day/ })).toBeTruthy();
    expect((within(dialog).getByRole("switch", { name: /Check for new versions every day/ }) as HTMLInputElement).checked).toBe(true);
    // Each option says what it means.
    const modes = within(dialog).getAllByTestId("updates-install-mode");
    expect(modes.map((m) => m.getAttribute("data-key"))).toEqual(["ui", "ui_step_up", "upload_only"]);
    expect((modes[1] as HTMLInputElement).checked).toBe(true);
    expect(within(dialog).getByText(/An administrator can install a new version with one click/)).toBeTruthy();
    expect(within(dialog).getByText(/must sign in again with a stronger method before the install starts/)).toBeTruthy();
    expect(within(dialog).getByText(/The server downloads nothing/)).toBeTruthy();
    expect((within(dialog).getByRole("button", { name: "Save setting" }) as HTMLButtonElement).disabled).toBe(true);

    fireEvent.click(within(dialog).getByRole("radio", { name: /Only from an uploaded file/ }));
    expect(await within(dialog).findByText(/Differs from the Standard profile/)).toBeTruthy();
    fireEvent.click(within(dialog).getByRole("button", { name: "Save setting" }));

    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(db.settings.updates).toEqual({ check: true, install: "upload_only" });
    const updates = row("TGL-23");
    expect(within(updates).getByText("Daily check on, install from an uploaded file only")).toBeTruthy();
    expect(within(updates).getByText("Differs from the profile")).toBeTruthy();
    expect(within(updates).queryByText("Weaker than Home")).toBeNull();
    expect(await screen.findByText("Saved Updates")).toBeTruthy();
  });

  it("calls a switched-off check weaker than Home, raises the banner and resets to the profile", async () => {
    await signInAs();
    await openPage();
    expect(session()?.banner.weaker_than_home).toBe(false);
    const dialog = await openEditor("Updates");
    fireEvent.click(within(dialog).getByRole("switch", { name: /Check for new versions every day/ }));
    expect(await within(dialog).findByText("Weaker than Home: the warning banner will show for everyone.")).toBeTruthy();
    fireEvent.click(within(dialog).getByRole("button", { name: "Save setting" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());

    expect(db.settings.updates).toEqual({ check: false, install: "ui_step_up" });
    expect(session()?.banner.weaker_than_home).toBe(true);
    expect(session()?.banner.deviations).toEqual(["TGL-23"]);
    const updates = row("TGL-23");
    expect(within(updates).getByText("Weaker than Home")).toBeTruthy();
    expect(within(updates).getByText("Daily check off, install after a fresh sign-in")).toBeTruthy();

    fireEvent.click(within(updates).getByRole("button", { name: "Reset to profile: Updates" }));
    await waitFor(() => expect(within(row("TGL-23")).queryByText("Weaker than Home")).toBeNull());
    expect(db.settings.updates).toEqual({ check: true, install: "ui_step_up" });
    expect(session()?.banner.weaker_than_home).toBe(false);
  });

  it("keeps the other toggles when only the updates change, and the updates when another toggle changes", async () => {
    await signInAs();
    await openPage();
    const first = await openEditor("Updates");
    fireEvent.click(within(first).getByRole("radio", { name: /^From the web interface\s*An administrator can install/ }));
    fireEvent.click(within(first).getByRole("button", { name: "Save setting" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(db.settings.updates).toEqual({ check: true, install: "ui" });

    const second = await openEditor("Lockout");
    fireEvent.change(within(second).getByLabelText("Lockout"), { target: { value: "lock_until_unlock" } });
    fireEvent.click(within(second).getByRole("button", { name: "Save setting" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(db.settings.lockout).toBe("lock_until_unlock");
    // The row of TGL-23 is still there, with the value the first edit saved.
    expect(within(row("TGL-23")).getByText("Daily check on, install from the web interface")).toBeTruthy();
  });

  it("is accessible", async () => {
    await signInAs();
    await openPage();
    const dialog = await openEditor("Updates");
    expect(await axeViolations(dialog)).toEqual([]);
  });
});
