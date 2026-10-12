import { afterEach, describe, expect, it } from "vitest";
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { api } from "../api/client";
import { db } from "../api/mock/db";
import { PROFILE_MATRIX as MOCK_PROFILE_MATRIX, profileSettings } from "../api/mock/profiles";
import { server } from "../api/mock/node";
import { REVEAL_DEFAULT as MOCK_REVEAL_DEFAULT } from "../api/mock/reveal-policy";
import { isApiError } from "../api/problem";
import type { SettingsPatch } from "../api/types";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { session, setSessionForTest } from "../auth/session";
import { PROFILE_DEFAULTS, valueOf } from "./profileMatrix";
import SecurityPage from "./SecurityPage";
import { SETTINGS_PATH, signInAs } from "./testkit";
import { patchFor } from "./toggleEdit";
import { AUDIT_EXPORT, AUDIT_EXPORT_DEFAULT, auditExportOf, formatToggle, REVEAL_DEFAULT, TOGGLES, weakerThan } from "./toggles";

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
  it("lists TGL-01 to TGL-07, TGL-21, TGL-23 and TGL-24 in order with the current and the profile value", async () => {
    await signInAs();
    await openPage();
    const ids = Array.from(document.querySelectorAll("tbody tr[data-toggle]")).map((r) => r.getAttribute("data-toggle"));
    expect(ids).toEqual(TOGGLES.map((d) => d.id));
    expect(ids).toHaveLength(10);
    expect(ids).toEqual(["TGL-01", "TGL-02", "TGL-03", "TGL-04", "TGL-05", "TGL-06", "TGL-07", "TGL-21", "TGL-23", "TGL-24"]);
    // The Standard profile: administrators need MFA, passwords are at least 12 characters.
    expect(within(row("TGL-02")).getAllByText("Required for administrators")).toHaveLength(2);
    expect(within(row("TGL-01")).getAllByText("Standard: at least 12 characters")).toHaveLength(2);
    expect(within(row("TGL-01")).getByText("TGL-01").className).toContain("mono");
    // Everything follows the profile: no deviation, no reset button, no banner.
    expect(screen.getByText("Every setting follows the profile.")).toBeTruthy();
    expect(screen.queryByRole("button", { name: /Reset to profile/ })).toBeNull();
    expect(screen.getByText(/of 24 settings are available/)).toBeTruthy();
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
    expect(within(dialog).getByText("10 settings change:")).toBeTruthy();
    const table = within(dialog).getByRole("table", { name: "Settings that change" });
    expect(within(table).getByText("Password policy preset")).toBeTruthy();
    expect(within(table).getByText("Lockout")).toBeTruthy();
    expect(within(table).getByText("Audit export")).toBeTruthy();
    expect(within(table).getByText("Updates")).toBeTruthy();
    expect(within(table).getByText("Secret reveal")).toBeTruthy();
    // The database has not changed before the confirmation.
    expect(db.settings.profile).toBe("standard");

    fireEvent.click(within(dialog).getByRole("button", { name: "Switch to Hardened" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(db.settings.profile).toBe("hardened");
    expect(db.settings.passkey_for_admins).toBe(true);
    expect(await screen.findByText("Switched to Hardened")).toBeTruthy();
    expect(within(row("TGL-03")).getAllByText("Yes")).toHaveLength(2);
  });

  it("carries the test ids of the profile dialog", async () => {
    await signInAs();
    await openPage();
    fireEvent.click(screen.getByTestId("security-change-profile"));
    const dialog = await screen.findByTestId("dialog-profile");
    const group = within(dialog).getByTestId("field-profile");
    expect(group.getAttribute("role")).toBe("radiogroup");
    fireEvent.click(within(group).getByTestId("field-profile-hardened"));
    expect((within(dialog).getByTestId("form-submit") as HTMLButtonElement).textContent).toBe("Switch to Hardened");
    fireEvent.click(within(dialog).getByTestId("form-cancel"));
    await waitFor(() => expect(screen.queryByTestId("dialog-profile")).toBeNull());
    expect(db.settings.profile).toBe("standard");
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

  it("shows why a PIN is refused while the vault holds secrets and MFA is optional", async () => {
    await signInAs();
    db.settings.mfa = "optional";
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
    db.settings.mfa = "optional";
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

  it("explains a switch refused because the profile requires an audit export (TGL-21)", async () => {
    await signInAs();
    server.use(
      http.patch("/api/v1/settings/security", () =>
        HttpResponse.json(
          { status: 409, code: "audit.export.required", title: "Conflict", detail: "the profile requires an audit export and no sink is enabled", params: {} },
          { status: 409 },
        ),
      ),
    );
    await openPage();
    fireEvent.click(screen.getByRole("button", { name: "Change profile" }));
    const dialog = await screen.findByRole("dialog", { name: "Change security profile" });
    fireEvent.click(within(dialog).getByRole("radio", { name: /Hardened/ }));
    fireEvent.click(await within(dialog).findByRole("button", { name: "Switch to Hardened" }));
    expect((await within(dialog).findByTestId("error-notice")).textContent).toBe(
      "The profile requires an audit export. Enable an export sink first, then switch the profile.",
    );
    expect(db.settings.profile).toBe("standard");
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

describe("TGL-24: what revealing an operator secret takes", () => {
  const STANDARD = "Sign-in within 5 minutes";
  const HOME = "Signed-in session";
  const HARDENED = "Passkey sign-in within 5 minutes, only secrets bound to the host in view";

  afterEach(() => server.events.removeAllListeners());

  /** The bodies of the PATCH requests of the settings, as they were sent. */
  function recordPatches(): unknown[] {
    const bodies: unknown[] = [];
    server.events.on("request:start", ({ request }) => {
      if (request.method === "PATCH" && new URL(request.url).pathname === "/api/v1/settings/security") {
        void request
          .clone()
          .json()
          .then((body: unknown) => bodies.push(body));
      }
    });
    return bodies;
  }

  it("lists the toggle with the value of the profile and no deviation", async () => {
    await signInAs();
    await openPage();
    const reveal = row("TGL-24");
    expect(within(reveal).getByText("Secret reveal")).toBeTruthy();
    expect(within(reveal).getAllByText(STANDARD)).toHaveLength(2);
    expect(within(reveal).getByText("Follows the profile")).toBeTruthy();
    expect(within(reveal).queryByRole("button", { name: /Reset to profile/ })).toBeNull();
    expect(screen.getByText("TGL-01 to TGL-07, TGL-21, TGL-23 and TGL-24")).toBeTruthy();
    expect(session()?.banner.deviations).toEqual([]);
  });

  it("has the four profile values of SECURITY-PROFILES.md in the matrix, in step with the mock", () => {
    const matrix = Object.fromEntries(
      (["home", "standard", "hardened", "lab"] as const).map((p) => [p, valueOf(PROFILE_DEFAULTS[p], "secret_reveal")]),
    );
    expect(matrix).toEqual({
      home: { step_up: "session", bound_host_only: false },
      standard: { step_up: "fresh", bound_host_only: false },
      hardened: { step_up: "passkey", bound_host_only: true },
      lab: { step_up: "session", bound_host_only: false },
    });
    expect(REVEAL_DEFAULT).toEqual(MOCK_REVEAL_DEFAULT);
    expect(formatToggle("secret_reveal", matrix.home)).toBe(HOME);
    expect(formatToggle("secret_reveal", matrix.standard)).toBe(STANDARD);
    expect(formatToggle("secret_reveal", matrix.hardened)).toBe(HARDENED);
    // No value is weaker than Home: the toggle never raises the banner.
    for (const value of Object.values(matrix)) {
      expect(weakerThan("secret_reveal", value, matrix.home)).toBe(false);
    }
    expect(weakerThan("secret_reveal", { step_up: "session", bound_host_only: false }, matrix.hardened)).toBe(false);
  });

  it("previews the value of the target profile in the profile dialog", async () => {
    await signInAs("lab");
    await openPage();
    expect(within(row("TGL-24")).getAllByText(HOME)).toHaveLength(2);
    fireEvent.click(screen.getByRole("button", { name: "Change profile" }));
    const dialog = await screen.findByRole("dialog", { name: "Change security profile" });

    fireEvent.click(within(dialog).getByRole("radio", { name: /Standard/ }));
    let table = await within(dialog).findByRole("table", { name: "Settings that change" });
    let changed = within(table).getByText("Secret reveal").closest("tr") as HTMLElement;
    expect(within(changed).getByText(HOME)).toBeTruthy();
    expect(within(changed).getByText(STANDARD)).toBeTruthy();

    fireEvent.click(within(dialog).getByRole("radio", { name: /Hardened/ }));
    table = await within(dialog).findByRole("table", { name: "Settings that change" });
    changed = within(table).getByText("Secret reveal").closest("tr") as HTMLElement;
    expect(within(changed).getByText(HOME)).toBeTruthy();
    expect(within(changed).getByText(HARDENED)).toBeTruthy();
    // None of the values is weaker than Home.
    expect(within(changed).queryByText("Weaker than Home")).toBeNull();

    // Home has the value that Lab has: nothing to change for this toggle.
    fireEvent.click(within(dialog).getByRole("radio", { name: /Home/ }));
    table = await within(dialog).findByRole("table", { name: "Settings that change" });
    expect(within(table).queryByText("Secret reveal")).toBeNull();
  });

  it("edits the step-up and the host binding, explains each option and sends the policy", async () => {
    await signInAs();
    await openPage();
    const bodies = recordPatches();
    const dialog = await openEditor("Secret reveal");
    const modes = ["session", "fresh", "passkey"].map((mode) => within(dialog).getByTestId(`field-step_up-${mode}`));
    expect(modes.map((m) => (m as HTMLInputElement).checked)).toEqual([false, true, false]);
    const bound = within(dialog).getByRole("switch", { name: /Only for the host in view/ }) as HTMLInputElement;
    expect(bound).toBe(within(dialog).getByTestId("field-bound_host_only"));
    expect(bound.checked).toBe(false);
    // Each option says what it means.
    expect(within(dialog).getByText("A session that is signed in with a password or something stronger is enough.")).toBeTruthy();
    expect(within(dialog).getByText("The person must have signed in within the last five minutes.")).toBeTruthy();
    expect(
      within(dialog).getByText("The person must have signed in with a passkey or security key within the last five minutes."),
    ).toBeTruthy();
    expect(within(dialog).getByText(/The secrets page cannot reveal it/)).toBeTruthy();
    expect(within(dialog).getByText(/a session of PIN strength never reveals a secret/)).toBeTruthy();
    expect((within(dialog).getByRole("button", { name: "Save setting" }) as HTMLButtonElement).disabled).toBe(true);

    fireEvent.click(modes[2] as HTMLElement);
    fireEvent.click(bound);
    expect(await within(dialog).findByText(/Differs from the Standard profile/)).toBeTruthy();
    // A stronger value is not weaker than Home: no warning.
    expect(within(dialog).queryByText("Weaker than Home")).toBeNull();
    fireEvent.click(within(dialog).getByRole("button", { name: "Save setting" }));

    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(bodies).toEqual([{ secret_reveal: { step_up: "passkey", bound_host_only: true } }]);
    expect(db.settings.secret_reveal).toEqual({ step_up: "passkey", bound_host_only: true });
    const reveal = row("TGL-24");
    expect(within(reveal).getByText(HARDENED)).toBeTruthy();
    expect(within(reveal).getByText("Differs from the profile")).toBeTruthy();
    expect(within(reveal).queryByText("Weaker than Home")).toBeNull();
    expect(session()?.banner.deviations).toEqual(["TGL-24"]);
    expect(session()?.banner.weaker_than_home).toBe(false);
    expect(await screen.findByText("Saved Secret reveal")).toBeTruthy();
  });

  it("does not call the weakest value weaker than Home", async () => {
    await signInAs();
    await openPage();
    const dialog = await openEditor("Secret reveal");
    fireEvent.click(within(dialog).getByTestId("field-step_up-session"));
    expect(await within(dialog).findByText(/Differs from the Standard profile/)).toBeTruthy();
    expect(within(dialog).queryByText(/Weaker than Home/)).toBeNull();
    fireEvent.click(within(dialog).getByRole("button", { name: "Save setting" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(db.settings.secret_reveal).toEqual({ step_up: "session", bound_host_only: false });
    expect(within(row("TGL-24")).queryByText("Weaker than Home")).toBeNull();
    expect(within(row("TGL-24")).getByText("Differs from the profile")).toBeTruthy();
    expect(session()?.banner.weaker_than_home).toBe(false);
  });

  it("shows a deviation set on the server and resets it to the profile", async () => {
    await signInAs();
    db.settings.secret_reveal = { step_up: "passkey", bound_host_only: false };
    await openPage();
    const reveal = row("TGL-24");
    expect(within(reveal).getByText("Passkey sign-in within 5 minutes")).toBeTruthy();
    expect(within(reveal).getByText(STANDARD)).toBeTruthy();
    expect(within(reveal).getByText("Differs from the profile")).toBeTruthy();
    expect(screen.getByTestId("deviation-count").textContent).toContain("1");

    const bodies = recordPatches();
    fireEvent.click(within(reveal).getByRole("button", { name: "Reset to profile: Secret reveal" }));
    await waitFor(() => expect(within(row("TGL-24")).queryByText("Differs from the profile")).toBeNull());
    expect(within(row("TGL-24")).getByText("Follows the profile")).toBeTruthy();
    expect(bodies).toEqual([{ secret_reveal: { step_up: "fresh", bound_host_only: false } }]);
    expect(db.settings.secret_reveal).toEqual({ step_up: "fresh", bound_host_only: false });
    expect(session()?.banner.deviations).toEqual([]);
  });

  it("keeps the reveal policy when another toggle changes", async () => {
    await signInAs();
    db.settings.secret_reveal = { step_up: "passkey", bound_host_only: true };
    await openPage();
    const dialog = await openEditor("Lockout");
    fireEvent.change(within(dialog).getByLabelText("Lockout"), { target: { value: "lock_until_unlock" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Save setting" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(db.settings.lockout).toBe("lock_until_unlock");
    expect(db.settings.secret_reveal).toEqual({ step_up: "passkey", bound_host_only: true });
    expect(within(row("TGL-24")).getByText(HARDENED)).toBeTruthy();
    expect(session()?.banner.deviations).toEqual(["TGL-07", "TGL-24"]);
  });

  it("puts the default of the profile back when the profile is switched", async () => {
    await signInAs();
    db.settings.secret_reveal = { step_up: "session", bound_host_only: false };
    await openPage();
    fireEvent.click(screen.getByRole("button", { name: "Change profile" }));
    const dialog = await screen.findByRole("dialog", { name: "Change security profile" });
    fireEvent.click(within(dialog).getByRole("radio", { name: /Hardened/ }));
    await within(dialog).findByRole("button", { name: "Switch to Hardened" });
    fireEvent.click(within(dialog).getByRole("button", { name: "Switch to Hardened" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(db.settings.profile).toBe("hardened");
    expect(db.settings.secret_reveal).toBeUndefined();
    expect(within(row("TGL-24")).getAllByText(HARDENED)).toHaveLength(2);
    expect(within(row("TGL-24")).getByText("Follows the profile")).toBeTruthy();
  });

  it("builds the request body of the toggle and refuses a value the server does not know", async () => {
    expect(patchFor("secret_reveal", { step_up: "fresh", bound_host_only: true })).toEqual({
      secret_reveal: { step_up: "fresh", bound_host_only: true },
    });
    await signInAs();
    const bad = { secret_reveal: { step_up: "never", bound_host_only: false } } as unknown as SettingsPatch;
    const error = await api.patch("/api/v1/settings/security", { body: bad }).catch((e: unknown) => e);
    expect(isApiError(error, "sys.invalid_value")).toBe(true);
    const missing = { secret_reveal: { step_up: "fresh" } } as unknown as SettingsPatch;
    const second = await api.patch("/api/v1/settings/security", { body: missing }).catch((e: unknown) => e);
    expect(isApiError(second, "sys.invalid_value")).toBe(true);
    expect(db.settings.secret_reveal).toBeUndefined();
  });

  it("is accessible", async () => {
    await signInAs();
    await openPage();
    const dialog = await openEditor("Secret reveal");
    expect(await axeViolations(dialog)).toEqual([]);
  });
});

describe("TGL-21: whether the audit log leaves the installation", () => {
  const LOCAL = "Local only";
  const OPTIONAL = "Local, export optional";
  const REQUIRED = "Export required";

  afterEach(() => server.events.removeAllListeners());

  /** The bodies of the PATCH requests of the settings, as they were sent. */
  function recordPatches(): unknown[] {
    const bodies: unknown[] = [];
    server.events.on("request:start", ({ request }) => {
      if (request.method === "PATCH" && new URL(request.url).pathname === "/api/v1/settings/security") {
        void request
          .clone()
          .json()
          .then((body: unknown) => bodies.push(body));
      }
    });
    return bodies;
  }

  it("lists the toggle between lockout and updates with the value of the profile and no deviation", async () => {
    await signInAs();
    await openPage();
    const rows = Array.from(document.querySelectorAll("tbody tr[data-toggle]")).map((r) => r.getAttribute("data-toggle"));
    expect(rows.indexOf("TGL-21")).toBe(rows.indexOf("TGL-07") + 1);
    expect(rows.indexOf("TGL-23")).toBe(rows.indexOf("TGL-21") + 1);
    const audit = row("TGL-21");
    expect(within(audit).getByText("Audit export")).toBeTruthy();
    expect(within(audit).getAllByText(OPTIONAL)).toHaveLength(2);
    expect(within(audit).getByText("Follows the profile")).toBeTruthy();
    expect(within(audit).queryByRole("button", { name: /Reset to profile/ })).toBeNull();
    expect(session()?.banner.deviations).toEqual([]);
  });

  it("has the four profile values of SECURITY-PROFILES.md in the matrix, in step with the mock", () => {
    const matrix = Object.fromEntries(
      (["home", "standard", "hardened", "lab"] as const).map((p) => [p, valueOf(PROFILE_DEFAULTS[p], "audit_export")]),
    );
    expect(matrix).toEqual({ home: "local", standard: "optional", hardened: "required", lab: "local" });
    expect(AUDIT_EXPORT_DEFAULT).toEqual(matrix);
    expect(Object.fromEntries(Object.entries(MOCK_PROFILE_MATRIX).map(([p, v]) => [p, v.audit_export]))).toEqual(matrix);
    expect(AUDIT_EXPORT).toEqual(["local", "optional", "required"]);
    expect(formatToggle("audit_export", "local")).toBe(LOCAL);
    expect(formatToggle("audit_export", "optional")).toBe(OPTIONAL);
    expect(formatToggle("audit_export", "required")).toBe(REQUIRED);
    // Home keeps the log local, the weakest value: no value is weaker, and the toggle never raises the banner.
    for (const value of AUDIT_EXPORT) expect(weakerThan("audit_export", value, "local")).toBe(false);
    expect(weakerThan("audit_export", "local", "required")).toBe(false);
  });

  it("follows the profile for settings stored before the toggle", () => {
    const old = { ...profileSettings("hardened") };
    delete old.audit_export;
    expect(auditExportOf(old)).toBe("required");
    expect(auditExportOf({ ...old, audit_export: "local" })).toBe("local");
    expect(auditExportOf({ ...profileSettings("lab"), audit_export: null })).toBe("local");
  });

  it("edits the choice, explains each option and sends it", async () => {
    await signInAs();
    await openPage();
    const bodies = recordPatches();
    const dialog = await openEditor("Audit export");
    const modes = AUDIT_EXPORT.map((mode) => within(dialog).getByTestId(`field-audit_export-${mode}`) as HTMLInputElement);
    expect(modes.map((m) => m.checked)).toEqual([false, true, false]);
    expect(within(dialog).getByRole("radiogroup", { name: "How the audit log leaves this installation" })).toBeTruthy();
    // Each option says what it means.
    expect(within(dialog).getByText("The audit log stays on this installation. No export is set up.")).toBeTruthy();
    expect(within(dialog).getByText(/you may send it on to syslog, CEF or JSON sinks/)).toBeTruthy();
    expect(within(dialog).getByText("At least one export sink must be set up, and an alarm shows while a sink fails.")).toBeTruthy();
    expect((within(dialog).getByRole("button", { name: "Save setting" }) as HTMLButtonElement).disabled).toBe(true);

    fireEvent.click(modes[2] as HTMLElement);
    expect(await within(dialog).findByText(/Differs from the Standard profile/)).toBeTruthy();
    // A stronger value is not weaker than Home: no warning.
    expect(within(dialog).queryByText("Weaker than Home")).toBeNull();
    fireEvent.click(within(dialog).getByRole("button", { name: "Save setting" }));

    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(bodies).toEqual([{ audit_export: "required" }]);
    expect(db.settings.audit_export).toBe("required");
    const audit = row("TGL-21");
    expect(within(audit).getByText(REQUIRED)).toBeTruthy();
    expect(within(audit).getByText("Differs from the profile")).toBeTruthy();
    expect(within(audit).queryByText("Weaker than Home")).toBeNull();
    expect(session()?.banner.deviations).toEqual(["TGL-21"]);
    expect(session()?.banner.weaker_than_home).toBe(false);
    expect(await screen.findByText("Saved Audit export")).toBeTruthy();
  });

  it("does not call the weakest value weaker than Home", async () => {
    await signInAs();
    await openPage();
    const dialog = await openEditor("Audit export");
    fireEvent.click(within(dialog).getByTestId("field-audit_export-local"));
    expect(await within(dialog).findByText(/Differs from the Standard profile/)).toBeTruthy();
    expect(within(dialog).queryByText(/Weaker than Home/)).toBeNull();
    fireEvent.click(within(dialog).getByRole("button", { name: "Save setting" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(db.settings.audit_export).toBe("local");
    expect(within(row("TGL-21")).queryByText("Weaker than Home")).toBeNull();
    expect(within(row("TGL-21")).getByText("Differs from the profile")).toBeTruthy();
    expect(session()?.banner.weaker_than_home).toBe(false);
  });

  it("shows a deviation set on the server and resets it to the profile", async () => {
    await signInAs();
    db.settings.audit_export = "required";
    await openPage();
    const audit = row("TGL-21");
    expect(within(audit).getByText(REQUIRED)).toBeTruthy();
    expect(within(audit).getByText(OPTIONAL)).toBeTruthy();
    expect(within(audit).getByText("Differs from the profile")).toBeTruthy();

    const bodies = recordPatches();
    fireEvent.click(within(audit).getByRole("button", { name: "Reset to profile: Audit export" }));
    await waitFor(() => expect(within(row("TGL-21")).queryByText("Differs from the profile")).toBeNull());
    expect(within(row("TGL-21")).getByText("Follows the profile")).toBeTruthy();
    expect(bodies).toEqual([{ audit_export: "optional" }]);
    expect(db.settings.audit_export).toBe("optional");
    expect(session()?.banner.deviations).toEqual([]);
  });

  it("previews the value of the target profile in the profile dialog and puts the default back on a switch", async () => {
    await signInAs("lab");
    await openPage();
    expect(within(row("TGL-21")).getAllByText(LOCAL)).toHaveLength(2);
    fireEvent.click(screen.getByRole("button", { name: "Change profile" }));
    const dialog = await screen.findByRole("dialog", { name: "Change security profile" });

    fireEvent.click(within(dialog).getByRole("radio", { name: /Hardened/ }));
    const table = await within(dialog).findByRole("table", { name: "Settings that change" });
    const changed = within(table).getByText("Audit export").closest("tr") as HTMLElement;
    expect(within(changed).getByText(LOCAL)).toBeTruthy();
    expect(within(changed).getByText(REQUIRED)).toBeTruthy();
    expect(within(changed).queryByText("Weaker than Home")).toBeNull();

    // Home has the value that Lab has: nothing to change for this toggle.
    fireEvent.click(within(dialog).getByRole("radio", { name: /Home/ }));
    const home = await within(dialog).findByRole("table", { name: "Settings that change" });
    expect(within(home).queryByText("Audit export")).toBeNull();

    fireEvent.click(within(dialog).getByRole("radio", { name: /Hardened/ }));
    await within(dialog).findByRole("button", { name: "Switch to Hardened" });
    fireEvent.click(within(dialog).getByRole("button", { name: "Switch to Hardened" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(db.settings.audit_export).toBe("required");
    expect(within(row("TGL-21")).getAllByText(REQUIRED)).toHaveLength(2);
    expect(within(row("TGL-21")).getByText("Follows the profile")).toBeTruthy();
  });

  it("keeps the choice when another toggle changes", async () => {
    await signInAs();
    db.settings.audit_export = "required";
    await openPage();
    const dialog = await openEditor("Lockout");
    fireEvent.change(within(dialog).getByLabelText("Lockout"), { target: { value: "lock_until_unlock" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Save setting" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(db.settings.audit_export).toBe("required");
    expect(session()?.banner.deviations).toEqual(["TGL-07", "TGL-21"]);
  });

  it("builds the request body of the toggle and refuses a value the server does not know", async () => {
    expect(patchFor("audit_export", "required")).toEqual({ audit_export: "required" });
    await signInAs();
    const bad = { audit_export: "sometimes" } as unknown as SettingsPatch;
    const error = await api.patch("/api/v1/settings/security", { body: bad }).catch((e: unknown) => e);
    expect(isApiError(error)).toBe(true);
    expect(db.settings.audit_export).toBe("optional");
  });

  it("is accessible", async () => {
    await signInAs();
    await openPage();
    const dialog = await openEditor("Audit export");
    expect(await axeViolations(dialog)).toEqual([]);
  });
});

describe("the PIN coupling rule (IAM-07)", () => {
  const PIN_NOTICE = "A PIN alone is not allowed while the vault holds secrets. Add a passkey or choose a password preset.";

  /** Home (the PIN preset, MFA optional), with or without an operator secret in the vault. */
  async function signInAtHome(secrets: boolean) {
    await signInAs();
    db.settings = profileSettings("home");
    db.vaultHasOperatorSecrets = secrets;
  }

  const saveButton = (dialog: HTMLElement) => within(dialog).getByTestId("form-submit") as HTMLButtonElement;
  const choose = (dialog: HTMLElement, label: string, value: string) =>
    fireEvent.change(within(dialog).getByLabelText(label), { target: { value } });
  const closed = () => waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  const noNotice = (dialog: HTMLElement) => waitFor(() => expect(within(dialog).queryByText(PIN_NOTICE)).toBeNull());
  const canSave = (dialog: HTMLElement) => waitFor(() => expect(saveButton(dialog).disabled).toBe(false));

  async function openProfileDialog() {
    fireEvent.click(screen.getByRole("button", { name: "Change profile" }));
    return screen.findByRole("dialog", { name: "Change security profile" });
  }

  describe("with an operator secret in the vault", () => {
    it("saves the reveal policy and the lockout under Home without the notice", async () => {
      await signInAtHome(true);
      await openPage();
      let dialog = await openEditor("Secret reveal");
      fireEvent.click(within(dialog).getByTestId("field-step_up-passkey"));
      await canSave(dialog);
      await noNotice(dialog);
      fireEvent.click(saveButton(dialog));
      await closed();
      expect(db.settings.secret_reveal).toEqual({ step_up: "passkey", bound_host_only: false });

      dialog = await openEditor("Lockout");
      choose(dialog, "Lockout", "off");
      await canSave(dialog);
      await noNotice(dialog);
      fireEvent.click(saveButton(dialog));
      await closed();
      expect(db.settings.lockout).toBe("off");
      expect(db.settings.password_policy).toEqual({ preset: "pin" });
    });

    it("lets MFA for everyone through, and refuses optional again while the policy admits a PIN", async () => {
      await signInAtHome(true);
      await openPage();
      let dialog = await openEditor("MFA requirement");
      choose(dialog, "MFA requirement", "everyone");
      await canSave(dialog);
      await noNotice(dialog);
      fireEvent.click(saveButton(dialog));
      await closed();
      expect(db.settings.mfa).toBe("everyone");

      dialog = await openEditor("MFA requirement");
      choose(dialog, "MFA requirement", "optional");
      expect(await within(dialog).findByText(PIN_NOTICE)).toBeTruthy();
      expect(saveButton(dialog).disabled).toBe(true);
      // A requirement that keeps the PIN from standing alone: the notice goes and saving is possible.
      choose(dialog, "MFA requirement", "administrators");
      await noNotice(dialog);
      await canSave(dialog);
    });

    it("refuses the PIN preset and a short Custom policy while MFA is optional and the preset is Standard", async () => {
      await signInAtHome(true);
      db.settings.password_policy = { preset: "standard" };
      await openPage();
      const dialog = await openEditor("Password policy preset");
      choose(dialog, "Preset", "pin");
      expect(await within(dialog).findByText(PIN_NOTICE)).toBeTruthy();
      expect(saveButton(dialog).disabled).toBe(true);

      // Custom starts at 12 characters, which no PIN meets; 8 characters would admit one.
      choose(dialog, "Preset", "custom");
      const min = await within(dialog).findByLabelText("Minimum length");
      await noNotice(dialog);
      await canSave(dialog);
      fireEvent.input(min, { target: { value: "8" } });
      expect(await within(dialog).findByText(PIN_NOTICE)).toBeTruthy();
      expect(saveButton(dialog).disabled).toBe(true);
      // A pattern that no number matches keeps the PIN out again; one that digits match does not.
      const pattern = within(dialog).getByLabelText("Required pattern (optional)");
      fireEvent.input(pattern, { target: { value: "[a-z]+" } });
      await noNotice(dialog);
      await canSave(dialog);
      fireEvent.input(pattern, { target: { value: "[0-9]+" } });
      expect(await within(dialog).findByText(PIN_NOTICE)).toBeTruthy();
      expect(saveButton(dialog).disabled).toBe(true);
    });

    it("lets the PIN preset through while MFA is required", async () => {
      await signInAs();
      db.vaultHasOperatorSecrets = true;
      await openPage();
      const dialog = await openEditor("Password policy preset");
      choose(dialog, "Preset", "pin");
      await canSave(dialog);
      await noNotice(dialog);
      fireEvent.click(saveButton(dialog));
      await closed();
      expect(db.settings.password_policy).toEqual({ preset: "pin" });
      expect(db.settings.mfa).toBe("administrators");
    });

    it("says nothing about the policy Home already has, and refuses a different one that admits a PIN", async () => {
      await signInAtHome(true);
      await openPage();
      const dialog = await openEditor("Password policy preset");
      expect(within(dialog).getByText(/Nothing changes yet/)).toBeTruthy();
      expect(within(dialog).queryByText(PIN_NOTICE)).toBeNull();
      choose(dialog, "Preset", "custom");
      const min = await within(dialog).findByLabelText("Minimum length");
      fireEvent.input(min, { target: { value: "6" } });
      expect(await within(dialog).findByText(PIN_NOTICE)).toBeTruthy();
      expect(saveButton(dialog).disabled).toBe(true);
    });

    it("refuses a switch from Standard to Home or Lab and lets Hardened through", async () => {
      await signInAs();
      db.vaultHasOperatorSecrets = true;
      await openPage();
      const dialog = await openProfileDialog();
      fireEvent.click(within(dialog).getByRole("radio", { name: /Home/ }));
      expect(await within(dialog).findByText(PIN_NOTICE)).toBeTruthy();
      expect((within(dialog).getByRole("button", { name: "Switch to Home" }) as HTMLButtonElement).disabled).toBe(true);
      fireEvent.click(within(dialog).getByRole("radio", { name: /Lab/ }));
      expect(await within(dialog).findByText(PIN_NOTICE)).toBeTruthy();
      fireEvent.click(within(dialog).getByRole("radio", { name: /Hardened/ }));
      await noNotice(dialog);
      expect((within(dialog).getByRole("button", { name: "Switch to Hardened" }) as HTMLButtonElement).disabled).toBe(false);
    });

    it("lets a switch from Home to Lab or Standard through", async () => {
      await signInAtHome(true);
      await openPage();
      const dialog = await openProfileDialog();
      // Lab sets the same policy and MFA as Home: the PIN is not new, so nothing is refused.
      fireEvent.click(within(dialog).getByRole("radio", { name: /Lab/ }));
      fireEvent.click(await within(dialog).findByRole("checkbox"));
      await waitFor(() =>
        expect((within(dialog).getByRole("button", { name: "Switch to Lab" }) as HTMLButtonElement).disabled).toBe(false),
      );
      expect(within(dialog).queryByText(PIN_NOTICE)).toBeNull();
      fireEvent.click(within(dialog).getByRole("radio", { name: /Standard/ }));
      await within(dialog).findByRole("button", { name: "Switch to Standard" });
      expect(within(dialog).queryByText(PIN_NOTICE)).toBeNull();
    });

    it("refuses a reset to Home that brings MFA back to optional", async () => {
      await signInAtHome(true);
      // MFA for everyone is a deviation from Home; resetting to Home would let the PIN stand alone.
      db.settings.mfa = "everyone";
      await openPage();
      const dialog = await openProfileDialog();
      expect(await within(dialog).findByText(PIN_NOTICE)).toBeTruthy();
      expect((within(dialog).getByRole("button", { name: "Reset to Home" }) as HTMLButtonElement).disabled).toBe(true);
    });
  });

  describe("without a secret in the vault", () => {
    it("shows no notice for MFA, for the PIN preset or for a switch to Home", async () => {
      await signInAs();
      await openPage();
      let dialog = await openEditor("MFA requirement");
      choose(dialog, "MFA requirement", "optional");
      await canSave(dialog);
      expect(within(dialog).queryByText(PIN_NOTICE)).toBeNull();
      fireEvent.click(saveButton(dialog));
      await closed();
      expect(db.settings.mfa).toBe("optional");

      dialog = await openEditor("Password policy preset");
      choose(dialog, "Preset", "pin");
      await canSave(dialog);
      expect(within(dialog).queryByText(PIN_NOTICE)).toBeNull();
      choose(dialog, "Preset", "custom");
      fireEvent.input(await within(dialog).findByLabelText("Minimum length"), { target: { value: "6" } });
      await canSave(dialog);
      expect(within(dialog).queryByText(PIN_NOTICE)).toBeNull();
      fireEvent.click(within(dialog).getByTestId("form-cancel"));
      await closed();

      dialog = await openProfileDialog();
      fireEvent.click(within(dialog).getByRole("radio", { name: /Home/ }));
      await within(dialog).findByRole("button", { name: "Switch to Home" });
      expect(within(dialog).queryByText(PIN_NOTICE)).toBeNull();
      expect((within(dialog).getByRole("button", { name: "Switch to Home" }) as HTMLButtonElement).disabled).toBe(false);
    });

    it("lets Home with MFA for everyone be reset to Home", async () => {
      await signInAtHome(false);
      db.settings.mfa = "everyone";
      await openPage();
      const dialog = await openProfileDialog();
      await within(dialog).findByRole("button", { name: "Reset to Home" });
      expect(within(dialog).queryByText(PIN_NOTICE)).toBeNull();
      expect((within(dialog).getByRole("button", { name: "Reset to Home" }) as HTMLButtonElement).disabled).toBe(false);
    });
  });
});

describe("the test ids of the security page", () => {
  it("marks each toggle row with its id and gives it an edit button, and a reset button when it differs", async () => {
    await signInAs("weak");
    await openPage();
    const rows = screen.getAllByTestId("toggle");
    expect(rows.map((r) => r.getAttribute("data-key"))).toEqual(TOGGLES.map((d) => d.id));
    expect(rows.map((r) => r.getAttribute("data-toggle"))).toEqual(TOGGLES.map((d) => d.id));
    for (const r of rows) expect(within(r).getAllByTestId("toggle-edit")).toHaveLength(1);
    // Home with lockout off: only TGL-07 differs from its profile.
    const resets = screen.getAllByTestId("toggle-reset");
    expect(resets).toHaveLength(1);
    expect(resets[0]?.closest("[data-testid='toggle']")?.getAttribute("data-key")).toBe("TGL-07");
  });

  it("gives the edit dialog its test ids and the reveal editor a field id for each control", async () => {
    await signInAs();
    await openPage();
    const reveal = screen.getAllByTestId("toggle").find((r) => r.getAttribute("data-key") === "TGL-24") as HTMLElement;
    fireEvent.click(within(reveal).getByTestId("toggle-edit"));
    const dialog = await screen.findByTestId("dialog-toggle");
    expect(dialog.getAttribute("role")).toBe("dialog");
    const submit = within(dialog).getByTestId("form-submit") as HTMLButtonElement;
    expect(submit.disabled).toBe(true);

    // Standard asks for a recent sign-in of any kind, and the host binding is off.
    const modes = ["session", "fresh", "passkey"].map((mode) => within(dialog).getByTestId(`field-step_up-${mode}`));
    expect(modes.map((m) => (m as HTMLInputElement).checked)).toEqual([false, true, false]);
    const bound = within(dialog).getByTestId("field-bound_host_only") as HTMLInputElement;
    expect(bound.type).toBe("checkbox");
    expect(bound.checked).toBe(false);
    fireEvent.click(bound);
    await waitFor(() => expect(submit.disabled).toBe(false));
    expect(within(dialog).getByTestId("form-cancel")).toBeTruthy();

    fireEvent.click(within(dialog).getByTestId("form-cancel"));
    await waitFor(() => expect(screen.queryByTestId("dialog-toggle")).toBeNull());
  });

  it("names the select of each choice editor after its setting", async () => {
    await signInAs();
    await openPage();
    for (const [id, field] of [
      ["TGL-01", "field-password_policy"],
      ["TGL-02", "field-mfa"],
      ["TGL-06", "field-breach_check"],
      ["TGL-07", "field-lockout"],
    ] as const) {
      const row = screen.getAllByTestId("toggle").find((r) => r.getAttribute("data-key") === id) as HTMLElement;
      fireEvent.click(within(row).getByTestId("toggle-edit"));
      const dialog = await screen.findByTestId("dialog-toggle");
      expect(within(dialog).getByTestId(field).tagName, id).toBe("SELECT");
      fireEvent.click(within(dialog).getByTestId("form-cancel"));
      await waitFor(() => expect(screen.queryByTestId("dialog-toggle")).toBeNull());
    }
  });
});
