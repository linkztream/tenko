import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MOCK_RECOVERY_CODES, MOCK_TOTP_CODE } from "../../api/mock/fixtures";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { session, setSessionForTest } from "../session";
import Account from "./Account";
import { alex, signInAlex, stubWebAuthn } from "./testkit";

function show() {
  return renderRoute(Account, { url: "/account/security", path: "/account/:section?" });
}

// The view is rendered without the shell's <main>, which holds all page content in the app.
const NO_SHELL = { disable: ["region"] } as const;

const totpRegion = () => screen.getByRole("region", { name: "Authenticator app" });
const recoveryRegion = () => screen.getByRole("region", { name: "Recovery codes" });

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("sign-in methods: the summary", () => {
  it("says how this session signed in and what the profile asks for", async () => {
    await signInAlex();
    show();
    expect(screen.getByRole("heading", { level: 1, name: /Security and sign-in/ })).toBeTruthy();
    expect(screen.getByText("This session signed in with a passkey.")).toBeTruthy();
    expect(
      screen.getByText("The Standard profile asks for at least a password and an authenticator code from your account."),
    ).toBeTruthy();
  });

  it("warns at the top when the session must add a method or change its password", async () => {
    await signInAlex({ prepare: (u) => (u.password_change_required = true) });
    const s = session();
    if (!s) throw new Error("no session");
    setSessionForTest({ ...s, flags: { ...s.flags, mfa_enrolment_required: true } });
    show();
    expect(screen.getByText(/You must choose a new password or PIN before you continue/)).toBeTruthy();
    expect(screen.getByText(/asks for a stronger sign-in than this session used/)).toBeTruthy();
  });
});

describe("sign-in methods: passkeys and security keys", () => {
  it("lists the passkey with its kind, when it was added and when it was used", async () => {
    await signInAlex();
    show();
    expect(await screen.findByText("Laptop passkey")).toBeTruthy();
    expect(screen.getByText("Synced passkey")).toBeTruthy();
    expect(screen.getByText(/^Added /)).toBeTruthy();
    expect(screen.getByText(/^Last used /)).toBeTruthy();
  });

  it("tells a hardware key from a synced passkey", async () => {
    await signInAlex({
      prepare: (u) => {
        const [first] = u.credentials;
        if (first) u.credentials.push({ ...first, id: "hw-1", label: "Office key", hardware_key: true, backup_eligible: false, last_used_at: null });
      },
    });
    show();
    expect(await screen.findByText("Office key")).toBeTruthy();
    expect(screen.getByText("Hardware security key")).toBeTruthy();
    expect(screen.getByText("Never used")).toBeTruthy();
  });

  it("asks before removing a passkey, and keeps it when you cancel", async () => {
    await signInAlex();
    show();
    fireEvent.click(await screen.findByRole("button", { name: "Remove Laptop passkey" }));
    const dialog = await screen.findByRole("dialog", { name: "Remove Laptop passkey?" });
    expect(alex().credentials).toHaveLength(1);
    fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(alex().credentials).toHaveLength(1);
    expect(screen.getByText("Laptop passkey")).toBeTruthy();
  });

  it("removes the passkey after the confirmation", async () => {
    await signInAlex();
    show();
    fireEvent.click(await screen.findByRole("button", { name: "Remove Laptop passkey" }));
    const dialog = await screen.findByRole("dialog");
    fireEvent.click(within(dialog).getByRole("button", { name: "Remove" }));
    await waitFor(() => expect(alex().credentials).toHaveLength(0));
    expect(await screen.findByText("You have not added a passkey or a security key yet.")).toBeTruthy();
    expect(screen.getByText("Laptop passkey removed")).toBeTruthy();
  });

  it("explains why the last factor the profile needs cannot be removed", async () => {
    await signInAlex({ prepare: (u) => (u.totp = false) });
    show();
    fireEvent.click(await screen.findByRole("button", { name: "Remove Laptop passkey" }));
    const dialog = await screen.findByRole("dialog");
    fireEvent.click(within(dialog).getByRole("button", { name: "Remove" }));
    const alert = await within(dialog).findByRole("alert");
    expect(alert.textContent).toContain("Your profile needs this method and it is the only one you have.");
    expect(alex().credentials).toHaveLength(1);
  });

  it("adds a passkey through the browser ceremony and shows the waiting state", async () => {
    await signInAlex();
    const authenticator = stubWebAuthn({ wait: true });
    show();
    fireEvent.input(await screen.findByLabelText("Name"), { target: { value: "Office laptop" } });
    fireEvent.click(screen.getByRole("button", { name: "Add a passkey" }));
    const waiting = await screen.findByText("Follow the prompt on this device or your phone");
    expect(waiting.classList.contains("jstate") && waiting.classList.contains("waiting")).toBe(true);
    expect(screen.getByRole("button", { name: "Add a passkey" }).hasAttribute("disabled")).toBe(true);
    await waitFor(() => expect(authenticator.create).toHaveBeenCalledTimes(1));
    authenticator.finish();
    expect(await screen.findByText("Office laptop")).toBeTruthy();
    expect(screen.getByText("Passkey added")).toBeTruthy();
    expect(screen.queryByText("Follow the prompt on this device or your phone")).toBeNull();
    expect(alex().credentials.map((c) => c.label)).toContain("Office laptop");
    // The ceremony ran with the server's options converted to ArrayBuffers.
    const first = authenticator.create.mock.calls[0] as unknown as [{ publicKey: PublicKeyCredentialCreationOptions }];
    expect(first[0].publicKey.challenge).toBeInstanceOf(ArrayBuffer);
  });

  it("adds a security key and asks the person to touch it", async () => {
    await signInAlex();
    const authenticator = stubWebAuthn({ wait: true });
    show();
    fireEvent.click(await screen.findByRole("button", { name: "Add a security key" }));
    const waiting = await screen.findByText("Touch your security key");
    expect(waiting.classList.contains("jstate") && waiting.classList.contains("waiting")).toBe(true);
    await waitFor(() => expect(authenticator.create).toHaveBeenCalledTimes(1));
    authenticator.finish();
    expect(await screen.findByText("Security key added")).toBeTruthy();
    expect(await screen.findByText("Hardware security key")).toBeTruthy();
    expect(alex().credentials.some((c) => c.hardware_key)).toBe(true);
  });

  it("explains a cancelled ceremony in words", async () => {
    await signInAlex();
    stubWebAuthn({ fail: "NotAllowedError" });
    show();
    fireEvent.click(await screen.findByRole("button", { name: "Add a passkey" }));
    expect((await screen.findByRole("alert")).textContent).toContain("The passkey request was cancelled or timed out.");
    expect(alex().credentials).toHaveLength(1);
  });

  it("says so when the browser has no passkey support", async () => {
    await signInAlex();
    show();
    expect(await screen.findByText("This browser or device does not support passkeys.")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Add a passkey" }).hasAttribute("disabled")).toBe(true);
  });

  it("shows the recovery codes an enrolment returns, once", async () => {
    await signInAlex({ prepare: (u) => (u.recovery_codes = []) });
    stubWebAuthn();
    show();
    fireEvent.click(await screen.findByRole("button", { name: "Add a passkey" }));
    const dialog = await screen.findByRole("dialog", { name: "Save your recovery codes" });
    expect(within(dialog).getAllByRole("listitem")).toHaveLength(10);
    const close = within(dialog).getByRole("button", { name: "Close" });
    expect(close.hasAttribute("disabled")).toBe(true);
    // Esc does not dismiss codes that are not saved yet.
    fireEvent.keyDown(dialog, { key: "Escape" });
    expect(screen.queryByRole("dialog", { name: "Save your recovery codes" })).not.toBeNull();
    fireEvent.click(within(dialog).getByLabelText("I have saved the recovery codes"));
    expect(close.hasAttribute("disabled")).toBe(false);
    fireEvent.click(close);
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  });
});

describe("sign-in methods: authenticator app", () => {
  it("reports that an authenticator app is set up", async () => {
    await signInAlex();
    show();
    expect(await within(totpRegion()).findByText("Set up")).toBeTruthy();
    expect(within(totpRegion()).getByRole("button", { name: "Remove" })).toBeTruthy();
    expect(within(totpRegion()).queryByRole("button", { name: "Set up an authenticator app" })).toBeNull();
  });

  it("reports that none is set up and offers to set one up", async () => {
    await signInAlex({ prepare: (u) => (u.totp = false) });
    show();
    expect(await within(totpRegion()).findByText("Not set up")).toBeTruthy();
    expect(within(totpRegion()).getByRole("button", { name: "Set up an authenticator app" })).toBeTruthy();
  });

  it("shows the key in blocks of four, rejects a wrong code and accepts the right one", async () => {
    await signInAlex({ prepare: (u) => (u.totp = false) });
    show();
    fireEvent.click(await screen.findByRole("button", { name: "Set up an authenticator app" }));
    const group = await screen.findByRole("group", { name: "Set up your authenticator app" });
    const secret = group.querySelector("code.secret")?.textContent ?? "";
    expect(secret).toMatch(/^(?:[A-Z2-7]{4} ){7}[A-Z2-7]{4}$/);
    expect(within(group).getByText("6 digits, a new code every 30 seconds, SHA1")).toBeTruthy();
    const link = within(group).getByRole("link", { name: "Open in an authenticator app on this device" });
    expect(link.getAttribute("href")).toMatch(/^otpauth:\/\/totp\//);
    expect(link.getAttribute("href")).toContain(`secret=${secret.replace(/ /g, "")}`);

    fireEvent.input(within(group).getByLabelText("Code from the app"), { target: { value: "000000" } });
    fireEvent.click(within(group).getByRole("button", { name: "Verify" }));
    expect((await within(group).findByRole("alert")).textContent).toContain("The code does not match.");
    expect(alex().totp).toBe(false);

    fireEvent.input(within(group).getByLabelText("Code from the app"), { target: { value: MOCK_TOTP_CODE } });
    fireEvent.click(within(group).getByRole("button", { name: "Verify" }));
    expect(await screen.findByText("Authenticator app set up")).toBeTruthy();
    expect(alex().totp).toBe(true);
    await waitFor(() => expect(screen.queryByRole("group", { name: "Set up your authenticator app" })).toBeNull());
    expect(within(totpRegion()).getByText("Set up")).toBeTruthy();
  });

  it("copies the key without the blocks", async () => {
    await signInAlex({ prepare: (u) => (u.totp = false) });
    const writeText = vi.fn(async () => {});
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
    show();
    fireEvent.click(await screen.findByRole("button", { name: "Set up an authenticator app" }));
    const group = await screen.findByRole("group", { name: "Set up your authenticator app" });
    fireEvent.click(within(group).getByRole("button", { name: "Copy" }));
    await waitFor(() => expect(writeText).toHaveBeenCalledTimes(1));
    const copied = (writeText.mock.calls[0] as unknown as [string])[0];
    expect(copied).toMatch(/^[A-Z2-7]{32}$/);
  });

  it("shows the recovery codes the first factor brings", async () => {
    await signInAlex({
      prepare: (u) => {
        u.totp = false;
        u.credentials = [];
        u.recovery_codes = [];
      },
    });
    show();
    fireEvent.click(await screen.findByRole("button", { name: "Set up an authenticator app" }));
    const group = await screen.findByRole("group", { name: "Set up your authenticator app" });
    fireEvent.input(within(group).getByLabelText("Code from the app"), { target: { value: MOCK_TOTP_CODE } });
    fireEvent.click(within(group).getByRole("button", { name: "Verify" }));
    const dialog = await screen.findByRole("dialog", { name: "Save your recovery codes" });
    expect(within(dialog).getAllByRole("listitem")).toHaveLength(10);
  });

  it("asks before removing the authenticator app", async () => {
    await signInAlex();
    show();
    fireEvent.click(await within(totpRegion()).findByRole("button", { name: "Remove" }));
    const dialog = await screen.findByRole("dialog", { name: "Remove the authenticator app?" });
    expect(alex().totp).toBe(true);
    fireEvent.click(within(dialog).getByRole("button", { name: "Remove" }));
    await waitFor(() => expect(alex().totp).toBe(false));
    expect(await within(totpRegion()).findByText("Not set up")).toBeTruthy();
  });

  it("learns that an app exists from the server when the page could not tell", async () => {
    // A password session of a non-administrator cannot read its user record: the page
    // does not know, offers the set-up and finds out from the answer.
    await signInAlex({ prepare: (u) => (u.roles = ["viewer"]) });
    const s = session();
    if (!s) throw new Error("no session");
    setSessionForTest({ ...s, roles: ["viewer"], strength: "password" });
    show();
    fireEvent.click(await screen.findByRole("button", { name: "Set up an authenticator app" }));
    expect((await screen.findByRole("alert")).textContent).toContain("An authenticator app is already set up");
    expect(await within(totpRegion()).findByRole("button", { name: "Remove" })).toBeTruthy();
  });
});

describe("sign-in methods: recovery codes", () => {
  it("reports how many codes are left", async () => {
    await signInAlex();
    show();
    expect(await within(recoveryRegion()).findByText("10 codes left")).toBeTruthy();
  });

  it("asks before replacing the codes, then shows ten new ones once", async () => {
    await signInAlex();
    show();
    fireEvent.click(await within(recoveryRegion()).findByRole("button", { name: "Generate new codes" }));
    const confirm = await screen.findByRole("dialog", { name: "Generate new recovery codes?" });
    expect(confirm.textContent).toContain("The codes you have now stop working at once.");
    // Nothing happened yet.
    expect(alex().recovery_codes).toEqual([...MOCK_RECOVERY_CODES]);

    fireEvent.click(within(confirm).getByRole("button", { name: "Generate new codes" }));
    const dialog = await screen.findByRole("dialog", { name: "Save your recovery codes" });
    const shown = within(dialog)
      .getAllByRole("listitem")
      .map((li) => li.textContent ?? "");
    expect(shown).toHaveLength(10);
    expect(shown).toEqual(alex().recovery_codes);
    expect(shown.some((code) => MOCK_RECOVERY_CODES.includes(code))).toBe(false);

    fireEvent.click(within(dialog).getByLabelText("I have saved the recovery codes"));
    fireEvent.click(within(dialog).getByRole("button", { name: "Close" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    // Shown once: the codes are not on the page any more.
    expect(document.body.textContent).not.toContain(shown[0]);
  });
});

describe("sign-in methods: accessibility", () => {
  it("has no violations on the page", async () => {
    await signInAlex();
    const { container } = show();
    await screen.findByText("Laptop passkey");
    await within(totpRegion()).findByText("Set up");
    expect(await axeViolations(container)).toEqual([]);
  });

  it("has no violations in the removal dialog", async () => {
    await signInAlex();
    show();
    fireEvent.click(await screen.findByRole("button", { name: "Remove Laptop passkey" }));
    await screen.findByRole("dialog");
    expect(await axeViolations(document.body, NO_SHELL)).toEqual([]);
  });

  it("has no violations while a key is being set up", async () => {
    await signInAlex({ prepare: (u) => (u.totp = false) });
    const { container } = show();
    fireEvent.click(await screen.findByRole("button", { name: "Set up an authenticator app" }));
    await screen.findByRole("group", { name: "Set up your authenticator app" });
    expect(await axeViolations(container)).toEqual([]);
  });

  it("has no violations in the recovery codes dialog", async () => {
    await signInAlex();
    show();
    fireEvent.click(await within(recoveryRegion()).findByRole("button", { name: "Generate new codes" }));
    const confirm = await screen.findByRole("dialog");
    fireEvent.click(within(confirm).getByRole("button", { name: "Generate new codes" }));
    await screen.findByRole("dialog", { name: "Save your recovery codes" });
    expect(await axeViolations(document.body, NO_SHELL)).toEqual([]);
  });
});
