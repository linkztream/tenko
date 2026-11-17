import { fireEvent, screen, waitFor } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { db, resetMockDb } from "../api/mock/db";
import { MOCK_PASSWORDS, MOCK_RECOVERY_CODES, MOCK_TOTP_CODE } from "../api/mock/fixtures";
import { PROFILE_MATRIX } from "../api/mock/profiles";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { locale, setLocale } from "../i18n";
import { authState, session, setSessionForTest } from "./session";
import SignIn from "./SignIn";
import { passkeyBlocker } from "./webauthn";

function bytes(...values: number[]): ArrayBuffer {
  return new Uint8Array(values).buffer;
}

/** A stand-in for navigator.credentials.get() returning an assertion-shaped object. */
function stubPasskey(result: "ok" | "cancel") {
  const get = vi.fn(async () => {
    if (result === "cancel") throw new DOMException("The operation either timed out or was not allowed.", "NotAllowedError");
    return {
      id: "Y3JlZA",
      rawId: bytes(99, 114, 101, 100),
      type: "public-key",
      authenticatorAttachment: "cross-platform",
      response: {
        clientDataJSON: bytes(1, 2, 3),
        authenticatorData: bytes(4, 5, 6),
        signature: bytes(7, 8, 9),
        userHandle: bytes(10, 11),
      },
    };
  });
  vi.stubGlobal("PublicKeyCredential", function PublicKeyCredential() {});
  Object.defineProperty(navigator, "credentials", { value: { get, create: vi.fn() }, configurable: true });
  return get;
}

beforeEach(async () => {
  resetMockDb("signed-out");
  setSessionForTest(null, "signed-out");
  await setLocale("en");
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

function show() {
  return renderRoute(SignIn, { url: "/signin" });
}

function signInWithPassword(user: string, password: string) {
  fireEvent.click(screen.getByRole("button", { name: "Use user name and password" }));
  fireEvent.input(screen.getByLabelText("User name"), { target: { value: user } });
  fireEvent.input(screen.getByLabelText("Password"), { target: { value: password } });
  fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
}

describe("sign-in", () => {
  it("offers the passkey first", () => {
    show();
    const buttons = screen.getAllByRole("button").map((b) => b.textContent?.trim());
    expect(buttons.indexOf("Sign in with a passkey")).toBeLessThan(buttons.indexOf("Use user name and password"));
    expect(screen.getByRole("heading", { name: "Sign in" })).toBeTruthy();
  });

  it("signs in with a password alone when the account has no second factor", async () => {
    show();
    signInWithPassword("sam", MOCK_PASSWORDS.sam);
    await waitFor(() => expect(authState()).toBe("signed-in"));
    expect(session()?.user.name).toBe("sam");
    // sam's account has Swedish fixed (API-08): the session switches the language.
    await waitFor(() => expect(locale()).toBe(session()?.user.language ?? "en"));
  });

  it("asks for the authenticator code after the password, then signs in", async () => {
    show();
    signInWithPassword("alex", MOCK_PASSWORDS.alex);
    expect(await screen.findByRole("heading", { name: "Confirm it is you" })).toBeTruthy();
    const code = screen.getByLabelText("Authenticator code");
    fireEvent.input(code, { target: { value: "000000" } });
    fireEvent.click(screen.getByRole("button", { name: "Verify" }));
    expect((await screen.findByRole("alert")).textContent).toContain("The code does not match.");
    fireEvent.input(screen.getByLabelText("Authenticator code"), { target: { value: MOCK_TOTP_CODE } });
    fireEvent.click(screen.getByRole("button", { name: "Verify" }));
    await waitFor(() => expect(authState()).toBe("signed-in"));
    expect(session()?.user.name).toBe("alex");
  });

  it("accepts a recovery code as the second factor", async () => {
    show();
    signInWithPassword("alex", MOCK_PASSWORDS.alex);
    fireEvent.click(await screen.findByRole("button", { name: "Use a recovery code (each code works once)" }));
    fireEvent.input(screen.getByLabelText("Recovery code"), { target: { value: MOCK_RECOVERY_CODES[0] } });
    fireEvent.click(screen.getByRole("button", { name: "Verify" }));
    await waitFor(() => expect(authState()).toBe("signed-in"));
  });

  it("says why a password is refused, in the user's language", async () => {
    show();
    signInWithPassword("sam", "not-the-password");
    expect((await screen.findByRole("alert")).textContent).toContain("The user name or password is wrong.");
    expect(authState()).toBe("signed-out");
  });

  it("counts down after repeated failures and disables the button meanwhile", async () => {
    show();
    signInWithPassword("sam", "wrong-0");
    await screen.findByRole("alert");
    for (let i = 1; i < 3; i++) {
      fireEvent.input(screen.getByLabelText("Password"), { target: { value: `wrong-${i}` } });
      fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
      await new Promise((r) => setTimeout(r, 30));
    }
    expect(await screen.findByText(/Try again in \d+ seconds?\./)).toBeTruthy();
    expect((screen.getByRole("button", { name: "Sign in" }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("says the wait in minutes, and says nothing of the account", async () => {
    db.settings.lockout_policy = { ...(db.settings.lockout_policy ?? PROFILE_MATRIX.standard.lockout_policy!), waits_secs: [180, 300] };
    show();
    signInWithPassword("nobody-here", "wrong-0");
    await screen.findByRole("alert");
    for (let i = 1; i < 3; i++) {
      fireEvent.input(screen.getByLabelText("Password"), { target: { value: `wrong-${i}` } });
      fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
      await new Promise((r) => setTimeout(r, 30));
    }
    // A name that does not exist is throttled like any other, and the words do not tell the difference.
    expect(await screen.findByText("Try again in 3 minutes.")).toBeTruthy();
    expect(
      screen.getByText(/A passkey, or a browser or network you have signed in from before, may let you in sooner\./),
    ).toBeTruthy();
    expect(document.body.textContent).not.toMatch(/account.*(locked|exist)/i);
  });

  it("always shows how to get out of a lock, whatever the account", () => {
    show();
    const help = screen.getByTestId("signin-locked-help");
    expect(help.textContent).toBe(
      "Locked out or PIN no longer accepted? An administrator can reset it. On a server with a single administrator, run tenko user unlock <name> on the host as the service account.",
    );
    expect(help.querySelector("code")?.textContent).toBe("tenko user unlock <name>");
    fireEvent.click(screen.getByRole("button", { name: "Use user name and password" }));
    expect(screen.getByTestId("signin-locked-help")).toBeTruthy();
  });

  it("signs in with a passkey through the WebAuthn ceremony", async () => {
    const get = stubPasskey("ok");
    show();
    fireEvent.click(screen.getByRole("button", { name: "Sign in with a passkey" }));
    await waitFor(() => expect(authState()).toBe("signed-in"));
    expect(get).toHaveBeenCalledTimes(1);
    const options = get.mock.calls[0] as unknown as [{ publicKey: PublicKeyCredentialRequestOptions }];
    expect(options[0].publicKey.challenge).toBeInstanceOf(ArrayBuffer);
  });

  it("explains a canceled passkey request", async () => {
    stubPasskey("cancel");
    show();
    fireEvent.click(screen.getByRole("button", { name: "Sign in with a passkey" }));
    expect((await screen.findByRole("alert")).textContent).toContain("canceled or timed out");
    expect(authState()).toBe("signed-out");
  });

  it("keeps break-glass access behind a link and uses the hardware key", async () => {
    stubPasskey("ok");
    show();
    expect(screen.queryByRole("button", { name: "Sign in with the break-glass key" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Break-glass access" }));
    fireEvent.click(await screen.findByRole("button", { name: "Sign in with the break-glass key" }));
    await waitFor(() => expect(authState()).toBe("signed-in"));
    expect(session()?.flags.break_glass).toBe(true);
  });

  it("has no accessibility violations in any stage", async () => {
    const { container } = show();
    expect(await axeViolations(container)).toEqual([]);
    fireEvent.click(screen.getByRole("button", { name: "Use user name and password" }));
    expect(await axeViolations(container)).toEqual([]);
    fireEvent.click(screen.getByRole("button", { name: "Break-glass access" }));
    expect(await axeViolations(container)).toEqual([]);
  });
});

describe("the second step after a password", () => {
  const PASSKEY = "Sign in with a passkey";
  const TOTP = "Authenticator code";
  const RECOVERY = "Recovery code";
  const USE_TOTP = "Use an authenticator code";
  const USE_RECOVERY = "Use a recovery code (each code works once)";
  const ADDRESS = /not its IP address\.$/;
  const BROWSER = /this browser does not support passkeys\.$/;

  type Env = "available" | "unsupported" | "insecure";
  // [authenticator app, passkey, recovery codes left, browser, first factor, other factors, why no passkey]
  const shapes: [boolean, boolean, boolean, Env, string | null, string[], RegExp | null][] = [
    [true, false, true, "available", TOTP, [USE_RECOVERY], null],
    [true, false, true, "insecure", TOTP, [USE_RECOVERY], null],
    [true, false, false, "available", TOTP, [], null],
    [false, true, true, "available", PASSKEY, [USE_RECOVERY], null],
    [false, true, true, "insecure", RECOVERY, [], ADDRESS],
    [false, true, true, "unsupported", RECOVERY, [], BROWSER],
    [false, true, false, "available", PASSKEY, [], null],
    [false, true, false, "insecure", null, [], ADDRESS],
    [true, true, true, "available", PASSKEY, [USE_TOTP, USE_RECOVERY], null],
    [true, true, true, "insecure", TOTP, [USE_RECOVERY], ADDRESS],
    [true, true, true, "unsupported", TOTP, [USE_RECOVERY], BROWSER],
    [true, true, false, "available", PASSKEY, [USE_TOTP], null],
    [true, true, false, "insecure", TOTP, [], ADDRESS],
  ];

  it.each(shapes)(
    "app %s, passkey %s, codes left %s, passkeys %s: asks for %s first",
    async (totp, passkey, codes, env, first, others, why) => {
      const alex = db.users.find((u) => u.name === "alex")!;
      alex.totp = totp;
      if (!passkey) alex.credentials = [];
      if (!codes) alex.recovery_codes = [];
      if (env !== "unsupported") vi.stubGlobal("PublicKeyCredential", function PublicKeyCredential() {});
      if (env === "insecure") vi.stubGlobal("isSecureContext", false);
      const { container } = show();
      signInWithPassword("alex", MOCK_PASSWORDS.alex);
      expect(await screen.findByRole("heading", { name: "Confirm it is you" })).toBeTruthy();

      const field = screen.queryByTestId("field-code");
      const submit = screen.queryByTestId("form-submit");
      // A code factor is the labeled field; a passkey is the step's button; nothing usable leaves neither.
      if (field) expect(screen.getByLabelText(first ?? "")).toBe(field);
      else expect(submit?.textContent ?? null).toBe(first);
      if (first === TOTP) expect(field?.getAttribute("autocomplete")).toBe("one-time-code");
      if (first === RECOVERY) {
        expect(field?.getAttribute("autocomplete")).toBe("off");
        expect(field?.getAttribute("inputmode")).toBe("text");
        expect(screen.getByText(/only a recovery code can finish this sign-in/)).toBeTruthy();
        expect(screen.getByText(/add an authenticator app on your account page/)).toBeTruthy();
      }
      if (first) await waitFor(() => expect(document.activeElement).toBe(field ?? submit));
      expect(screen.queryAllByTestId("signin-method").map((b) => b.textContent)).toEqual(others);
      const note = screen.queryByTestId("signin-passkey-blocked")?.textContent ?? null;
      if (why) expect(note).toMatch(why);
      else expect(note).toBeNull();
      expect(await axeViolations(container)).toEqual([]);
    },
  );

  it("signs in with the passkey it asks for first", async () => {
    const get = stubPasskey("ok");
    show();
    signInWithPassword("alex", MOCK_PASSWORDS.alex);
    fireEvent.click(await screen.findByRole("button", { name: PASSKEY }));
    await waitFor(() => expect(authState()).toBe("signed-in"));
    expect(get).toHaveBeenCalledTimes(1);
  });

  it("knows a passkey cannot work on an IP address", () => {
    vi.stubGlobal("PublicKeyCredential", function PublicKeyCredential() {});
    expect(passkeyBlocker("192.0.2.10")).toBe("insecure");
    expect(passkeyBlocker("[2001:db8::1]")).toBe("insecure");
    expect(passkeyBlocker("ddi.example.test")).toBeNull();
  });
});
