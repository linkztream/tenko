import { fireEvent, screen, waitFor } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../api/client";
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
      // Nothing usable: the lead says why, and the focus waits on "Start over".
      if (!first) expect(container.querySelector(".lead")?.textContent).toMatch(why ?? /^$/);
      await waitFor(() =>
        expect(document.activeElement).toBe(first ? (field ?? submit) : screen.getByRole("button", { name: "Start over" })),
      );
      expect(screen.queryAllByTestId("signin-method").map((b) => b.textContent)).toEqual(others);
      const note = screen.queryByTestId("signin-passkey-blocked")?.textContent ?? null;
      if (why && first) expect(note).toMatch(why);
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

  it("switches from the passkey to the authenticator code, then to a recovery code", async () => {
    stubPasskey("cancel");
    show();
    signInWithPassword("alex", MOCK_PASSWORDS.alex);
    expect(await screen.findByRole("button", { name: PASSKEY })).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: USE_TOTP }));
    const totp = screen.getByLabelText(TOTP);
    await waitFor(() => expect(document.activeElement).toBe(totp));
    expect(totp.getAttribute("autocomplete")).toBe("one-time-code");
    fireEvent.click(screen.getByRole("button", { name: USE_RECOVERY }));
    const recovery = screen.getByLabelText(RECOVERY);
    await waitFor(() => expect(document.activeElement).toBe(recovery));
    expect(recovery.getAttribute("autocomplete")).toBe("off");
    // The passkey link starts the ceremony again from where it is.
    expect(screen.getByRole("button", { name: "Use a passkey instead" })).toBeTruthy();
  });

  // The browser refuses a ceremony the page could not foresee: "SecurityError" for an origin
  // the passkey does not belong to, "NotAllowedError" as Chrome answers on a certificate error.
  it.each([
    ["SecurityError", /not its IP address\.$/],
    ["NotAllowedError", null],
  ] as const)("asks for the authenticator code first after the browser refused a passkey (%s)", async (name, why) => {
    stubPasskey("cancel").mockRejectedValue(new DOMException("refused", name));
    show();
    fireEvent.click(screen.getByRole("button", { name: PASSKEY }));
    await screen.findByRole("alert");
    signInWithPassword("alex", MOCK_PASSWORDS.alex);
    expect(await screen.findByLabelText(TOTP)).toBeTruthy();
    expect(screen.queryByRole("button", { name: PASSKEY })).toBeNull();
    const note = screen.queryByTestId("signin-passkey-blocked")?.textContent ?? null;
    if (why) expect(note).toMatch(why);
    else expect(note).toBeNull();
    // A refusal for the origin leaves the passkey out; any other keeps it as a way to try again.
    expect(screen.queryByRole("button", { name: "Use a passkey instead" }) === null).toBe(why !== null);
  });

  it("shows no error and keeps the user's choice when they leave a passkey request", async () => {
    // A request the user leaves open: it ends only when the page aborts it.
    const get = vi.fn(
      (options: { signal: AbortSignal }) =>
        new Promise<never>((_, reject) =>
          options.signal.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError"))),
        ),
    );
    vi.stubGlobal("PublicKeyCredential", function PublicKeyCredential() {});
    Object.defineProperty(navigator, "credentials", { value: { get, create: vi.fn() }, configurable: true });
    show();
    signInWithPassword("alex", MOCK_PASSWORDS.alex);
    fireEvent.click(await screen.findByRole("button", { name: PASSKEY }));
    await waitFor(() => expect(get).toHaveBeenCalledTimes(1));
    fireEvent.click(screen.getByRole("button", { name: "Break-glass access" }));
    expect(await screen.findByRole("heading", { name: "Break-glass access" })).toBeTruthy();
    await waitFor(() => expect((screen.getByRole("button", { name: "Sign in with the break-glass key" }) as HTMLButtonElement).disabled).toBe(false));
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("goes back to the password when the passkey step fails after it started", async () => {
    stubPasskey("ok");
    const post = api.post.bind(api);
    vi.spyOn(api, "post").mockImplementation(((path: string, ...rest: unknown[]) =>
      path === "/api/v1/auth/webauthn/login/finish"
        ? Promise.reject(new Error("The passkey could not be checked."))
        : (post as (p: string, ...r: unknown[]) => unknown)(path, ...rest)) as typeof api.post);
    show();
    signInWithPassword("alex", MOCK_PASSWORDS.alex);
    fireEvent.click(await screen.findByRole("button", { name: PASSKEY }));
    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeTruthy();
    expect(screen.getByRole("alert")).toBeTruthy();
    await waitFor(() => expect(document.activeElement).toBe(screen.getByLabelText("Password")));
  });

  it("goes back to the password after a passkey step the browser refused, then asks for the code", async () => {
    stubPasskey("cancel");
    show();
    signInWithPassword("alex", MOCK_PASSWORDS.alex);
    fireEvent.click(await screen.findByRole("button", { name: PASSKEY }));
    // The passkey step spent the password's challenge: a code typed now could only be refused.
    expect((await screen.findByRole("alert")).textContent).toContain("canceled or timed out");
    expect(screen.getByRole("heading", { name: "Sign in" })).toBeTruthy();
    await waitFor(() => expect(document.activeElement).toBe(screen.getByLabelText("Password")));
    fireEvent.input(screen.getByLabelText("Password"), { target: { value: MOCK_PASSWORDS.alex } });
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByLabelText(TOTP)).toBeTruthy();
  });

  it("knows a passkey cannot work on an IP address", () => {
    vi.stubGlobal("PublicKeyCredential", function PublicKeyCredential() {});
    expect(passkeyBlocker("192.0.2.10")).toBe("insecure");
    expect(passkeyBlocker("[2001:db8::1]")).toBe("insecure");
    expect(passkeyBlocker("ddi.example.test")).toBeNull();
  });
});
