// The signed-in session (IAM-08) and the state the whole UI keys off: whether first-run
// setup is still open, whether someone is signed in, with which roles, profile and banner.
import { createSignal } from "solid-js";
import { api, setUnauthorizedHandler } from "../api/client";
import { isApiError } from "../api/problem";
import type { Banner, LoginResponse, RoleName, SessionInfo } from "../api/types";
import { events } from "../api/events";
import { browserLocales, resolveLocale, setLocale, storedLocale } from "../i18n";

export type AuthState = "loading" | "setup" | "signed-out" | "signed-in";

const [state, setState] = createSignal<AuthState>("loading");
const [session, setSessionSignal] = createSignal<SessionInfo | null>(null);

/** Where the UI stands: loading, setup open, signed out or signed in. */
export { state as authState, session };

let expiredHandler: (() => void) | undefined;

/** The router registers how to get to the sign-in page when a session ends. */
export function onSessionExpired(handler: () => void): void {
  expiredHandler = handler;
}

// eslint-disable-next-line solid/reactivity -- called from a request, like an event handler
setUnauthorizedHandler(() => {
  if (state() !== "signed-in") return;
  clear();
  expiredHandler?.();
});

/** The language for the current user (API-08): account, browser choice, browser, installation. */
export function applyLanguage(s: SessionInfo | null = session()): Promise<void> {
  return setLocale(
    resolveLocale({
      user: s?.user.language,
      stored: storedLocale(),
      browser: browserLocales(),
      installation: s?.default_language,
    }),
  );
}

function clear(): void {
  events.stop();
  setSessionSignal(null);
  setState("signed-out");
}

/** Starts a session from a sign-in or setup answer. */
export async function establish(s: SessionInfo): Promise<void> {
  setSessionSignal(s);
  setState("signed-in");
  await applyLanguage(s);
  events.start();
}

/** Asks the server who is signed in; on 401, whether setup is still open. */
export async function loadSession(): Promise<AuthState> {
  try {
    const s = await api.get("/api/v1/auth/session");
    await establish(s);
    return "signed-in";
  } catch (err) {
    if (!isApiError(err) || err.status !== 401) {
      // The server is unreachable or broken: treat as signed out; the sign-in page says why.
      setState("signed-out");
      return "signed-out";
    }
  }
  try {
    const setup = await api.get("/api/v1/setup");
    if (setup.open) {
      setState("setup");
      return "setup";
    }
  } catch {
    // Setup state unknown: fall through to sign-in.
  }
  setState("signed-out");
  return "signed-out";
}

/** Completes a sign-in step: a session, or the second factor the server asks for. */
export async function acceptLogin(res: LoginResponse): Promise<LoginResponse> {
  if (res.status === "authenticated") await establish(res.session);
  return res;
}

export async function signOut(): Promise<void> {
  try {
    await api.post("/api/v1/auth/logout");
  } catch {
    // Signed out locally either way; the cookie expires on the server.
  } finally {
    clear();
  }
}

/** Updates the banner after a settings change without a new session request. */
export function updateBanner(banner: Banner): void {
  const s = session();
  if (s) setSessionSignal({ ...s, banner });
}

/** Updates the account's fixed language after the user changed it. */
export function updateUserLanguage(language: string | null): void {
  const s = session();
  if (s) setSessionSignal({ ...s, user: { ...s.user, language } });
}

export function hasRole(role: RoleName): boolean {
  return session()?.roles.includes(role) ?? false;
}

export const isAdmin = (): boolean => hasRole("admin");

/** For tests: a known state without the network. */
export function setSessionForTest(s: SessionInfo | null, next?: AuthState): void {
  setSessionSignal(s);
  setState(next ?? (s ? "signed-in" : "signed-out"));
}
