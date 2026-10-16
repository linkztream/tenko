// Other accounts than the administrator, arranged through the API for the scenarios that look
// at a page as someone else: a viewer, who reads and acts on nothing. The browser shares the
// cookies of the API context, so the sign-in here signs the page in as well.

import { expect } from "@playwright/test";
import type { Api } from "./api";

/** The initial PIN of the viewer (digits only, like the administrator's). */
const VIEWER_PIN = "628401";
/** What the viewer changes it to, as the server demands for an initial password. */
const VIEWER_PIN_CHANGED = "915273";

/**
 * Signs the page in as an account the administrator created with a PIN: the administrator is
 * signed out, the account signs in with its initial PIN, changes it (the server demands that of
 * an initial password) and signs in again with the new one. Needs the account to exist.
 */
export async function signInCreatedAccount(api: Api, name: string, initialPin: string, changedPin: string): Promise<void> {
  await api.logout();
  await api.loginPassword(name, initialPin);
  await api.post("/auth/password", { current_password: initialPin, new_password: changedPin }, { idempotencyKey: null });
  await api.logout().catch(() => undefined);
  const login = await api.loginPassword(name, changedPin);
  expect(login.status).toBe("authenticated");
}

/** The login name of the viewer `signInAsViewer` creates. */
export const VIEWER_NAME = "vera";

/**
 * Creates the viewer account, signs the administrator out and the viewer in, and changes the
 * initial password (until then the server answers every other call with "password change
 * required"). Needs the signed-in administrator.
 */
export async function signInAsViewer(api: Api): Promise<void> {
  await api.post("/users", { name: VIEWER_NAME, roles: ["viewer"], password: VIEWER_PIN }, { idempotencyKey: null });
  await api.logout();
  const login = await api.loginPassword(VIEWER_NAME, VIEWER_PIN);
  expect(login.status).toBe("authenticated");
  await api.post("/auth/password", { current_password: VIEWER_PIN, new_password: VIEWER_PIN_CHANGED }, { idempotencyKey: null });
}
