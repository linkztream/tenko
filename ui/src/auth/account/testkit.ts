// Helpers of the account tests: a signed-in alex against the mock API and a stand-in for
// the browser's WebAuthn API that returns objects shaped like a PublicKeyCredential.
import { vi } from "vitest";
import { api } from "../../api/client";
import { db, findUserByName, resetMockDb, type MockUser } from "../../api/mock/db";
import type { MockScenario } from "../../api/mock/db";
import { dismissToast } from "../../components/toast";
import { setLocale } from "../../i18n";
import { setSessionForTest } from "../session";

/**
 * alex, signed in through the mock (a passkey session under the Standard profile). `prepare`
 * changes what the account has before the session is read, so the session shows it too.
 */
export async function signInAlex(
  options: { scenario?: MockScenario; prepare?: (user: MockUser) => void } = {},
): Promise<void> {
  resetMockDb(options.scenario ?? "signed-in");
  resetToasts();
  await setLocale("en");
  options.prepare?.(alex());
  setSessionForTest(await api.get("/api/v1/auth/session"));
}

/** Toasts outlive a test (they are module state); clear the ones earlier tests left. */
export function resetToasts(): void {
  for (let id = 1; id <= 500; id++) dismissToast(id);
}

/** The mock's record of alex, to change what the account has before a page is shown. */
export function alex(): MockUser {
  const user = findUserByName("alex");
  if (!user) throw new Error("the mock has no alex");
  return user;
}

export { db };

function bytes(...values: number[]): ArrayBuffer {
  return new Uint8Array(values).buffer;
}

let counter = 0;

/** A credential as `navigator.credentials.create()` returns it. */
function newCredential() {
  counter += 1;
  const id = `ZmFrZS1jcmVkLSR7${counter}`;
  return {
    id,
    rawId: bytes(102, 97, 107, 101, counter),
    type: "public-key",
    authenticatorAttachment: "platform",
    response: {
      clientDataJSON: bytes(1, 2, 3),
      attestationObject: bytes(4, 5, 6),
      getTransports: () => ["internal"],
    },
  };
}

export interface FakeAuthenticator {
  create: ReturnType<typeof vi.fn>;
  /** For a ceremony that waits: ends it with a credential. */
  finish: () => void;
}

/**
 * Makes `PublicKeyCredential` and `navigator.credentials` available. With `wait` the
 * ceremony stays open until `finish()`; with `fail` it ends with that DOMException name.
 */
export function stubWebAuthn(options: { wait?: boolean; fail?: string } = {}): FakeAuthenticator {
  let release: () => void = () => {};
  const create = vi.fn(
    () =>
      new Promise((resolve, reject) => {
        if (options.fail) {
          reject(new DOMException("The operation either timed out or was not allowed.", options.fail));
          return;
        }
        if (options.wait) release = () => resolve(newCredential());
        else resolve(newCredential());
      }),
  );
  vi.stubGlobal("PublicKeyCredential", function PublicKeyCredential() {});
  Object.defineProperty(navigator, "credentials", { value: { create, get: vi.fn() }, configurable: true });
  return { create, finish: () => release() };
}
