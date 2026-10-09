// What the sign-in methods page knows about the account: its passkeys and security keys,
// and (when the server lets this account read it) the summary of its factors.
//
// No endpoint tells an ordinary account whether an authenticator app is set up or how many
// recovery codes are left; `GET /users/{id}` does for those who may read their own user
// record (`factors`). Where it is refused, the page infers what it can and learns the rest
// from the server's answers (`auth.totp.already_enrolled`).
import { createEffect, createSignal, on } from "solid-js";
import { api } from "../../api/client";
import { createLiveQuery, type LiveQuery } from "../../api/live";
import { fetchAll } from "../../api/paginate";
import { isApiError } from "../../api/problem";
import type { CredentialInfo, FactorSummary } from "../../api/types";
import { session } from "../session";
import { latest } from "./shared";

export interface MethodsData {
  credentials: LiveQuery<CredentialInfo[]>;
  factors: LiveQuery<FactorSummary | null>;
  /** The passkeys and security keys; undefined until the first load. */
  keys: () => CredentialInfo[] | undefined;
  /** Whether an authenticator app is set up; undefined when nothing tells. */
  totp: () => boolean | undefined;
  /** Recovery codes left; undefined when nothing tells. */
  codesLeft: () => number | undefined;
  /** Records what an action of this page changed, until the server's answer catches up. */
  setTotp: (enrolled: boolean) => void;
  refetch: () => void;
}

export function createMethodsData(): MethodsData {
  const credentials = createLiveQuery<CredentialInfo[]>({
    topics: ["admin"],
    fetch: async (signal) => {
      const all = await fetchAll<CredentialInfo>("/api/v1/auth/webauthn/credentials", { signal });
      return { value: all.items, revision: all.revision };
    },
  });

  const factors = createLiveQuery<FactorSummary | null>({
    topics: ["admin"],
    fetch: async (signal) => {
      const id = session()?.user.id;
      if (!id) return { value: null };
      try {
        const user = await api.get("/api/v1/users/{id}", { path: { id }, signal });
        return { value: user.factors };
      } catch (err) {
        // Not readable for this account (or gone): the page falls back to what it can infer.
        if (isApiError(err)) return { value: null };
        throw err;
      }
    },
  });

  const [totpHint, setTotpHint] = createSignal<boolean | undefined>(undefined);
  // The server's answer wins as soon as it arrives after an action of this page.
  createEffect(
    on(
      () => latest(factors),
      () => setTotpHint(undefined),
      { defer: true },
    ),
  );

  const known = () => latest(factors) ?? undefined;
  return {
    credentials,
    factors,
    keys: () => latest(credentials),
    totp: () => totpHint() ?? known()?.totp ?? (session()?.strength === "password_totp" ? true : undefined),
    codesLeft: () => known()?.recovery_codes,
    setTotp: (enrolled) => {
      setTotpHint(enrolled);
      factors.refetch();
    },
    refetch: () => {
      credentials.refetch();
      factors.refetch();
    },
  };
}
