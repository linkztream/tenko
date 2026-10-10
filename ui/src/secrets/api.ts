// The only module of the secrets area that talks to the API (IAM-15, IAM-16, API-11):
// operator secrets, their references and reveal, the credentials of a host and its remote
// access hand-off. Values travel only in `createSecret`, `updateSecret` (requests) and
// `revealSecret` (the one answer that carries a value); every other call is metadata.
//
// Creating or replacing a value sends no `Idempotency-Key`: the server keeps a fingerprint
// of keyed requests for its replay check, and a request body that holds a value should not
// leave even a hash behind. A retried create is refused by nothing but shows up as a second
// secret, which the person sees and deletes.
import { ANY_REVISION, api } from "../api/client";
import type { components } from "../api/generated/schema";
import type { Revision } from "../api/types";

type S = components["schemas"];

export type OperatorSecret = S["OperatorSecretView"];
export type NewOperatorSecret = S["NewOperatorSecret"];
export type OperatorSecretPatch = S["OperatorSecretPatch"];
export type SecretKind = S["SecretKind"];
export type SecretOrigin = S["SecretOrigin"];
export type CredentialRole = S["CredentialRole"];
export type LastReveal = S["LastReveal"];
export type SecretReferences = S["SecretReferences"];
export type SecretHostReference = S["SecretHostReference"];
export type SecretConnectorReference = S["SecretConnectorReference"];
export type RevealRequest = S["RevealRequest"];
export type RevealedSecret = S["RevealedSecret"];
export type HostCredentials = S["HostCredentialsView"];
export type HostCredentialItem = S["HostCredentialItem"];
export type HostCredentialBinding = S["HostCredentialBinding"];
export type SshHandoff = S["SshHandoff"];
export type RevealPolicy = S["RevealPolicy"];
export type RevealStepUp = S["RevealStepUp"];

export const SECRET_KINDS: readonly SecretKind[] = ["password", "api_key", "ssh_key", "token", "other"];
export const CREDENTIAL_ROLES: readonly CredentialRole[] = ["admin", "rdp", "ssh", "web", "other"];

export interface SecretQuery {
  q?: string | undefined;
  kind?: SecretKind | undefined;
  tag?: string | undefined;
  host?: string | undefined;
}

/** Every operator secret the caller may see, by name (a viewer sees none). */
export async function listSecrets(query: SecretQuery = {}, signal?: AbortSignal): Promise<OperatorSecret[]> {
  const items: OperatorSecret[] = [];
  let cursor: string | undefined;
  do {
    const page = await api.get("/api/v1/secrets", {
      query: { ...query, limit: 1000, cursor },
      signal,
    });
    items.push(...page.items);
    cursor = page.next_cursor ?? undefined;
  } while (cursor);
  return items;
}

export function getSecret(id: string, signal?: AbortSignal): Promise<OperatorSecret> {
  return api.get("/api/v1/secrets/{id}", { path: { id }, signal });
}

/** Creates a secret. No `Idempotency-Key` (see the module comment). */
export function createSecret(body: NewOperatorSecret): Promise<OperatorSecret> {
  return api.post("/api/v1/secrets", { body, idempotencyKey: null });
}

/** Changes the metadata and, with `value`, the value; `revision` guards against a concurrent change. */
export function updateSecret(id: string, body: OperatorSecretPatch, revision?: Revision): Promise<OperatorSecret> {
  return api.patch("/api/v1/secrets/{id}", { path: { id }, body, ifMatch: revision ?? ANY_REVISION });
}

/** Deletes a secret; 409 `vault.secret.in_use` while something references it. */
export function deleteSecret(id: string, revision?: Revision): Promise<undefined> {
  return api.delete("/api/v1/secrets/{id}", { path: { id }, ifMatch: revision ?? ANY_REVISION }) as Promise<undefined>;
}

export function secretReferences(id: string, signal?: AbortSignal): Promise<SecretReferences> {
  return api.get("/api/v1/secrets/{id}/references", { path: { id }, signal });
}

/**
 * Reveals the value once. The answer is never stored for a replay, so a retry needs a new
 * key (the server answers a reused one with 409 `sys.idempotency_not_replayable`).
 */
export function revealSecret(id: string, body: RevealRequest): Promise<RevealedSecret> {
  return api.post("/api/v1/secrets/{id}/reveal", { path: { id }, body });
}

export function hostCredentials(host: string, signal?: AbortSignal): Promise<HostCredentials> {
  return api.get("/api/v1/hosts/{id}/credentials", { path: { id: host }, signal });
}

/** Replaces the credentials bound to a host; `version` is the one read with them. */
export function setHostCredentials(
  host: string,
  credentials: HostCredentialBinding[],
  version?: number,
): Promise<HostCredentials> {
  return api.put("/api/v1/hosts/{id}/credentials", {
    path: { id: host },
    body: { credentials },
    ifMatch: version ?? ANY_REVISION,
  });
}

export interface RemoteQuery {
  /** An IP address of the host. */
  address?: string | undefined;
  /** An interface of the host. */
  interface?: string | undefined;
  port?: number | undefined;
  user?: string | undefined;
}

/** The text of the `.rdp` file of a host (no secret in it). */
export async function remoteRdp(host: string, query: RemoteQuery = {}): Promise<string> {
  const text: unknown = await api.get("/api/v1/hosts/{id}/remote", {
    path: { id: host },
    query: { ...query, protocol: "rdp" },
  });
  return typeof text === "string" ? text : "";
}

/** The `ssh://` hand-off of a host (no secret in it). */
export async function remoteSsh(host: string, query: RemoteQuery = {}): Promise<SshHandoff> {
  const answer: unknown = await api.get("/api/v1/hosts/{id}/remote", {
    path: { id: host },
    query: { ...query, protocol: "ssh" },
  });
  return answer as SshHandoff;
}
