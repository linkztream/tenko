// Passkeys and security keys through the WebAuthn browser API. The server speaks the
// JSON forms of the specification (PublicKeyCredentialCreationOptionsJSON and friends);
// this module converts between them and the browser's ArrayBuffers itself, so it works
// in browsers without PublicKeyCredential.parseCreationOptionsFromJSON().
//
// The relying-party id is the public host name (plan Q5; `localhost` in development), so
// a passkey only works when Tenko DDI is opened by that name over HTTPS or on localhost.
import { api } from "../api/client";
import type {
  AuthenticationResponseJSON,
  CreationOptionsJSON,
  FactorEnrolled,
  LoginResponse,
  RegistrationResponseJSON,
  RequestOptionsJSON,
  WebAuthnLoginStart,
} from "../api/types";

export function base64urlToBuffer(value: string): ArrayBuffer {
  const b64 = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out.buffer;
}

export function bufferToBase64url(value: ArrayBuffer | ArrayBufferView): string {
  const bytes = value instanceof ArrayBuffer ? new Uint8Array(value) : new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Whether this browser can do WebAuthn at all (it needs a secure context). */
export function webauthnAvailable(): boolean {
  return typeof window !== "undefined" && window.isSecureContext !== false && typeof window.PublicKeyCredential === "function";
}

function toDescriptor(c: { id: string; type: string; transports?: string[] | null }): PublicKeyCredentialDescriptor {
  return {
    type: "public-key",
    id: base64urlToBuffer(c.id),
    ...(c.transports ? { transports: c.transports as AuthenticatorTransport[] } : {}),
  };
}

export function toRequestOptions(json: RequestOptionsJSON): PublicKeyCredentialRequestOptions {
  const out: PublicKeyCredentialRequestOptions = { challenge: base64urlToBuffer(json.challenge) };
  if (json.timeout !== undefined) out.timeout = json.timeout;
  if (json.rpId !== undefined) out.rpId = json.rpId;
  if (json.userVerification !== undefined) out.userVerification = json.userVerification as UserVerificationRequirement;
  if (json.allowCredentials?.length) out.allowCredentials = json.allowCredentials.map(toDescriptor);
  if (json.hints?.length) (out as { hints?: string[] }).hints = json.hints;
  return out;
}

export function toCreationOptions(json: CreationOptionsJSON): PublicKeyCredentialCreationOptions {
  const out: PublicKeyCredentialCreationOptions = {
    rp: json.rp,
    user: { id: base64urlToBuffer(json.user.id), name: json.user.name, displayName: json.user.displayName },
    challenge: base64urlToBuffer(json.challenge),
    pubKeyCredParams: json.pubKeyCredParams.map((p) => ({ type: "public-key", alg: p.alg })),
  };
  if (json.timeout !== undefined) out.timeout = json.timeout;
  const sel = json.authenticatorSelection;
  if (sel) {
    out.authenticatorSelection = {
      requireResidentKey: sel.requireResidentKey,
      residentKey: sel.residentKey as ResidentKeyRequirement,
      userVerification: sel.userVerification as UserVerificationRequirement,
      ...(sel.authenticatorAttachment ? { authenticatorAttachment: sel.authenticatorAttachment as AuthenticatorAttachment } : {}),
    };
  }
  if (json.attestation) out.attestation = json.attestation as AttestationConveyancePreference;
  if (json.excludeCredentials?.length) out.excludeCredentials = json.excludeCredentials.map(toDescriptor);
  if (json.hints?.length) (out as { hints?: string[] }).hints = json.hints;
  return out;
}

export function assertionToJSON(cred: PublicKeyCredential): AuthenticationResponseJSON {
  const r = cred.response as AuthenticatorAssertionResponse;
  return {
    id: cred.id,
    rawId: bufferToBase64url(cred.rawId),
    type: "public-key",
    response: {
      clientDataJSON: bufferToBase64url(r.clientDataJSON),
      authenticatorData: bufferToBase64url(r.authenticatorData),
      signature: bufferToBase64url(r.signature),
      ...(r.userHandle ? { userHandle: bufferToBase64url(r.userHandle) } : {}),
    },
    ...(cred.authenticatorAttachment ? { authenticatorAttachment: cred.authenticatorAttachment } : {}),
    clientExtensionResults: {},
  };
}

export function attestationToJSON(cred: PublicKeyCredential): RegistrationResponseJSON {
  const r = cred.response as AuthenticatorAttestationResponse;
  return {
    id: cred.id,
    rawId: bufferToBase64url(cred.rawId),
    type: "public-key",
    response: {
      clientDataJSON: bufferToBase64url(r.clientDataJSON),
      attestationObject: bufferToBase64url(r.attestationObject),
      transports: typeof r.getTransports === "function" ? r.getTransports() : [],
    },
    ...(cred.authenticatorAttachment ? { authenticatorAttachment: cred.authenticatorAttachment } : {}),
    clientExtensionResults: {},
  };
}

/** Why a ceremony ended without a credential, in terms the UI can explain. */
export type CeremonyFailure = "cancelled" | "unsupported" | "insecure" | "exists" | "failed";

export class CeremonyError extends Error {
  constructor(readonly reason: CeremonyFailure) {
    super(reason);
    this.name = "CeremonyError";
  }
}

function classify(err: unknown): CeremonyError {
  if (err instanceof DOMException) {
    if (err.name === "NotAllowedError" || err.name === "AbortError") return new CeremonyError("cancelled");
    if (err.name === "InvalidStateError") return new CeremonyError("exists");
    if (err.name === "SecurityError") return new CeremonyError("insecure");
    if (err.name === "NotSupportedError") return new CeremonyError("unsupported");
  }
  return new CeremonyError("failed");
}

/**
 * Signs in with a passkey: the `/auth/webauthn/login/{start,finish}` ceremony. With a
 * `challengeId` it completes a password sign-in as the second factor; with `breakGlass`
 * it asks for the break-glass hardware key (IAM-09).
 */
export async function signInWithPasskey(
  options: WebAuthnLoginStart & {
    /** Proposed: ask for the break-glass key only (the server may also tell it by the credential). */
    break_glass?: boolean;
    signal?: AbortSignal;
  } = {},
): Promise<LoginResponse> {
  if (!webauthnAvailable()) throw new CeremonyError(window.isSecureContext === false ? "insecure" : "unsupported");
  const { signal, ...body } = options;
  const start = await api.post("/api/v1/auth/webauthn/login/start", { body, signal });
  let cred: Credential | null;
  try {
    cred = await navigator.credentials.get({ publicKey: toRequestOptions(start.public_key), signal });
  } catch (err) {
    throw classify(err);
  }
  if (!cred) throw new CeremonyError("cancelled");
  return api.post("/api/v1/auth/webauthn/login/finish", {
    body: { ceremony_id: start.ceremony_id, credential: assertionToJSON(cred as PublicKeyCredential) },
  });
}

/** Registers a passkey (or, with `securityKey`, a hardware security key) for the signed-in account. */
export async function registerPasskey(options: { label?: string; securityKey?: boolean; signal?: AbortSignal } = {}): Promise<FactorEnrolled> {
  if (!webauthnAvailable()) throw new CeremonyError(window.isSecureContext === false ? "insecure" : "unsupported");
  const start = await api.post("/api/v1/auth/webauthn/register/start", {
    body: { label: options.label ?? null, security_key: options.securityKey ?? false },
    signal: options.signal,
  });
  let cred: Credential | null;
  try {
    cred = await navigator.credentials.create({ publicKey: toCreationOptions(start.public_key), signal: options.signal });
  } catch (err) {
    throw classify(err);
  }
  if (!cred) throw new CeremonyError("cancelled");
  return api.post("/api/v1/auth/webauthn/register/finish", {
    body: { ceremony_id: start.ceremony_id, credential: attestationToJSON(cred as PublicKeyCredential) },
  });
}
