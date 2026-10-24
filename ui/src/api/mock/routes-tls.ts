// Mock route of the certificates of the listener (OPS-22, TGL-08): `GET /system/tls`. It answers
// for the TLS mode the installation was set up with (`db.installation.tls`): the internal CA with
// the root and its download, imported files with the profile's rule for a certificate replaced
// from outside, a reverse proxy with its trusted networks, or plain HTTP. Tests change `tlsState`
// (the days the served certificate has left, a newer certificate on disk, a failed reload) and
// the status route takes its warnings from `tlsWarnings`. Administrators only.
import type { components } from "../generated/schema";
import { requireAdmin } from "./auth";
import { db, onMockReset } from "./db";
import { ok } from "./reply";
import { route } from "./route";
import { DAY_MS, iso } from "./util";

type S = components["schemas"];
type Details = S["TlsDetails"];
type Certificate = S["TlsCertificate"];
type Warning = S["StatusWarning"];

export interface TlsState {
  /** Whole days the served certificate has left. */
  daysLeft: number;
  /** A newer certificate is on disk and waits for a restart (imported files only). */
  pending: boolean;
  /** The last failed reload, if any. */
  lastError: string | null;
  /** The setting `tls.accept_external_replacement`; unset, the profile decides. */
  accept: boolean | null;
  /** When the served certificate was loaded, as an offset before now. */
  loadedAgoMs: number;
}

function fresh(): TlsState {
  return { daysLeft: 62, pending: false, lastError: null, accept: null, loadedAgoMs: 3 * DAY_MS };
}

/** The state of the mock; tests change it. */
export const tlsState: TlsState = fresh();

onMockReset(() => {
  Object.assign(tlsState, fresh());
});

const FINGERPRINT = "7c1f3a9e5b2d4086a3c1e9d8f7b6a5c4d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7";
const PENDING_FINGERPRINT = "b4e2a1d09c8f7e6d5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f";
const CA_FINGERPRINT = "3f1c8a9d5e7b2046a1d3c9e8f7a6b5c4d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7";

function hostName(): string {
  return db.installation.host_name ?? "tenko.example.test";
}

function stateOf(days: number): Certificate["state"] {
  if (days < 0) return "expired";
  if (days < 7) return "critical";
  if (days < 30) return "warning";
  return "valid";
}

function certificate(days: number, sha256: string): Certificate {
  const now = Date.now();
  const host = hostName();
  return {
    subject: `CN=${host}`,
    issuer: db.installation.tls.mode === "internal_ca" ? "CN=Tenko Internal CA" : "CN=Example Issuing CA R1",
    dns_names: [host],
    ip_addresses: ["192.0.2.10"],
    not_before: iso(now + days * DAY_MS - 90 * DAY_MS),
    not_after: iso(now + days * DAY_MS),
    days_left: days,
    state: stateOf(days),
    chain_len: db.installation.tls.mode === "internal_ca" ? 1 : 2,
    sha256,
  };
}

/** Whether a replaced certificate is loaded while the listener runs, under the profile in force. */
export function acceptsReplacement(): boolean {
  const profile = db.settings.profile;
  if (profile === "hardened") return false;
  return tlsState.accept ?? profile !== "standard";
}

/** The answer of `GET /system/tls`. */
export function tlsDetails(): Details {
  const { mode, trusted_proxies } = db.installation.tls;
  const now = Date.now();
  const terminates = mode === "internal_ca" || mode === "imported";
  const served = terminates ? certificate(tlsState.daysLeft, FINGERPRINT) : null;
  return {
    mode,
    min_version: terminates ? (db.settings.profile === "hardened" ? "1.3" : "1.2") : null,
    hsts: mode !== "plain",
    certificate: served,
    loaded_at: terminates ? iso(now - tlsState.loadedAgoMs) : null,
    last_error: tlsState.lastError,
    pending:
      mode === "imported" && tlsState.pending
        ? { certificate: { ...certificate(90, PENDING_FINGERPRINT), chain_len: 2 }, detected_at: iso(now - 20 * 60 * 1000) }
        : null,
    imported:
      mode === "imported"
        ? {
            cert_path: "/etc/tenko/tls/fullchain.pem",
            key_path: "/etc/tenko/tls/privkey.pem",
            watch_interval_secs: 5,
            accept_external_replacement: acceptsReplacement(),
          }
        : null,
    internal_ca:
      mode === "internal_ca"
        ? {
            root_subject: "CN=Tenko Internal CA",
            root_not_after: iso(now + 3000 * DAY_MS),
            root_sha256: CA_FINGERPRINT,
            download_path: "/api/v1/system/ca-root",
          }
        : null,
    reverse_proxy:
      mode === "reverse_proxy"
        ? { trusted_proxies: [...trusted_proxies], proxy_protocol: false, public_host: hostName() }
        : null,
  };
}

/** The status warnings of the certificates, as the server raises them. */
export function tlsWarnings(): Warning[] {
  const details = tlsDetails();
  const warnings: Warning[] = [];
  const cert = details.certificate;
  if (cert && cert.state !== "valid") {
    warnings.push({
      code: "sys.tls.certificate_expiry",
      detail: `the server certificate is ${cert.state}: ${cert.days_left} days left`,
      params: { state: cert.state, days_left: String(cert.days_left) },
    });
  }
  if (details.pending) {
    warnings.push({
      code: "sys.tls.certificate_pending",
      detail: "a newer certificate is on disk and is not served; restart to apply it",
      params: { not_after: details.pending.certificate.not_after, sha256: details.pending.certificate.sha256 },
    });
  }
  return warnings;
}

export const tlsRoutes = [
  route("get", "/api/v1/system/tls", () => {
    requireAdmin();
    return ok(tlsDetails());
  }),
];
