// What the certificates page shows, apart from the markup: the types of the two reads, the
// status warnings it cares about and the rule of each security profile for a certificate that is
// replaced in the files while the listener runs (TGL-08, `tls.accept_external_replacement`).
import type { components } from "../../api/generated/schema";
import type { MessageKey } from "../../i18n";

type S = components["schemas"];

export type TlsDetails = S["TlsDetails"];
export type TlsCertificate = S["TlsCertificate"];
export type CertificateState = S["CertificateState"];
export type TlsMode = S["TlsMode"];
export type StatusWarning = S["StatusWarning"];
export type Profile = S["Profile"];

/** The status warning for a certificate that is expiring, expired or not valid yet. */
export const EXPIRY_WARNING = "sys.tls.certificate_expiry";
/** The status warning for a newer certificate on disk that waits for a restart. */
export const PENDING_WARNING = "sys.tls.certificate_pending";

/** What the page was built from: both reads happen together, on opening and on Refresh. */
export interface Loaded {
  tls: TlsDetails;
  warnings: StatusWarning[];
  /** The security profile in force; `null` when the settings could not be read. */
  profile: Profile | null;
  /** When the page read them. */
  readAt: number;
}

/** The warning with `code` among the status warnings, if it is active. */
export function warningOf(loaded: Pick<Loaded, "warnings">, code: string): StatusWarning | undefined {
  return loaded.warnings.find((warning) => warning.code === code);
}

/**
 * The style of the days-left tag: plain while the certificate is valid (the green tag of the
 * design does not reach the contrast of 4.5:1 at this size), the warning style under 30 days, the
 * danger style under 7.
 */
export function stateClass(state: CertificateState): string {
  switch (state) {
    case "valid":
      return "";
    case "warning":
      return "discrepancy";
    case "critical":
    case "expired":
    case "not_yet_valid":
      return "conflict";
  }
}

/** The kind of the note for an expiry state: a warning, or an error once it is serious. */
export function noticeKind(state: CertificateState): "warn" | "bad" {
  return state === "warning" ? "warn" : "bad";
}

/** The message that names the mode. */
export const MODE_NAME: Readonly<Record<TlsMode, MessageKey>> = {
  internal_ca: "certificates.mode.internal_ca",
  imported: "certificates.mode.imported",
  reverse_proxy: "certificates.mode.reverse_proxy",
  plain: "certificates.mode.plain",
};

/** The message that says what the mode means. */
export const MODE_HELP: Readonly<Record<TlsMode, MessageKey>> = {
  internal_ca: "certificates.mode.internal_ca.help",
  imported: "certificates.mode.imported.help",
  reverse_proxy: "certificates.mode.reverse_proxy.help",
  plain: "certificates.mode.plain.help",
};

/** The sentence on what a profile allows for a replaced certificate. */
export function profileRule(profile: Profile): MessageKey {
  switch (profile) {
    case "lab":
      return "certificates.rule.lab";
    case "home":
      return "certificates.rule.home";
    case "standard":
      return "certificates.rule.standard";
    case "hardened":
      return "certificates.rule.hardened";
  }
}

/** The fingerprint in groups of eight hexadecimal digits, easier to compare by eye. */
export function groupedFingerprint(hex: string): string {
  return hex.match(/.{1,8}/g)?.join(" ") ?? hex;
}
