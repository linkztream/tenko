// Names for the request and response bodies the UI works with. Every type the OpenAPI
// document describes is an alias of the generated schema (src/api/generated/schema.d.ts),
// so a backend change shows up as a compile error where the UI depends on it. The few
// shapes marked "proposed" are not in the document yet: they are what the views need from
// the API owners (see the WP1.9 report) and are sent or read as optional extras.
import type { components } from "./generated/schema";

type S = components["schemas"];

export type Timestamp = string;
export type Revision = number;

// ---------------------------------------------------------------------------------
// Profiles and security settings (SECURITY-PROFILES.md, TGL-01 to TGL-07)

export type Profile = S["Profile"];
export const PROFILES: readonly Profile[] = ["home", "standard", "hardened", "lab"];

export type PasswordPolicy = S["PasswordPolicy"];
export type MfaRequirement = S["MfaRequirement"];
export type BreachMode = S["BreachMode"];
export type LockoutMode = S["LockoutMode"];
export type SessionLifetime = S["SessionLifetime"];
export type SecuritySettings = S["SecuritySettings"];
/** One toggle with its markers. `value` and `profile_default` are JSON values. */
export type ToggleState = Omit<S["ToggleState"], "value" | "profile_default"> & {
  value: unknown;
  profile_default: unknown;
};
export type Banner = S["Banner"];
export type SecuritySettingsView = Omit<S["SecuritySettingsView"], "toggles"> & { toggles: ToggleState[] };
export type TokenMaxLifetime = S["TokenMaxLifetime"];
export type SettingsPatch = S["SettingsPatch"];

// ---------------------------------------------------------------------------------
// Sessions and sign-in

export type RoleName = S["RoleName"];
export type AuthStrength = S["AuthStrength"];
export type UserSummary = S["UserSummary"];
export type SessionFlags = S["SessionFlags"];
export type SessionInfo = S["SessionInfo"];
export type SecondFactorMethod = S["SecondFactorMethod"];
export type LoginResponse = S["LoginResponse"];
export type PasswordLogin = S["PasswordLogin"];
export type CodeLogin = S["CodeLogin"];
export type WebAuthnLoginStart = S["WebAuthnLoginStart"];
/** `PublicKeyCredentialRequestOptionsJSON`. */
export type RequestOptionsJSON = S["RequestOptions"];
/** `PublicKeyCredentialCreationOptionsJSON`. */
export type CreationOptionsJSON = S["CreationOptions"];
export type WebAuthnLoginOptions = S["WebAuthnLoginOptions"];
export type WebAuthnRegisterOptions = S["WebAuthnRegisterOptions"];
/** `AuthenticationResponseJSON`. */
export type AuthenticationResponseJSON = S["AuthenticationResponse"];
/** `RegistrationResponseJSON`. */
export type RegistrationResponseJSON = S["RegistrationResponse"];
export type SessionSummary = S["SessionSummary"];

// ---------------------------------------------------------------------------------
// Factors and tokens

export type PolicyViolation = S["PolicyViolation"];
export type BreachStatus = S["BreachStatus"];
export type PasswordCheck = S["PasswordCheck"];
export type PasswordCheckResult = S["PasswordCheckResult"];
export type PasswordChange = S["PasswordChange"];
export type TotpEnrolment = S["TotpEnrolment"];
export type FactorEnrolled = S["FactorEnrolled"];
export type AttestationKind = S["AttestationKind"];
export type CredentialInfo = S["CredentialInfo"];
export type RecoveryCodes = S["RecoveryCodes"];
export type TokenCreate = S["TokenCreate"];
export type TokenInfo = S["TokenInfo"];
export type CreatedToken = S["CreatedToken"];

// ---------------------------------------------------------------------------------
// Users and roles

export type FactorSummary = S["FactorSummary"];
export type AccountLock = S["AccountLock"];
export type UserInfo = S["UserInfo"];
export type UserCreate = S["UserCreate"];
export type UserUpdate = S["UserUpdate"];
export type RoleInfo = S["RoleInfo"];

// ---------------------------------------------------------------------------------
// First-run setup (API-10)

export type ProfileInfo = S["ProfileInfo"];
export type TlsMode = S["TlsMode"];

/** Proposed: what the node found about itself, for the wizard. */
export interface NodeFacts {
  name: string;
  os?: string | null;
  cores?: number | null;
  memory_bytes?: number | null;
  addresses?: string[];
  data_dir?: DataDirFacts | null;
  networks?: NetworkFacts[];
  roles?: NodeRole[];
}

export type NodeRole = "controller" | "dns" | "dhcp" | "probe";
export const NODE_ROLES: readonly NodeRole[] = ["controller", "dns", "dhcp", "probe"];

/** Proposed: the data directory and the disk behind it (OPS-19). */
export interface DataDirFacts {
  path: string;
  device?: string | null;
  /** `nvme`, `ssd`, `hdd`, `smr` or `unknown`. */
  media: "nvme" | "ssd" | "hdd" | "smr" | "unknown";
  free_bytes?: number | null;
  /** Median durable commit latency from the start-up probe. */
  fsync_p50_micros?: number | null;
}

/** Proposed: a network this node is attached to, for the probe. */
export interface NetworkFacts {
  id: string;
  name: string;
  prefix: string;
  vlan?: number | null;
  interface: string;
  address: string;
}

/** GET /setup, with the proposed node facts. */
export type SetupState = S["SetupState"] & { node?: NodeFacts | null };

/** Proposed: TLS choice of the wizard. */
export interface SetupTls {
  mode: TlsMode;
  /** reverse_proxy: addresses or prefixes allowed to send forwarded headers. */
  trusted_proxies?: string[];
}

/**
 * POST /setup: the document's request plus the wizard's proposed extras. The server
 * ignores members it does not know, so the extras are safe to send ahead of the backend.
 */
export type SetupRequest = S["SetupRequest"] & {
  tls?: SetupTls;
  /** The operator accepted an unsupported data disk (rotating or SMR). */
  accept_slow_disk?: boolean;
  roles?: NodeRole[];
  /** Networks the probe listens on (NetworkFacts.id). */
  probe_networks?: string[];
};

/** POST /setup answers with the new session; a CA fingerprint is a proposed extra. */
export type SetupResult = SessionInfo & { ca_fingerprint?: string | null };

// ---------------------------------------------------------------------------------
// System status, jobs and search (shell)

export type SystemStatus = S["SystemStatus"];
export type JobState = S["JobState"];
export type JobSummary = S["JobSummary"];
export type SearchHit = S["SearchHit"];
export type ObjectRef = S["ObjectRef"];

export interface Page<T> {
  items: T[];
  next_cursor?: string | null;
  revision: Revision;
}
