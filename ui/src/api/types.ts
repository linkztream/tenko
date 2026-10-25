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
export type SystemDiagnostics = S["SystemDiagnostics"];
export type JobState = S["JobState"];
export type JobSummary = S["JobSummary"];
export type SearchHit = S["SearchHit"];
export type ObjectRef = S["ObjectRef"];
export type ObjectKind = S["ObjectKind"];
export type Principal = S["Principal"];
export type Stamp = S["Stamp"];

// ---------------------------------------------------------------------------------
// IPAM (IPAM-01 to IPAM-23)

export type Status = S["Status"];
export const STATUSES: readonly Status[] = ["planned", "active", "reserved", "deprecated"];
export type Deleted = S["Deleted"];
export type SortOrder = S["SortOrder"];
export type Meta = S["Meta"];
export type Tag = S["Tag"];
export type TagCount = S["TagCount"];
export type CustomValue = S["CustomValue"];
export type CustomKind = S["CustomKind"];
export type CustomFieldDef = S["CustomFieldDef"];
export type CustomFieldInput = S["CustomFieldInput"];
export type CustomFieldPatch = S["CustomFieldPatch"];
export type Tenant = S["Tenant"];
export type TenantInput = S["TenantInput"];
export type TenantPatch = S["TenantPatch"];
export type Vrf = S["Vrf"];
export type VrfInput = S["VrfInput"];
export type VrfPatch = S["VrfPatch"];
export type Site = S["Site"];
export type SiteInput = S["SiteInput"];
export type SitePatch = S["SitePatch"];
export type Vlan = S["Vlan"];
export type VlanInput = S["VlanInput"];
export type VlanPatch = S["VlanPatch"];
export type Prefix = S["Prefix"];
export type PrefixInput = S["PrefixInput"];
export type PrefixPatch = S["PrefixPatch"];
export type PrefixRole = S["PrefixRole"];
export type AllocPolicy = S["AllocPolicy"];
export type UtilizationView = S["UtilizationView"];
export type UtilizationAlarm = S["UtilizationAlarm"];
export type AlarmLevel = S["AlarmLevel"];
export type RoleUsage = S["RoleUsage"];
export type TreeNode = S["TreeNode"];
export type TreeResponse = S["TreeResponse"];
export type PrefixAddressItem = S["PrefixAddressItem"];
export type Range = S["Range"];
export type RangeRole = S["RangeRole"];
export const RANGE_ROLES: readonly RangeRole[] = ["dhcp_pool", "dhcp_pd_pool", "reserved", "infrastructure"];
export type NewRange = S["NewRange"];
export type RangePatch = S["RangePatch"];
export type Address = S["Address"];
/** An address of a list; with `expand=host` it also carries its interface and host. */
export type AddressRow = S["AddressRow"];
export type HostSummary = S["HostSummary"];
export type InterfaceSummary = S["InterfaceSummary"];
export type AddressInput = S["AddressInput"];
export type AddressPatch = S["AddressPatch"];
export type AssignmentMode = S["AssignmentMode"];
export const ASSIGNMENT_MODES: readonly AssignmentMode[] = ["reserved", "static", "dynamic", "unmanaged"];
export type Host = S["Host"];
export type Decommission = S["Decommission"];
export type ReleasedAddress = S["ReleasedAddress"];
/** The `lifecycle` filter of the host list. */
export type HostLifecycle = "active" | "decommissioned" | "all";
export type HostInput = S["HostInput"];
export type HostPatch = S["HostPatch"];
export type Interface = S["Interface"];
export type InterfaceInput = S["InterfaceInput"];
export type InterfacePatch = S["InterfacePatch"];
export type NextFreeAddress = S["NextFreeAddress"];
export type NextFreePrefix = S["NextFreePrefix"];
export type IpamObject = S["IpamObject"];
export type IpamCommand = S["IpamCommand"];
export type BulkRequest = S["BulkRequest"];
export type BulkResponse = S["BulkResponse"];
export type PlanView = S["PlanView"];
export type PlanSummary = S["PlanSummary"];
export type PlanWarning = S["PlanWarning"];
export type PlannedChange = S["PlannedChange"];
export type ChangeAction = S["ChangeAction"];
export type FieldChange = S["FieldChange"];
export type SummaryCount = S["SummaryCount"];
export type HistoryEntry = S["HistoryEntry"];

/** The answer of every IPAM write (`WriteResponse_<Kind>` in the document). */
export interface WriteResponse<T> {
  dry_run: boolean;
  item?: T | null;
  job_id?: string | null;
  plan?: PlanView | null;
  replayed: boolean;
  revision?: number | null;
  warnings: PlanWarning[];
}

// ---------------------------------------------------------------------------------
// Jobs (IPAM-17) and audit (IAM-18)

export type Job = S["Job"];
export type JobDetail = S["JobDetail"];
export type JobPreview = S["JobPreview"];
export type StepRecord = S["StepRecord"];
export type StepState = S["StepState"];
export type StepStateKind = S["StepStateKind"];
export type StepPreview = S["StepPreview"];
export type ManualTask = S["ManualTask"];
export type Transition = S["Transition"];
export type CodedError = S["CodedError"];
export type CompleteStepRequest = S["CompleteStepRequest"];
export const JOB_STATES: readonly JobState[] = [
  "queued",
  "running",
  "waiting",
  "rolling_back",
  "succeeded",
  "failed",
  "rolled_back",
  "cancelled",
];
export type AuditRecord = S["AuditRecord"];
export type AuditDraft = S["AuditDraft"];
export type AuditOutcome = S["AuditOutcome"];
export type AuditVerifyReport = S["AuditVerifyReport"];
export type EventData = S["EventData"];

export interface Page<T> {
  items: T[];
  next_cursor?: string | null;
  revision: Revision;
}
