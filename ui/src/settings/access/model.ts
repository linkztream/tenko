// The access area (IAM-01, IAM-06, IAM-10; docs/access.md): grants, service accounts, scoped
// tokens and the MFA policy per role, on the generated types of the API document. Pure apart
// from `t`: the words of a role, a policy and a scope rule, the order the page lists them in,
// and the names a scope rule shows with.
import type { components } from "../../api/generated/schema";
import { t } from "../../i18n";

type S = components["schemas"];

export type GrantView = S["GrantView"];
export type GrantCreate = S["GrantCreate"];
export type GrantsRevoked = S["GrantsRevoked"];
export type GrantSubject = S["GrantSubject"];
export type RolePolicyView = S["RolePolicyView"];
export type RoleMfa = S["RoleMfa"];
export type ServiceAccountCreate = S["ServiceAccountCreate"];
export type TokenGrant = S["TokenGrant"];
export type TokenScope = S["TokenScope"];
export type TokenCreate = S["TokenCreate"];
export type ScopeRule = S["ScopeRule"];
export type RoleName = S["RoleName"];
export type UserInfo = S["UserInfo"];
export type TokenInfo = S["TokenInfo"];

/** Every role, from the most to the least powerful, then the auditor (docs/access.md section 2). */
export const ROLES: readonly RoleName[] = ["admin", "operator", "viewer", "auditor"];
/** The roles a grant or a scoped token grant over a scope can carry. */
export const GRANTABLE_ROLES: readonly RoleName[] = ["operator", "viewer"];
/** The MFA requirements from the weakest to the strongest. */
export const MFA_LEVELS: readonly RoleMfa[] = ["optional", "totp_or_stronger", "passkey"];
/** The special scopes of a scoped token. */
export const TOKEN_SCOPES: readonly TokenScope[] = ["metrics", "audit:read"];
/** The rule kinds a grant can name in Phase 1. */
export type GrantableKind = "vrf" | "site" | "prefix";
export const GRANTABLE_KINDS: readonly GrantableKind[] = ["vrf", "site", "prefix"];

/** The name of a role: "Administrator", "Operator", "Viewer", "Auditor". */
export function roleName(role: RoleName): string {
  return t(`access.role.${role}`);
}

/** What a role may do, in one sentence. */
export function roleDescription(role: RoleName): string {
  return t(`access.role.${role}_description`);
}

/** Whether a role can only be held globally (admin and auditor). */
export function globalOnly(role: RoleName): boolean {
  return role === "admin" || role === "auditor";
}

/** The words of an MFA requirement. */
export function mfaText(mfa: RoleMfa): string {
  return t(`access.mfa.${mfa}`);
}

/** The words of a special token scope. */
export function tokenScopeText(scope: TokenScope): string {
  return scope === "metrics" ? t("access.token_scope.metrics") : t("access.token_scope.audit_read");
}

/** Where the names of the objects a scope rule names come from. */
export interface ScopeNames {
  vrf: (id: string) => string | undefined;
  site: (id: string) => string | undefined;
  prefix: (id: string) => string | undefined;
}

/** No names known: rules show their identifiers. */
export const NO_NAMES: ScopeNames = { vrf: () => undefined, site: () => undefined, prefix: () => undefined };

/** The id a rule names; tenant and object rules too, although they are not granted. */
export function ruleId(rule: ScopeRule): string {
  switch (rule.kind) {
    case "tenant":
    case "vrf":
      return rule.value;
    case "site":
    case "prefix":
      return rule.value.id;
    case "object":
      return rule.value.id;
  }
}

/** Whether a site or prefix rule includes what lies below it. */
export function ruleSubtree(rule: ScopeRule): boolean {
  return (rule.kind === "site" || rule.kind === "prefix") && rule.value.subtree;
}

/** A stable key of a rule, to compare and deduplicate rules. */
export function ruleKey(rule: ScopeRule): string {
  return `${rule.kind}:${ruleId(rule)}:${ruleSubtree(rule) ? "subtree" : "own"}`;
}

/**
 * A scope rule in words: "Prefix 203.0.113.0/24 and everything inside it", "Site Garage only",
 * "VRF default". An object whose name is not known shows its identifier.
 */
export function scopeText(rule: ScopeRule | null | undefined, names: ScopeNames = NO_NAMES): string {
  if (!rule) return t("access.scope.everything");
  const id = ruleId(rule);
  switch (rule.kind) {
    case "vrf":
      return t("access.scope.vrf", { name: names.vrf(id) ?? id });
    case "site":
      return rule.value.subtree
        ? t("access.scope.site_subtree", { name: names.site(id) ?? id })
        : t("access.scope.site", { name: names.site(id) ?? id });
    case "prefix":
      return rule.value.subtree
        ? t("access.scope.prefix_subtree", { cidr: names.prefix(id) ?? id })
        : t("access.scope.prefix", { cidr: names.prefix(id) ?? id });
    case "tenant":
      return t("access.scope.tenant", { id });
    case "object":
      return t("access.scope.object", { kind: rule.value.kind, id });
  }
}

/** Builds a rule of a grantable kind. */
export function makeRule(kind: GrantableKind, id: string, subtree: boolean): ScopeRule {
  switch (kind) {
    case "vrf":
      return { kind: "vrf", value: id };
    case "site":
      return { kind: "site", value: { id, subtree } };
    case "prefix":
      return { kind: "prefix", value: { id, subtree } };
  }
}

/** A grant in words: "Operator over prefix 203.0.113.0/24 and everything inside it". */
export function grantText(grant: { role: RoleName; scope?: ScopeRule | null | undefined }, names: ScopeNames = NO_NAMES): string {
  return t("access.grant.text", { role: roleName(grant.role), scope: scopeText(grant.scope, names) });
}

/** Grants in the order of the page: by holder name, then oldest first (as the server lists them). */
export function sortGrants(grants: readonly GrantView[]): GrantView[] {
  return [...grants].sort(
    (a, b) => a.subject.name.localeCompare(b.subject.name) || a.granted_at.localeCompare(b.granted_at) || a.id.localeCompare(b.id),
  );
}

/** Whether a user record is a service account (IAM-10). */
export function isServiceAccount(user: Pick<UserInfo, "kind">): boolean {
  return user.kind === "service";
}

/**
 * A valid service account name: 1 to 64 characters without spaces or control characters (the
 * server checks it too and shares the name space with users).
 */
export function validAccountName(name: string): boolean {
  // eslint-disable-next-line no-control-regex -- control characters are what the rule refuses
  return name.length >= 1 && [...name].length <= 64 && !/[\s\u0000-\u001f\u007f]/.test(name);
}

/**
 * A scoped token's body from the dialog's rows: the grants (a role over the whole installation
 * or over a rule) and the special scopes. A token needs at least one of either.
 */
export function scopedTokenBody(
  name: string,
  days: number | null,
  grants: readonly TokenGrant[],
  scopes: readonly TokenScope[],
): TokenCreate {
  return {
    name,
    expires_in_days: days,
    grants: grants.map((g) => (g.scope ? { role: g.role, scope: g.scope } : { role: g.role })),
    scopes: [...scopes],
  };
}

/** What a scoped token may do, in words: its grants and scopes; a personal token says so. */
export function tokenReach(token: Pick<TokenInfo, "scoped" | "grants" | "scopes">, names: ScopeNames = NO_NAMES): string[] {
  if (!token.scoped) return [t("access.token.personal")];
  return [...(token.grants ?? []).map((g) => grantText(g, names)), ...(token.scopes ?? []).map(tokenScopeText)];
}
