// Display gating of the DNS area (docs/dns-contracts.md, section 3): `dns.read` for every role
// that reads the inventory, `dns.write` for operators and administrators, `dns.keys` (TSIG and
// DNSSEC keys) for administrators. Grants are global only for the DNS kinds in Phase 2, so the
// global roles decide; the server still decides every request.
import { hasRole, isAdmin } from "../auth/session";

/** Whether the session may create, change and delete zones, records and access lists. */
export function mayWriteDns(): boolean {
  return hasRole("admin") || hasRole("operator");
}

/** Whether the session holds `dns.keys`: the key pages are hidden without it. */
export function mayKeys(): boolean {
  return isAdmin();
}
