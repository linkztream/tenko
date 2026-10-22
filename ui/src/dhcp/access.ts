// Display gating of the DHCP area (docs/dhcp-contracts.md): `dhcp.read` for every role that reads
// the inventory, `dhcp.write` for operators and administrators. The server still decides every
// request; grants on a prefix reach its scope, the server-wide objects need a global role.
import { hasRole } from "../auth/session";

/** Whether the session may create, change and delete DHCP configuration. */
export function mayWriteDhcp(): boolean {
  return hasRole("admin") || hasRole("operator");
}
