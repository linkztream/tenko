// Who may do what in the discovery area (docs/reconciliation.md, section 9.2): everyone signed
// in reads proposals and observations; administrators and operators decide proposals and run
// the reconciler. The server checks again; this only hides what would be refused.
import { hasRole, isAdmin } from "../auth/session";

export const isDecider = (): boolean => isAdmin() || hasRole("operator");
