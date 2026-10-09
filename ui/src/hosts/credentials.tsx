// EXTENSION POINT (Slice 2): the audited password copy of API-11.
//
// Secrets are not shown in Slice 1. When the vault exposes operator secrets per host
// (IAM-15, IAM-16), this component lists the host's logins and offers "Copy password":
//   1. read the secret references of the host (no values) from the vault API;
//   2. on "Copy", ask for the step-up the profile requires (IAM-07) and call the reveal
//      endpoint, which writes the audit record of the reveal;
//   3. put the value on the clipboard with navigator.clipboard.writeText, never into the
//      DOM, and clear the clipboard after a short time when the browser allows it;
//   4. show a toast that names the audit record.
// The host page already renders <CredentialSlot> in its connect section, so only this file
// changes. Until then it renders nothing.
import type { Host } from "../api/types";

export function CredentialSlot(_props: { host: Host }) {
  return null;
}
