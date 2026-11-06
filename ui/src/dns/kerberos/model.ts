// The rules of the Kerberos wizard and status (identity plan sections 3.1, 3.10 and 3.18): the
// realm, the account name and the SPNs as the server takes them, the values an administrator
// types into the static PowerShell block of docs/active-directory.md section 4.1 (shown as
// text, never as code: the block takes nothing Tenko wrote, R130), the keytab file in
// base64url, and the finding codes of the self-test with their parameters.

/** The finding codes of the self-test, in the order the status lists them. */
export const FINDING_CODES = [
  "dns.gss.self_test_failed",
  "dns.gss.kvno_unknown",
  "dns.gss.spn_missing",
  "dns.gss.spn_duplicate",
  "dns.gss.weak_etype",
  "dns.gss.clock_skew",
  "dns.gss.rotation_failed",
] as const;

export type FindingCode = (typeof FINDING_CODES)[number];

/** The key suffix of a finding: the code without `dns.gss.`, or `other`. */
export type FindingKey = (FindingCode extends `dns.gss.${infer K}` ? K : never) | "other";

/** The key suffix of a finding code (`dns.gss.spn_missing` is `spn_missing`); unknown codes are `other`. */
export function findingKey(code: string): FindingKey {
  const known = (FINDING_CODES as readonly string[]).includes(code);
  return (known ? code.slice("dns.gss.".length) : "other") as FindingKey;
}

/** Where the PowerShell block is: the documentation shipped with the release. */
export const POWERSHELL_SECTION = "docs/active-directory.md, section 4.1";

/** A realm as the server takes it: upper case, a DNS-style name without `@`, `/` or spaces. */
export function canonicalRealm(text: string): string {
  return text.trim().toUpperCase();
}

export function validRealm(text: string): boolean {
  const realm = canonicalRealm(text);
  return realm.length > 0 && realm.length <= 253 && /^[A-Z0-9]([A-Z0-9-]*[A-Z0-9])?(\.[A-Z0-9]([A-Z0-9-]*[A-Z0-9])?)*$/.test(realm);
}

/** The computer account's name with its `$` (`tenko-dns` becomes `TENKO-DNS$`). */
export function accountName(text: string): string {
  const name = text.trim().toUpperCase();
  return name.endsWith("$") ? name : `${name}$`;
}

/** The name the PowerShell block takes: 1 to 15 letters, digits or hyphens, without the `$`. */
export function blockName(text: string): string {
  return accountName(text).slice(0, -1);
}

export function validAccountName(text: string): boolean {
  return /^[A-Za-z0-9][A-Za-z0-9-]{0,14}$/.test(blockName(text));
}

const SPN = /^(DNS|HTTP)\/[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?)+$/;

/** The SPNs of a text, one per line, without blank lines and repeats. */
export function parseLines(text: string): string[] {
  const out: string[] = [];
  for (const line of text.split(/\r?\n/)) {
    const value = line.trim();
    if (value && !out.some((v) => v.toLowerCase() === value.toLowerCase())) out.push(value);
  }
  return out;
}

/** Whether every SPN is `DNS/<fqdn>` or `HTTP/<fqdn>`, the form the PowerShell block accepts. */
export function validSpns(spns: readonly string[]): boolean {
  return spns.length > 0 && spns.every((spn) => SPN.test(spn));
}

/** A KDC entry: `host`, `host:port`, `[address]` or `[address]:port`. */
export function validKdc(entry: string): boolean {
  return /^(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+|[0-9A-Fa-f:]+)(:[0-9]{1,5})?$/.test(entry);
}

/** The octets of a file in base64url without padding (RFC 4648 section 5), as the import takes them. */
export function base64url(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** The largest keytab the server takes (`tenko_krb::keytab::MAX_KEYTAB_LEN`). */
export const MAX_KEYTAB_BYTES = 1 << 20;
