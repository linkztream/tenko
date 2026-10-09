/**
 * Remote access hand-off from the host view (API-11): an `.rdp` file or an `ssh://` URI with
 * the host, the port and the user. Pure functions, plus `saveTextFile`, the one DOM helper.
 */

const DEFAULT_RDP_PORT = 3389;
const DEFAULT_SSH_PORT = 22;
const MAX_FILE_NAME_BASE = 64;
const REPLACEMENT_CHARACTER = String.fromCharCode(0xfffd);
const FALLBACK_FILE_NAME_BASE = "host";

/** The media type of an `.rdp` file, for `saveTextFile`. */
export const RDP_MIME = "application/x-rdp";

export interface RdpOptions {
  /** Host name or IP address; an IPv6 address may be given with or without brackets. */
  address: string;
  /** TCP port, 1 to 65535 (default 3389). */
  port?: number;
  username?: string | null;
}

export interface SshOptions {
  /** Host name or IP address; an IPv6 address may be given with or without brackets. */
  host: string;
  /** TCP port, 1 to 65535 (default 22, which the URI leaves out). */
  port?: number;
  user?: string | null;
}

/** Whether a port number is valid (an integer from 1 to 65535). */
export function isValidPort(port: number): boolean {
  return Number.isInteger(port) && port >= 1 && port <= 65535;
}

/**
 * Removes control characters (CR and LF among them) and the Unicode line and paragraph
 * separators, so a value can never end its line in an `.rdp` file and start another setting.
 */
function singleLine(value: string): string {
  return value.replace(/[\p{Cc}\p{Zl}\p{Zp}]/gu, "");
}

/** The host without surrounding brackets and whitespace, as a single line. */
function bareHost(host: string): string {
  const text = singleLine(host).trim();
  return text.startsWith("[") && text.endsWith("]") ? text.slice(1, -1).trim() : text;
}

/** A valid IPv6 literal has at least two colons; "host:port" has one. */
function isIpv6Literal(host: string): boolean {
  let colons = 0;
  for (const ch of host) if (ch === ":") colons++;
  return colons >= 2;
}

/** The part of a host that goes before ":port": an IPv6 literal in brackets. */
function rdpHost(host: string): string {
  return isIpv6Literal(host) ? `[${host}]` : host;
}

/** `encodeURIComponent` that tolerates lone surrogates (they become U+FFFD). */
function encodeComponent(value: string): string {
  return encodeURIComponent(value.replace(/\p{Cs}/gu, REPLACEMENT_CHARACTER));
}

const IPV6_WITH_ZONE = /^([0-9A-Fa-f:.]+)(?:%(.+))?$/;

/** The host of an `ssh://` URI: an IPv6 literal in brackets (RFC 6874 zone), else a reg-name. */
function uriHost(host: string): string {
  if (isIpv6Literal(host)) {
    const match = IPV6_WITH_ZONE.exec(host);
    if (match) {
      const zone = match[2];
      return `[${match[1]}${zone === undefined ? "" : `%25${encodeComponent(zone)}`}]`;
    }
  }
  return encodeComponent(host);
}

/**
 * The text of a `.rdp` file: CRLF line ends, ending with CRLF. The address always carries the
 * port (default 3389) and an IPv6 literal is bracketed (`[2001:db8::10]:3389`). The user name
 * is written only when given. Control characters are removed from the values, so a value
 * cannot inject another setting. Throws a `RangeError` for an invalid port or an empty address.
 */
export function rdpFile(options: RdpOptions): string {
  const port = options.port ?? DEFAULT_RDP_PORT;
  if (!isValidPort(port)) throw new RangeError(`Invalid RDP port: ${String(port)}`);
  const host = bareHost(options.address);
  if (host === "") throw new RangeError("The RDP address is empty");
  const username = singleLine(options.username ?? "").trim();

  const lines = [`full address:s:${rdpHost(host)}:${port}`];
  if (username !== "") lines.push(`username:s:${username}`);
  lines.push("prompt for credentials:i:1", "administrative session:i:0", "screen mode id:i:2", "authentication level:i:2");
  return `${lines.join("\r\n")}\r\n`;
}

/**
 * A safe file name for the `.rdp` file of a host: every character outside `[A-Za-z0-9._-]`
 * becomes "_", at most 64 characters, plus ".rdp"; "host.rdp" when nothing is left.
 */
export function rdpFileName(hostName: string): string {
  const base = hostName.replace(/[^A-Za-z0-9._-]/g, "_").slice(0, MAX_FILE_NAME_BASE);
  return `${base === "" ? FALLBACK_FILE_NAME_BASE : base}.rdp`;
}

/**
 * `ssh://[user@]host[:port]`: the user percent-encoded as RFC 3986 userinfo, an IPv6 literal
 * in brackets, the port only when it is not 22. Throws a `RangeError` for an invalid port or
 * an empty host.
 */
export function sshUri(options: SshOptions): string {
  const port = options.port ?? DEFAULT_SSH_PORT;
  if (!isValidPort(port)) throw new RangeError(`Invalid SSH port: ${String(port)}`);
  const host = bareHost(options.host);
  if (host === "") throw new RangeError("The SSH host is empty");
  const user = singleLine(options.user ?? "").trim();

  const userinfo = user === "" ? "" : `${encodeComponent(user)}@`;
  const suffix = port === DEFAULT_SSH_PORT ? "" : `:${port}`;
  return `ssh://${userinfo}${uriHost(host)}${suffix}`;
}

/**
 * Offers `text` as a file download: a Blob behind an object URL and a temporary `<a download>`
 * that is clicked and removed again; the URL is revoked afterwards.
 */
export function saveTextFile(fileName: string, text: string, mime = "text/plain;charset=utf-8"): void {
  const url = URL.createObjectURL(new Blob([text], { type: mime }));
  const a = document.createElement("a");
  a.href = url;
  a.download = fileName;
  document.body.appendChild(a);
  try {
    a.click();
  } finally {
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 0);
  }
}
