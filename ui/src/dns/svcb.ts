// SVCB and HTTPS records (RFC 9460) in the presentation format, shared by the zone pages and the
// cache view. Pure and free of any page, so the lazy cache chunk and the zone pages both take it
// without pulling each other in.
import type { RecordData } from "./types";

export type SvcRecord = Extract<RecordData, { type: "SVCB" | "HTTPS" }>;

// SVCB and HTTPS records (RFC 9460). The API carries a parameter as its key and its value in wire
// form (hex); the presentation format of section 2.1 is `priority target key=value ...` in key
// order, the registered keys by name (section 14.3.2) and any other as `keyNNNNN`.

/** The registered keys of RFC 9460 by number. */
const SVC_KEYS: Readonly<Record<number, string>> = {
  0: "mandatory",
  1: "alpn",
  2: "no-default-alpn",
  3: "port",
  4: "ipv4hint",
  5: "ech",
  6: "ipv6hint",
};

function keyName(key: number): string {
  return SVC_KEYS[key] ?? `key${key}`;
}

/** The bytes of a hex string, or null when it is not one. */
function hexBytes(hex: string): number[] | null {
  if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) return null;
  const out: number[] = [];
  for (let i = 0; i < hex.length; i += 2) out.push(Number.parseInt(hex.slice(i, i + 2), 16));
  return out;
}

const BACKSLASH = "\\";

/** A byte string as a zone file character-string without quotes (RFC 1035 section 5.1): the
 * printable ASCII characters as they are, a backslash and a double quote with a backslash in
 * front, every other byte (the space too) as a backslash and three decimal digits. In an alpn
 * list (`list`) a comma and a backslash of an identifier are escaped for the list first and then
 * for the zone file, RFC 9460 appendix D: `\\,` and `\\\\`. */
function escapeBytes(bytes: readonly number[], list = false): string {
  let out = "";
  for (const byte of bytes) {
    const c = String.fromCharCode(byte);
    if (byte < 0x21 || byte > 0x7e) out += `${BACKSLASH}${String(byte).padStart(3, "0")}`;
    else if (list && (c === "," || c === BACKSLASH)) out += c === "," ? `${BACKSLASH}${BACKSLASH},` : BACKSLASH.repeat(4);
    else if (c === BACKSLASH || c === '"') out += `${BACKSLASH}${c}`;
    else out += c;
  }
  return out;
}

/** Sixteen bytes as an IPv6 address in the compressed form of RFC 5952 (the longest run of two or
 * more zero groups as `::`, the first on a tie). */
function ipv6(bytes: readonly number[]): string {
  const groups: number[] = [];
  for (let i = 0; i < 16; i += 2) groups.push(((bytes[i] ?? 0) << 8) | (bytes[i + 1] ?? 0));
  let start = -1;
  let length = 0;
  for (let i = 0; i < 8; ) {
    if (groups[i] !== 0) {
      i++;
      continue;
    }
    let end = i;
    while (end < 8 && groups[end] === 0) end++;
    if (end - i > length) {
      start = i;
      length = end - i;
    }
    i = end;
  }
  const hex = (list: number[]) => list.map((g) => g.toString(16)).join(":");
  if (length < 2) return hex(groups);
  return `${hex(groups.slice(0, start))}::${hex(groups.slice(start + length))}`;
}

/** The value of a registered key in presentation form ("" for a key that takes none), or null
 * when the wire form does not fit the key (a port of three bytes): the parameter is then
 * written in the generic form. */
function knownValue(key: number, bytes: readonly number[]): string | null {
  const u16 = (i: number) => ((bytes[i] ?? 0) << 8) | (bytes[i + 1] ?? 0);
  const chunks = (size: number) => Array.from({ length: bytes.length / size }, (_, n) => bytes.slice(n * size, (n + 1) * size));
  switch (key) {
    case 0:
      if (bytes.length === 0 || bytes.length % 2 !== 0) return null;
      return chunks(2)
        .map((_, n) => keyName(u16(n * 2)))
        .join(",");
    case 1: {
      // Length-prefixed identifiers, RFC 9460 section 7.1.
      const ids: string[] = [];
      for (let i = 0; i < bytes.length; ) {
        const end = i + 1 + (bytes[i] ?? 0);
        if (end > bytes.length || end === i + 1) return null;
        ids.push(escapeBytes(bytes.slice(i + 1, end), true));
        i = end;
      }
      return ids.length > 0 ? ids.join(",") : null;
    }
    case 2:
      return bytes.length === 0 ? "" : null;
    case 3:
      return bytes.length === 2 ? String(u16(0)) : null;
    case 4:
      return bytes.length > 0 && bytes.length % 4 === 0 ? chunks(4).map((a) => a.join(".")).join(",") : null;
    case 5:
      return bytes.length > 0 ? btoa(String.fromCharCode(...bytes)) : null;
    case 6:
      return bytes.length > 0 && bytes.length % 16 === 0 ? chunks(16).map(ipv6).join(",") : null;
    default:
      return null;
  }
}

/** One parameter as `key=value`, or the bare key when it has no value. */
function svcParamText(param: { key: number; value: string }): string {
  const bytes = hexBytes(param.value);
  // A value that is no hex cannot be decoded: shown as it came, never guessed at.
  if (bytes === null) return `${keyName(param.key)}=${param.value}`;
  const known = knownValue(param.key, bytes);
  if (known !== null) return known === "" ? keyName(param.key) : `${keyName(param.key)}=${known}`;
  // The generic form, `key65280=\000\001`; also for a registered key whose value does not fit.
  return bytes.length === 0 ? `key${param.key}` : `key${param.key}=${escapeBytes(bytes)}`;
}

/** An SVCB or HTTPS record in the presentation format of RFC 9460 section 2.1: the priority, the
 * target and the parameters in key order, `1 . alpn=h2,h3 ipv4hint=192.0.2.10`. An alias record
 * (priority 0) is the priority and the target. */
export function svcbText(record: SvcRecord): string {
  const params = [...record.params].sort((a, b) => a.key - b.key).map(svcParamText);
  return [String(record.priority), record.target, ...params].join(" ");
}
