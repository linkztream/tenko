// Small helpers of the mock: random values, encodings and times. The values are random so
// that two runs differ, but they are test values only and protect nothing.

export function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
}

/** Base64url without padding. */
export function b64url(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** `length` random base64url characters. */
export function randomToken(length: number): string {
  return b64url(randomBytes(Math.ceil((length * 3) / 4))).slice(0, length);
}

export function randomHex(bytes: number): string {
  return Array.from(randomBytes(bytes), (b) => b.toString(16).padStart(2, "0")).join("");
}

const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/** RFC 4648 base32 without padding. */
export function base32(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32[(value << (5 - bits)) & 31];
  return out;
}

export function randomId(): string {
  const c = globalThis.crypto;
  if (typeof c.randomUUID === "function") return c.randomUUID();
  const b = randomBytes(16);
  b[6] = ((b[6] ?? 0) & 0x0f) | 0x40;
  b[8] = ((b[8] ?? 0) & 0x3f) | 0x80;
  const hex = Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export function isUuid(text: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(text);
}

/** The 16 bytes of a UUID, base64url (the WebAuthn user handle). */
export function uuidHandle(uuid: string): string {
  const hex = uuid.replace(/-/g, "");
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 16; i += 1) bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16) || 0;
  return b64url(bytes);
}

const CODE_ALPHABET = "ABCDEFGHJKMNPQRSTVWXYZ23456789";

/** A recovery code such as `K7QM-4XD2`. */
export function recoveryCode(): string {
  const pick = () => CODE_ALPHABET[(randomBytes(1)[0] ?? 0) % CODE_ALPHABET.length] ?? "A";
  const group = () => Array.from({ length: 4 }, pick).join("");
  return `${group()}-${group()}`;
}

export function recoveryCodes(count = 10): string[] {
  const codes = new Set<string>();
  while (codes.size < count) codes.add(recoveryCode());
  return [...codes];
}

/** Recovery codes compare without dashes, spaces and case. */
export function normalizeCode(code: string): string {
  return code.replace(/[\s-]/g, "").toUpperCase();
}

export function iso(ms: number): string {
  return new Date(ms).toISOString();
}

export const MINUTE = 60_000;
export const HOUR_MS = 3_600_000;
export const DAY_MS = 86_400_000;
