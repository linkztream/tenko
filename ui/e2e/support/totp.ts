// Time-based one-time passwords (RFC 6238) over HOTP (RFC 4226) for the sign-in tests: the
// codes an authenticator app would show for the secret the enrolment displays. SHA-1, six
// digits and 30-second steps are the parameters Tenko enrols with; the others are accepted
// for completeness.

import { createHmac } from "node:crypto";

export interface TotpOptions {
  digits?: number;
  period?: number;
  algorithm?: "sha1" | "sha256" | "sha512";
}

const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/** Decodes RFC 4648 base32, ignoring spaces, case and padding. */
export function base32Decode(text: string): Buffer {
  const clean = text.replace(/[\s=]/g, "").toUpperCase();
  const bytes: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const char of clean) {
    const value = BASE32.indexOf(char);
    if (value < 0) throw new Error(`not a base32 character: ${char}`);
    buffer = (buffer << 5) | value;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((buffer >> bits) & 0xff);
    }
  }
  return Buffer.from(bytes);
}

/** The HOTP value of `counter` (RFC 4226, section 5.3). */
export function hotp(key: Buffer, counter: number, digits = 6, algorithm: TotpOptions["algorithm"] = "sha1"): string {
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(counter));
  const mac = createHmac(algorithm, key).update(message).digest();
  const offset = (mac[mac.length - 1] ?? 0) & 0x0f;
  const binary = mac.readUInt32BE(offset) & 0x7fffffff;
  return String(binary % 10 ** digits).padStart(digits, "0");
}

/** The time step of a moment (seconds since the epoch). */
export function totpStep(unixSeconds: number, period = 30): number {
  return Math.floor(unixSeconds / period);
}

/** The TOTP code of a base32 secret for a time step (RFC 6238). */
export function totpAt(secret: string, step: number, options: TotpOptions = {}): string {
  return hotp(base32Decode(secret), step, options.digits ?? 6, options.algorithm ?? "sha1");
}

/**
 * An authenticator for one secret that never hands out a code of a step it already used:
 * the server refuses a replayed step, and a test may need two codes within 30 seconds
 * (enrolment, then sign-in). The server accepts one step of clock skew, so the next step
 * is used when the current one is spent.
 */
export class Authenticator {
  private lastStep = -1;

  constructor(
    readonly secret: string,
    private readonly options: TotpOptions = {},
  ) {}

  /** A fresh code: the current step, or the next one when the current one was used. */
  code(now: number = Date.now()): string {
    const current = totpStep(now / 1000, this.options.period ?? 30);
    const step = Math.max(current, this.lastStep + 1);
    if (step > current + 1) {
      throw new Error("no unused TOTP step within the allowed skew; wait for the next period");
    }
    this.lastStep = step;
    return totpAt(this.secret, step, this.options);
  }
}
