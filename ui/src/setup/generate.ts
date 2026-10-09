// Generated passwords for the first administrator. Everything draws from
// `crypto.getRandomValues` with rejection sampling, so no character is likelier than another.
// The result never contains the words in `avoid` (the user name, the host name, the product).
import type { PasswordPolicy } from "../api/types";
import { WORDS } from "./words";

/** Letters and digits without the look-alikes 0 O 1 l I. */
export const UNAMBIGUOUS_ALPHABET = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";

export type GeneratorKind = "pin" | "password" | "passphrase";

/** Which generator belongs to a password policy preset. */
export function generatorFor(policy: PasswordPolicy | undefined): GeneratorKind {
  switch (policy?.preset) {
    case "pin":
      return "pin";
    case "hardened":
      return "passphrase";
    default:
      return "password";
  }
}

/** A uniformly random integer in [0, max). */
export type RandomInt = (max: number) => number;

/** Uniform integers from the platform's random source (rejection sampling, no modulo bias). */
export const secureRandomInt: RandomInt = (max) => {
  if (!Number.isInteger(max) || max < 1 || max > 0x1_0000_0000) throw new RangeError("max out of range");
  const buffer = new Uint32Array(1);
  const limit = 0x1_0000_0000 - (0x1_0000_0000 % max);
  for (;;) {
    crypto.getRandomValues(buffer);
    const value = buffer[0] ?? 0;
    if (value < limit) return value % max;
  }
};

export const PIN_DIGITS = 8;
export const PASSWORD_LENGTH = 16;
export const PASSPHRASE_WORDS = 4;

export interface GenerateOptions {
  /** Substrings the result must not contain, compared without case. */
  avoid?: readonly string[];
  random?: RandomInt;
  /** The length of a generated password (at least the policy minimum). */
  length?: number;
}

function draw(source: string, count: number, random: RandomInt): string {
  let out = "";
  for (let i = 0; i < count; i += 1) out += source.charAt(random(source.length));
  return out;
}

/** Repeated or sequential digits such as 00000000 or 12345678. */
export function isTrivialDigits(digits: string): boolean {
  if (digits.length < 2) return true;
  const values = Array.from(digits, Number);
  const step = (values[1] ?? 0) - (values[0] ?? 0);
  const arithmetic = values.every((v, i) => i === 0 || v - (values[i - 1] ?? 0) === step);
  return arithmetic && (step === 0 || step === 1 || step === -1);
}

function candidate(kind: GeneratorKind, random: RandomInt, length: number): string {
  switch (kind) {
    case "pin":
      return draw("0123456789", PIN_DIGITS, random);
    case "password":
      return draw(UNAMBIGUOUS_ALPHABET, length, random);
    case "passphrase": {
      const words: string[] = [];
      for (let i = 0; i < PASSPHRASE_WORDS; i += 1) words.push(WORDS[random(WORDS.length)] ?? "");
      return words.join("-");
    }
  }
}

const MAX_TRIES = 200;

/**
 * A new password for the preset. A PIN is 8 digits, a password 16 characters from an
 * unambiguous alphabet, a passphrase four words joined by dashes.
 */
export function generatePassword(kind: GeneratorKind, options: GenerateOptions = {}): string {
  const random = options.random ?? secureRandomInt;
  const length = Math.max(options.length ?? PASSWORD_LENGTH, 12);
  const avoid = (options.avoid ?? []).map((a) => a.trim().toLowerCase()).filter((a) => a.length > 0);
  let out = "";
  for (let tries = 0; tries < MAX_TRIES; tries += 1) {
    out = candidate(kind, random, length);
    const folded = out.toLowerCase();
    if (kind === "pin" && isTrivialDigits(out)) continue;
    if (avoid.some((a) => folded.includes(a))) continue;
    return out;
  }
  return out;
}
