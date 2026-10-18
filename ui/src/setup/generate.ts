// What the wizard generates. Passwords for the first administrator: everything draws from
// `crypto.getRandomValues` with rejection sampling, so no character is likelier than another, and
// the result never contains the words in `avoid` (the user name, the host name, the product).
// And the `[dns]` section of `tenko.toml` from the DNS step (`generateDnsConfig`).
import type { PasswordPolicy } from "../api/types";
import type { ForwardTransport, Upstream } from "../dns/forwarders/model";
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

// ---------------------------------------------------------------------------------
// The [dns] section of tenko.toml (P2-Q5)

/** What the DNS step chose: the upstreams as typed, their transport, and the Home preset's switches. */
export interface DnsChoice {
  upstreams: readonly Upstream[];
  transport: ForwardTransport;
  tlsName: string | null;
  cache: boolean;
  /** Cache entries at most; null keeps the profile's bound. */
  cacheEntries: number | null;
  dot: boolean;
  doh: boolean;
  log: boolean;
}

/** The transport word of the configuration file: `udp` for plain, as `[dns] forwarders` reads it. */
const FILE_TRANSPORT: Readonly<Record<ForwardTransport, string>> = { plain: "udp", dot: "dot", doh: "doh" };

function tomlString(text: string): string {
  return JSON.stringify(text);
}

function forwarderEntry(u: Upstream, choice: DnsChoice): string {
  const parts = [`address = ${tomlString(u.address)}`];
  if (u.port) parts.push(`port = ${u.port}`);
  if (choice.transport !== "plain") parts.push(`transport = ${tomlString(FILE_TRANSPORT[choice.transport])}`);
  if (choice.tlsName && choice.transport !== "plain") parts.push(`tls_name = ${tomlString(choice.tlsName)}`);
  if (u.path) parts.push(`path = ${tomlString(u.path)}`);
  return `  { ${parts.join(", ")} },`;
}

/**
 * The `[dns]`, `[dns.cache]`, `[dns.tls]` and `[dns.log]` keys of the choice, for `tenko.toml`
 * (deploy/tenko.example.toml). The forwarders of the file apply only while no root rule of
 * the store covers a name; the wizard also stores them as that rule. Comments are part of the
 * file, so they are English like the example file.
 */
export function generateDnsConfig(choice: DnsChoice): string {
  const lines = ["[dns]", "# The default forwarder while no root rule of the store covers a name (P2-Q5: chosen in setup)."];
  if (choice.upstreams.length === 0) lines.push("forwarders = []");
  else lines.push("forwarders = [", ...choice.upstreams.map((u) => forwarderEntry(u, choice)), "]");
  lines.push("", "[dns.cache]", `enabled = ${choice.cache}`);
  if (choice.cacheEntries !== null) lines.push(`entries = ${choice.cacheEntries}`);
  lines.push("", "[dns.tls]", `dot = ${choice.dot}`, `doh = ${choice.doh}`, "", "[dns.log]", `enabled = ${choice.log}`, "");
  return lines.join("\n");
}
