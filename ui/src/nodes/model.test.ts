import { beforeEach, describe, expect, it } from "vitest";
import type { CertificateRef, CreatedEnrolment } from "../api/nodes";
import { hasMessage, setLocale } from "../i18n";
import { formatBytes } from "./format";
import {
  CLUSTER_JOB_KEYS,
  DEFAULT_LIFETIME,
  LIFETIMES,
  certificateState,
  enrolCommand,
  fingerprintPairs,
  lifetimeWord,
  linkIcon,
  linkState,
  linkWord,
  roleWord,
  tokenStateWord,
  type LinkState,
} from "./model";

beforeEach(async () => {
  await setLocale("en");
});

const DAY = 86_400_000;
const NOW = Date.parse("2030-06-01T12:00:00.000Z");

/** A certificate that is valid `lifetimeDays` days and has `leftDays` days (or milliseconds) left at `NOW`. */
function certificate(lifetimeDays: number, left: { days?: number; ms?: number }): Pick<CertificateRef, "not_before" | "not_after"> {
  const end = NOW + (left.ms ?? (left.days ?? 0) * DAY);
  return { not_before: new Date(end - lifetimeDays * DAY).toISOString(), not_after: new Date(end).toISOString() };
}

describe("linkState", () => {
  const mismatch = { ours: [1], theirs: [2], at: "2030-06-01T11:00:00.000Z", version: "0.2.0" };

  it("is connected for a node that is connected", () => {
    expect(linkState({ connected: true, protocol: { offered: [1], agreed: 1, mismatch: null } })).toBe("connected");
  });

  it("is connected even when an older handshake was refused", () => {
    expect(linkState({ connected: true, protocol: { offered: [1, 2], agreed: 1, mismatch } })).toBe("connected");
  });

  it("is a refusal for a node that is not connected after a handshake that shared no protocol major", () => {
    expect(linkState({ connected: false, protocol: { offered: [2], agreed: 1, mismatch } })).toBe("mismatch");
  });

  it("is not connected for a node that is simply away", () => {
    expect(linkState({ connected: false, protocol: { offered: [1], agreed: 1, mismatch: null } })).toBe("disconnected");
    expect(linkState({ connected: false, protocol: { offered: [], agreed: null } })).toBe("disconnected");
  });

  it("has a word and a glyph of its own for each state", () => {
    const states: LinkState[] = ["connected", "mismatch", "disconnected"];
    expect(states.map(linkWord)).toEqual(["Connected", "Refused: protocol", "Not connected"]);
    expect(states.map(linkIcon)).toEqual(["check", "conflict", "pause"]);
  });
});

describe("certificateState", () => {
  it("counts whole days left", () => {
    expect(certificateState(certificate(365, { days: 200 }), NOW).daysLeft).toBe(200);
    expect(certificateState(certificate(365, { ms: 10.9 * DAY }), NOW).daysLeft).toBe(10);
    expect(certificateState(certificate(365, { ms: 59_000 }), NOW).daysLeft).toBe(0);
  });

  it("is not due while more than a third of the lifetime remains", () => {
    const state = certificateState(certificate(365, { days: 300 }), NOW);
    expect(state).toEqual({ daysLeft: 300, renewalDue: false, expired: false });
  });

  it("is due when less than a third of the lifetime remains", () => {
    const state = certificateState(certificate(365, { days: 100 }), NOW);
    expect(state).toEqual({ daysLeft: 100, renewalDue: true, expired: false });
  });

  it("is due from the instant that less than a third remains, not at it", () => {
    // 360 days: a third is exactly 120 days.
    expect(certificateState(certificate(360, { days: 120 }), NOW).renewalDue).toBe(false);
    expect(certificateState(certificate(360, { ms: 120 * DAY - 1 }), NOW).renewalDue).toBe(true);
    expect(certificateState(certificate(360, { days: 121 }), NOW).renewalDue).toBe(false);
  });

  it("is due when fewer than 30 days remain, even when that is more than a third", () => {
    // 60 days: a third is 20 days, so the rule of 30 days is the one that applies at 25.
    expect(certificateState(certificate(60, { days: 31 }), NOW).renewalDue).toBe(false);
    expect(certificateState(certificate(60, { days: 30 }), NOW).renewalDue).toBe(false);
    expect(certificateState(certificate(60, { ms: 30 * DAY - 1 }), NOW).renewalDue).toBe(true);
    expect(certificateState(certificate(60, { days: 25 }), NOW)).toEqual({ daysLeft: 25, renewalDue: true, expired: false });
  });

  it("is due and expired at the end of the validity and after it", () => {
    expect(certificateState(certificate(365, { days: 0 }), NOW)).toEqual({ daysLeft: 0, renewalDue: true, expired: true });
    const after = certificateState(certificate(365, { ms: -1 }), NOW);
    expect(after.expired).toBe(true);
    expect(after.renewalDue).toBe(true);
    expect(after.daysLeft).toBe(-1);
    expect(certificateState(certificate(365, { days: -10 }), NOW).daysLeft).toBe(-10);
  });

  it("reads the clock when no time is given", () => {
    const left = Date.now() + 300 * DAY;
    const state = certificateState({ not_before: new Date(left - 365 * DAY).toISOString(), not_after: new Date(left).toISOString() });
    expect(state.expired).toBe(false);
    expect(state.renewalDue).toBe(false);
    expect(state.daysLeft).toBeGreaterThanOrEqual(299);
  });
});

describe("enrolCommand", () => {
  const TOKEN = "tnk1.0190d1c2000070008000000f00000001.Zm9vYmFyLWV4YW1wbGUtdG9rZW4tb2YtdGhlLXRlc3RzLTEyMw";
  const FINGERPRINT = "3f1c8a9d5e7b2046a1d3c9e8f7a6b5c4d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7";
  const ORIGIN = "https://tenko.example.test:8443";
  const created = (command: string | null | undefined): Pick<CreatedEnrolment, "command" | "token" | "ca_fingerprint"> => ({
    command: command as string,
    token: TOKEN,
    ca_fingerprint: FINGERPRINT,
  });

  it("returns the command of the server as it is", () => {
    const command = `tenko node enrol --controller https://controller.example.net:8443 --token ${TOKEN} --ca-fingerprint ${FINGERPRINT}`;
    expect(enrolCommand(created(command), ORIGIN)).toBe(command);
  });

  it("trims the command of the server", () => {
    const command = `tenko node enrol --controller ${ORIGIN} --token ${TOKEN}`;
    expect(enrolCommand(created(`  ${command}\n`), "https://other.example.test")).toBe(command);
  });

  it("fills in the address of the browser where the server named a placeholder", () => {
    const command = `tenko node enrol --controller https://<controller>:8443 --token ${TOKEN} --ca-fingerprint ${FINGERPRINT}`;
    expect(enrolCommand(created(command), ORIGIN)).toBe(
      `tenko node enrol --controller ${ORIGIN} --token ${TOKEN} --ca-fingerprint ${FINGERPRINT}`,
    );
    // Whatever port the placeholder has.
    expect(enrolCommand(created("tenko node enrol --controller https://<controller>:8444 --token t"), "https://tenko.example.test")).toBe(
      "tenko node enrol --controller https://tenko.example.test --token t",
    );
  });

  it("composes the command when the server sent none", () => {
    const expected = `tenko node enrol --controller ${ORIGIN} --token ${TOKEN} --ca-fingerprint ${FINGERPRINT}`;
    expect(enrolCommand(created(undefined), ORIGIN)).toBe(expected);
    expect(enrolCommand(created(null), ORIGIN)).toBe(expected);
    expect(enrolCommand(created(""), ORIGIN)).toBe(expected);
    expect(enrolCommand(created("   "), ORIGIN)).toBe(expected);
  });
});

describe("fingerprintPairs", () => {
  it("writes a fingerprint in upper case pairs", () => {
    expect(fingerprintPairs("3f1c8a9d")).toBe("3F:1C:8A:9D");
    const sha256 = "3f1c8a9d5e7b2046a1d3c9e8f7a6b5c4d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7";
    const pairs = fingerprintPairs(sha256);
    expect(pairs.split(":")).toHaveLength(32);
    expect(pairs.replaceAll(":", "")).toBe(sha256.toUpperCase());
  });

  it("keeps a last single digit and tolerates nothing", () => {
    expect(fingerprintPairs("abc")).toBe("AB:C");
    expect(fingerprintPairs("a")).toBe("A");
    expect(fingerprintPairs("")).toBe("");
  });
});

describe("lifetimes, roles and token states", () => {
  it("offers lifetimes in ascending order with the default among them", () => {
    expect(LIFETIMES).toEqual([900, 3600, 86_400, 604_800]);
    expect(LIFETIMES).toContain(DEFAULT_LIFETIME);
    expect(DEFAULT_LIFETIME).toBe(3600);
  });

  it("words each lifetime on offer", () => {
    expect(LIFETIMES.map(lifetimeWord)).toEqual(["15 minutes", "1 hour", "1 day", "7 days"]);
  });

  it("words a lifetime that is not on offer as a duration", () => {
    const word = lifetimeWord(7200);
    expect(word).toMatch(/2/);
    expect(word).not.toContain("nodes.lifetime");
  });

  it("names the roles, and an unknown role by itself", () => {
    expect(roleWord("probe")).toBe("Probe");
    expect(roleWord("dns")).toBe("DNS");
    expect(roleWord("dhcp")).toBe("DHCP");
    expect(roleWord("controller")).toBe("Controller");
    expect(roleWord("gateway")).toBe("gateway");
  });

  it("names the states of a token", () => {
    expect(tokenStateWord("pending")).toBe("Waiting");
    expect(tokenStateWord("used")).toBe("Used");
    expect(tokenStateWord("expired")).toBe("Expired");
  });

  it("has a message for every job title the server sends for node edits", () => {
    for (const key of CLUSTER_JOB_KEYS) expect(hasMessage(key), key).toBe(true);
  });
});

describe("formatBytes", () => {
  it("uses decimal units with at most three significant digits", () => {
    expect(formatBytes(0)).toBe("0 byte");
    expect(formatBytes(999)).toBe("999 byte");
    expect(formatBytes(1000)).toBe("1 kB");
    expect(formatBytes(1536)).toBe("1.54 kB");
    expect(formatBytes(12_345_678)).toBe("12.3 MB");
    expect(formatBytes(2_000_000_000)).toBe("2 GB");
    expect(formatBytes(5_000_000_000_000)).toBe("5,000 GB");
  });

  it("does not show a negative size", () => {
    expect(formatBytes(-5)).toBe("0 byte");
  });
});
