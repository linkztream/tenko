import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type {
  AlarmLevel,
  AssignmentMode,
  ChangeAction,
  CustomKind,
  PrefixRole,
  RangeRole,
  Status,
} from "../api/types";
import { setLocale } from "../i18n";
import {
  actionWord,
  alarmWord,
  countTitle,
  customKindWord,
  kindTitle,
  kindWord,
  modeHint,
  modeWord,
  prefixRoleWord,
  rangeRoleWord,
  siCount,
  statusWord,
} from "./words";

const STATUSES: readonly Status[] = ["planned", "active", "reserved", "deprecated"];
const MODES: readonly AssignmentMode[] = ["reserved", "static", "dynamic", "unmanaged"];
const PREFIX_ROLES: readonly PrefixRole[] = ["supernet", "network"];
const RANGE_ROLES: readonly RangeRole[] = ["dhcp_pool", "reserved", "infrastructure"];
const ALARMS: readonly AlarmLevel[] = ["normal", "warning", "critical"];
const KINDS = [
  "tenant",
  "vrf",
  "site",
  "vlan",
  "prefix",
  "range",
  "address",
  "host",
  "interface",
  "custom_field",
] as const;
const ACTIONS: readonly ChangeAction[] = ["create", "update", "delete", "restore", "lock", "unlock", "remove"];
const CUSTOM_KINDS: readonly CustomKind["type"][] = ["text", "integer", "boolean", "date", "url", "select"];

beforeEach(async () => {
  await setLocale("en");
});

afterEach(async () => {
  await setLocale("en");
});

describe("status, mode, role and alarm words (English)", () => {
  it("names the lifecycle statuses", () => {
    expect(STATUSES.map(statusWord)).toEqual(["Planned", "Active", "Reserved", "Deprecated"]);
  });

  it("names the assignment modes in lowercase", () => {
    expect(MODES.map(modeWord)).toEqual(["reserved", "static", "dynamic", "unmanaged"]);
  });

  it("states what each assignment mode does", () => {
    expect(modeHint("reserved")).toBe("An address change moves the DHCP reservation and updates DNS.");
    expect(modeHint("static")).toBe("Only DNS follows. The device itself is configured by hand.");
    expect(modeHint("dynamic")).toBe("Tenko only observes this host.");
    expect(modeHint("unmanaged")).toBe("Tenko never touches this host.");
  });

  it("names the prefix and range roles", () => {
    expect(PREFIX_ROLES.map(prefixRoleWord)).toEqual(["Supernet", "Network"]);
    expect(RANGE_ROLES.map(rangeRoleWord)).toEqual(["DHCP pool", "Reserved", "Infrastructure"]);
  });

  it("names the alarm levels", () => {
    expect(ALARMS.map(alarmWord)).toEqual(["Normal", "Warning", "Critical"]);
  });

  it("names the custom field types", () => {
    expect(CUSTOM_KINDS.map(customKindWord)).toEqual([
      "Text",
      "Whole number",
      "Yes or no",
      "Date",
      "URL",
      "List of choices",
    ]);
  });
});

describe("kind words (English)", () => {
  it("uses the singular for one and the plural for any other count", () => {
    expect(kindWord("prefix")).toBe("prefix");
    expect(kindWord("prefix", 1)).toBe("prefix");
    expect(kindWord("prefix", 0)).toBe("prefixes");
    expect(kindWord("prefix", 2)).toBe("prefixes");
    expect(kindWord("address", 1234)).toBe("addresses");
  });

  it("has a singular and a plural for every kind", () => {
    expect(KINDS.map((k) => kindWord(k, 1))).toEqual([
      "tenant",
      "VRF",
      "site",
      "VLAN",
      "prefix",
      "range",
      "address",
      "host",
      "interface",
      "custom field",
    ]);
    expect(KINDS.map((k) => kindWord(k, 2))).toEqual([
      "tenants",
      "VRFs",
      "sites",
      "VLANs",
      "prefixes",
      "ranges",
      "addresses",
      "hosts",
      "interfaces",
      "custom fields",
    ]);
  });

  it("returns an unknown kind as it is", () => {
    expect(kindWord("api_token")).toBe("api_token");
    expect(kindWord("api_token", 5)).toBe("api_token");
    expect(kindWord("")).toBe("");
  });

  it("gives headings the capitalized singular", () => {
    expect(KINDS.map(kindTitle)).toEqual([
      "Tenant",
      "VRF",
      "Site",
      "VLAN",
      "Prefix",
      "Range",
      "Address",
      "Host",
      "Interface",
      "Custom field",
    ]);
    expect(kindTitle("api_token")).toBe("api_token");
  });
});

describe("action words (English)", () => {
  it("counts the objects a change touched", () => {
    expect(actionWord("create", 1)).toBe("1 created");
    expect(actionWord("create", 3)).toBe("3 created");
    expect(actionWord("update", 2)).toBe("2 updated");
    expect(actionWord("delete", 1)).toBe("1 deleted");
    expect(actionWord("restore", 4)).toBe("4 restored");
    expect(actionWord("lock", 1)).toBe("1 locked");
    expect(actionWord("unlock", 12)).toBe("12 unlocked");
    expect(actionWord("remove", 0)).toBe("0 removed");
  });

  it("groups large counts", () => {
    expect(actionWord("create", 1234)).toBe("1,234 created");
  });

  it("covers every action", () => {
    for (const action of ACTIONS) {
      expect(actionWord(action, 2), action).toMatch(/^2 [a-z]+$/);
    }
  });
});

describe("Swedish", () => {
  beforeEach(async () => {
    await setLocale("sv");
  });

  it("has a translation for every word", () => {
    const all = [
      ...STATUSES.map(statusWord),
      ...MODES.map(modeWord),
      ...MODES.map(modeHint),
      ...PREFIX_ROLES.map(prefixRoleWord),
      ...RANGE_ROLES.map(rangeRoleWord),
      ...ALARMS.map(alarmWord),
      ...KINDS.map((k) => kindWord(k, 1)),
      ...KINDS.map((k) => kindWord(k, 2)),
      ...KINDS.map(kindTitle),
      ...ACTIONS.map((a) => actionWord(a, 2)),
      ...CUSTOM_KINDS.map(customKindWord),
    ];
    for (const text of all) expect(text).not.toMatch(/^ipam\./);
    expect(all.every((w) => w.length > 0)).toBe(true);
  });

  it("uses the terms of a network administrator", () => {
    expect(statusWord("deprecated")).toBe("Utfasad");
    expect(modeWord("unmanaged")).toBe("ohanterad");
    expect(kindWord("host", 2)).toBe("värdar");
    expect(kindWord("prefix", 2)).toBe("prefix");
    expect(kindTitle("range")).toBe("Intervall");
    expect(alarmWord("critical")).toBe("Kritisk");
  });

  it("agrees in number", () => {
    expect(actionWord("create", 1)).toBe("1 skapad");
    expect(actionWord("create", 3)).toBe("3 skapade");
    expect(actionWord("lock", 1)).toBe("1 låst");
    expect(actionWord("lock", 2)).toBe("2 låsta");
  });

  it("uses the decimal comma in compact counts", () => {
    expect(siCount(1234)).toBe("1,2K");
    expect(siCount("30000000000000000000")).toBe("3,0e19");
  });
});

describe("siCount", () => {
  it("shows numbers below a thousand as they are", () => {
    expect(siCount(0)).toBe("0");
    expect(siCount(982)).toBe("982");
    expect(siCount("982")).toBe("982");
    expect(siCount(982n)).toBe("982");
  });

  it("uses SI suffixes up to the largest safe integer", () => {
    expect(siCount(1234)).toBe("1.2K");
    expect(siCount("1234")).toBe("1.2K");
    expect(siCount(48213)).toBe("48K");
    expect(siCount(1_300_000)).toBe("1.3M");
    expect(siCount("4294967296")).toBe("4.3G");
    expect(siCount(Number.MAX_SAFE_INTEGER)).toBe("9.0P");
    expect(siCount(BigInt(Number.MAX_SAFE_INTEGER))).toBe("9.0P");
  });

  it("writes an exact power of two above that as 2^n", () => {
    expect(siCount("9007199254740992")).toBe("2^53");
    expect(siCount("18446744073709551616")).toBe("2^64");
    expect(siCount("340282366920938463463374607431768211456")).toBe("2^128");
    expect(siCount(2n ** 96n)).toBe("2^96");
  });

  it("writes any other large count in exponent form with one decimal", () => {
    expect(siCount("30000000000000000000")).toBe("3.0e19");
    expect(siCount("18446744073709551617")).toBe("1.8e19");
    expect(siCount("18446744073709551615")).toBe("1.8e19");
    expect(siCount("9007199254740993")).toBe("9.0e15");
    expect(siCount("340282366920938463463374607431768211455")).toBe("3.4e38");
  });

  it("carries a mantissa that rounds up to ten into the exponent", () => {
    expect(siCount("99960000000000000000")).toBe("1.0e20");
    expect(siCount("19960000000000000000")).toBe("2.0e19");
  });

  it("keeps the sign of a negative count", () => {
    expect(siCount(-1234)).toBe("-1.2K");
    expect(siCount("-18446744073709551616")).toBe("-2^64");
    expect(siCount("-30000000000000000000")).toBe("-3.0e19");
  });

  it("accepts plain numbers beyond 2^53 and bigints", () => {
    expect(siCount(2 ** 64)).toBe("2^64");
    expect(siCount(3e19)).toBe("3.0e19");
    expect(siCount(18446744073709551616n)).toBe("2^64");
  });

  it("passes fractions to the SI form and leaves non-numbers alone", () => {
    expect(siCount(1234.5)).toBe("1.2K");
    expect(siCount("1234.5")).toBe("1.2K");
    expect(siCount("n/a")).toBe("n/a");
    expect(siCount("")).toBe("");
    expect(siCount(Number.NaN)).toBe("");
    expect(siCount(Number.POSITIVE_INFINITY)).toBe("");
  });

  it("uses the language given", () => {
    expect(siCount(1234, "sv")).toBe("1,2K");
    expect(siCount("30000000000000000000", "sv")).toBe("3,0e19");
    expect(siCount("18446744073709551616", "sv")).toBe("2^64");
  });
});

describe("countTitle", () => {
  it("groups the exact value", () => {
    expect(countTitle(982)).toBe("982");
    expect(countTitle(1234)).toBe("1,234");
    expect(countTitle("4294967296")).toBe("4,294,967,296");
  });

  it("is exact beyond 2^53", () => {
    expect(countTitle("18446744073709551616")).toBe("18,446,744,073,709,551,616");
    expect(countTitle("340282366920938463463374607431768211456")).toBe(
      "340,282,366,920,938,463,463,374,607,431,768,211,456",
    );
    expect(countTitle(2n ** 64n + 1n)).toBe("18,446,744,073,709,551,617");
  });

  it("keeps the sign and leaves non-numbers alone", () => {
    expect(countTitle("-1234")).toBe("-1,234");
    expect(countTitle("n/a")).toBe("n/a");
    expect(countTitle(1234.5)).toBe("1,234.5");
  });

  it("uses the grouping of the language given", () => {
    const sv = countTitle("4294967296", "sv");
    expect(sv.replace(/\s/g, " ")).toBe("4 294 967 296");
  });
});
