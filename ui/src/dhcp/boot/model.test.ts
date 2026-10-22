import { describe, expect, it } from "vitest";
import type { OptionSet, OptionValueItem, Policy } from "../types";
import {
  BOOT_KINDS,
  bootFileOf,
  bootPolicies,
  buildSet,
  checkBootFile,
  draftOfSet,
  EMPTY_DRAFT,
  fieldOfCode,
  ipxeOrder,
  ipxeTies,
  kindMatches,
  kindName,
  sameMatches,
  uniqueName,
} from "./model";

const item = (code: number, data: string, typed?: OptionValueItem["typed"], space = "dhcp4"): OptionValueItem => ({ space, code, data, ...(typed === undefined ? {} : { typed }) });

const ROUTERS = item(3, "c0000201", { ipv4: { values: ["192.0.2.1"] } });
const FILE = item(67, "6970786540", { text: "ipxe@" });
const NEXT = item(150, "c000020a", { ipv4: { values: ["192.0.2.10"] } });

describe("the boot options of a set", () => {
  it("reads the six boot options as text and leaves the others out", () => {
    expect(draftOfSet([ROUTERS, FILE, NEXT, item(211, "0000001e", { unsigned: [30] })])).toEqual({ ...EMPTY_DRAFT, file: "ipxe@", next_server: "192.0.2.10", pxe_reboot: "30" });
    expect(draftOfSet([])).toEqual(EMPTY_DRAFT);
    // A boot code in another option space is another option.
    expect(draftOfSet([item(67, "00", { text: "x" }, "vendor")])).toEqual(EMPTY_DRAFT);
  });

  it("names the field of a code", () => {
    expect(fieldOfCode(150)).toBe("next_server");
    expect(fieldOfCode(211)).toBe("pxe_reboot");
    expect(fieldOfCode(3)).toBeUndefined();
  });
});

describe("building the set to send", () => {
  it("replaces only the boot options and sends the others back with their data", () => {
    const built = buildSet([ROUTERS, FILE], { ...draftOfSet([ROUTERS, FILE]), file: "undionly.kpxe", next_server: "192.0.2.20, 192.0.2.21", pxe_reboot: "30" });
    expect(built).toEqual({
      ok: true,
      changed: true,
      values: [
        { code: 3, data: "c0000201" },
        { code: 150, typed: { ipv4: { values: ["192.0.2.20", "192.0.2.21"] } } },
        { code: 67, typed: { text: "undionly.kpxe" } },
        { code: 211, typed: { unsigned: [30] } },
      ],
    });
  });

  it("keeps a boot option whose text did not change exactly as the server has it", () => {
    const built = buildSet([FILE, NEXT], { ...draftOfSet([FILE, NEXT]), tftp_name: "tftp.example.test" });
    expect(built).toEqual({
      ok: true,
      changed: true,
      values: [
        { code: 67, data: "6970786540" },
        { code: 150, data: "c000020a" },
        { code: 66, typed: { text: "tftp.example.test" } },
      ],
    });
  });

  it("takes out an option whose field was emptied", () => {
    const built = buildSet([ROUTERS, FILE], { ...draftOfSet([ROUTERS, FILE]), file: "  " });
    expect(built).toEqual({ ok: true, changed: true, values: [{ code: 3, data: "c0000201" }] });
  });

  it("says nothing changed when no text differs", () => {
    const built = buildSet([ROUTERS, FILE], draftOfSet([ROUTERS, FILE]));
    expect(built).toEqual({
      ok: true,
      changed: false,
      values: [
        { code: 3, data: "c0000201" },
        { code: 67, data: "6970786540" },
      ],
    });
    expect(buildSet([], EMPTY_DRAFT)).toEqual({ ok: true, changed: false, values: [] });
  });

  it("refuses addresses, numbers and texts the options cannot hold", () => {
    const built = buildSet([], { ...EMPTY_DRAFT, next_server: "192.0.2.300", pxe_reboot: "-1", file: "x".repeat(256), tftp_name: "ok" });
    expect(built).toEqual({ ok: false, errors: { next_server: "ipv4", pxe_reboot: "number", file: "long" } });
    expect(buildSet([], { ...EMPTY_DRAFT, pxe_reboot: "4294967296" })).toEqual({ ok: false, errors: { pxe_reboot: "range" } });
    expect(buildSet([], { ...EMPTY_DRAFT, next_server: "2001:db8::1" })).toEqual({ ok: false, errors: { next_server: "ipv4" } });
  });

  it("counts the octets of a text, not its characters", () => {
    expect(buildSet([], { ...EMPTY_DRAFT, file: "å".repeat(127) }).ok).toBe(true);
    expect(buildSet([], { ...EMPTY_DRAFT, file: "å".repeat(128) })).toEqual({ ok: false, errors: { file: "long" } });
  });
});

describe("the client types", () => {
  it("gives each type the matches of its class", () => {
    expect(kindMatches("bios")).toEqual([{ architecture: { code: 0 } }]);
    expect(kindMatches("uefi-x64")).toEqual([{ architecture: { code: 7 } }, { architecture: { code: 9 } }]);
    expect(kindMatches("uefi-arm64")).toEqual([{ architecture: { code: 11 } }]);
    expect(kindMatches("http-x64")).toEqual([{ architecture: { code: 16 } }]);
    expect(kindMatches("http")).toEqual([{ vendor_class: { value: "HTTPClient", prefix: true } }]);
    expect(kindMatches("ipxe")).toEqual([{ user_class: { value: "iPXE" } }]);
    expect(BOOT_KINDS.map(kindName)).toEqual(["boot-bios", "boot-uefi-x64", "boot-uefi-arm64", "boot-http-x64", "boot-http", "boot-ipxe"]);
  });

  it("compares matches as a set, in any order, with the prefix flag defaulting to off", () => {
    expect(sameMatches(kindMatches("uefi-x64"), [{ architecture: { code: 9 } }, { architecture: { code: 7 } }])).toBe(true);
    expect(sameMatches(kindMatches("bios"), kindMatches("uefi-arm64"))).toBe(false);
    expect(sameMatches(kindMatches("uefi-x64"), [{ architecture: { code: 7 } }])).toBe(false);
    expect(sameMatches([{ vendor_class: { value: "HTTPClient" } }], kindMatches("http"))).toBe(false);
    expect(sameMatches([{ vendor_class: { value: "HTTPClient", prefix: true } }], kindMatches("http"))).toBe(true);
    expect(sameMatches([{ user_class: { value: "iPXE" } }], [{ vendor_class: { value: "iPXE", prefix: false } }])).toBe(false);
  });

  it("makes a name unique with a number", () => {
    expect(uniqueName("boot-bios", new Set())).toBe("boot-bios");
    expect(uniqueName("boot-bios", new Set(["boot-bios"]))).toBe("boot-bios-2");
    expect(uniqueName("boot-bios", new Set(["boot-bios", "boot-bios-2"]))).toBe("boot-bios-3");
  });

  it("orders the iPXE policy before the others", () => {
    expect(ipxeOrder([])).toBe(1);
    expect(ipxeOrder([3, 5])).toBe(2);
    expect(ipxeOrder([1])).toBe(0);
    expect(ipxeOrder([0, 4])).toBe(0);
    expect(ipxeTies([])).toBe(false);
    expect(ipxeTies([1, 2])).toBe(false);
    expect(ipxeTies([0, 2])).toBe(true);
  });

  it("checks the boot file", () => {
    expect(checkBootFile("   ")).toBe("empty");
    expect(checkBootFile("http://boot.example.test/boot.ipxe")).toBeNull();
    expect(checkBootFile("a".repeat(256))).toBe("long");
  });
});

describe("the policies of a scope that set a boot file", () => {
  const policy = (id: string, name: string, order: number, scope?: string): Policy => ({
    id,
    name,
    order,
    enabled: true,
    condition: { join: "or", terms: [{ class: "c1" }] },
    action: {},
    ...(scope ? { scope } : {}),
    created: { at: "2025-01-01T00:00:00Z", by: "u" },
    updated: { at: "2025-01-01T00:00:00Z", by: "u" },
    revision: 1,
  } as unknown as Policy);
  const set = (id: string, ...values: OptionValueItem[]): OptionSet => ({ path: `policy:${id}`, owner: { policy: id }, level: "policy", values, revision: 1, updated: { at: "2025-01-01T00:00:00Z", by: "u" } } as unknown as OptionSet);

  it("reads the boot file of a set", () => {
    expect(bootFileOf(undefined)).toBeUndefined();
    expect(bootFileOf({ values: [ROUTERS] })).toBeUndefined();
    expect(bootFileOf({ values: [FILE] })).toBe("ipxe@");
    expect(bootFileOf({ values: [item(67, "00ff")] })).toBe("00ff");
  });

  it("lists the scope's policies with option 67, lowest order first, and no others", () => {
    const policies = [policy("a", "bios", 4, "s1"), policy("b", "ipxe", 1, "s1"), policy("c", "other-scope", 1, "s2"), policy("d", "no-file", 2, "s1"), policy("e", "server", 1)];
    const sets = [set("a", item(67, "00", { text: "undionly.kpxe" })), set("b", item(67, "00", { text: "http://boot.example.test/boot.ipxe" })), set("c", item(67, "00", { text: "x" })), set("d", ROUTERS), set("e", item(67, "00", { text: "y" }))];
    expect(bootPolicies("s1", policies, sets).map((r) => [r.policy.name, r.file])).toEqual([
      ["ipxe", "http://boot.example.test/boot.ipxe"],
      ["bios", "undionly.kpxe"],
    ]);
  });

  it("breaks a tie of the order by name", () => {
    const policies = [policy("a", "b-policy", 1, "s1"), policy("b", "a-policy", 1, "s1")];
    const sets = [set("a", item(67, "00", { text: "1" })), set("b", item(67, "00", { text: "2" }))];
    expect(bootPolicies("s1", policies, sets).map((r) => r.policy.name)).toEqual(["a-policy", "b-policy"]);
  });
});
