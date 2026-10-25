// The words of the router advertisement check (DHCP-10): each finding of the check in English and in
// Swedish, the severity of each code, and the fallback to the English detail of the server.
import { afterEach, describe, expect, it } from "vitest";
import { setLocale } from "../../i18n";
import { isRaCode, raFindingKind, raFindingText } from "./raWords";

afterEach(async () => {
  await setLocale("en");
});

const LINK = { node: "1", interface: "eth1", routers: "fe80::1, fe80::2" };

describe("raFindingText", () => {
  it("says what flags_off means and what to do", () => {
    const text = raFindingText({
      code: "dhcp.ra.flags_off",
      detail: "detail",
      params: { ...LINK, scopes: "2001:db8:0:30::/64" },
    });
    expect(text).toBe(
      "The routers fe80::1, fe80::2 on eth1 of node 1 set neither the M nor the O flag, so the hosts on that link do not ask DHCPv6 and the scopes 2001:db8:0:30::/64 serve nobody. Turn on M (addresses) or O (options only) in the router advertisements.",
    );
  });

  it("says that O without M gives options only", () => {
    const text = raFindingText({
      code: "dhcp.ra.other_only",
      detail: "detail",
      params: { ...LINK, scopes: "2001:db8:0:10::/64" },
    });
    expect(text).toContain("set the O flag without M");
    expect(text).toContain("options only");
    expect(text).toContain("turn on M if the hosts should get addresses from 2001:db8:0:10::/64");
  });

  it("says that M without a scope asks a server that does not answer", () => {
    const text = raFindingText({
      code: "dhcp.ra.managed_without_scope",
      detail: "detail",
      params: { ...LINK, prefixes: "2001:db8:0:50::/64" },
    });
    expect(text).toContain("set the M flag for 2001:db8:0:50::/64");
    expect(text).toContain("no enabled DHCPv6 scope covers that link");
    expect(text).toContain("Add a scope for the link or turn M off.");
  });

  it("says why the check cannot run and what it needs", () => {
    const text = raFindingText({
      code: "dhcp.ra.unchecked",
      detail: "detail",
      params: { node: "1", reason: "permission denied" },
    });
    expect(text).toBe(
      "The router advertisement check cannot run on node 1: permission denied. It needs the CAP_NET_RAW capability of the probe role on Linux.",
    );
  });

  it("speaks Swedish after a language switch", async () => {
    await setLocale("sv");
    const text = raFindingText({
      code: "dhcp.ra.flags_off",
      detail: "detail",
      params: { ...LINK, scopes: "2001:db8:0:30::/64" },
    });
    expect(text).toContain("sätter varken M- eller O-flaggan");
    expect(text).toContain("eth1");
    expect(text).toContain("2001:db8:0:30::/64");
  });

  it("falls back to the detail of the server for a code it has no words for", () => {
    expect(
      raFindingText({
        code: "dhcp.ra.something_new",
        detail: "a new finding",
        params: { node: "1" },
      }),
    ).toBe("a new finding");
  });

  it("falls back to the detail when a parameter is missing", () => {
    expect(
      raFindingText({
        code: "dhcp.ra.flags_off",
        detail: "the English detail",
        params: {},
      }),
    ).toBe("the English detail");
    expect(
      raFindingText({
        code: "dhcp.ra.flags_off",
        detail: "the English detail",
      }),
    ).toBe("the English detail");
  });
});

describe("the severity", () => {
  it("warns where hosts get no configuration and informs otherwise", () => {
    expect(raFindingKind("dhcp.ra.flags_off")).toBe("warn");
    expect(raFindingKind("dhcp.ra.managed_without_scope")).toBe("warn");
    expect(raFindingKind("dhcp.ra.other_only")).toBe("info");
    expect(raFindingKind("dhcp.ra.unchecked")).toBe("info");
  });

  it("knows the codes of the check", () => {
    expect(isRaCode("dhcp.ra.flags_off")).toBe(true);
    expect(isRaCode("node.roles.privileges")).toBe(false);
  });
});
