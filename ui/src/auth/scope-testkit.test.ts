import { afterEach, describe, expect, it } from "vitest";
import { IPAM_IDS } from "../api/mock/ipam/seed";
import { may, writes, writesAll, writesAny } from "./gate";
import { signInScopedOperator, signInWithRoles } from "./scope-testkit";
import { session, setSessionForTest } from "./session";

afterEach(() => setSessionForTest(null));

describe("the gate over the mock seed", () => {
  it("lets the scoped operator write the documentation prefixes and nothing else", async () => {
    await signInScopedOperator();
    expect(session()?.grants?.length).toBe(2);
    expect(writes().kind).toBe("only");
    expect(writesAll()).toBe(false);
    expect(may.prefix(IPAM_IDS.prefix.documentation)).toBe(true);
    expect(may.prefix(IPAM_IDS.prefix.lab)).toBe(true);
    expect(may.prefix(IPAM_IDS.prefix.cameras)).toBe(true);
    expect(may.prefix(IPAM_IDS.prefix.iot)).toBe(false);
    expect(may.prefix(IPAM_IDS.prefix.lan)).toBe(false);
    expect(may.create("prefix")).toBe(true);
    expect(may.create("vlan")).toBe(false);
    expect(may.create("host")).toBe(false);
  });

  it("lets global writers write everything and viewers and the auditor nothing", async () => {
    await signInWithRoles(["operator"]);
    expect(may.prefix(IPAM_IDS.prefix.lan)).toBe(true);
    expect(may.create("vlan")).toBe(true);
    for (const role of ["viewer", "auditor"] as const) {
      await signInWithRoles([role]);
      expect(writesAny()).toBe(false);
      expect(may.prefix(IPAM_IDS.prefix.lan)).toBe(false);
      expect(may.create("prefix")).toBe(false);
    }
  });
});
