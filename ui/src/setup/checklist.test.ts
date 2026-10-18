import { describe, expect, it } from "vitest";
import type { BreachStatus, PasswordCheckResult } from "../api/types";
import { buildChecklist } from "./checklist";

function result(breach: BreachStatus, breached = false): PasswordCheckResult {
  return {
    acceptable: !breached,
    violations: breached ? [{ kind: "breached" }] : [],
    breach_check: breach,
    policy: { preset: "pin" },
  } as PasswordCheckResult;
}

function breachRow(check: PasswordCheckResult) {
  const row = buildChecklist({ hasPassword: true, pending: false, result: check, breachOff: false }).find(
    (item) => item.id === "breach",
  );
  if (!row) throw new Error("the checklist has no breach row");
  return row;
}

describe("buildChecklist, the breach row", () => {
  it("passes a clean answer and fails a breached one", () => {
    expect(breachRow(result("clean")).state).toBe("ok");
    expect(breachRow(result("breached", true)).state).toBe("bad");
  });

  it("shows an answer that was not looked up as off, without a note", () => {
    expect(breachRow(result("off"))).toEqual({ id: "breach", state: "off", violations: [] });
    expect(breachRow(result("unavailable"))).toEqual({ id: "breach", state: "off", violations: [] });
  });

  it("explains that a PIN is not checked against the corpus", () => {
    expect(breachRow(result("not_applicable"))).toEqual({ id: "breach", state: "off", violations: [], note: "pin" });
  });
});
