import { render } from "@solidjs/testing-library";
import { beforeEach, describe, expect, it } from "vitest";
import type { AuditDraft } from "../api/types";
import { setLocale } from "../i18n";
import { AuditAction, auditActionLabel } from "./actionLabel";

beforeEach(async () => {
  await setLocale("en");
});

function draft(action: string, extra: Partial<AuditDraft> = {}): AuditDraft {
  return { action, outcome: { kind: "success" }, objects: [], ...extra };
}

describe("the label of an audit action", () => {
  it("has a sentence-case label for a known action", () => {
    expect(auditActionLabel(draft("ipam.proposal.open"))).toBe("Open a proposal");
    expect(auditActionLabel(draft("ipam.reconcile.run"))).toBe("Reconcile IPAM");
    expect(auditActionLabel(draft("connect.secret.inject"))).toBe("Pass credentials to a connector");
  });

  it("has none for an unknown action", () => {
    expect(auditActionLabel(draft("vendor.thing.happen"))).toBeUndefined();
  });

  it("is in the language of the UI", async () => {
    await setLocale("sv");
    expect(auditActionLabel(draft("ipam.proposal.open"))).toBe("Öppna ett förslag");
  });
});

describe("the action of a record", () => {
  it("shows the label with the code after it, in the data font", () => {
    const { container } = render(() => <AuditAction draft={draft("ipam.proposal.open")} />);
    expect(container.querySelector(".audit-action-label")?.textContent).toBe("Open a proposal");
    const code = container.querySelector(".audit-action-code");
    expect(code?.textContent).toBe("ipam.proposal.open");
    expect(code?.classList.contains("mono")).toBe(true);
    expect(container.querySelector(".audit-action")?.classList.contains("stacked")).toBe(false);
  });

  it("stacks the code below the label when asked", () => {
    const { container } = render(() => <AuditAction draft={draft("ipam.proposal.open")} stacked />);
    expect(container.querySelector(".audit-action")?.classList.contains("stacked")).toBe(true);
  });

  it("shows the code alone for an unknown action", () => {
    const { container } = render(() => <AuditAction draft={draft("vendor.thing.happen")} />);
    expect(container.querySelector(".audit-action")).toBeNull();
    expect(container.textContent).toBe("vendor.thing.happen");
    expect(container.querySelector(".mono")?.textContent).toBe("vendor.thing.happen");
  });
});
