import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ACCESS_IDS, seedAccess } from "../../api/mock/access-store";
import { integrationsState, mockCertificate } from "../../api/mock/routes-integrations";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { setSessionForTest } from "../../auth/session";
import { signInAs } from "../testkit";
import AccessPage from "./AccessPage";
import { lineages, unreachableListener, waitingCodes, type CertRecord } from "./integrations";

// The dialogs render in a portal outside the view; axe looks at the whole document there.
const NO_SHELL = { disable: ["region"] } as const;

const DAY = 86_400_000;

beforeEach(async () => {
  await signInAs();
  seedAccess();
});

afterEach(() => setSessionForTest(null));

async function openPage() {
  const view = renderRoute(AccessPage, { url: "/settings/access", path: "/settings/access" });
  await screen.findAllByTestId("integration-lineage");
  return view;
}

const lineageRow = (label: string) =>
  screen.getAllByTestId("integration-lineage").find((row) => row.dataset.key === label)!;

describe("the state of an enrolled host", () => {
  const record = (patch: Partial<CertRecord>): CertRecord => ({ ...mockCertificate("a", "host", 5), ...patch });

  it("reads active, expiring, lapsed and revoked, with what needs a person first", () => {
    const now = Date.now();
    const active = record({ label: "b-active" });
    const expiring = record({ label: "c-expiring", not_before: new Date(now - 28 * DAY).toISOString(), not_after: new Date(now + 2 * DAY).toISOString() });
    const lapsed = record({ label: "d-lapsed", not_after: new Date(now - DAY).toISOString() });
    const revoked = record({ label: "a-revoked", state: "revoked" });
    const list = lineages([active, expiring, lapsed, revoked], now);
    expect(list.map((l) => [l.label, l.state])).toEqual([
      ["d-lapsed", "lapsed"],
      ["c-expiring", "expiring"],
      ["b-active", "active"],
      ["a-revoked", "revoked"],
    ]);
  });

  it("counts a renewed lineage as active, whatever its old certificate says", () => {
    const now = Date.now();
    const old = record({ label: "h", not_before: new Date(now - 28 * DAY).toISOString(), not_after: new Date(now + 2 * DAY).toISOString() });
    const successor = { ...record({ label: "h", lineage: old.lineage }), state: "pending" as const };
    const [one] = lineages([old, successor], now);
    expect(one!.state).toBe("active");
    expect(one!.pending?.serial).toBe(successor.serial);
    expect(one!.current.serial).toBe(old.serial);
  });

  it("lists only codes that can still be used", () => {
    const now = Date.now();
    const code = (state: "pending" | "withdrawn", expires: number) => ({
      id: String(expires),
      account: "a",
      created_by: "b",
      created_at: new Date(now).toISOString(),
      expires_at: new Date(expires).toISOString(),
      state: { state },
      expired: false,
    });
    const codes = [code("pending", now + 1000), code("pending", now - 1000), code("withdrawn", now + 2000)];
    expect(waitingCodes(codes, now).map((c) => c.id)).toEqual([String(now + 1000)]);
  });
});

describe("the integration certificates of the access page", () => {
  it("shows each host with its account and its state at a glance", async () => {
    const now = Date.now();
    integrationsState().certs.set("lapsed", {
      ...mockCertificate(ACCESS_IDS.serviceAccount, "old-host", 40),
      serial: "lapsed",
      not_after: new Date(now - DAY).toISOString(),
    });
    await openPage();
    const rows = screen.getAllByTestId("integration-lineage");
    expect(rows.map((r) => [r.dataset.key, r.dataset.state])).toEqual([
      ["old-host", "lapsed"],
      ["dns-sync-host", "active"],
    ]);
    expect(lineageRow("dns-sync-host").textContent).toContain("for dns-sync");
    expect(within(lineageRow("old-host")).getByTestId("integration-state").textContent).toBe("Lapsed");
    expect(lineageRow("old-host").textContent).toContain("Enroll the host again with a new code and a new key.");
    expect(await axeViolations(screen.getByTestId("access-integrations"))).toEqual([]);
  });

  it("makes a code that is shown once with what to do with it, and withdraws a waiting one", async () => {
    await openPage();
    fireEvent.click(screen.getByTestId("integrations-enroll"));
    const form = await screen.findByTestId("dialog-integration-code");
    fireEvent.click(within(form).getByTestId("form-submit"));
    const once = await screen.findByTestId("dialog-integration-code-once");
    const code = within(once).getByTestId("integration-code-text").textContent ?? "";
    expect(code.startsWith("tnki.")).toBe(true);
    expect(code.split(".")).toHaveLength(5);
    expect(within(once).getByTestId("integration-code-once").textContent).toContain("shown only now and works once");
    expect(once.textContent).toContain("save the code to the file enroll.code");
    expect(within(once).getByTestId("integration-code-fingerprint").textContent).toMatch(/^[0-9A-F]{2}(:[0-9A-F]{2})+$/);
    expect(await axeViolations(document.body, NO_SHELL)).toEqual([]);
    fireEvent.click(within(once).getByTestId("integration-code-done"));
    await waitFor(() => expect(screen.queryByTestId("dialog-integration-code-once")).toBeNull());

    const waiting = await screen.findByTestId("integration-code");
    expect(waiting.textContent).toContain("For dns-sync");
    fireEvent.click(within(waiting).getByTestId("integration-code-withdraw"));
    await waitFor(() => expect(screen.queryByTestId("integration-code")).toBeNull());
    expect([...integrationsState().codes.values()].map((c) => c.state.state)).toEqual(["withdrawn"]);
  });

  it("refuses a malformed network before sending anything", async () => {
    await openPage();
    fireEvent.click(screen.getByTestId("integrations-enroll"));
    const form = await screen.findByTestId("dialog-integration-code");
    fireEvent.input(within(form).getByTestId("field-source"), { target: { value: "not a network" } });
    fireEvent.click(within(form).getByTestId("form-submit"));
    await screen.findByText("Write a network as an address and a prefix length, such as 192.0.2.0/24.");
    expect(integrationsState().codes.size).toBe(0);
  });

  it("revokes a host only after saying what that ends", async () => {
    await openPage();
    fireEvent.click(within(lineageRow("dns-sync-host")).getByTestId("integration-revoke"));
    const dialog = await screen.findByRole("dialog");
    expect(dialog.textContent).toContain("loses its access as dns-sync at once, on every controller");
    expect(dialog.textContent).toContain("Its key can never enroll again");
    expect(dialog.textContent).toContain("This cannot be undone.");
    fireEvent.click(within(dialog).getByRole("button", { name: "Revoke" }));
    await waitFor(() => expect(lineageRow("dns-sync-host").dataset.state).toBe("revoked"));
    expect(within(lineageRow("dns-sync-host")).queryByTestId("integration-revoke")).toBeNull();
    expect(screen.getByText("Certificate of dns-sync-host revoked")).toBeTruthy();
  });
});

describe("where hosts reach the integration listener", () => {
  it("warns when it is closed or listens on loopback only", () => {
    expect(unreachableListener(["0.0.0.0:8445"])).toBeUndefined();
    expect(unreachableListener(["127.0.0.1:8445", "192.0.2.5:8445"])).toBeUndefined();
    expect(unreachableListener(["127.0.0.1:8445"])).toBe("loopback");
    expect(unreachableListener(["127.0.0.1:8445", "[::1]:8445"])).toBe("loopback");
    expect(unreachableListener(["[::ffff:127.0.0.1]:8445"])).toBe("loopback");
    expect(unreachableListener([])).toBe("closed");
    expect(unreachableListener(undefined)).toBeUndefined();
  });
});
