import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { db } from "../../api/mock/db";
import { kekState, ROTATION_STEP_MS } from "../../api/mock/routes-kek";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { session, setSessionForTest } from "../../auth/session";
import { signInAs } from "../testkit";
import VaultPage, { protectionText, rotating, warningText } from "./VaultPage";

beforeEach(async () => {
  await signInAs();
});

afterEach(() => setSessionForTest(null));

async function openPage() {
  const view = renderRoute(VaultPage, { url: "/settings/vault", path: "/settings/vault" });
  await screen.findByTestId("vault-key");
  return view;
}

/** Makes the mock's session older than the five minutes of the fresh-sign-in rule. */
function ageSession(): void {
  const current = db.sessions.find((s) => s.id === db.currentSessionId);
  if (current) current.created_at = Date.now() - 10 * 60 * 1000;
}

describe("the vault page", () => {
  it("shows the key of the controller, every controller and the generations", async () => {
    await openPage();
    const key = screen.getByTestId("vault-key");
    expect(key.textContent).toContain("Key of controller 1");
    expect(within(key).getByTestId("vault-provider").textContent).toBe("systemd-creds directory");
    expect(within(key).getByTestId("vault-protection").dataset.code).toBe("systemd_creds_host");
    expect(within(key).getByTestId("vault-active").textContent).toBe("kek-000002");
    expect(within(key).getByTestId("vault-epoch").textContent).toBe("2");
    expect(screen.getAllByTestId("vault-controller")).toHaveLength(1);
    const generations = screen.getAllByTestId("vault-generation");
    expect(generations.map((g) => g.dataset.key)).toEqual(["kek-000001", "kek-000002"]);
    expect(generations.map((g) => g.dataset.active)).toEqual(["false", "true"]);
    expect(screen.getByTestId("vault-rotation-none")).toBeTruthy();
    expect(screen.queryByTestId("vault-warnings")).toBeNull();
  });

  it("rotates the key after a confirmation and follows the phases to the new generation", async () => {
    await openPage();
    fireEvent.click(screen.getByTestId("vault-rotate"));
    const dialog = await screen.findByTestId("dialog-confirm");
    fireEvent.click(within(dialog).getByTestId("confirm-ok"));
    expect(await screen.findByText("Key rotation requested")).toBeTruthy();
    await waitFor(() => expect(screen.getByTestId("vault-rotation-state")).toBeTruthy());
    expect((screen.getByTestId("vault-rotate") as HTMLButtonElement).disabled).toBe(true);
    // The mock moves one phase on per step; the page reads the status on a timer while it runs.
    await waitFor(() => expect(screen.getByTestId("vault-rotation-state").dataset.phase).toBe("done"), {
      timeout: ROTATION_STEP_MS * 4 + 4000,
    });
    await waitFor(() => expect(screen.getByTestId("vault-active").textContent).toBe("kek-000003"));
    expect(screen.getByTestId("vault-epoch").textContent).toBe("3");
    expect((screen.getByTestId("vault-rotate") as HTMLButtonElement).disabled).toBe(false);
  }, 15000);

  it("asks for a fresh sign-in when the session is older than five minutes", async () => {
    ageSession();
    await openPage();
    fireEvent.click(screen.getByTestId("vault-rotate"));
    fireEvent.click(within(await screen.findByTestId("dialog-confirm")).getByTestId("confirm-ok"));
    const notice = await screen.findByTestId("vault-step-up");
    expect(notice.textContent).toContain("A rotation needs a sign-in within the last five minutes.");
    expect(screen.queryByTestId("dialog-confirm")).toBeNull();
    expect(kekState.rotation).toBeNull();
    fireEvent.click(screen.getByTestId("vault-sign-in-again"));
    await waitFor(() => expect(session()).toBeNull());
  });

  it("shows a failed rotation as a warning", async () => {
    kekState.rotation = {
      phase: "failed",
      requested_at: new Date().toISOString(),
      requested_by: "user:x",
      updated_at: new Date().toISOString(),
      waiting_for: [],
      unreachable: [2],
      rewrapped: 3,
      error: "controller 2 did not answer",
      started: Date.now(),
    };
    await openPage();
    const warning = await screen.findByTestId("vault-warning");
    expect(warning.dataset.code).toBe("vault.kek.rotation_failed");
    expect(warning.textContent).toBe("The last key rotation failed: controller 2 did not answer");
    expect(screen.getByTestId("vault-rotation-state").dataset.phase).toBe("failed");
    expect(screen.getByTestId("vault-rotation-state").textContent).toContain("Controllers 2 fetch the new key when they start.");
  });

  it("has no accessibility violations", async () => {
    const view = await openPage();
    expect(await axeViolations(view.container)).toEqual([]);
  });
});

describe("the words of the vault", () => {
  it("names a protection by its code, else by the server's text", () => {
    expect(protectionText({ code: "dpapi_machine", text: "x", weak: false })).toBe("DPAPI, bound to the machine");
    expect(protectionText({ code: "future_thing", text: "Something new", weak: false })).toBe("Something new");
  });

  it("translates the warnings with their parameters, else shows the detail", () => {
    expect(warningText({ code: "vault.kek.missing", detail: "x", params: { generations: "kek-000003" } })).toBe(
      "This controller lacks the key generations kek-000003; it fetches them from another controller.",
    );
    expect(warningText({ code: "vault.kek.other", detail: "Plain detail" })).toBe("Plain detail");
  });

  it("knows which phases run", () => {
    expect(["requested", "distributing", "rewrapping"].every((p) => rotating(p as never))).toBe(true);
    expect(rotating("done")).toBe(false);
    expect(rotating("failed")).toBe(false);
    expect(rotating(undefined)).toBe(false);
  });
});
