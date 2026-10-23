import { cleanup, fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { server } from "../api/mock/node";
import { NODE_IDS } from "../api/mock/nodes-store";
import { renderRoute } from "../app/testing/render";
import { axeViolations } from "../app/testing/axe";
import { signInAlex } from "../auth/account/testkit";
import { setSessionForTest } from "../auth/session";
import { RolesEditor } from "./RolesEditor";
import { changeOf, lockOf, nextPhase } from "./roles";

const OWN = 1;
const PROBE = NODE_IDS.dmz;

beforeEach(async () => {
  await signInAlex();
});

afterEach(() => {
  cleanup();
  setSessionForTest(null);
});

function open(id: number) {
  return renderRoute(() => <RolesEditor id={id} pollMs={10} deadlineMs={2_000} />);
}

const box = (role: string) => screen.getByTestId(`node-role-${role}`) as HTMLInputElement;

describe("the rules", () => {
  it("locks the controller role, and every role but probe on a node without it", () => {
    expect(lockOf("controller", { pinned: false, controller: true })).toBe("membership");
    expect(lockOf("dns", { pinned: false, controller: true })).toBeUndefined();
    expect(lockOf("dns", { pinned: false, controller: false })).toBe("controller_only");
    expect(lockOf("probe", { pinned: false, controller: false })).toBeUndefined();
    expect(lockOf("probe", { pinned: true, controller: true })).toBe("pinned");
    expect(changeOf(["controller", "dns"], ["dhcp", "controller"])).toEqual({ on: ["dhcp"], off: ["dns"] });
  });

  it("follows a restart until the node runs the new roles", () => {
    const wanted = ["controller", "dhcp"];
    expect(nextPhase("waiting", wanted, { running: ["controller"] }, false)).toBe("waiting");
    expect(nextPhase("waiting", wanted, undefined, false)).toBe("down");
    expect(nextPhase("down", wanted, undefined, true)).toBe("late");
    expect(nextPhase("down", wanted, { running: ["dhcp", "controller"] }, false)).toBe("back");
  });
});

describe("RolesEditor", () => {
  it("changes this controller's roles after a confirmation and follows it until it is back", async () => {
    const view = open(OWN);
    await waitFor(() => expect(box("dns").checked).toBe(true));
    // The controller role follows the cluster membership.
    expect(box("controller").disabled).toBe(true);
    expect(screen.getByTestId("node-roles-running").textContent).toContain("DNS");
    const save = screen.getByTestId("node-roles-save") as HTMLButtonElement;
    expect(save.disabled).toBe(true);

    fireEvent.click(box("probe"));
    expect(box("probe").checked).toBe(false);
    expect(save.disabled).toBe(false);
    fireEvent.click(save);
    const dialog = await screen.findByTestId("node-roles-confirm");
    expect(dialog.textContent).toContain("restarts");
    expect(dialog.textContent).toMatch(/Switched off: .*probe/i);
    fireEvent.click(within(dialog).getByRole("button", { name: "Change and restart" }));

    const status = await screen.findByTestId("node-roles-restart");
    await waitFor(() => expect(status.querySelector("[data-phase]")?.getAttribute("data-phase")).toBe("back"));
    expect(box("probe").checked).toBe(false);
    expect(screen.getByTestId("node-roles-running").textContent).not.toMatch(/probe/i);
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("shows a pin read-only and the findings under the editor", async () => {
    server.use(
      http.get("*/api/v1/nodes/:id/roles", () =>
        HttpResponse.json({
          node: OWN,
          configured: ["controller", "dns", "probe"],
          running: ["controller", "dns", "probe"],
          stored: true,
          revision: 4,
          pinned: true,
          controller: true,
          restart: "none",
          findings: [
            {
              code: "node.roles.privileges",
              detail: "the role(s) probe need raw sockets",
              params: { roles: "probe", dropins: "probe.conf" },
            },
          ],
        }),
      ),
    );
    open(OWN);
    const pinned = await screen.findByTestId("node-roles-pinned");
    expect(pinned.textContent).toContain("--roles controller,dns,probe");
    expect(box("dns").disabled || box("dns").closest("fieldset")?.disabled).toBe(true);
    expect(screen.queryByTestId("node-roles-save")).toBeNull();
    const finding = screen.getByTestId("node-roles-finding");
    expect(finding.dataset.code).toBe("node.roles.privileges");
    expect(finding.textContent).toContain("probe.conf");
  });

  it("offers only the probe role on an enrolled node and says the node applies the change", async () => {
    open(PROBE);
    await waitFor(() => expect(box("probe").checked).toBe(true));
    expect(box("dns").disabled).toBe(true);
    expect(box("dhcp").disabled).toBe(true);
    expect(screen.queryByTestId("node-roles-running")).toBeNull();
  });

  it("shows a refusal of the server", async () => {
    server.use(
      http.put("*/api/v1/nodes/:id/roles", () =>
        HttpResponse.json(
          { type: "about:blank", title: "Conflict", status: 409, code: "node.roles.last_controller", detail: "the last controller" },
          { status: 409, headers: { "Content-Type": "application/problem+json" } },
        ),
      ),
    );
    open(OWN);
    await waitFor(() => expect(box("dhcp").disabled).toBe(false));
    fireEvent.click(box("dhcp"));
    fireEvent.click(screen.getByTestId("node-roles-save"));
    const dialog = await screen.findByTestId("node-roles-confirm");
    fireEvent.click(within(dialog).getByRole("button", { name: "Change and restart" }));
    const error = await screen.findByTestId("error-notice");
    expect(error.dataset.code).toBe("node.roles.last_controller");
    expect(error.textContent).toContain("last controller");
  });

  it("is read-only for an operator", async () => {
    await signInAlex({
      prepare: (user) => {
        user.roles = ["operator"];
      },
    });
    open(OWN);
    await waitFor(() => expect(box("dns").checked).toBe(true));
    expect(box("dns").closest("fieldset")?.disabled).toBe(true);
    expect(screen.queryByTestId("node-roles-save")).toBeNull();
  });
});
