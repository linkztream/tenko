import { cleanup, fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { api } from "../api/client";
import { server } from "../api/mock/node";
import { NODE_IDS } from "../api/mock/nodes-store";
import { renderRoute } from "../app/testing/render";
import { axeViolations } from "../app/testing/axe";
import { signInAlex } from "../auth/account/testkit";
import { setSessionForTest } from "../auth/session";
import { RolesEditor } from "./RolesEditor";
import { changeOf, lockOf, nextPhase, unpreparedOn } from "./roles";

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

  it("lists the roles a draft switches on that the machine is not prepared for", () => {
    const prepared = {
      file: "prepared-roles",
      dropins: [],
      ports: [],
      roles: [
        { role: "dns", prepared: true, missing: [] },
        { role: "probe", prepared: false, missing: ["CAP_NET_RAW"], command: "sudo bash install.sh --prepare" },
      ],
    };
    expect(unpreparedOn(["controller", "dns", "probe"], ["controller", "dns"], prepared).map((p) => p.role)).toEqual(["probe"]);
    // A role that is stored already is not warned about, and nothing is without a record.
    expect(unpreparedOn(["controller", "probe"], ["controller", "probe"], prepared)).toEqual([]);
    expect(unpreparedOn(["controller", "probe"], ["controller"], undefined)).toEqual([]);
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
              params: { roles: "probe", dropins: "probe.conf", capability: "CAP_NET_RAW", command: "sudo bash install.sh --prepare" },
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
    expect(finding.textContent).toContain("sudo bash install.sh --prepare");
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

describe("what the installer prepared", () => {
  const COMMAND = "sudo bash install.sh --prepare --roles controller,dns,probe";
  const prepared = {
    file: "/var/lib/tenko/prepared-roles",
    profile: "hardened",
    dropins: [],
    ports: [],
    roles: [
      { role: "controller", prepared: true, missing: [] },
      { role: "dns", prepared: true, missing: [] },
      { role: "dhcp", prepared: false, missing: ["dhcp-direct.conf", "67/udp"], command: COMMAND },
      { role: "probe", prepared: false, missing: ["probe.conf", "CAP_NET_RAW"], command: COMMAND },
    ],
  };

  /** Answers the roles of this controller with `extra` on top of the mock (stored set: controller and dns). */
  async function answer(extra: Record<string, unknown>) {
    const roles = await api.get("/api/v1/nodes/{id}/roles", { path: { id: OWN } });
    const body = { ...roles, configured: ["controller", "dns"], running: ["controller", "dns"], prepared: undefined, ...extra };
    server.use(http.get("*/api/v1/nodes/:id/roles", () => HttpResponse.json(body)));
  }

  const tag = (role: string) => screen.getByTestId(`node-role-prepared-${role}`);

  it("labels every role as prepared or not prepared", async () => {
    await answer({ prepared });
    open(OWN);
    await waitFor(() => expect(tag("dns").dataset.state).toBe("prepared"));
    expect(tag("dns").textContent).toBe("Prepared");
    expect(tag("controller").dataset.state).toBe("prepared");
    expect(tag("dhcp").dataset.state).toBe("unprepared");
    expect(tag("probe").textContent).toBe("Not prepared");
    expect(screen.queryByTestId("node-roles-unprepared")).toBeNull();
  });

  it("shows no label without a record of the installer", async () => {
    await answer({});
    open(OWN);
    await waitFor(() => expect(box("dns").checked).toBe(true));
    expect(screen.queryByTestId("node-role-prepared-dns")).toBeNull();
    expect(screen.queryByTestId("node-role-prepared-probe")).toBeNull();
    fireEvent.click(box("probe"));
    expect(screen.queryByTestId("node-roles-unprepared")).toBeNull();
  });

  it("warns, with what is missing and the command, while the draft switches on an unprepared role", async () => {
    await answer({ prepared });
    open(OWN);
    await waitFor(() => expect(box("dns").checked).toBe(true));
    // Switching on a role is not locked.
    fireEvent.click(box("probe"));
    expect(box("probe").checked).toBe(true);
    const warning = await screen.findByTestId("node-roles-unprepared");
    expect(warning.textContent).toContain("probe");
    expect(warning.textContent).toContain("probe.conf and CAP_NET_RAW");
    expect(within(warning).getByTestId("node-roles-unprepared-command").textContent).toBe(COMMAND);
    expect(screen.getAllByTestId("node-roles-unprepared")).toHaveLength(1);

    fireEvent.click(box("dhcp"));
    expect(screen.getAllByTestId("node-roles-unprepared")).toHaveLength(2);

    // The warning is part of the confirmation.
    fireEvent.click(screen.getByTestId("node-roles-save"));
    const dialog = await screen.findByTestId("node-roles-confirm");
    expect(within(dialog).getAllByTestId("node-roles-unprepared")).toHaveLength(2);
    expect(within(dialog).getAllByTestId("node-roles-unprepared-command")[0]?.textContent).toBe(COMMAND);
    fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));

    // Switched off again, the warning goes.
    fireEvent.click(box("probe"));
    fireEvent.click(box("dhcp"));
    expect(screen.queryByTestId("node-roles-unprepared")).toBeNull();
  });

  it("does not warn when the draft switches on a prepared role", async () => {
    await answer({ configured: ["controller"], running: ["controller"], prepared });
    open(OWN);
    await waitFor(() => expect(box("controller").checked).toBe(true));
    fireEvent.click(box("dns"));
    expect(box("dns").checked).toBe(true);
    expect(screen.queryByTestId("node-roles-unprepared")).toBeNull();
  });

  it("shows the labels but no switches to a non-administrator", async () => {
    await signInAlex({
      prepare: (user) => {
        user.roles = ["operator"];
      },
    });
    await answer({ prepared });
    open(OWN);
    await waitFor(() => expect(tag("probe").dataset.state).toBe("unprepared"));
    expect(box("probe").closest("fieldset")?.disabled).toBe(true);
    expect(screen.queryByTestId("node-roles-save")).toBeNull();
  });
});
