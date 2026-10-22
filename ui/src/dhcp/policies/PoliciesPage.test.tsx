// The DHCP policies: the list in evaluation order (scope first, then the server) with the condition
// and the action in words, creating a policy with a condition over classes and matches and an
// action (the local checks first, the server's refusals under the field), editing with the
// revision, deleting, the note that matching comes later, who sees what, Swedish.
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { DHCP_IDS } from "../../api/mock/dhcp-model";
import { DNS_IDS } from "../../api/mock/dns-model";
import { dhcpState } from "../../api/mock/routes-dhcp";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { signInAlex } from "../../auth/account/testkit";
import { signInWithRoles } from "../../auth/scope-testkit";
import { setSessionForTest } from "../../auth/session";
import { setLocale } from "../../i18n";
import { dhcpSwitchedOff, recordIfMatch, row, rowAction, rowActions, rows } from "../testkit";
import PoliciesPage from "./PoliciesPage";

beforeEach(async () => {
  await signInAlex();
});

afterEach(async () => {
  setSessionForTest(null);
  await setLocale("en");
});

const open = () => renderRoute(PoliciesPage, { url: "/dhcp/policies", path: "/dhcp/policies" });
const loaded = () => waitFor(() => expect(rows("dhcp-policies").length).toBeGreaterThan(0));
const termRows = (dialog: HTMLElement) => within(dialog).getAllByTestId("term-row");
const chooseScope = async (dialog: HTMLElement, value: string) => {
  const select = within(dialog).getByTestId("field-scope") as HTMLSelectElement;
  await waitFor(() => expect(select.options.length).toBeGreaterThan(1));
  fireEvent.change(select, { target: { value } });
};

describe("the policies", () => {
  it("lists the policy with its scope, the condition and the action in words, and says matching comes later", async () => {
    const view = open();
    await loaded();
    expect(screen.getByTestId("policies-note").textContent).toContain("first matching policy sets");
    const pxe = row("dhcp-policies", "pxe-boot");
    await waitFor(() => expect(within(pxe).getByTestId("policy-scope").dataset.key).toBe("192.0.2.0/24"));
    expect(within(pxe).getByTestId("policy-scope").getAttribute("href")).toBe(`/dhcp/scopes/${DHCP_IDS.lan}`);
    await waitFor(() => expect(within(pxe).getByTestId("policy-condition-words").textContent).toBe("in class pxe-clients"));
    expect(within(pxe).getByTestId("policy-action-words").textContent).toContain("lease time default 1 hr");
    expect(within(pxe).getByTestId("policy-enabled").dataset.key).toBe("on");
    expect(within(pxe).getByTestId("policy-order").textContent).toBe("1");
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("puts the policies of the scopes first and those of the server last", async () => {
    dhcpState().policies.push({
      ...dhcpState().policies[0]!,
      id: "0190d1c2-0000-7000-8000-00000000e1f1",
      name: "everywhere",
      scope: undefined,
      order: 1,
    });
    dhcpState().policies.push({ ...dhcpState().policies[0]!, id: "0190d1c2-0000-7000-8000-00000000e1f2", name: "second", order: 2 });
    open();
    await loaded();
    await waitFor(() => expect(rows("dhcp-policies")).toHaveLength(3));
    expect(rows("dhcp-policies").map((r) => r.dataset.key)).toEqual(["pxe-boot", "second", "everywhere"]);
    expect(within(row("dhcp-policies", "everywhere")).getByTestId("policy-scope").dataset.key).toBe("server");
  });

  it("creates a policy with a condition over a class and a match, and an action", async () => {
    const writes = recordIfMatch();
    open();
    await loaded();
    fireEvent.click(screen.getByTestId("dhcp-policy-create"));
    const dialog = await screen.findByTestId("dialog-policy-form");
    fireEvent.input(within(dialog).getByTestId("field-name"), { target: { value: "printers" } });
    await chooseScope(dialog, DHCP_IDS.lan);
    fireEvent.change(within(dialog).getByTestId("field-join"), { target: { value: "or" } });
    // Term 1: not in the class; term 2: the host name starts with.
    const first = termRows(dialog)[0]!;
    fireEvent.change(within(first).getByTestId("term-kind"), { target: { value: "not_class" } });
    await waitFor(() => expect((within(first).getByTestId("term-class") as HTMLSelectElement).options.length).toBeGreaterThan(1));
    fireEvent.change(within(first).getByTestId("term-class"), { target: { value: DHCP_IDS.class } });
    fireEvent.click(within(dialog).getByTestId("term-add"));
    const second = termRows(dialog)[1]!;
    fireEvent.change(within(second).getByTestId("term-kind"), { target: { value: "match" } });
    fireEvent.change(within(second).getByTestId("match-kind"), { target: { value: "host_name" } });
    fireEvent.input(within(second).getByTestId("match-value"), { target: { value: "printer" } });
    fireEvent.click(within(second).getByTestId("match-prefix"));
    fireEvent.input(within(dialog).getByTestId("field-range-first"), { target: { value: "192.0.2.120" } });
    fireEvent.input(within(dialog).getByTestId("field-range-last"), { target: { value: "192.0.2.129" } });
    fireEvent.click(within(dialog).getByTestId("field-lease-inherit"));
    fireEvent.input(within(dialog).getByTestId("field-lease-default"), { target: { value: "8" } });
    fireEvent.change(within(dialog).getByTestId("field-lease-default-unit"), { target: { value: "hours" } });
    fireEvent.input(within(dialog).getByTestId("field-lease-min"), { target: { value: "1" } });
    fireEvent.change(within(dialog).getByTestId("field-lease-min-unit"), { target: { value: "hours" } });
    fireEvent.input(within(dialog).getByTestId("field-lease-max"), { target: { value: "1" } });
    fireEvent.change(within(dialog).getByTestId("field-lease-max-unit"), { target: { value: "days" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(rows("dhcp-policies").map((r) => r.dataset.key)).toEqual(["pxe-boot", "printers"]));
    expect(writes().find((w) => w.method === "POST")?.body).toEqual({
      name: "printers",
      scope: DHCP_IDS.lan,
      enabled: true,
      condition: { join: "or", terms: [{ not_class: DHCP_IDS.class }, { match: { host_name: { value: "printer", prefix: true } } }] },
      action: { range: { first: "192.0.2.120", last: "192.0.2.129" }, lease: { default_secs: 28_800, min_secs: 3600, max_secs: 86_400 } },
    });
    expect(dhcpState().policies.find((p) => p.name === "printers")?.order).toBe(2);
    await waitFor(() => expect(within(row("dhcp-policies", "printers")).getByTestId("policy-condition-words").textContent).toBe('not in class pxe-clients or host name starting with "printer"'));
  });

  it("checks the name, the terms, the range and the lease times before it sends", async () => {
    const writes = recordIfMatch();
    open();
    await loaded();
    fireEvent.click(screen.getByTestId("dhcp-policy-create"));
    const dialog = await screen.findByTestId("dialog-policy-form");
    await chooseScope(dialog, DHCP_IDS.lan);
    fireEvent.input(within(dialog).getByTestId("field-name"), { target: { value: "Bad" } });
    fireEvent.input(within(dialog).getByTestId("field-order"), { target: { value: "x" } });
    fireEvent.input(within(dialog).getByTestId("field-range-first"), { target: { value: "192.0.2.120" } });
    fireEvent.input(within(dialog).getByTestId("field-range-last"), { target: { value: "198.51.100.5" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(within(dialog).getAllByTestId("field-error").map((e) => e.dataset.field)).toEqual(["name", "order", "term-0", "range-first"]));
    expect(within(dialog).getByTestId("term-row").textContent).toContain("Choose a class.");
    expect(within(dialog).getAllByTestId("field-error")[3]?.textContent).toBe("The range must lie inside the network of the scope.");
    expect(writes()).toHaveLength(0);
  });

  it("shows the refusal of the server when the name exists in the scope", async () => {
    open();
    await loaded();
    fireEvent.click(screen.getByTestId("dhcp-policy-create"));
    const dialog = await screen.findByTestId("dialog-policy-form");
    await chooseScope(dialog, DHCP_IDS.lan);
    fireEvent.input(within(dialog).getByTestId("field-name"), { target: { value: "pxe-boot" } });
    const first = termRows(dialog)[0]!;
    await waitFor(() => expect((within(first).getByTestId("term-class") as HTMLSelectElement).options.length).toBeGreaterThan(1));
    fireEvent.change(within(first).getByTestId("term-class"), { target: { value: DHCP_IDS.class } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(within(dialog).getByTestId("field-error").textContent).toBe("The policy is not valid (name)."));
  });

  it("edits a policy with the revision read, without changing its scope", async () => {
    const writes = recordIfMatch();
    open();
    await loaded();
    const revision = dhcpState().policies[0]!.revision;
    await rowAction(row("dhcp-policies", "pxe-boot"), "edit");
    const dialog = await screen.findByTestId("dialog-policy-form");
    const scope = within(dialog).getByTestId("field-scope") as HTMLSelectElement;
    expect(scope.disabled).toBe(true);
    await waitFor(() => expect(scope.value).toBe(DHCP_IDS.lan));
    expect((within(dialog).getByTestId("field-lease-inherit") as HTMLInputElement).checked).toBe(false);
    expect((within(dialog).getByTestId("field-lease-default") as HTMLInputElement).value).toBe("1");
    fireEvent.click(within(dialog).getByTestId("field-enabled"));
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(dhcpState().policies[0]!.enabled).toBe(false));
    const sent = writes().find((w) => w.method === "PATCH");
    expect(sent?.ifMatch).toBe(`"${revision}"`);
    expect(sent?.body).toMatchObject({ name: "pxe-boot", enabled: false, order: 1 });
    await waitFor(() => expect(within(row("dhcp-policies", "pxe-boot")).getByTestId("policy-enabled").dataset.key).toBe("off"));
  });

  it("deletes a policy after the confirmation", async () => {
    open();
    await loaded();
    await rowAction(row("dhcp-policies", "pxe-boot"), "delete");
    fireEvent.click(within(await screen.findByTestId("dialog-policy-delete")).getByTestId("confirm-ok"));
    await waitFor(() => expect(rows("dhcp-policies")).toHaveLength(0));
    expect(await screen.findByTestId("dhcp-policies-empty")).toBeTruthy();
  });

  it("creates a policy for an architecture with a DDNS action, then continues with its options", async () => {
    const writes = recordIfMatch();
    open();
    await loaded();
    fireEvent.click(screen.getByTestId("dhcp-policy-create"));
    const dialog = await screen.findByTestId("dialog-policy-form");
    fireEvent.input(within(dialog).getByTestId("field-name"), { target: { value: "uefi-boot" } });
    await chooseScope(dialog, DHCP_IDS.lan);
    const first = termRows(dialog)[0]!;
    fireEvent.change(within(first).getByTestId("term-kind"), { target: { value: "match" } });
    fireEvent.change(within(first).getByTestId("match-kind"), { target: { value: "architecture" } });
    fireEvent.change(within(first).getByTestId("match-arch"), { target: { value: "7" } });
    // The options come once the policy exists.
    expect(within(dialog).getByTestId("policy-options-new")).toBeTruthy();
    expect(within(dialog).queryByTestId("policy-optset")).toBeNull();
    // The DDNS action starts from the settings of the server, with DDNS on.
    const ddns = within(dialog).getByTestId("policy-ddns");
    expect(within(ddns).queryByTestId("ddns-fields")).toBeNull();
    fireEvent.click(within(ddns).getByTestId("field-policy-ddns-on"));
    const zone = within(ddns).getByTestId("field-ddns-zone") as HTMLSelectElement;
    await waitFor(() => expect([...zone.options].map((o) => o.textContent)).toContain("example.test"));
    expect([...zone.options].map((o) => o.textContent)).not.toContain("2.0.192.in-addr.arpa");
    fireEvent.change(zone, { target: { value: DNS_IDS.zone.example } });
    fireEvent.input(within(ddns).getByTestId("field-ddns-ttl"), { target: { value: "300" } });
    fireEvent.click(within(ddns).getByTestId("field-ddns-client-a"));
    fireEvent.click(within(dialog).getByTestId("form-submit"));

    await waitFor(() => expect(rows("dhcp-policies").map((r) => r.dataset.key)).toEqual(["pxe-boot", "uefi-boot"]));
    expect(writes().find((w) => w.method === "POST")?.body).toEqual({
      name: "uefi-boot",
      scope: DHCP_IDS.lan,
      enabled: true,
      condition: { join: "and", terms: [{ match: { architecture: { code: 7 } } }] },
      action: {
        ddns: { enabled: true, reverse: true, conflict: "protect", client_may_update_a: true, legacy_clients: true, refuse_foreign: false, forward_zone: DNS_IDS.zone.example, ttl: 300 },
      },
    });
    await waitFor(() => expect(within(row("dhcp-policies", "uefi-boot")).getByTestId("policy-condition-words").textContent).toBe("client architecture UEFI x64 (7)"));
    await waitFor(() => expect(within(row("dhcp-policies", "uefi-boot")).getByTestId("policy-action-words").textContent).toBe("DDNS on, zone example.test"));

    // The dialog now edits the policy that exists, with the editor of its option set.
    const editor = await screen.findByTestId("policy-optset");
    const made = dhcpState().policies.find((p) => p.name === "uefi-boot")!;
    expect(editor.dataset.owner).toBe(`policy:${made.id}`);
    expect(screen.getByTestId("dialog-policy-form").textContent).toContain("Policy uefi-boot");
    expect((screen.getByTestId("field-scope") as HTMLSelectElement).disabled).toBe(true);
    await waitFor(() => expect(screen.getByTestId("optset-add")).toBeTruthy());
    fireEvent.change(screen.getByTestId("optset-add"), { target: { value: "dhcp4|3" } });
    const routers = await waitFor(() => within(editor).getAllByTestId("optset-row").find((r) => r.dataset.key === "dhcp4:3") as HTMLElement);
    fireEvent.input(within(routers).getByTestId("optset-value"), { target: { value: "192.0.2.1" } });
    fireEvent.click(within(editor).getByTestId("optset-save"));
    await waitFor(() => expect(dhcpState().optionSets.get(`policy:${made.id}`)?.values).toHaveLength(1));
    expect(writes().find((w) => w.method === "PUT")?.url).toContain(`/option-sets/policy%3A${made.id}`);
    // The list says the policy has options now.
    await waitFor(() => expect(within(row("dhcp-policies", "uefi-boot")).getByTestId("policy-action-words").textContent).toBe("DDNS on, zone example.test; options"));
  });

  it("edits the DDNS action of a policy and takes it away with the switch", async () => {
    dhcpState().policies[0]!.action = { ddns: { enabled: true, ttl: 600, conflict: "replace" } };
    const writes = recordIfMatch();
    open();
    await loaded();
    await waitFor(() => expect(within(row("dhcp-policies", "pxe-boot")).getByTestId("policy-action-words").textContent).toBe("DDNS on"));
    await rowAction(row("dhcp-policies", "pxe-boot"), "edit");
    const dialog = await screen.findByTestId("dialog-policy-form");
    expect((within(dialog).getByTestId("field-policy-ddns-on") as HTMLInputElement).checked).toBe(true);
    expect((within(dialog).getByTestId("field-ddns-ttl") as HTMLInputElement).value).toBe("600");
    expect((within(dialog).getByTestId("field-ddns-conflict") as HTMLSelectElement).value).toBe("replace");
    // The editor of the policy's own option set is there for a policy that exists.
    expect(await within(dialog).findByTestId("policy-optset")).toBeTruthy();
    fireEvent.click(within(dialog).getByTestId("field-policy-ddns-on"));
    expect(within(dialog).queryByTestId("ddns-fields")).toBeNull();
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(dhcpState().policies[0]!.action?.ddns).toBeUndefined());
    expect((writes().find((w) => w.method === "PATCH")?.body as { action: object }).action).toEqual({});
  });

  it("checks the TTL of the DDNS action and shows the refusal of the server under it", async () => {
    const writes = recordIfMatch();
    open();
    await loaded();
    await rowAction(row("dhcp-policies", "pxe-boot"), "edit");
    const dialog = await screen.findByTestId("dialog-policy-form");
    fireEvent.click(within(dialog).getByTestId("field-policy-ddns-on"));
    fireEvent.input(within(dialog).getByTestId("field-ddns-ttl"), { target: { value: "abc" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(within(dialog).getAllByTestId("field-error").map((e) => e.dataset.field)).toEqual(["ddns-ttl"]));
    expect(within(dialog).getByTestId("field-error").textContent).toContain("whole number of seconds");
    expect(writes()).toHaveLength(0);
    // A week and a second: the form accepts it, the server does not.
    fireEvent.input(within(dialog).getByTestId("field-ddns-ttl"), { target: { value: "604801" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(writes().filter((w) => w.method === "PATCH")).toHaveLength(1));
    await waitFor(() => expect(within(dialog).getAllByTestId("field-error").map((e) => e.dataset.field)).toEqual(["ddns-ttl"]));
    expect(dhcpState().policies[0]!.action?.ddns).toBeUndefined();
  });

  it("offers a viewer nothing to change", async () => {
    await signInWithRoles(["viewer"]);
    open();
    await loaded();
    expect(screen.queryByTestId("dhcp-policy-create")).toBeNull();
    expect(await rowActions(row("dhcp-policies", "pxe-boot"))).toEqual([]);
  });

  it("says the module is switched off", async () => {
    dhcpSwitchedOff();
    open();
    expect(await screen.findByTestId("dhcp-off")).toBeTruthy();
    expect(screen.queryByTestId("policies-note")).toBeNull();
  });

  it("speaks Swedish", async () => {
    await setLocale("sv");
    open();
    await loaded();
    expect(screen.getByRole("heading", { level: 1 }).textContent).toContain("DHCP-principer");
    await waitFor(() => expect(within(row("dhcp-policies", "pxe-boot")).getByTestId("policy-condition-words").textContent).toBe("i klassen pxe-clients"));
    expect(screen.getByTestId("policies-note").textContent).toContain("första matchande principen");
  });
});
