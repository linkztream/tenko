// "Why did this client get this value" on the options tab of a scope: the form sends every fact of
// the client, the answer shows the reservation, the classes the client is in and the policies that
// match it in order, and for each option its value, level, owner and the line saying why; the local
// checks of the facts; Swedish.
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DHCP_IDS } from "../api/mock/dhcp-model";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { signInAlex } from "../auth/account/testkit";
import { setSessionForTest } from "../auth/session";
import { setLocale } from "../i18n";
import { createClass, createPolicy, putOptionSet } from "./api";
import ScopePage from "./ScopePage";

beforeEach(async () => {
  await signInAlex();
});

afterEach(async () => {
  vi.restoreAllMocks();
  setSessionForTest(null);
  await setLocale("en");
});

const open = () => renderRoute(ScopePage, { url: `/dhcp/scopes/${DHCP_IDS.lan}/options`, path: "/dhcp/scopes/:prefix/:tab?" });
const type = (id: string, text: string) => fireEvent.input(screen.getByTestId(id), { target: { value: text } });
const show = () => fireEvent.click(screen.getByTestId("effective-show"));

/** The effective-options requests made so far, as their query strings. */
function queries(spy: { mock: { calls: readonly (readonly unknown[])[] } }): URLSearchParams[] {
  return spy.mock.calls.map(([url]) => String(url)).filter((url) => url.includes("/effective-options")).map((url) => new URL(url, "http://localhost").searchParams);
}

/** A class for UEFI x64 clients and a policy of the LAN, first in order, that gives them a boot file and a domain name. */
async function bootPolicy() {
  const uefi = await createClass({ name: "uefi-x64", matches: [{ architecture: { code: 7 } }] });
  const policy = await createPolicy({ name: "uefi-boot", scope: DHCP_IDS.lan, order: 0, condition: { join: "and", terms: [{ class: uefi.id }] } });
  await putOptionSet({ path: `policy:${policy.id}`, revision: 0 }, [
    { space: "dhcp4", code: 15, typed: { text: "uefi.example.test" } },
    { space: "dhcp4", code: 67, typed: { text: "uefi.efi" } },
  ]);
  return { uefi, policy };
}

describe("the facts of the client", () => {
  it("sends every one of them and shows the classes, the policies and where each option comes from", async () => {
    await bootPolicy();
    const spy = vi.spyOn(globalThis, "fetch");
    const view = open();
    await screen.findByTestId("field-mac");
    type("field-mac", "00:00:5E:00:53:01");
    type("field-client_id", "01:aa:bb");
    type("field-vendor_class", "PXEClient:Arch:00007");
    type("field-user_class", "iPXE");
    fireEvent.change(screen.getByTestId("field-architecture"), { target: { value: "7" } });
    type("field-host_name", "boot-1");
    show();
    const result = await screen.findByTestId("effective-options");
    const sent = queries(spy).at(-1)!;
    expect(Object.fromEntries(sent)).toEqual({
      mac: "00:00:5e:00:53:01",
      client_id: "01aabb",
      vendor_class: "PXEClient:Arch:00007",
      user_class: "iPXE",
      architecture: "7",
      host_name: "boot-1",
    });

    // The classes by name, and the policies by name in the order the matcher gives, linked to the policies.
    await waitFor(() => expect(within(result).getAllByTestId("effective-class").map((c) => c.dataset.key).sort()).toEqual(["pxe-clients", "uefi-x64"]));
    await waitFor(() => expect(within(result).getAllByTestId("effective-policy").map((p) => p.dataset.key)).toEqual(["uefi-boot", "pxe-boot"]));
    const policies = within(result).getAllByTestId("effective-policy");
    expect(within(policies[0]!).getByRole("link").getAttribute("href")).toBe("/dhcp/policies");

    // Each option: its level, its owner (the policy's name for the policy level) and why.
    await waitFor(() => expect(within(result).getAllByTestId("effective-option")[1]?.dataset.owner).toBe("uefi-boot"));
    const options = within(result).getAllByTestId("effective-option");
    expect(options.map((o) => [o.dataset.code, o.dataset.level, o.dataset.owner])).toEqual([
      ["6", "server", "server"],
      ["15", "policy", "uefi-boot"],
      ["3", "scope", "scope"],
      ["67", "policy", "uefi-boot"],
    ]);
    const domain = options[1]!;
    expect(domain.textContent).toContain("uefi.example.test");
    expect(within(domain).getByTestId("effective-level").textContent).toBe("Policy");
    expect(within(domain).getByTestId("effective-why").textContent).toBe("From policy uefi-boot, the first matching policy that sets it");
    expect(within(options[0]!).getByTestId("effective-why").textContent).toBe("From the options of the server");
    expect(within(options[2]!).getByTestId("effective-why").textContent).toBe("From the options of this scope");
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("sends only the MAC address when nothing else is filled in, and says the client is in no class and no policy", async () => {
    const spy = vi.spyOn(globalThis, "fetch");
    open();
    await screen.findByTestId("field-mac");
    type("field-mac", "02:00:00:00:00:01");
    show();
    await screen.findByTestId("effective-options");
    expect(Object.fromEntries(queries(spy).at(-1)!)).toEqual({ mac: "02:00:00:00:00:01" });
    expect(screen.getByTestId("effective-classes-none")).toBeTruthy();
    expect(screen.getByTestId("effective-policies-none")).toBeTruthy();
    expect(screen.queryAllByTestId("effective-class")).toEqual([]);
    expect(screen.getAllByTestId("effective-option").map((o) => o.dataset.owner)).toEqual(["server", "server", "scope"]);
  });

  it("takes an architecture that has no name with the number input", async () => {
    const spy = vi.spyOn(globalThis, "fetch");
    open();
    await screen.findByTestId("field-mac");
    type("field-mac", "02:00:00:00:00:01");
    const picker = screen.getByTestId("field-architecture") as HTMLSelectElement;
    expect([...picker.options].map((o) => o.value)).toEqual(["", "0", "6", "7", "9", "10", "11", "15", "16", "19", "other"]);
    expect(picker.options[0]?.textContent).toBe("Not sent");
    expect(screen.queryByTestId("field-architecture-value")).toBeNull();
    fireEvent.change(picker, { target: { value: "other" } });
    type("field-architecture-value", "33");
    show();
    await screen.findByTestId("effective-options");
    expect(queries(spy).at(-1)!.get("architecture")).toBe("33");
  });

  it("checks the facts before it asks", async () => {
    const spy = vi.spyOn(globalThis, "fetch");
    open();
    await screen.findByTestId("field-mac");
    type("field-mac", "not a mac");
    type("field-client_id", "xyz");
    fireEvent.change(screen.getByTestId("field-architecture"), { target: { value: "other" } });
    type("field-architecture-value", "70000");
    show();
    await waitFor(() => expect(screen.getAllByTestId("field-error").map((e) => e.dataset.field).sort()).toEqual(["architecture-menu", "client_id", "mac"]));
    expect(queries(spy)).toHaveLength(0);
  });

  it("asks again for the client shown when the options of the scope were saved", async () => {
    const spy = vi.spyOn(globalThis, "fetch");
    open();
    await screen.findByTestId("field-mac");
    type("field-mac", "02:00:00:00:00:01");
    show();
    await screen.findByTestId("effective-options");
    const asked = queries(spy).length;
    const editor = await screen.findByTestId("scope-optset");
    await waitFor(() => expect(within(editor).getAllByTestId("optset-row")).toHaveLength(1));
    fireEvent.change(within(editor).getByTestId("optset-add"), { target: { value: "dhcp4|42" } });
    const row = within(editor).getAllByTestId("optset-row").find((r) => r.dataset.key === "dhcp4:42")!;
    fireEvent.input(within(row).getByTestId("optset-value"), { target: { value: "192.0.2.123" } });
    fireEvent.click(within(editor).getByTestId("optset-save"));
    await waitFor(() => expect(queries(spy).length).toBeGreaterThan(asked));
    await waitFor(() => expect(screen.getAllByTestId("effective-option").map((o) => o.dataset.code)).toContain("42"));
  });
});

describe("the language", () => {
  it("speaks Swedish", async () => {
    await bootPolicy();
    await setLocale("sv");
    open();
    await screen.findByTestId("field-mac");
    type("field-mac", "02:00:00:00:00:01");
    fireEvent.change(screen.getByTestId("field-architecture"), { target: { value: "7" } });
    show();
    const result = await screen.findByTestId("effective-options");
    await waitFor(() => expect(within(result).getAllByTestId("effective-option").some((o) => o.dataset.owner === "uefi-boot")).toBe(true));
    const policy = within(result).getAllByTestId("effective-option").find((o) => o.dataset.owner === "uefi-boot")!;
    expect(within(policy).getByTestId("effective-why").textContent).toBe("Från principen uefi-boot, den första matchande principen som anger det");
    expect(screen.getByText("Klasser som klienten ingår i")).toBeTruthy();
    expect(screen.getByTestId("field-architecture").getAttribute("aria-label")).toBe("Klientarkitektur (alternativ 93, valfri)");
  });
});
