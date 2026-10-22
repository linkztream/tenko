// The network boot tab of a scope: the form over the six boot options (only those are replaced, the
// other options of the set stay, the revision goes along, bad values are refused before anything is
// sent), what applies while a field is empty, the policies of the scope that set a boot file, the
// dialog that adds a boot file (a class reused or created, a policy, option 67, a partial result
// told as it is), and who sees what.
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { DHCP_IDS } from "../../api/mock/dhcp-model";
import { server } from "../../api/mock/node";
import { dhcpState } from "../../api/mock/routes-dhcp";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { signInAlex } from "../../auth/account/testkit";
import { signInWithRoles } from "../../auth/scope-testkit";
import { setSessionForTest } from "../../auth/session";
import { setLocale } from "../../i18n";
import { createClass, createPolicy, putOptionSet } from "../api";
import ScopePage from "../ScopePage";
import { recordIfMatch } from "../testkit";

beforeEach(async () => {
  await signInAlex();
});

afterEach(async () => {
  setSessionForTest(null);
  await setLocale("en");
});

const open = () => renderRoute(ScopePage, { url: `/dhcp/scopes/${DHCP_IDS.lan}/boot`, path: "/dhcp/scopes/:prefix/:tab?" });
/** Waits until the form is there with the set of the scope read. */
const ready = async () => screen.findByTestId("boot-form");
const type = (id: string, value: string) => fireEvent.input(screen.getByTestId(id), { target: { value } });
const input = (id: string) => screen.getByTestId(id) as HTMLInputElement;
/** The octets of a text in hexadecimal, as an option set holds them. */
const hexOf = (text: string) => [...new TextEncoder().encode(text)].map((b) => b.toString(16).padStart(2, "0")).join("");
const SCOPE_SET = `scope:${DHCP_IDS.lan}`;
const scopeSet = () => dhcpState().optionSets.get(SCOPE_SET);
const optionWrites = (writes: ReturnType<typeof recordIfMatch>) => writes().filter((w) => w.method === "PUT" && w.url.includes("/option-sets/"));

/** A policy of the seeded scope that sets a boot file, made through the API as a person would. */
async function bootPolicy(name: string, file: string, options: { order?: number; enabled?: boolean } = {}) {
  const policy = await createPolicy({
    name,
    scope: DHCP_IDS.lan,
    ...(options.order === undefined ? {} : { order: options.order }),
    enabled: options.enabled ?? true,
    condition: { join: "or", terms: [{ class: DHCP_IDS.class }] },
    action: {},
  });
  await putOptionSet({ path: `policy:${policy.id}`, revision: 0 }, [{ code: 67, typed: { text: file } }]);
  return policy;
}

describe("the boot form", () => {
  it("shows the six fields over the scope's own set, empty where the set holds no boot option", async () => {
    const view = open();
    await ready();
    for (const id of ["next-server", "tftp-name", "file", "pxelinux-config", "pxelinux-prefix", "pxelinux-reboot"]) {
      expect(input(`field-boot-${id}`).value).toBe("");
    }
    expect(screen.getByTestId("scope-boot")).toBeTruthy();
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("saves only the boot options, keeps the other option of the set, and sends the revision it read", async () => {
    const writes = recordIfMatch();
    open();
    await ready();
    const revision = scopeSet()?.revision;
    type("field-boot-next-server", "192.0.2.10, 192.0.2.11");
    type("field-boot-tftp-name", "tftp.example.test");
    type("field-boot-file", "undionly.kpxe");
    type("field-boot-pxelinux-config", "pxelinux.cfg/default");
    type("field-boot-pxelinux-prefix", "/srv/tftp/");
    type("field-boot-pxelinux-reboot", "30");
    fireEvent.click(screen.getByTestId("boot-save"));
    await waitFor(() => expect(scopeSet()?.values.map((v) => v.code).sort((a, b) => a - b)).toEqual([3, 66, 67, 150, 209, 210, 211]));
    const sent = optionWrites(writes);
    expect(sent).toHaveLength(1);
    expect(sent[0]?.ifMatch).toBe(`"${revision}"`);
    const values = (sent[0]?.body as { values: { code: number; data?: string; typed?: unknown }[] }).values;
    // The router option of the scope goes back as it is, with its hexadecimal data.
    expect(values[0]).toEqual({ code: 3, data: "c0000201" });
    expect(values.slice(1).map((v) => v.code)).toEqual([150, 66, 67, 209, 210, 211]);
    expect(values.find((v) => v.code === 150)?.typed).toEqual({ ipv4: { values: ["192.0.2.10", "192.0.2.11"] } });
    expect(values.find((v) => v.code === 211)?.typed).toEqual({ unsigned: [30] });
    expect(await screen.findByText("Boot settings saved")).toBeTruthy();
    // The form shows the set the server now holds.
    await waitFor(() => expect(input("field-boot-file").value).toBe("undionly.kpxe"));
  });

  it("takes an option out when its field is emptied, and leaves the others alone", async () => {
    await putOptionSet({ path: SCOPE_SET, revision: scopeSet()?.revision ?? 0 }, [
      { code: 3, typed: { ipv4: { values: ["192.0.2.1"] } } },
      { code: 67, typed: { text: "undionly.kpxe" } },
      { code: 150, typed: { ipv4: { values: ["192.0.2.10"] } } },
    ]);
    const writes = recordIfMatch();
    open();
    await ready();
    await waitFor(() => expect(input("field-boot-file").value).toBe("undionly.kpxe"));
    type("field-boot-file", "");
    fireEvent.click(screen.getByTestId("boot-save"));
    await waitFor(() => expect(scopeSet()?.values.map((v) => v.code)).toEqual([3, 150]));
    const sent = optionWrites(writes);
    expect((sent[0]?.body as { values: { code: number; data?: string }[] }).values).toEqual([
      { code: 3, data: "c0000201" },
      { code: 150, data: "c000020a" },
    ]);
  });

  it("refuses a bad next server, a bad number and a long text before it sends anything", async () => {
    const writes = recordIfMatch();
    open();
    await ready();
    type("field-boot-next-server", "192.0.2.300");
    type("field-boot-pxelinux-reboot", "soon");
    type("field-boot-file", "x".repeat(256));
    fireEvent.click(screen.getByTestId("boot-save"));
    await waitFor(() => expect(screen.getAllByTestId("field-error").map((e) => e.dataset.field)).toEqual(["boot-next-server", "boot-file", "boot-pxelinux-reboot"]));
    expect(input("field-boot-next-server").getAttribute("aria-invalid")).toBe("true");
    expect(optionWrites(writes)).toHaveLength(0);
    // An address of the wrong family is refused too.
    type("field-boot-next-server", "2001:db8::1");
    fireEvent.click(screen.getByTestId("boot-save"));
    await waitFor(() => expect(screen.getAllByTestId("field-error").map((e) => e.dataset.field)).toContain("boot-next-server"));
    expect(optionWrites(writes)).toHaveLength(0);
  });

  it("sends nothing when nothing changed", async () => {
    const writes = recordIfMatch();
    open();
    await ready();
    fireEvent.click(screen.getByTestId("boot-save"));
    expect(await screen.findByText("Nothing was changed.")).toBeTruthy();
    expect(optionWrites(writes)).toHaveLength(0);
  });

  it("shows the field the server names when it refuses a value", async () => {
    server.use(
      http.put("/api/v1/dhcp/option-sets/:owner", () =>
        HttpResponse.json(
          { type: "about:blank", status: 400, code: "dhcp.option.invalid", title: "Bad Request", detail: "option dhcp4 150: an address is required", params: { space: "dhcp4", code: "150", reason: "an address is required" } },
          { status: 400, headers: { "content-type": "application/problem+json" } },
        ),
      ),
    );
    open();
    await ready();
    type("field-boot-next-server", "192.0.2.10");
    fireEvent.click(screen.getByTestId("boot-save"));
    await waitFor(() => expect(screen.getAllByTestId("field-error").map((e) => e.dataset.field)).toEqual(["boot-next-server"]));
    expect(scopeSet()?.values.map((v) => v.code)).toEqual([3]);
  });

  it("says where the value comes from while a field is empty", async () => {
    await putOptionSet({ path: "server", revision: dhcpState().optionSets.get("server")?.revision ?? 0 }, [
      { code: 6, typed: { ipv4: { values: ["192.0.2.53"] } } },
      { code: 67, typed: { text: "pxelinux.0" } },
    ]);
    open();
    await ready();
    const inherited = await screen.findAllByTestId("boot-inherited");
    const byField = Object.fromEntries(inherited.map((e) => [e.dataset.field, e]));
    expect(byField["boot-file"]?.dataset.server).toBe("pxelinux.0");
    expect(byField["boot-file"]?.textContent).toBe("Not set here: the server's value applies, pxelinux.0.");
    expect(byField["boot-next-server"]?.dataset.server).toBe("");
    expect(byField["boot-next-server"]?.textContent).toBe("Not set here, and the server sets none.");
    // Once the scope sets a value there is nothing to say about the server's.
    type("field-boot-file", "undionly.kpxe");
    await waitFor(() => expect(inherited.some((e) => e.dataset.field === "boot-file" && e.isConnected)).toBe(false));
  });

  it("lets a viewer read the form and change nothing", async () => {
    await signInWithRoles(["viewer"]);
    scopeSet()?.values.push({ space: "dhcp4", code: 67, data: hexOf("undionly.kpxe") });
    open();
    await ready();
    await waitFor(() => expect(input("field-boot-file").value).toBe("undionly.kpxe"));
    expect(input("field-boot-file").readOnly).toBe(true);
    expect(screen.queryByTestId("boot-save")).toBeNull();
    expect(screen.queryByTestId("boot-add")).toBeNull();
  });
});

describe("the boot files per client type", () => {
  it("lists the policies of the scope that set option 67, lowest order first, with their condition in words", async () => {
    await bootPolicy("boot-bios", "undionly.kpxe", { order: 5 });
    await bootPolicy("boot-ipxe", "http://boot.example.test/boot.ipxe", { order: 2, enabled: false });
    // A policy of the scope without a boot file is not a boot policy.
    await createPolicy({ name: "no-boot", scope: DHCP_IDS.lan, condition: { join: "and", terms: [{ class: DHCP_IDS.class }] }, action: {} });
    open();
    const list = await screen.findByTestId("boot-policies");
    const rows = within(list).getAllByTestId("boot-policy");
    expect(rows.map((r) => r.dataset.key)).toEqual(["boot-ipxe", "boot-bios"]);
    expect(rows[0]?.dataset.file).toBe("http://boot.example.test/boot.ipxe");
    expect(rows[0]?.dataset.enabled).toBe("off");
    expect(rows[1]?.dataset.enabled).toBe("on");
    expect(within(rows[1] as HTMLElement).getByTestId("boot-policy-condition").textContent).toBe("in class pxe-clients");
    expect(screen.getByTestId("boot-policies-note").textContent).toMatch(/first matching policy wins/);
    expect(screen.getByTestId("boot-policies-link").getAttribute("href")).toBe("/dhcp/policies");
  });

  it("says so when no policy sets a boot file", async () => {
    open();
    expect(await screen.findByTestId("boot-policies-empty")).toBeTruthy();
    expect(screen.queryByTestId("boot-policies")).toBeNull();
  });
});

describe("adding a boot file", () => {
  const openDialog = async () => {
    open();
    await screen.findByTestId("boot-policies-empty");
    fireEvent.click(screen.getByTestId("boot-add"));
    return screen.findByTestId("dialog-boot-add");
  };
  const choose = (dialog: HTMLElement, kind: string, file: string) => {
    fireEvent.change(within(dialog).getByTestId("field-boot-kind"), { target: { value: kind } });
    fireEvent.input(within(dialog).getByTestId("field-boot-add-file"), { target: { value: file } });
  };
  const policyOf = (name: string) => dhcpState().policies.find((p) => p.name === name && p.scope === DHCP_IDS.lan);

  it("offers the six client types", async () => {
    const dialog = await openDialog();
    const select = within(dialog).getByTestId("field-boot-kind") as HTMLSelectElement;
    expect([...select.options].map((o) => o.value)).toEqual(["bios", "uefi-x64", "uefi-arm64", "http-x64", "http", "ipxe"]);
    fireEvent.change(select, { target: { value: "uefi-x64" } });
    expect(within(dialog).getByTestId("boot-add-matches").textContent).toBe("Applies to clients with: client architecture UEFI x64 (7) or client architecture UEFI x64 (EBC id) (9)");
  });

  it("creates the class, the policy of the scope and its option 67 for UEFI x64", async () => {
    const writes = recordIfMatch();
    const dialog = await openDialog();
    choose(dialog, "uefi-x64", "ipxe.efi");
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(screen.queryByTestId("dialog-boot-add")).toBeNull());
    const made = dhcpState().classes.find((c) => c.name === "boot-uefi-x64");
    expect(made?.matches).toEqual([{ architecture: { code: 7 } }, { architecture: { code: 9 } }]);
    const policy = policyOf("boot-uefi-x64");
    expect(policy?.condition).toEqual({ join: "or", terms: [{ class: made?.id }] });
    expect(policy?.enabled).toBe(true);
    // After the last policy of the scope.
    expect(policy?.order).toBe(2);
    const set = dhcpState().optionSets.get(`policy:${policy?.id}`);
    expect(set?.values).toEqual([{ space: "dhcp4", code: 67, data: hexOf("ipxe.efi") }]);
    expect(writes().map((w) => `${w.method} ${new URL(w.url, "http://x").pathname}`)).toEqual([
      "POST /api/v1/dhcp/classes",
      "POST /api/v1/dhcp/policies",
      `PUT /api/v1/dhcp/option-sets/policy%3A${policy?.id}`,
    ]);
    // The new policy shows in the list.
    const row = await screen.findByTestId("boot-policy");
    expect(row.dataset.key).toBe("boot-uefi-x64");
    expect(row.dataset.file).toBe("ipxe.efi");
    expect(await screen.findByText("Boot file added with the policy boot-uefi-x64")).toBeTruthy();
  });

  it("reuses a class whose matches are exactly those of the client type", async () => {
    const mine = await createClass({ name: "my-uefi", matches: [{ architecture: { code: 9 } }, { architecture: { code: 7 } }] });
    const writes = recordIfMatch();
    const dialog = await openDialog();
    choose(dialog, "uefi-x64", "ipxe.efi");
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(screen.queryByTestId("dialog-boot-add")).toBeNull());
    expect(writes().some((w) => w.method === "POST" && w.url.endsWith("/dhcp/classes"))).toBe(false);
    expect(dhcpState().classes.some((c) => c.name === "boot-uefi-x64")).toBe(false);
    expect(policyOf("boot-uefi-x64")?.condition).toEqual({ join: "or", terms: [{ class: mine.id }] });
  });

  it("makes the names unique with a number", async () => {
    await createClass({ name: "boot-bios", matches: [{ host_name: { value: "other", prefix: true } }] });
    await bootPolicy("boot-bios", "old.kpxe", { order: 3 });
    open();
    await screen.findByTestId("boot-policies");
    fireEvent.click(screen.getByTestId("boot-add"));
    const dialog = await screen.findByTestId("dialog-boot-add");
    choose(dialog, "bios", "undionly.kpxe");
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(screen.queryByTestId("dialog-boot-add")).toBeNull());
    const made = dhcpState().classes.find((c) => c.name === "boot-bios-2");
    expect(made?.matches).toEqual([{ architecture: { code: 0 } }]);
    expect(policyOf("boot-bios-2")?.condition).toEqual({ join: "or", terms: [{ class: made?.id }] });
  });

  it("orders the iPXE policy before the others of the scope", async () => {
    const dialog = await openDialog();
    // The seeded policy of the scope has the order 1: the chain policy gets 0.
    choose(dialog, "ipxe", "http://boot.example.test/boot.ipxe");
    expect(within(dialog).getByTestId("boot-add-order-help").textContent).toMatch(/goes before the others/);
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(screen.queryByTestId("dialog-boot-add")).toBeNull());
    expect(dhcpState().classes.find((c) => c.name === "boot-ipxe")?.matches).toEqual([{ user_class: { value: "iPXE" } }]);
    expect(policyOf("boot-ipxe")?.order).toBe(0);
  });

  it("checks the boot file before it sends anything", async () => {
    const writes = recordIfMatch();
    const dialog = await openDialog();
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(within(dialog).getByTestId("field-error").dataset.field).toBe("boot-add-file"));
    expect(writes()).toHaveLength(0);
  });

  it("reports a partial result as it is and goes on from there when tried again", async () => {
    server.use(
      http.put("/api/v1/dhcp/option-sets/:owner", () =>
        HttpResponse.json(
          { type: "about:blank", status: 503, code: "dhcp.store_refused", title: "Service Unavailable", detail: "the store refuses writes", params: {} },
          { status: 503, headers: { "content-type": "application/problem+json" } },
        ),
      ),
    );
    const dialog = await openDialog();
    choose(dialog, "bios", "undionly.kpxe");
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    const partial = await within(dialog).findByTestId("boot-add-partial");
    expect(partial.textContent).toBe("The policy boot-bios was created, but its boot file was not set. Try again to set the boot file.");
    expect(within(dialog).getByTestId("error-notice")).toBeTruthy();
    expect(dhcpState().classes.filter((c) => c.name === "boot-bios")).toHaveLength(1);
    expect(dhcpState().policies.filter((p) => p.name === "boot-bios")).toHaveLength(1);
    expect(dhcpState().optionSets.has(`policy:${policyOf("boot-bios")?.id}`)).toBe(false);
    // The server takes writes again: the retry sets the file and makes nothing twice.
    server.resetHandlers();
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(screen.queryByTestId("dialog-boot-add")).toBeNull());
    expect(dhcpState().classes.filter((c) => c.name === "boot-bios")).toHaveLength(1);
    expect(dhcpState().policies.filter((p) => p.name.startsWith("boot-bios"))).toHaveLength(1);
    expect(dhcpState().optionSets.get(`policy:${policyOf("boot-bios")?.id}`)?.values).toHaveLength(1);
  });
});
