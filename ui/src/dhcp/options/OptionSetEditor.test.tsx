// The option set editor on its own, on the option set of the server: a value input by the type of
// each option (a list of addresses, a number, true or false, text, names, classless routes, octets,
// a flag), the typed data it sends, a code without a known type as hexadecimal, removing a row, the
// refusals under the row they name or at the top, and the read-only view.
import { fireEvent, render, screen, waitFor, within } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { DHCP_IDS } from "../../api/mock/dhcp-model";
import { dhcpState } from "../../api/mock/routes-dhcp";
import { axeViolations } from "../../app/testing/axe";
import { IconSprite } from "../../components/Icon";
import { Toasts } from "../../components/toast";
import { signInAlex } from "../../auth/account/testkit";
import { setSessionForTest } from "../../auth/session";
import { setLocale } from "../../i18n";
import { recordIfMatch } from "../testkit";
import { OptionSetEditor } from "./OptionSetEditor";

beforeEach(async () => {
  await signInAlex();
});

afterEach(async () => {
  setSessionForTest(null);
  await setLocale("en");
});

function mount(props: { owner?: string; canWrite?: boolean; space?: "dhcp4" | "dhcp6" | "both" } = {}) {
  const view = render(() => (
    <>
      <IconSprite />
      <OptionSetEditor owner={props.owner ?? "server"} label="Options of the server" canWrite={props.canWrite ?? true} space={props.space} />
      <Toasts />
    </>
  ));
  return view;
}

const rowsOf = () => screen.getAllByTestId("optset-row");
const rowOf = (key: string) => rowsOf().find((r) => r.dataset.key === key) as HTMLElement;
const loaded = () => waitFor(() => expect(screen.getAllByTestId("optset-row").length).toBeGreaterThan(0));
const add = (value: string) => fireEvent.change(screen.getByTestId("optset-add"), { target: { value } });
const type = (key: string, text: string) => fireEvent.input(within(rowOf(key)).getByTestId("optset-value"), { target: { value: text } });
const serverSet = () => dhcpState().optionSets.get("server");

describe("the option set editor", () => {
  it("shows the options of the set with their names and types, and is accessible", async () => {
    const view = mount();
    await loaded();
    expect(rowsOf().map((r) => r.dataset.key)).toEqual(["dhcp4:6", "dhcp4:15"]);
    const dns = rowOf("dhcp4:6");
    expect(dns.textContent).toContain("domain-name-servers");
    expect(dns.textContent).toContain("IPv4 address, list");
    expect((within(dns).getByTestId("optset-value") as HTMLTextAreaElement).value).toBe("192.0.2.53");
    expect((within(rowOf("dhcp4:15")).getByTestId("optset-value") as HTMLInputElement).value).toBe("example.test");
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("offers the codes of the catalog and the definitions that are not in the set and are not the server's own", async () => {
    mount();
    await loaded();
    const options = Array.from((screen.getByTestId("optset-add") as HTMLSelectElement).options).map((o) => o.value);
    expect(options).toContain("dhcp4|3");
    expect(options).toContain("dhcp4|230");
    expect(options).not.toContain("dhcp4|6");
    expect(options).not.toContain("dhcp4|54");
    expect(options).not.toContain("dhcp4|51");
  });

  it("types each value by the type of its option and sends the typed data", async () => {
    const writes = recordIfMatch();
    mount();
    await loaded();
    add("dhcp4|3");
    type("dhcp4:3", "192.0.2.1");
    add("dhcp4|19");
    fireEvent.change(within(rowOf("dhcp4:19")).getByTestId("optset-value"), { target: { value: "false" } });
    add("dhcp4|2");
    type("dhcp4:2", "-3600");
    add("dhcp4|119");
    type("dhcp4:119", "example.test, lab.example.test");
    add("dhcp4|121");
    type("dhcp4:121", "203.0.113.0/24 via 192.0.2.1");
    add("dhcp4|43");
    type("dhcp4:43", "c0:ff");
    add("dhcp4|230");
    type("dhcp4:230", "4");
    fireEvent.click(screen.getByTestId("optset-save"));
    await waitFor(() => expect(serverSet()?.values).toHaveLength(9));
    const sent = writes().find((w) => w.method === "PUT");
    expect((sent?.body as { values: unknown[] }).values).toEqual([
      { code: 6, typed: { ipv4: { values: ["192.0.2.53"] } } },
      { code: 15, typed: { text: "example.test" } },
      { code: 3, typed: { ipv4: { values: ["192.0.2.1"] } } },
      { code: 19, typed: { bool: [false] } },
      { code: 2, typed: { signed: -3600 } },
      { code: 119, typed: { names: ["example.test", "lab.example.test"] } },
      { code: 121, typed: { routes: [{ destination: "203.0.113.0/24", router: "192.0.2.1" }] } },
      { code: 43, typed: { binary: "c0ff" } },
      { code: 230, typed: { unsigned: [4] } },
    ]);
    // Read back, the routes and the octets show the way they were typed.
    await waitFor(() => expect((within(rowOf("dhcp4:121")).getByTestId("optset-value") as HTMLTextAreaElement).value).toBe("203.0.113.0/24 via 192.0.2.1"));
    expect(serverSet()?.values.find((v) => v.code === 43)?.data).toBe("c0ff");
  });

  it("names what is wrong with a value under its row and sends nothing", async () => {
    const writes = recordIfMatch();
    mount();
    await loaded();
    add("dhcp4|26");
    type("dhcp4:26", "70000");
    add("dhcp4|121");
    type("dhcp4:121", "203.0.113.0/24");
    type("dhcp4:15", "");
    fireEvent.click(screen.getByTestId("optset-save"));
    await waitFor(() => expect(screen.getAllByTestId("optset-row-error").map((e) => e.dataset.key)).toEqual(["dhcp4:15", "dhcp4:26", "dhcp4:121"]));
    expect(screen.getAllByTestId("optset-row-error").map((e) => e.textContent)).toEqual([
      "Enter a value.",
      "A number is out of range for this option.",
      "Enter one route per line: destination via router.",
    ]);
    expect(writes()).toHaveLength(0);
  });

  it("edits a code without a known type as hexadecimal", async () => {
    mount();
    await loaded();
    fireEvent.input(screen.getByTestId("optset-add-code"), { target: { value: "x" } });
    fireEvent.click(screen.getByTestId("optset-add-code-go"));
    expect(screen.getByTestId("optset-code-error").textContent).toBe("Enter a code from 1 to 254.");
    fireEvent.input(screen.getByTestId("optset-add-code"), { target: { value: "200" } });
    fireEvent.click(screen.getByTestId("optset-add-code-go"));
    const raw = rowOf("dhcp4:200");
    expect(raw.textContent).toContain("no known type");
    type("dhcp4:200", "zz");
    fireEvent.click(screen.getByTestId("optset-save"));
    expect((await screen.findByTestId("optset-row-error")).textContent).toBe("Enter the value in hexadecimal, such as c0ff.");
  });

  it("shows the refusal of the server under the row of its code and keeps what was typed", async () => {
    mount();
    await loaded();
    fireEvent.input(screen.getByTestId("optset-add-code"), { target: { value: "200" } });
    fireEvent.click(screen.getByTestId("optset-add-code-go"));
    type("dhcp4:200", "c0ff");
    fireEvent.click(screen.getByTestId("optset-save"));
    const error = await screen.findByTestId("optset-row-error");
    expect(error.dataset.key).toBe("dhcp4:200");
    expect(error.textContent).toBe("This code has no definition. Define the option first.");
    expect((within(rowOf("dhcp4:200")).getByTestId("optset-value") as HTMLInputElement).value).toBe("c0ff");
    expect(serverSet()?.values).toHaveLength(2);
  });

  it("shows a refusal that names no row at the top", async () => {
    mount();
    await loaded();
    // Another session changed the set: the revision the editor holds is stale.
    serverSet()!.revision += 3;
    fireEvent.click(screen.getByTestId("optset-save"));
    const notice = await screen.findByTestId("error-notice");
    expect(notice.dataset.code).toBe("sys.store.precondition_failed");
  });

  it("removes a row and saves the rest, and clears the set when every row is gone", async () => {
    mount();
    await loaded();
    fireEvent.click(within(rowOf("dhcp4:15")).getByTestId("optset-remove"));
    fireEvent.click(screen.getByTestId("optset-save"));
    await waitFor(() => expect(serverSet()?.values.map((v) => v.code)).toEqual([6]));
    // The editor reads the saved set again before it takes new edits.
    await waitFor(() => expect((screen.getByTestId("optset-save") as HTMLButtonElement).disabled).toBe(false));
    fireEvent.click(within(rowOf("dhcp4:6")).getByTestId("optset-remove"));
    expect(await screen.findByTestId("optset-empty")).toBeTruthy();
    fireEvent.click(screen.getByTestId("optset-save"));
    await waitFor(() => expect(serverSet()).toBeUndefined());
  });

  it("discards the changes that are not saved", async () => {
    mount();
    await loaded();
    add("dhcp4|26");
    expect(rowsOf()).toHaveLength(3);
    fireEvent.click(screen.getByTestId("optset-revert"));
    await waitFor(() => expect(rowsOf()).toHaveLength(2));
  });

  it("shows a set without options at revision 0 as empty", async () => {
    mount({ owner: `shared_network:${DHCP_IDS.sharedNetwork}` });
    expect(await screen.findByText("No options are set at this level.")).toBeTruthy();
  });

  it("is read only without the right to write", async () => {
    mount({ canWrite: false });
    await loaded();
    expect(screen.queryByTestId("optset-save")).toBeNull();
    expect(screen.queryByTestId("optset-add")).toBeNull();
    expect(screen.queryByTestId("optset-remove")).toBeNull();
    expect((within(rowOf("dhcp4:15")).getByTestId("optset-value") as HTMLInputElement).readOnly).toBe(true);
  });

  it("speaks Swedish", async () => {
    await setLocale("sv");
    mount();
    await loaded();
    expect(screen.getByTestId("optset-save").textContent).toBe("Spara alternativen");
    expect(rowOf("dhcp4:6").textContent).toContain("IPv4-adress, lista");
  });
});

// WP9.4: the option space whose codes the editor offers.
describe("the option space of the editor", () => {
  const lan6 = `scope:${DHCP_IDS.lanV6}`;
  const offered = () => Array.from((screen.getByTestId("optset-add") as HTMLSelectElement).options).map((o) => o.value).filter((v) => v !== "");

  it("offers the DHCPv4 catalog by default and none of the DHCPv6 one", async () => {
    mount();
    await loaded();
    expect(offered().every((v) => v.startsWith("dhcp4|"))).toBe(true);
    expect(offered()).toContain("dhcp4|3");
  });

  it("offers the DHCPv6 catalog and the definitions of the space for dhcp6, without the codes the server writes", async () => {
    dhcpState().optionDefs.push({ id: "def-six", space: "dhcp6", code: 200, name: "site-six", kind: "string", array: false, created: dhcpState().optionDefs[0]!.created, updated: dhcpState().optionDefs[0]!.updated, revision: 1 });
    mount({ owner: lan6, space: "dhcp6" });
    await loaded();
    const codes = offered();
    expect(codes.every((v) => v.startsWith("dhcp6|"))).toBe(true);
    expect(codes).toEqual(expect.arrayContaining(["dhcp6|21", "dhcp6|22", "dhcp6|31", "dhcp6|56", "dhcp6|82", "dhcp6|200"]));
    // 23 and 24 are in the set; 1 to 14, 18 to 20, 25, 26, 37, 39 and 79 are the server's.
    for (const code of [23, 24, 1, 2, 3, 6, 14, 18, 25, 26, 37, 39, 79]) expect(codes, String(code)).not.toContain(`dhcp6|${code}`);
    // The options of the DHCPv4 set stay out, the kind of each option is the catalog's.
    expect(rowsOf().map((r) => r.dataset.key)).toEqual(["dhcp6:23", "dhcp6:24"]);
    expect(rowOf("dhcp6:24").textContent).toContain("Domain name, list");
  });

  it("types a dhcp6 value by its catalog type and sends it with its space", async () => {
    const writes = recordIfMatch();
    mount({ owner: lan6, space: "dhcp6" });
    await loaded();
    add("dhcp6|32");
    type("dhcp6:32", "3600");
    add("dhcp6|64");
    type("dhcp6:64", "aftr.example.net");
    fireEvent.click(screen.getByTestId("optset-save"));
    await waitFor(() => expect(dhcpState().optionSets.get(lan6)?.values.map((v) => v.code)).toEqual([23, 24, 32, 64]));
    expect(writes().find((w) => w.method === "PUT")?.body).toEqual({
      values: [
        { space: "dhcp6", code: 23, typed: { ipv6: { values: ["2001:db8:0:10::53"] } } },
        { space: "dhcp6", code: 24, typed: { names: ["example.net"] } },
        { space: "dhcp6", code: 32, typed: { unsigned: [3600] } },
        { space: "dhcp6", code: 64, typed: { names: ["aftr.example.net"] } },
      ],
    });
  });

  it("refuses an IPv4 address for an IPv6 option, and a number for a name, before it sends", async () => {
    const writes = recordIfMatch();
    mount({ owner: lan6, space: "dhcp6" });
    await loaded();
    type("dhcp6:23", "192.0.2.53");
    type("dhcp6:24", "not a name!");
    fireEvent.click(screen.getByTestId("optset-save"));
    await waitFor(() => expect(screen.getAllByTestId("optset-row-error").map((e) => e.dataset.key)).toEqual(["dhcp6:23", "dhcp6:24"]));
    expect(screen.getAllByTestId("optset-row-error")[0]?.textContent).toBe("Enter IPv6 addresses.");
    expect(writes()).toHaveLength(0);
  });

  it("takes a DHCPv6 code typed in up to 65535 and not a code the server writes", async () => {
    mount({ owner: lan6, space: "dhcp6" });
    await loaded();
    const go = (code: string) => {
      fireEvent.input(screen.getByTestId("optset-add-code"), { target: { value: code } });
      fireEvent.click(screen.getByTestId("optset-add-code-go"));
    };
    go("70000");
    expect(screen.getByTestId("optset-code-error").textContent).toBe("Enter a code from 1 to 65535.");
    go("3");
    expect(screen.getByTestId("optset-code-error").textContent).toBe("The server sets this option itself.");
    go("300");
    await waitFor(() => expect(rowsOf().map((r) => r.dataset.key)).toEqual(["dhcp6:23", "dhcp6:24", "dhcp6:300"]));
    expect(screen.queryByTestId("optset-code-error")).toBeNull();
  });

  it("offers both spaces in groups, DHCPv4 first, and says a DHCPv6 row is one", async () => {
    mount({ owner: "server", space: "both" });
    await loaded();
    const groups = Array.from((screen.getByTestId("optset-add") as HTMLSelectElement).querySelectorAll("optgroup"));
    expect(groups.map((g) => g.label)).toEqual(["DHCPv4", "DHCPv6"]);
    expect(Array.from(groups[0]?.querySelectorAll("option") ?? []).every((o) => o.value.startsWith("dhcp4|"))).toBe(true);
    expect(Array.from(groups[1]?.querySelectorAll("option") ?? []).every((o) => o.value.startsWith("dhcp6|"))).toBe(true);
    add("dhcp6|23");
    expect(rowOf("dhcp6:23").textContent).toContain("DHCPv6");
    expect(rowOf("dhcp4:6").textContent).not.toContain("DHCPv6");
  });
});
