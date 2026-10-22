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

function mount(props: { owner?: string; canWrite?: boolean } = {}) {
  const view = render(() => (
    <>
      <IconSprite />
      <OptionSetEditor owner={props.owner ?? "server"} label="Options of the server" canWrite={props.canWrite ?? true} />
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
