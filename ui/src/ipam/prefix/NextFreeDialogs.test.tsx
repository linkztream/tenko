import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../../api/client";
import { IPAM_IDS, ipamState } from "../../api/mock/ipam/api";
import type { Address, Prefix, Range } from "../../api/types";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { signInAlex } from "../../auth/account/testkit";
import { applied, choose, noteOf, recordWrites, submitForm, typeInto } from "../testkit";
import { NextFreeAddressDialog, NextFreePrefixDialog, nibbleLengths } from "./NextFreeDialogs";

const prefix = (id: string) => ipamState().data.prefix.get(id) as Prefix;
const rangesOf = (id: string) => [...ipamState().data.range.values()].filter((r) => r.prefix === id) as Range[];
const addressNamed = (ip: string) => [...ipamState().data.address.values()].find((a) => a.ip === ip && a.vrf === IPAM_IDS.vrf.default);

beforeEach(async () => {
  await signInAlex();
});

describe("next free address", () => {
  it("shows the address it would take and claims it", async () => {
    const writes = recordWrites();
    const done = vi.fn();
    const lan = prefix(IPAM_IDS.prefix.lan);
    renderRoute(() => <NextFreeAddressDialog prefix={lan} ranges={rangesOf(lan.id)} onDone={done} onClose={() => {}} />);
    const form = await screen.findByTestId("dialog-next-free-address");
    expect(within(form).getByRole("heading", { name: "Next free address in 192.0.2.0/24" })).toBeTruthy();
    await waitFor(() => expect(document.activeElement).toBe(screen.getByTestId("field-dns_name")));
    typeInto("field-dns_name", "Printer-2.example.test.");
    typeInto("field-description", "Second printer");
    expect(screen.getByTestId("form-submit").textContent).toBe("Find next free address");
    submitForm();

    const plan = await screen.findByTestId("dialog-plan");
    const result = await within(plan).findByTestId("next-free-result");
    expect(result.textContent).toBe("Next free address: 192.0.2.6");
    const confirm = within(plan).getByTestId("plan-confirm") as HTMLButtonElement;
    await waitFor(() => expect(confirm.textContent).toBe("Claim 192.0.2.6"));
    // The preview claimed nothing.
    expect(addressNamed("192.0.2.6")).toBeUndefined();
    fireEvent.click(confirm);
    await waitFor(() => expect(done).toHaveBeenCalledTimes(1));
    const claimed = done.mock.calls[0]?.[0] as Address;
    expect(claimed.ip).toBe("192.0.2.6");
    expect(addressNamed("192.0.2.6")?.dns_name).toBe("printer-2.example.test");
    expect(addressNamed("192.0.2.6")?.meta.description).toBe("Second printer");
    const sent = applied(writes());
    expect(sent).toHaveLength(1);
    expect(sent[0]?.url).toBe(`/api/v1/prefixes/${lan.id}/next-free-address`);
    expect(sent[0]?.body).toEqual({ policy: "lowest", status: "active", dns_name: "printer-2.example.test", description: "Second printer" });
    expect(await screen.findByText("Claimed 192.0.2.6")).toBeTruthy();
  });

  it("allocates from the other end or from one of the ranges", async () => {
    const lan = prefix(IPAM_IDS.prefix.lan);
    renderRoute(() => <NextFreeAddressDialog prefix={lan} ranges={rangesOf(lan.id)} onDone={() => {}} onClose={() => {}} />);
    await screen.findByTestId("dialog-next-free-address");
    const from = screen.getByTestId("field-range") as HTMLSelectElement;
    expect([...from.options].map((o) => o.textContent)).toEqual([
      "The whole network 192.0.2.0/24",
      "192.0.2.1 - 192.0.2.19 (Infrastructure)",
      "192.0.2.100 - 192.0.2.199 (DHCP pool)",
    ]);
    choose("field-range", IPAM_IDS.range.pool);
    choose("field-policy", "highest");
    submitForm();
    const plan = await screen.findByTestId("dialog-plan");
    expect((await within(plan).findByTestId("next-free-result")).textContent).toBe("Next free address: 192.0.2.199");
  });

  it("checks the DNS name before it goes anywhere", async () => {
    const lan = prefix(IPAM_IDS.prefix.lan);
    renderRoute(() => <NextFreeAddressDialog prefix={lan} ranges={[]} onDone={() => {}} onClose={() => {}} />);
    await screen.findByTestId("dialog-next-free-address");
    expect(screen.queryByTestId("field-range")).toBeNull();
    typeInto("field-dns_name", "single");
    submitForm();
    expect(noteOf("field-dns_name")).toBe("Enter a full DNS name, such as host.example.com.");
    expect(screen.queryByTestId("dialog-plan")).toBeNull();
  });

  it("says so when the network is full", async () => {
    const cameras = prefix(IPAM_IDS.prefix.cameras);
    // One address is left in the camera network (203.0.113.192/28).
    await api.post("/api/v1/prefixes/{id}/next-free-address", { path: { id: cameras.id }, body: {} as never });
    renderRoute(() => <NextFreeAddressDialog prefix={cameras} ranges={[]} onDone={() => {}} onClose={() => {}} />);
    await screen.findByTestId("dialog-next-free-address");
    submitForm();
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toMatch(/free address/i);
    expect((screen.getByTestId("plan-confirm") as HTMLButtonElement).disabled).toBe(true);
  });

  it("has no accessibility violations", async () => {
    const lan = prefix(IPAM_IDS.prefix.lan);
    renderRoute(() => <NextFreeAddressDialog prefix={lan} ranges={rangesOf(lan.id)} onDone={() => {}} onClose={() => {}} />);
    const form = await screen.findByTestId("dialog-next-free-address");
    expect(await axeViolations(form.closest("[role='dialog']") as HTMLElement)).toEqual([]);
    submitForm();
    const plan = await screen.findByTestId("dialog-plan");
    await within(plan).findByTestId("next-free-result");
    expect(await axeViolations(plan.closest("[role='dialog']") as HTMLElement)).toEqual([]);
  });
});

describe("next free prefix", () => {
  it("finds the next free /28 of a supernet and creates it", async () => {
    const writes = recordWrites();
    const done = vi.fn();
    const supernet = prefix(IPAM_IDS.prefix.documentation);
    renderRoute(() => <NextFreePrefixDialog prefix={supernet} onDone={done} onClose={() => {}} />);
    const form = await screen.findByTestId("dialog-next-free-prefix");
    expect(within(form).getByRole("heading", { name: "Next free prefix in 203.0.113.0/24" })).toBeTruthy();
    await waitFor(() => expect(document.activeElement).toBe(screen.getByTestId("field-length")));
    // IPv4: no nibble lengths to suggest.
    expect(screen.queryByTestId("length-picks")).toBeNull();
    typeInto("field-length", "28");
    typeInto("field-description", "Printers");
    submitForm();
    const plan = await screen.findByTestId("dialog-plan");
    expect((await within(plan).findByTestId("next-free-result")).textContent).toBe("Next free prefix: 203.0.113.208/28");
    const confirm = within(plan).getByTestId("plan-confirm") as HTMLButtonElement;
    await waitFor(() => expect(confirm.textContent).toBe("Create 203.0.113.208/28"));
    expect([...ipamState().data.prefix.values()].some((p) => p.cidr === "203.0.113.208/28")).toBe(false);
    fireEvent.click(confirm);
    await waitFor(() => expect(done).toHaveBeenCalledTimes(1));
    const created = done.mock.calls[0]?.[0] as Prefix;
    expect(created.cidr).toBe("203.0.113.208/28");
    expect(created.role).toBe("network");
    expect(created.meta.description).toBe("Printers");
    const sent = applied(writes());
    expect(sent[0]?.url).toBe(`/api/v1/prefixes/${supernet.id}/next-free-prefix`);
    expect(sent[0]?.body).toEqual({ length: 28, role: "network", status: "active", policy: "lowest", description: "Printers" });
    expect(await screen.findByText("Created prefix 203.0.113.208/28")).toBeTruthy();
  });

  it("checks the length against the parent", async () => {
    const supernet = prefix(IPAM_IDS.prefix.documentation);
    renderRoute(() => <NextFreePrefixDialog prefix={supernet} onDone={() => {}} onClose={() => {}} />);
    await screen.findByTestId("dialog-next-free-prefix");
    submitForm();
    expect(noteOf("field-length")).toBe("Enter the length.");
    typeInto("field-length", "24");
    expect(noteOf("field-length")).toBe("Enter a whole number from 25 to 32.");
    typeInto("field-length", "33");
    expect(noteOf("field-length")).toBe("Enter a whole number from 25 to 32.");
    typeInto("field-length", "32");
    expect(screen.getByTestId("field-length").getAttribute("aria-invalid")).toBeNull();
    expect(screen.queryByTestId("dialog-plan")).toBeNull();
  });

  it("suggests the lengths on a nibble boundary for IPv6", async () => {
    const supernet = prefix(IPAM_IDS.prefix.v6);
    renderRoute(() => <NextFreePrefixDialog prefix={supernet} onDone={() => {}} onClose={() => {}} />);
    await screen.findByTestId("dialog-next-free-prefix");
    const picks = screen.getAllByTestId("length-pick");
    expect(picks.map((p) => p.textContent)).toEqual(["/36", "/40", "/44", "/48", "/52", "/56", "/60", "/64"]);
    fireEvent.click(picks[3] as HTMLElement);
    expect((screen.getByTestId("field-length") as HTMLInputElement).value).toBe("48");
    expect(noteOf("field-length")).toMatch(/from 33 to 128/);
    submitForm();
    const plan = await screen.findByTestId("dialog-plan");
    expect((await within(plan).findByTestId("next-free-result")).textContent).toBe("Next free prefix: 2001:db8:2::/48");
  });

  it("says so when a network is asked for room", async () => {
    // The LAN is a network, not a supernet: the server refuses to carve prefixes out of it.
    const lan = prefix(IPAM_IDS.prefix.lan);
    renderRoute(() => <NextFreePrefixDialog prefix={lan} onDone={() => {}} onClose={() => {}} />);
    await screen.findByTestId("dialog-next-free-prefix");
    typeInto("field-length", "26");
    submitForm();
    // The refusal names a field the dialog does not have: the form shows it above its buttons.
    const alert = await screen.findByRole("alert");
    expect(within(screen.getByTestId("dialog-next-free-prefix")).getByRole("alert")).toBe(alert);
    expect(screen.queryByTestId("dialog-plan")).toBeNull();
    expect((screen.getByTestId("field-length") as HTMLInputElement).value).toBe("26");
  });

  it("has no accessibility violations", async () => {
    const supernet = prefix(IPAM_IDS.prefix.v6);
    renderRoute(() => <NextFreePrefixDialog prefix={supernet} onDone={() => {}} onClose={() => {}} />);
    const form = await screen.findByTestId("dialog-next-free-prefix");
    await waitFor(() => expect(screen.getByTestId("field-vlan").querySelectorAll("option").length).toBeGreaterThan(1));
    expect(await axeViolations(form.closest("[role='dialog']") as HTMLElement)).toEqual([]);
  });
});

describe("nibble lengths", () => {
  it("starts above the parent and stops after eight", () => {
    expect(nibbleLengths(32)).toEqual([36, 40, 44, 48, 52, 56, 60, 64]);
    expect(nibbleLengths(48)).toEqual([52, 56, 60, 64, 68, 72, 76, 80]);
    expect(nibbleLengths(64)).toEqual([68, 72, 76, 80, 84, 88, 92, 96]);
    expect(nibbleLengths(62)).toEqual([64, 68, 72, 76, 80, 84, 88, 92]);
    expect(nibbleLengths(126)).toEqual([128]);
  });
});
