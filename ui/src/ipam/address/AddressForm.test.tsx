import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../../api/client";
import { ADDRESS_IDS, IPAM_IDS, ipamState } from "../../api/mock/ipam/api";
import type { Address } from "../../api/types";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { signInAlex } from "../../auth/account/testkit";
import { applied, choose, confirmPlan, noteOf, recordWrites, submitForm, typeInto } from "../testkit";
import { AddressForm, normalizeDnsName } from "./AddressForm";

const address = (ip: string) => ipamState().data.address.get(ADDRESS_IDS[ip] as string) as Address;

beforeEach(async () => {
  await signInAlex();
});

describe("address form", () => {
  it("shows the address and has nothing to save until something changed", async () => {
    renderRoute(() => <AddressForm address={address("192.0.2.30")} onDone={() => {}} onClose={() => {}} />);
    const form = await screen.findByTestId("dialog-address-form");
    expect(within(form).getByRole("heading", { name: "Edit address 192.0.2.30" })).toBeTruthy();
    await waitFor(() => expect(document.activeElement).toBe(screen.getByTestId("field-ip")));
    expect((screen.getByTestId("field-ip") as HTMLInputElement).value).toBe("192.0.2.30");
    expect((screen.getByTestId("field-dns_name") as HTMLInputElement).value).toBe("printer-1.example.test");
    expect((screen.getByTestId("field-status") as HTMLSelectElement).value).toBe("active");
    expect(screen.getByTestId("form-submit").textContent).toBe("Save changes");
    expect((screen.getByTestId("form-submit") as HTMLButtonElement).disabled).toBe(true);
  });

  it("sends only the changed fields with the revision it was opened with", async () => {
    const writes = recordWrites();
    const before = address("192.0.2.30");
    const done = vi.fn();
    renderRoute(() => <AddressForm address={before} onDone={done} onClose={() => {}} />);
    await screen.findByTestId("dialog-address-form");
    typeInto("field-dns_name", "Printer-Main.Example.Test.");
    choose("field-status", "reserved");
    typeInto("field-description", "Office printer");
    typeInto("field-tags", "office");
    // Leaving the input, as pressing the button does, takes the tag.
    fireEvent.blur(screen.getByTestId("field-tags"));
    submitForm();
    const plan = await screen.findByTestId("dialog-plan");
    expect(within(plan).getByRole("heading", { name: "Save changes to address 192.0.2.30" })).toBeTruthy();
    await confirmPlan();
    await waitFor(() => expect(done).toHaveBeenCalledTimes(1));
    const patches = writes().filter((w) => w.method === "PATCH");
    expect(patches).toHaveLength(2);
    for (const p of patches) {
      expect(p.url).toContain(`/api/v1/addresses/${before.id}`);
      expect(p.headers["If-Match"]).toBe(`"${before.meta.revision}"`);
      expect(p.body).toEqual({ dns_name: "printer-main.example.test", status: "reserved", description: "Office printer", tags: ["office"] });
    }
    expect(address("192.0.2.30").dns_name).toBe("printer-main.example.test");
    expect(address("192.0.2.30").status).toBe("reserved");
    expect((done.mock.calls[0]?.[0] as Address).ip).toBe("192.0.2.30");
    expect(await screen.findByText("Saved 192.0.2.30")).toBeTruthy();
  });

  it("clears the DNS name with null", async () => {
    const writes = recordWrites();
    const done = vi.fn();
    renderRoute(() => <AddressForm address={address("192.0.2.30")} onDone={done} onClose={() => {}} />);
    await screen.findByTestId("dialog-address-form");
    typeInto("field-dns_name", "");
    submitForm();
    await confirmPlan();
    await waitFor(() => expect(done).toHaveBeenCalledTimes(1));
    expect(applied(writes())[0]?.body).toEqual({ dns_name: null });
    expect(address("192.0.2.30").dns_name).toBeNull();
  });

  it("renumbers the address and returns the new one", async () => {
    const writes = recordWrites();
    const done = vi.fn();
    renderRoute(() => <AddressForm address={address("192.0.2.30")} onDone={done} onClose={() => {}} />);
    await screen.findByTestId("dialog-address-form");
    typeInto("field-ip", " 192.0.2.31 ");
    submitForm();
    await confirmPlan();
    await waitFor(() => expect(done).toHaveBeenCalledTimes(1));
    expect(applied(writes())[0]?.body).toEqual({ ip: "192.0.2.31" });
    expect((done.mock.calls[0]?.[0] as Address).ip).toBe("192.0.2.31");
    expect(address("192.0.2.30").ip).toBe("192.0.2.31");
    expect(address("192.0.2.30").prefix).toBe(IPAM_IDS.prefix.lan);
  });

  it("shows an address that is taken under the address field", async () => {
    renderRoute(() => <AddressForm address={address("192.0.2.30")} onDone={() => {}} onClose={() => {}} />);
    await screen.findByTestId("dialog-address-form");
    // 192.0.2.1 is the gateway.
    typeInto("field-ip", "192.0.2.1");
    submitForm();
    await waitFor(() => expect(screen.getByTestId("field-ip").getAttribute("aria-invalid")).toBe("true"));
    expect(screen.queryByTestId("dialog-plan")).toBeNull();
    expect(noteOf("field-ip")).toBe("192.0.2.1 already exists in this VRF.");
    expect((screen.getByTestId("field-ip") as HTMLInputElement).value).toBe("192.0.2.1");
    expect(address("192.0.2.30").ip).toBe("192.0.2.30");
  });

  it("checks the address and the DNS name", async () => {
    renderRoute(() => <AddressForm address={address("192.0.2.30")} onDone={() => {}} onClose={() => {}} />);
    await screen.findByTestId("dialog-address-form");
    typeInto("field-ip", "192.0.2.300");
    typeInto("field-dns_name", "printer");
    submitForm();
    expect(noteOf("field-ip")).toBe("This is not a valid IP address.");
    expect(noteOf("field-dns_name")).toBe("Enter a full DNS name, such as host.example.com.");
    expect(document.activeElement).toBe(screen.getByTestId("field-ip"));
    expect(screen.queryByTestId("dialog-plan")).toBeNull();
    typeInto("field-ip", "");
    expect(noteOf("field-ip")).toBe("Enter an address.");
  });

  it("edits the custom values that apply to addresses", async () => {
    await api.post("/api/v1/custom-fields", { body: { key: "owner", kind: { type: "text" }, applies_to: ["address"], required: false } });
    const writes = recordWrites();
    const done = vi.fn();
    renderRoute(() => <AddressForm address={address("192.0.2.30")} onDone={done} onClose={() => {}} />);
    await screen.findByTestId("dialog-address-form");
    await waitFor(() => expect(screen.getByTestId("field-custom-owner")).toBeTruthy());
    typeInto("field-custom-owner", "alex");
    submitForm();
    await confirmPlan();
    await waitFor(() => expect(done).toHaveBeenCalledTimes(1));
    expect(applied(writes())[0]?.body).toEqual({ custom: { owner: { type: "text", value: "alex" } } });
    expect(address("192.0.2.30").meta.custom).toEqual({ owner: { type: "text", value: "alex" } });
  });

  it("returns from the plan to the form with the values intact", async () => {
    renderRoute(() => <AddressForm address={address("192.0.2.30")} onDone={() => {}} onClose={() => {}} />);
    await screen.findByTestId("dialog-address-form");
    typeInto("field-description", "Kept");
    submitForm();
    const plan = await screen.findByTestId("dialog-plan");
    await within(plan).findByTestId("plan-preview");
    fireEvent.click(within(plan).getByRole("button", { name: "Cancel" }));
    expect(((await screen.findByTestId("field-description")) as HTMLInputElement).value).toBe("Kept");
    expect(address("192.0.2.30").meta.description).toBeNull();
  });

  it("has no accessibility violations", async () => {
    renderRoute(() => <AddressForm address={address("192.0.2.30")} onDone={() => {}} onClose={() => {}} />);
    const form = await screen.findByTestId("dialog-address-form");
    expect(await axeViolations(form.closest("[role='dialog']") as HTMLElement)).toEqual([]);
    typeInto("field-ip", "nope");
    submitForm();
    expect(await axeViolations(form.closest("[role='dialog']") as HTMLElement)).toEqual([]);
  });
});

describe("DNS names", () => {
  it("are kept in lowercase without the final dot, with at least two labels", () => {
    expect(normalizeDnsName(" NAS.Example.Test. ")).toBe("nas.example.test");
    expect(normalizeDnsName("nas")).toBeNull();
    expect(normalizeDnsName("-nas.example.test")).toBeNull();
    expect(normalizeDnsName("nas..example.test")).toBeNull();
    expect(normalizeDnsName("na s.example.test")).toBeNull();
    expect(normalizeDnsName("")).toBeNull();
  });
});
