import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { IPAM_IDS, ipamState } from "../../api/mock/ipam/api";
import type { Prefix, Vrf } from "../../api/types";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { signInAlex } from "../../auth/account/testkit";
import { applied, choose, confirmPlan, noteOf, recordWrites, submitForm, typeInto } from "../testkit";
import { PrefixForm } from "./PrefixForm";

const vrf = () => ipamState().data.vrf.get(IPAM_IDS.vrf.default) as Vrf;
const lan = () => ipamState().data.prefix.get(IPAM_IDS.prefix.lan) as Prefix;
const byCidr = (cidr: string) => [...ipamState().data.prefix.values()].find((p) => p.cidr === cidr && p.vrf === IPAM_IDS.vrf.default);

beforeEach(async () => {
  await signInAlex();
});

describe("prefix form: create", () => {
  it("creates a prefix through the form and the plan, with the nibble acknowledgement", async () => {
    const done = vi.fn();
    renderRoute(() => <PrefixForm vrf={vrf()} onDone={done} onClose={() => {}} />);
    const form = await screen.findByTestId("dialog-prefix-form");
    expect(within(form).getByRole("heading", { name: "Create prefix" })).toBeTruthy();
    // The first field has the focus.
    await waitFor(() => expect(document.activeElement).toBe(screen.getByTestId("field-cidr")));
    typeInto("field-cidr", "2001:db8:0:40::/62");
    typeInto("field-description", "Lab v6");
    submitForm();

    const plan = await screen.findByTestId("dialog-plan");
    expect(within(plan).getByRole("heading", { name: "Create prefix 2001:db8:0:40::/62" })).toBeTruthy();
    const blocking = await within(plan).findByTestId("plan-blocking");
    expect(blocking.textContent).toMatch(/nibble boundary/);
    const confirm = within(plan).getByTestId("plan-confirm") as HTMLButtonElement;
    expect(confirm.textContent).toBe("Create prefix");
    expect(confirm.disabled).toBe(true);
    // The preview wrote nothing.
    expect(byCidr("2001:db8:0:40::/62")).toBeUndefined();
    fireEvent.click(within(blocking).getByTestId("plan-ack"));
    expect(confirm.disabled).toBe(false);
    fireEvent.click(confirm);

    await waitFor(() => expect(done).toHaveBeenCalledTimes(1));
    const created = done.mock.calls[0]?.[0] as Prefix;
    expect(created.cidr).toBe("2001:db8:0:40::/62");
    expect(byCidr("2001:db8:0:40::/62")?.meta.description).toBe("Lab v6");
    expect(byCidr("2001:db8:0:40::/62")?.status).toBe("active");
    expect(await screen.findByText("Created prefix 2001:db8:0:40::/62")).toBeTruthy();
  });

  it("submits with Enter", async () => {
    renderRoute(() => <PrefixForm vrf={vrf()} onDone={() => {}} onClose={() => {}} />);
    const form = await screen.findByTestId("dialog-prefix-form");
    expect(form.tagName).toBe("FORM");
    expect((screen.getByTestId("form-submit") as HTMLButtonElement).type).toBe("submit");
    typeInto("field-cidr", "203.0.113.224/27");
    // A form with a submit button submits when Enter is pressed in a text field.
    fireEvent.submit(form);
    expect(await screen.findByTestId("dialog-plan")).toBeTruthy();
  });

  it("closes with Cancel and with Escape", async () => {
    const onClose = vi.fn();
    renderRoute(() => <PrefixForm vrf={vrf()} onDone={() => {}} onClose={onClose} />);
    const form = await screen.findByTestId("dialog-prefix-form");
    fireEvent.click(within(form).getByRole("button", { name: "Cancel" }));
    expect(onClose).toHaveBeenCalledTimes(1);
    fireEvent.keyDown(screen.getByRole("dialog"), { key: "Escape" });
    expect(onClose).toHaveBeenCalledTimes(2);
  });

  it("offers the network when host bits are set and takes it with one click", async () => {
    renderRoute(() => <PrefixForm vrf={vrf()} onDone={() => {}} onClose={() => {}} />);
    await screen.findByTestId("dialog-prefix-form");
    const cidr = screen.getByTestId("field-cidr") as HTMLInputElement;
    typeInto("field-cidr", "198.51.100.77/26");
    fireEvent.blur(cidr);
    expect(cidr.getAttribute("aria-invalid")).toBe("true");
    expect(noteOf("field-cidr")).toMatch(/198\.51\.100\.77\/26 has host bits set; the network is 198\.51\.100\.64\/26/);
    const fix = screen.getByTestId("cidr-fix");
    expect(fix.textContent).toBe("Use 198.51.100.64/26");
    fireEvent.click(fix);
    expect(cidr.value).toBe("198.51.100.64/26");
    expect(cidr.getAttribute("aria-invalid")).toBeNull();
    expect(screen.queryByTestId("cidr-fix")).toBeNull();
  });

  it("stays in the form while the network is missing or wrong, and focuses the field", async () => {
    renderRoute(() => <PrefixForm vrf={vrf()} onDone={() => {}} onClose={() => {}} />);
    await screen.findByTestId("dialog-prefix-form");
    submitForm();
    const cidr = screen.getByTestId("field-cidr");
    expect(cidr.getAttribute("aria-invalid")).toBe("true");
    expect(noteOf("field-cidr")).toBe("Enter the network.");
    expect(document.activeElement).toBe(cidr);
    expect(screen.queryByTestId("dialog-plan")).toBeNull();
    typeInto("field-cidr", "192.0.2.1");
    submitForm();
    expect(noteOf("field-cidr")).toMatch(/CIDR form/);
    expect(screen.queryByTestId("dialog-plan")).toBeNull();
  });

  it("checks the alarm thresholds", async () => {
    renderRoute(() => <PrefixForm vrf={vrf()} onDone={() => {}} onClose={() => {}} />);
    await screen.findByTestId("dialog-prefix-form");
    typeInto("field-cidr", "203.0.113.224/27");
    typeInto("field-alarm-warn", "90");
    typeInto("field-alarm-crit", "80");
    submitForm();
    expect(screen.queryByTestId("dialog-plan")).toBeNull();
    expect(noteOf("field-alarm-crit")).toMatch(/above the warning/);
    typeInto("field-alarm-warn", "");
    expect(noteOf("field-alarm-warn")).toMatch(/Set both/);
    typeInto("field-alarm-warn", "70");
    typeInto("field-alarm-crit", "90");
    expect(screen.getByTestId("field-alarm-warn").getAttribute("aria-invalid")).toBeNull();
    expect(screen.getByTestId("field-alarm-crit").getAttribute("aria-invalid")).toBeNull();
  });

  it("shows a refusal of the server under its field and keeps the values", async () => {
    renderRoute(() => <PrefixForm vrf={vrf()} onDone={() => {}} onClose={() => {}} />);
    await screen.findByTestId("dialog-prefix-form");
    // 192.0.2.0/24 exists in this VRF already.
    typeInto("field-cidr", "192.0.2.0/24");
    typeInto("field-description", "Duplicate");
    submitForm();
    // The preview is refused with a field error: back in the form, the message under the field.
    const cidr = (await screen.findByTestId("field-cidr")) as HTMLInputElement;
    await waitFor(() => expect(cidr.getAttribute("aria-invalid")).toBe("true"));
    expect(screen.queryByTestId("dialog-plan")).toBeNull();
    expect(noteOf("field-cidr")).toMatch(/192\.0\.2\.0\/24 overlaps 192\.0\.2\.0\/24/);
    expect(cidr.value).toBe("192.0.2.0/24");
    expect((screen.getByTestId("field-description") as HTMLInputElement).value).toBe("Duplicate");
    // The message is about what was sent: changing the network drops it.
    typeInto("field-cidr", "192.0.2.0/25");
    expect(screen.getByTestId("field-cidr").getAttribute("aria-invalid")).toBeNull();
  });

  it("returns from the plan to the form with the values intact", async () => {
    renderRoute(() => <PrefixForm vrf={vrf()} onDone={() => {}} onClose={() => {}} />);
    await screen.findByTestId("dialog-prefix-form");
    typeInto("field-cidr", "203.0.113.224/27");
    typeInto("field-description", "Spare");
    submitForm();
    const plan = await screen.findByTestId("dialog-plan");
    expect(await within(plan).findByTestId("plan-summary")).toBeTruthy();
    fireEvent.click(within(plan).getByRole("button", { name: "Cancel" }));
    const cidr = (await screen.findByTestId("field-cidr")) as HTMLInputElement;
    expect(cidr.value).toBe("203.0.113.224/27");
    expect((screen.getByTestId("field-description") as HTMLInputElement).value).toBe("Spare");
    expect(byCidr("203.0.113.224/27")).toBeUndefined();
  });

  it("starts from the network part of the supernet", async () => {
    renderRoute(() => <PrefixForm vrf={vrf()} parentCidr="2001:db8::/32" onDone={() => {}} onClose={() => {}} />);
    await screen.findByTestId("dialog-prefix-form");
    expect((screen.getByTestId("field-cidr") as HTMLInputElement).value).toBe("2001:db8:");
  });

  it("sends the choices of the form and the tags", async () => {
    const writes = recordWrites();
    const done = vi.fn();
    renderRoute(() => <PrefixForm vrf={vrf()} onDone={done} onClose={() => {}} />);
    await screen.findByTestId("dialog-prefix-form");
    typeInto("field-cidr", "203.0.113.224/27");
    choose("field-status", "planned");
    choose("field-alloc", "highest");
    await waitFor(() => expect(screen.getByTestId("field-vlan").querySelectorAll("option").length).toBeGreaterThan(1));
    choose("field-vlan", IPAM_IDS.vlan.v40);
    typeInto("field-alarm-warn", "70");
    typeInto("field-alarm-crit", "90");
    typeInto("field-tags", "lab, spare,");
    submitForm();
    await confirmPlan();
    await waitFor(() => expect(done).toHaveBeenCalledTimes(1));
    const sent = applied(writes());
    expect(sent).toHaveLength(1);
    expect(sent[0]?.url).toBe("/api/v1/prefixes");
    expect(sent[0]?.body).toEqual({
      cidr: "203.0.113.224/27",
      vrf: IPAM_IDS.vrf.default,
      status: "planned",
      alloc: "highest",
      vlan: IPAM_IDS.vlan.v40,
      alarm: { warn_pct: 70, crit_pct: 90 },
      tags: ["lab", "spare"],
    });
    expect(byCidr("203.0.113.224/27")?.vlan).toBe(IPAM_IDS.vlan.v40);
  });

  it("has no accessibility violations", async () => {
    renderRoute(() => <PrefixForm vrf={vrf()} onDone={() => {}} onClose={() => {}} />);
    const form = await screen.findByTestId("dialog-prefix-form");
    const dialog = form.closest("[role='dialog']") as HTMLElement;
    await waitFor(() => expect(screen.getByTestId("custom-fields")).toBeTruthy());
    expect(await axeViolations(dialog)).toEqual([]);
    typeInto("field-cidr", "198.51.100.77/26");
    submitForm();
    expect(screen.getByTestId("field-cidr").getAttribute("aria-invalid")).toBe("true");
    expect(await axeViolations(dialog)).toEqual([]);
  });
});

describe("prefix form: edit", () => {
  it("sends only the changed fields with the revision it was opened with", async () => {
    const writes = recordWrites();
    const prefix = lan();
    const done = vi.fn();
    renderRoute(() => <PrefixForm vrf={vrf()} prefix={prefix} onDone={done} onClose={() => {}} />);
    const form = await screen.findByTestId("dialog-prefix-form");
    expect(within(form).getByRole("heading", { name: "Edit prefix 192.0.2.0/24" })).toBeTruthy();
    const submit = screen.getByTestId("form-submit") as HTMLButtonElement;
    expect(submit.textContent).toBe("Save changes");
    // Nothing to save yet.
    expect(submit.disabled).toBe(true);
    expect((screen.getByTestId("field-cidr") as HTMLInputElement).value).toBe("192.0.2.0/24");
    expect((screen.getByTestId("field-alarm-warn") as HTMLInputElement).value).toBe("80");
    typeInto("field-description", "Main LAN");
    typeInto("field-alarm-crit", "97");
    expect(submit.disabled).toBe(false);
    submitForm();
    const plan = await screen.findByTestId("dialog-plan");
    expect(within(plan).getByRole("heading", { name: "Save changes to prefix 192.0.2.0/24" })).toBeTruthy();
    await confirmPlan();
    await waitFor(() => expect(done).toHaveBeenCalledTimes(1));

    const patches = writes().filter((w) => w.method === "PATCH");
    expect(patches).toHaveLength(2); // the dry run and the apply
    for (const p of patches) {
      expect(p.url).toContain(`/api/v1/prefixes/${prefix.id}`);
      expect(p.headers["If-Match"]).toBe(`"${prefix.meta.revision}"`);
      expect(p.body).toEqual({ description: "Main LAN", alarm: { warn_pct: 80, crit_pct: 97 } });
    }
    expect(patches[0]?.url).toContain("dry_run=true");
    expect(patches[1]?.url).not.toContain("dry_run");
    expect(lan().meta.description).toBe("Main LAN");
    expect(lan().alarm).toEqual({ warn_pct: 80, crit_pct: 97 });
    expect(await screen.findByText("Saved 192.0.2.0/24")).toBeTruthy();
  });

  it("clears fields with null and changes the custom values and tags", async () => {
    const writes = recordWrites();
    const prefix = lan();
    const done = vi.fn();
    renderRoute(() => <PrefixForm vrf={vrf()} prefix={prefix} onDone={done} onClose={() => {}} />);
    await screen.findByTestId("dialog-prefix-form");
    await waitFor(() => expect(screen.getByTestId("field-vlan").querySelectorAll("option").length).toBeGreaterThan(1));
    choose("field-vlan", "");
    typeInto("field-alarm-warn", "");
    typeInto("field-alarm-crit", "");
    await waitFor(() => expect(screen.getByTestId("field-custom-rack")).toBeTruthy());
    choose("field-custom-rack", "A2");
    fireEvent.click(within(screen.getByTestId("tags-chips")).getByRole("button", { name: "Remove tag home" }));
    typeInto("field-tags", "wired");
    fireEvent.blur(screen.getByTestId("field-tags"));
    submitForm();
    await confirmPlan();
    await waitFor(() => expect(done).toHaveBeenCalledTimes(1));
    const sent = applied(writes());
    expect(sent[0]?.body).toEqual({ vlan: null, alarm: null, tags: ["wired"], custom: { rack: { type: "select", value: "A2" } } });
    expect(lan().vlan).toBeNull();
    expect(lan().alarm).toBeNull();
    expect(lan().meta.tags).toEqual(["wired"]);
    expect(lan().meta.custom).toEqual({ rack: { type: "select", value: "A2" } });
  });

  it("shows the refusal of a role change under the role field", async () => {
    renderRoute(() => <PrefixForm vrf={vrf()} prefix={lan()} onDone={() => {}} onClose={() => {}} />);
    await screen.findByTestId("dialog-prefix-form");
    // The LAN has ranges, so it must stay a network.
    choose("field-role", "supernet");
    submitForm();
    await waitFor(() => expect(screen.getByTestId("field-role").getAttribute("aria-invalid")).toBe("true"));
    expect(noteOf("field-role")).toBe("192.0.2.0/24 has ranges, so it must stay a network.");
    expect(screen.queryByTestId("dialog-plan")).toBeNull();
    expect((screen.getByTestId("field-role") as HTMLSelectElement).value).toBe("supernet");
  });

  it("changes the network of a prefix", async () => {
    const done = vi.fn();
    const cameras = ipamState().data.prefix.get(IPAM_IDS.prefix.cameras) as Prefix;
    renderRoute(() => <PrefixForm vrf={vrf()} prefix={cameras} onDone={done} onClose={() => {}} />);
    await screen.findByTestId("dialog-prefix-form");
    typeInto("field-cidr", "203.0.113.192/27");
    submitForm();
    await confirmPlan();
    await waitFor(() => expect(done).toHaveBeenCalledTimes(1));
    expect((done.mock.calls[0]?.[0] as Prefix).cidr).toBe("203.0.113.192/27");
  });
});
