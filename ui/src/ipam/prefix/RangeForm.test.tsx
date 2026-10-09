import { screen, waitFor, within } from "@solidjs/testing-library";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../../api/client";
import { isApiError } from "../../api/problem";
import { IPAM_IDS, ipamState } from "../../api/mock/ipam/api";
import type { Prefix, Range } from "../../api/types";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { signInAlex } from "../../auth/account/testkit";
import { applied, choose, confirmPlan, noteOf, recordWrites, submitForm, typeInto } from "../testkit";
import { checkLease, leaseParts, RangeForm } from "./RangeForm";

const lan = () => ipamState().data.prefix.get(IPAM_IDS.prefix.lan) as Prefix;
const pool = () => ipamState().data.range.get(IPAM_IDS.range.pool) as Range;
const rangesOf = (prefix: string) => [...ipamState().data.range.values()].filter((r) => r.prefix === prefix && !r.meta.deleted);

beforeEach(async () => {
  await signInAlex();
});

describe("lease time", () => {
  it("is shown in the largest whole unit", () => {
    expect(leaseParts(86_400)).toEqual({ value: "1", unit: "days" });
    expect(leaseParts(43_200)).toEqual({ value: "12", unit: "hours" });
    expect(leaseParts(5_400)).toEqual({ value: "90", unit: "minutes" });
    expect(leaseParts(90)).toEqual({ value: "1.5", unit: "minutes" });
  });
  it("is checked against the limits of the API", () => {
    expect(checkLease("", "hours")).toEqual({ ok: true, secs: null });
    expect(checkLease("12", "hours")).toEqual({ ok: true, secs: 43_200 });
    expect(checkLease("1,5", "minutes")).toEqual({ ok: true, secs: 90 });
    expect(checkLease("365", "days")).toEqual({ ok: true, secs: 31_536_000 });
    expect(checkLease("366", "days")).toEqual({ ok: false, reason: "range" });
    expect(checkLease("0.5", "minutes")).toEqual({ ok: false, reason: "range" });
    expect(checkLease("abc", "hours")).toEqual({ ok: false, reason: "number" });
    expect(checkLease("-1", "hours")).toEqual({ ok: false, reason: "number" });
  });
});

describe("range form: create", () => {
  it("creates a DHCP pool with a lease time", async () => {
    const writes = recordWrites();
    const done = vi.fn();
    renderRoute(() => <RangeForm prefix={lan()} onDone={done} onClose={() => {}} />);
    const form = await screen.findByTestId("dialog-range-form");
    expect(within(form).getByRole("heading", { name: "Create range" })).toBeTruthy();
    await waitFor(() => expect(document.activeElement).toBe(screen.getByTestId("field-first")));
    // A new range is a DHCP pool until the person chooses otherwise.
    expect((screen.getByTestId("field-role") as HTMLSelectElement).value).toBe("dhcp_pool");
    typeInto("field-first", "192.0.2.200");
    typeInto("field-last", "192.0.2.220");
    typeInto("field-lease", "12");
    choose("field-lease-unit", "hours");
    typeInto("field-description", "Guests");
    submitForm();
    const plan = await screen.findByTestId("dialog-plan");
    expect(within(plan).getByRole("heading", { name: "Create range 192.0.2.200 - 192.0.2.220" })).toBeTruthy();
    await confirmPlan();
    await waitFor(() => expect(done).toHaveBeenCalledTimes(1));
    const sent = applied(writes());
    expect(sent).toHaveLength(1);
    expect(sent[0]?.url).toBe(`/api/v1/prefixes/${IPAM_IDS.prefix.lan}/ranges`);
    expect(sent[0]?.body).toEqual({
      first: "192.0.2.200",
      last: "192.0.2.220",
      role: "dhcp_pool",
      status: "active",
      description: "Guests",
      lease_secs: 43_200,
    });
    const created = rangesOf(IPAM_IDS.prefix.lan).find((r) => r.first === "192.0.2.200");
    expect(created?.lease_secs).toBe(43_200);
    expect(created?.meta.description).toBe("Guests");
    expect((done.mock.calls[0]?.[0] as Range).id).toBe(created?.id);
    expect(await screen.findByText("Created range 192.0.2.200 - 192.0.2.220")).toBeTruthy();
  });

  it("offers a lease time only for a DHCP pool and sends none for another role", async () => {
    const writes = recordWrites();
    const done = vi.fn();
    renderRoute(() => <RangeForm prefix={lan()} onDone={done} onClose={() => {}} />);
    await screen.findByTestId("dialog-range-form");
    typeInto("field-first", "192.0.2.230");
    typeInto("field-last", "192.0.2.240");
    typeInto("field-lease", "2");
    expect(screen.getByTestId("field-lease")).toBeTruthy();
    choose("field-role", "reserved");
    expect(screen.queryByTestId("field-lease")).toBeNull();
    expect(screen.queryByTestId("field-lease-unit")).toBeNull();
    submitForm();
    await confirmPlan();
    await waitFor(() => expect(done).toHaveBeenCalledTimes(1));
    expect(applied(writes())[0]?.body).toEqual({ first: "192.0.2.230", last: "192.0.2.240", role: "reserved", status: "active" });
    expect(rangesOf(IPAM_IDS.prefix.lan).find((r) => r.first === "192.0.2.230")?.lease_secs).toBeUndefined();
  });

  it("is refused by the server when a lease time is sent for another role", async () => {
    const attempt = api.post("/api/v1/prefixes/{id}/ranges", {
      path: { id: IPAM_IDS.prefix.lan },
      body: { first: "192.0.2.230", last: "192.0.2.240", role: "reserved", lease_secs: 3600 } as never,
    });
    await expect(attempt).rejects.toSatisfy((err) => isApiError(err, "ipam.validation") && err.field("lease_secs") !== undefined);
  });

  it("checks the addresses against the prefix and each other, and the lease time", async () => {
    renderRoute(() => <RangeForm prefix={lan()} onDone={() => {}} onClose={() => {}} />);
    await screen.findByTestId("dialog-range-form");
    submitForm();
    expect(noteOf("field-first")).toBe("Enter an address.");
    expect(screen.queryByTestId("dialog-plan")).toBeNull();
    typeInto("field-first", "198.51.100.5");
    typeInto("field-last", "nonsense");
    expect(noteOf("field-first")).toBe("The range lies outside 192.0.2.0/24.");
    expect(noteOf("field-last")).toBe("This is not a valid IP address.");
    typeInto("field-first", "192.0.2.50");
    typeInto("field-last", "192.0.2.40");
    expect(noteOf("field-last")).toBe("The last address must not come before the first.");
    typeInto("field-last", "192.0.2.60");
    expect(screen.getByTestId("field-last").getAttribute("aria-invalid")).toBeNull();
    typeInto("field-lease", "400");
    choose("field-lease-unit", "days");
    submitForm();
    expect(noteOf("field-lease")).toBe("The lease time must be between 1 minute and 365 days.");
    expect(screen.queryByTestId("dialog-plan")).toBeNull();
    typeInto("field-lease", "x");
    expect(noteOf("field-lease")).toBe("Enter a number, for example 12.");
    typeInto("field-lease", "");
    submitForm();
    expect(await screen.findByTestId("dialog-plan")).toBeTruthy();
  });

  it("shows an overlap under the first address and keeps the values", async () => {
    renderRoute(() => <RangeForm prefix={lan()} onDone={() => {}} onClose={() => {}} />);
    await screen.findByTestId("dialog-range-form");
    // The DHCP pool of the LAN is 192.0.2.100 to 192.0.2.199.
    typeInto("field-first", "192.0.2.150");
    typeInto("field-last", "192.0.2.160");
    submitForm();
    await waitFor(() => expect(screen.getByTestId("field-first").getAttribute("aria-invalid")).toBe("true"));
    expect(screen.queryByTestId("dialog-plan")).toBeNull();
    expect(noteOf("field-first")).toBe("The range overlaps 192.0.2.100-192.0.2.199.");
    expect((screen.getByTestId("field-last") as HTMLInputElement).value).toBe("192.0.2.160");
  });

  it("has no accessibility violations", async () => {
    renderRoute(() => <RangeForm prefix={lan()} onDone={() => {}} onClose={() => {}} />);
    const form = await screen.findByTestId("dialog-range-form");
    const dialog = form.closest("[role='dialog']") as HTMLElement;
    expect(await axeViolations(dialog)).toEqual([]);
    submitForm();
    expect(screen.getByTestId("field-first").getAttribute("aria-invalid")).toBe("true");
    expect(await axeViolations(dialog)).toEqual([]);
  });
});

describe("range form: edit", () => {
  it("shows the range and sends only the lease time that changed, with the revision", async () => {
    const writes = recordWrites();
    const range = pool();
    const done = vi.fn();
    renderRoute(() => <RangeForm prefix={lan()} range={range} onDone={done} onClose={() => {}} />);
    const form = await screen.findByTestId("dialog-range-form");
    expect(within(form).getByRole("heading", { name: "Edit range 192.0.2.100 - 192.0.2.199" })).toBeTruthy();
    expect((screen.getByTestId("field-first") as HTMLInputElement).value).toBe("192.0.2.100");
    expect((screen.getByTestId("field-lease") as HTMLInputElement).value).toBe("1");
    expect((screen.getByTestId("field-lease-unit") as HTMLSelectElement).value).toBe("days");
    const submit = screen.getByTestId("form-submit") as HTMLButtonElement;
    expect(submit.textContent).toBe("Save changes");
    expect(submit.disabled).toBe(true);
    typeInto("field-lease", "12");
    choose("field-lease-unit", "hours");
    expect(submit.disabled).toBe(false);
    submitForm();
    await confirmPlan();
    await waitFor(() => expect(done).toHaveBeenCalledTimes(1));
    const patches = writes().filter((w) => w.method === "PATCH");
    expect(patches).toHaveLength(2);
    for (const p of patches) {
      expect(p.url).toContain(`/api/v1/ranges/${range.id}`);
      expect(p.headers["If-Match"]).toBe(`"${range.meta.revision}"`);
      expect(p.body).toEqual({ lease_secs: 43_200 });
    }
    expect(pool().lease_secs).toBe(43_200);
    expect(await screen.findByText("Saved 192.0.2.100 - 192.0.2.199")).toBeTruthy();
  });

  it("clears the lease time when the role leaves DHCP", async () => {
    const writes = recordWrites();
    const done = vi.fn();
    renderRoute(() => <RangeForm prefix={lan()} range={pool()} onDone={done} onClose={() => {}} />);
    await screen.findByTestId("dialog-range-form");
    choose("field-role", "reserved");
    submitForm();
    await confirmPlan();
    await waitFor(() => expect(done).toHaveBeenCalledTimes(1));
    expect(applied(writes())[0]?.body).toEqual({ role: "reserved", lease_secs: null });
    expect(pool().role).toBe("reserved");
    expect(pool().lease_secs).toBeUndefined();
  });

  it("moves the range with new addresses", async () => {
    const done = vi.fn();
    renderRoute(() => <RangeForm prefix={lan()} range={pool()} onDone={done} onClose={() => {}} />);
    await screen.findByTestId("dialog-range-form");
    typeInto("field-last", "192.0.2.180");
    submitForm();
    await confirmPlan();
    await waitFor(() => expect(done).toHaveBeenCalledTimes(1));
    expect(pool().last).toBe("192.0.2.180");
  });
});
