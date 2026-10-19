// WP6.2: the dynamic update section of the settings tab: the access list chips, TSIG and the
// IPAM rule saved in one PATCH, the profile's rule beside them (TGL-09), Swedish, and what a
// secondary zone and a viewer see.
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { DNS_IDS } from "../api/mock/dns-model";
import { dnsState } from "../api/mock/routes-dns";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { signInAlex } from "../auth/account/testkit";
import { signInWithRoles } from "../auth/scope-testkit";
import { session, setSessionForTest } from "../auth/session";
import { setLocale } from "../i18n";
import { recordWrites } from "./testkit";
import ZonePage from "./ZonePage";

const PRIMARY = DNS_IDS.zone.example;
const SECONDARY = DNS_IDS.zone.lab;

beforeEach(async () => {
  await signInAlex();
});

afterEach(async () => {
  setSessionForTest(null);
  await setLocale("en");
});

async function settings(zone: string) {
  const view = renderRoute(ZonePage, { url: `/dns/zones/${zone}/settings`, path: "/dns/zones/:id/:tab?", routes: { "/dns": () => <div data-testid="zones-page" /> } });
  const form = await screen.findByTestId("zone-settings");
  if (zone !== SECONDARY) await waitFor(() => expect((within(form).getByTestId("field-name_servers") as HTMLInputElement).value).not.toBe(""));
  return { view, form };
}

function withProfile(profile: "home" | "standard" | "hardened" | "lab") {
  const current = session();
  if (current) setSessionForTest({ ...current, profile });
}

const input = (scope: HTMLElement, id: string) => within(scope).getByTestId(id) as HTMLInputElement;

describe("the update section of a primary zone", () => {
  it("says that nobody may update without a list, with the rule of the profile", async () => {
    withProfile("home");
    const { view, form } = await settings(PRIMARY);
    const section = within(form).getByTestId("zone-update");
    expect(section.dataset.key).toBe("home");
    expect(within(section).getByTestId("update-allow-none").textContent).toContain("nobody may update this zone");
    expect(within(section).getByTestId("update-allow-none").textContent).toContain("The profile Home allows no dynamic updates");
    expect(input(section, "field-update.require_tsig").checked).toBe(true);
    expect(input(section, "field-update.may_replace_ipam").checked).toBe(false);
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("sends the update policy in one PATCH and keeps it", async () => {
    const writes = recordWrites();
    const { form } = await settings(PRIMARY);
    const add = input(form, "field-update-allow-add");
    await waitFor(() => expect(Array.from((add as unknown as HTMLSelectElement).options).map((o) => o.textContent)).toContain("internal"));
    fireEvent.change(add, { target: { value: DNS_IDS.acl.internal } });
    await waitFor(() => expect(within(form).getAllByTestId("update-allow").map((c) => c.textContent)).toEqual(["internal"]));
    fireEvent.click(input(form, "field-update.may_replace_ipam"));
    fireEvent.click(within(form).getByTestId("form-submit"));
    expect(await screen.findByText("Settings of example.test saved")).toBeTruthy();
    const sent = writes().filter((w) => w.method === "PATCH");
    expect(sent).toHaveLength(1);
    expect(sent[0]?.body).toMatchObject({ update: { allowed: [DNS_IDS.acl.internal], require_tsig: true, may_replace_ipam: true } });
    expect(sent[0]?.body).not.toHaveProperty("transfer");
    const zone = dnsState().zones.find((z) => z.id === PRIMARY) as { update?: unknown } | undefined;
    expect(zone?.update).toEqual({ allowed: [DNS_IDS.acl.internal], require_tsig: true, may_replace_ipam: true });
    // Saved: a second save with no change leaves the policy out.
    fireEvent.input(input(form, "field-description"), { target: { value: "Updated by nsupdate" } });
    fireEvent.click(within(form).getByTestId("form-submit"));
    await waitFor(() => expect(writes().filter((w) => w.method === "PATCH")).toHaveLength(2));
    expect(writes().filter((w) => w.method === "PATCH")[1]?.body).not.toHaveProperty("update");
  });

  it("removes a chip and leaves the policy out when nothing changed", async () => {
    const writes = recordWrites();
    const { form } = await settings(PRIMARY);
    fireEvent.input(input(form, "field-description"), { target: { value: "The home zone" } });
    fireEvent.click(within(form).getByTestId("form-submit"));
    expect(await screen.findByText("Settings of example.test saved")).toBeTruthy();
    expect(writes().filter((w) => w.method === "PATCH")[0]?.body).not.toHaveProperty("update");
  });

  it("names the rule of the hardened and the lab profile beside the signature", async () => {
    withProfile("hardened");
    const first = await settings(PRIMARY);
    const hardened = within(first.form).getByTestId("zone-update");
    expect(hardened.textContent).toContain("The profile Hardened requires the key whatever this setting says.");
    expect(within(hardened).getByTestId("update-allow-none").textContent).toContain("unsigned updates are refused");
    first.view.unmount();
    withProfile("lab");
    const second = await settings(PRIMARY);
    const lab = within(second.form).getByTestId("zone-update");
    expect(lab.dataset.key).toBe("lab");
    expect(lab.textContent).toContain("takes unsigned updates from the lists whatever this setting says");
  });

  it("speaks Swedish", async () => {
    await setLocale("sv");
    withProfile("standard");
    const { form } = await settings(PRIMARY);
    const section = within(form).getByTestId("zone-update");
    expect(within(section).getByRole("heading", { name: "Dynamiska uppdateringar" })).toBeTruthy();
    expect(within(section).getByTestId("update-allow-none").textContent).toContain("ingen får uppdatera den här zonen");
  });
});

describe("where updates do not apply", () => {
  it("has no update section on a secondary zone", async () => {
    const { form } = await settings(SECONDARY);
    await waitFor(() => expect(within(form).getByTestId("zone-transfer")).toBeTruthy());
    expect(within(form).queryByTestId("zone-update")).toBeNull();
  });

  it("disables the controls for a viewer", async () => {
    await signInWithRoles(["viewer"]);
    const { form } = await settings(PRIMARY);
    const section = within(form).getByTestId("zone-update");
    for (const id of ["field-update-allow-add", "field-update.require_tsig", "field-update.may_replace_ipam"]) {
      expect(input(section, id).disabled).toBe(true);
    }
  });
});
