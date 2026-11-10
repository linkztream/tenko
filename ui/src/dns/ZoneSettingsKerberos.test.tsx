// The Kerberos part of the update section on the settings tab: it shows and saves the realms,
// the ownership rule, the hold, the privileged groups and the DnsUpdateProxy group; saving the
// update section keeps every field of the policy the form does not edit (the dhcp flag, the
// Kerberos settings) because a PATCH replaces the whole policy.
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { components } from "../api/generated/schema";
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

type Policy = components["schemas"]["DnsUpdatePolicy"];

const PRIMARY = DNS_IDS.zone.example;
const DOMAIN = "S-1-5-21-1000-2000-3000";
/** The Kerberos settings of a zone, as the server holds them. */
const kerberos = (extra: Partial<NonNullable<Policy["kerberos"]>> = {}): NonNullable<Policy["kerberos"]> => ({
  realms: ["CORP.EXAMPLE.TEST"],
  ownership: "windows",
  owner_hold_days: 21,
  privileged: [`${DOMAIN}-512`],
  update_proxy: `${DOMAIN}-1105`,
  ...extra,
});

beforeEach(async () => {
  await signInAlex();
});

afterEach(async () => {
  setSessionForTest(null);
  await setLocale("en");
});

/** Sets the update policy the zone already has, as a server that keeps one would answer it. */
function givenPolicy(policy: Policy) {
  const zone = dnsState().zones.find((z) => z.id === PRIMARY) as { update?: Policy } | undefined;
  if (zone) zone.update = policy;
}

const storedPolicy = () => (dnsState().zones.find((z) => z.id === PRIMARY) as { update?: Policy } | undefined)?.update;

async function settings() {
  const view = renderRoute(ZonePage, { url: `/dns/zones/${PRIMARY}/settings`, path: "/dns/zones/:id/:tab?", routes: { "/dns": () => <div data-testid="zones-page" /> } });
  const form = await screen.findByTestId("zone-settings");
  await waitFor(() => expect((within(form).getByTestId("field-name_servers") as HTMLInputElement).value).not.toBe(""));
  return { view, form };
}

const input = (scope: HTMLElement, id: string) => within(scope).getByTestId(id) as HTMLInputElement;
const patches = (writes: ReturnType<typeof recordWrites>) => writes().filter((w) => w.method === "PATCH");

describe("saving the update section keeps what the form does not edit", () => {
  it("sends the dhcp flag and the Kerberos settings back with the changed field", async () => {
    givenPolicy({ allowed: [], require_tsig: true, may_replace_ipam: false, dhcp: true, kerberos: kerberos() });
    const writes = recordWrites();
    const { form } = await settings();
    fireEvent.click(input(form, "field-update.may_replace_ipam"));
    fireEvent.click(within(form).getByTestId("form-submit"));
    expect(await screen.findByText("Settings of example.test saved")).toBeTruthy();
    const sent = patches(writes);
    expect(sent).toHaveLength(1);
    expect(sent[0]?.body).toMatchObject({
      update: { may_replace_ipam: true, dhcp: true, kerberos: { realms: ["CORP.EXAMPLE.TEST"], ownership: "windows", owner_hold_days: 21, privileged: [`${DOMAIN}-512`], update_proxy: `${DOMAIN}-1105` } },
    });
    expect(storedPolicy()).toMatchObject({ dhcp: true, kerberos: { owner_hold_days: 21 } });
  });

  it("leaves the policy out when only another section changed", async () => {
    givenPolicy({ allowed: [], require_tsig: true, may_replace_ipam: false, dhcp: false, kerberos: kerberos() });
    const writes = recordWrites();
    const { form } = await settings();
    fireEvent.input(input(form, "field-description"), { target: { value: "Another description" } });
    fireEvent.click(within(form).getByTestId("form-submit"));
    expect(await screen.findByText("Settings of example.test saved")).toBeTruthy();
    expect(patches(writes)[0]?.body).not.toHaveProperty("update");
    expect(storedPolicy()).toMatchObject({ dhcp: false, kerberos: { realms: ["CORP.EXAMPLE.TEST"] } });
  });

  it("keeps a policy without Kerberos settings free of them", async () => {
    givenPolicy({ allowed: [], require_tsig: true, may_replace_ipam: false, dhcp: true });
    const writes = recordWrites();
    const { form } = await settings();
    fireEvent.click(input(form, "field-update.require_tsig"));
    fireEvent.click(within(form).getByTestId("form-submit"));
    expect(await screen.findByText("Settings of example.test saved")).toBeTruthy();
    const update = patches(writes)[0]?.body?.update as Policy;
    expect(update).toMatchObject({ require_tsig: false, dhcp: true });
    expect(update).not.toHaveProperty("kerberos");
  });
});

describe("the Kerberos block", () => {
  it("is off for a zone without Kerberos settings and shows no fields", async () => {
    const { form, view } = await settings();
    const block = within(form).getByTestId("zone-kerberos");
    expect(block.dataset.state).toBe("off");
    expect(input(block, "field-update.kerberos.enabled").checked).toBe(false);
    expect(within(block).queryByTestId("field-update.kerberos.realms")).toBeNull();
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("shows the settings a zone has", async () => {
    givenPolicy({ kerberos: kerberos() });
    const { form, view } = await settings();
    const block = within(form).getByTestId("zone-kerberos");
    expect(block.dataset.state).toBe("on");
    expect(input(block, "field-update.kerberos.realms").value).toBe("CORP.EXAMPLE.TEST");
    expect(input(block, "field-update.kerberos.owner_hold_days").value).toBe("21");
    expect((within(block).getByTestId("field-update.kerberos.ownership") as unknown as HTMLSelectElement).value).toBe("windows");
    expect(within(block).getAllByTestId("kerberos-privileged").map((li) => li.dataset.key)).toEqual([`${DOMAIN}-512`]);
    expect(within(block).getByTestId("kerberos-privileged").textContent).toContain("Domain Admins");
    expect(input(block, "field-update.kerberos.update_proxy").value).toBe(`${DOMAIN}-1105`);
    expect(within(block).queryByTestId("kerberos-no-privileged")).toBeNull();
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("turns Kerberos on with the standard groups of a domain and saves it in one PATCH", async () => {
    const writes = recordWrites();
    const { form } = await settings();
    const block = within(form).getByTestId("zone-kerberos");
    fireEvent.click(input(block, "field-update.kerberos.enabled"));
    // Nothing privileged yet: the warning says why that matters.
    expect(within(block).getByTestId("kerberos-no-privileged").textContent).toContain("No domain controller can then register");
    fireEvent.input(input(block, "field-update.kerberos.realms"), { target: { value: "corp.example.test, dev.example.test" } });
    fireEvent.input(input(block, "field-update.kerberos.domain_sid"), { target: { value: DOMAIN } });
    fireEvent.click(within(block).getByTestId("kerberos-domain-add"));
    expect(within(block).getAllByTestId("kerberos-privileged").map((li) => li.dataset.key)).toEqual([`${DOMAIN}-512`, `${DOMAIN}-516`, `${DOMAIN}-519`]);
    expect(within(block).queryByTestId("kerberos-no-privileged")).toBeNull();
    // A group by its own SID, and one removed again.
    fireEvent.input(input(block, "field-update.kerberos.sid"), { target: { value: `${DOMAIN}-1107` } });
    fireEvent.click(within(block).getByTestId("kerberos-sid-add"));
    fireEvent.click(within(within(block).getAllByTestId("kerberos-privileged")[2] as HTMLElement).getByTestId("kerberos-privileged-remove"));
    fireEvent.change(within(block).getByTestId("field-update.kerberos.ownership"), { target: { value: "none" } });
    fireEvent.input(input(block, "field-update.kerberos.owner_hold_days"), { target: { value: "30" } });
    fireEvent.input(input(block, "field-update.kerberos.update_proxy"), { target: { value: `${DOMAIN}-1105` } });
    fireEvent.click(within(form).getByTestId("form-submit"));
    expect(await screen.findByText("Settings of example.test saved")).toBeTruthy();
    const sent = patches(writes);
    expect(sent).toHaveLength(1);
    expect((sent[0]?.body?.update as Policy).kerberos).toEqual({
      realms: ["CORP.EXAMPLE.TEST", "DEV.EXAMPLE.TEST"],
      ownership: "none",
      owner_hold_days: 30,
      privileged: [`${DOMAIN}-512`, `${DOMAIN}-516`, `${DOMAIN}-1107`],
      update_proxy: `${DOMAIN}-1105`,
    });
    expect(storedPolicy()?.kerberos?.realms).toEqual(["CORP.EXAMPLE.TEST", "DEV.EXAMPLE.TEST"]);
  });

  it("sends null when Kerberos is turned off", async () => {
    givenPolicy({ allowed: [], require_tsig: true, may_replace_ipam: false, dhcp: true, kerberos: kerberos() });
    const writes = recordWrites();
    const { form } = await settings();
    fireEvent.click(input(form, "field-update.kerberos.enabled"));
    fireEvent.click(within(form).getByTestId("form-submit"));
    expect(await screen.findByText("Settings of example.test saved")).toBeTruthy();
    expect(patches(writes)[0]?.body).toMatchObject({ update: { dhcp: true, kerberos: null } });
  });

  it("checks the realm, the days, the proxy SID and the SIDs before it sends", async () => {
    const writes = recordWrites();
    const { form } = await settings();
    const block = within(form).getByTestId("zone-kerberos");
    fireEvent.click(input(block, "field-update.kerberos.enabled"));
    fireEvent.input(input(block, "field-update.kerberos.owner_hold_days"), { target: { value: "4000" } });
    fireEvent.input(input(block, "field-update.kerberos.update_proxy"), { target: { value: "DnsUpdateProxy" } });
    fireEvent.input(input(block, "field-update.kerberos.sid"), { target: { value: "S-1-5" } });
    fireEvent.click(within(block).getByTestId("kerberos-sid-add"));
    fireEvent.click(within(form).getByTestId("form-submit"));
    await waitFor(() => expect(within(block).getAllByTestId("field-error").map((e) => e.dataset.field).sort()).toEqual([
      "update.kerberos.owner_hold_days",
      "update.kerberos.privileged",
      "update.kerberos.realms",
      "update.kerberos.update_proxy",
    ]));
    expect(within(block).getByText("Name at least one realm.")).toBeTruthy();
    expect(patches(writes)).toHaveLength(0);
  });

  it("puts the refusal of the server on the field it names", async () => {
    const { form } = await settings();
    const block = within(form).getByTestId("zone-kerberos");
    fireEvent.click(input(block, "field-update.kerberos.enabled"));
    fireEvent.input(input(block, "field-update.kerberos.realms"), { target: { value: "CORP.EXAMPLE.TEST CORP.EXAMPLE.TEST" } });
    fireEvent.click(within(form).getByTestId("form-submit"));
    await waitFor(() => expect(within(block).getByTestId("field-error").dataset.field).toBe("update.kerberos.realms"));
    expect(storedPolicy()?.kerberos).toBeUndefined();
  });

  it("says that the Hardened profile enforces ownership whatever the select says", async () => {
    const current = session();
    if (current) setSessionForTest({ ...current, profile: "hardened" });
    givenPolicy({ kerberos: kerberos({ ownership: "none" }) });
    const { form } = await settings();
    expect(within(form).getByTestId("kerberos-ownership-help").textContent).toContain("The profile Hardened enforces ownership whatever this setting says.");
  });

  it("helps with the PowerShell that reads the SIDs", async () => {
    const { form } = await settings();
    fireEvent.click(input(form, "field-update.kerberos.enabled"));
    const text = within(form).getByTestId("zone-kerberos").textContent ?? "";
    expect(text).toContain("(Get-ADGroup DnsAdmins).SID.Value");
    expect(text).toContain("(Get-ADDomain).DomainSID.Value");
    expect(text).toContain("(Get-ADGroup DnsUpdateProxy).SID.Value");
  });

  it("speaks Swedish", async () => {
    await setLocale("sv");
    const { form } = await settings();
    const block = within(form).getByTestId("zone-kerberos");
    expect(within(block).getByRole("heading", { name: "Säkra uppdateringar (Kerberos)" })).toBeTruthy();
  });

  it("is read-only for a viewer", async () => {
    await signInWithRoles(["viewer"]);
    givenPolicy({ kerberos: kerberos() });
    const { form } = await settings();
    const block = within(form).getByTestId("zone-kerberos");
    for (const id of ["field-update.kerberos.enabled", "field-update.kerberos.realms", "field-update.kerberos.ownership", "kerberos-sid-add"]) {
      expect((within(block).getByTestId(id) as HTMLInputElement).disabled).toBe(true);
    }
  });
});
