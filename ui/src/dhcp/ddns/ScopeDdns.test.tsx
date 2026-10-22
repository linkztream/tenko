// The DDNS tab of a scope: every field, the settings of the server the scope starts from, copying
// them into the form (a scope cannot go back to following the server), saving with the revision and
// only when something changed, the local check of the TTL and the server's refusal under it, what
// the security profile does (Hardened treats Replace as Protect; a zone takes DHCP updates by the
// profile), the zone list that cannot be read, the read-only view, Swedish.
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { DHCP_IDS } from "../../api/mock/dhcp-model";
import { dhcpState } from "../../api/mock/routes-dhcp";
import { DNS_IDS } from "../../api/mock/dns-model";
import { dnsState } from "../../api/mock/routes-dns";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { signInAlex } from "../../auth/account/testkit";
import { signInWithRoles } from "../../auth/scope-testkit";
import { session, setSessionForTest } from "../../auth/session";
import { dnsSwitchedOff } from "../../dns/testkit";
import { setLocale } from "../../i18n";
import ScopePage from "../ScopePage";
import { recordIfMatch } from "../testkit";

beforeEach(async () => {
  await signInAlex();
  setProfile("home");
});

afterEach(async () => {
  setSessionForTest(null);
  await setLocale("en");
});

const open = (tab = "ddns") => renderRoute(ScopePage, { url: `/dhcp/scopes/${DHCP_IDS.lan}/${tab}`, path: "/dhcp/scopes/:prefix/:tab?" });
const loaded = async () => screen.findByTestId("ddns-form");
const lan = () => dhcpState().scopes.find((s) => s.prefix === DHCP_IDS.lan)!;
const checked = (id: string) => (screen.getByTestId(id) as HTMLInputElement).checked;
const value = (id: string) => (screen.getByTestId(id) as HTMLInputElement | HTMLSelectElement).value;
const zoneChoices = () => [...(screen.getByTestId("field-ddns-zone") as HTMLSelectElement).options].map((o) => o.textContent);
const zonesLoaded = () => waitFor(() => expect(zoneChoices()).toContain("example.test"));
const setProfile = (profile: "home" | "standard" | "hardened" | "lab") => {
  const current = session();
  if (!current) throw new Error("no session");
  setSessionForTest({ ...current, profile });
};

describe("the form", () => {
  it("shows every field, the settings of the server in words, and that DDNS needs the DNS module", async () => {
    const view = open();
    await loaded();
    expect(screen.getByTestId("scope-ddns")).toBeTruthy();
    expect(checked("field-ddns-enabled")).toBe(false);
    expect(checked("field-ddns-reverse")).toBe(true);
    expect(value("field-ddns-ttl")).toBe("");
    expect(value("field-ddns-conflict")).toBe("protect");
    expect(checked("field-ddns-client-a")).toBe(false);
    expect(checked("field-ddns-legacy")).toBe(true);
    expect(checked("field-ddns-foreign")).toBe(false);
    expect(value("field-ddns-zone")).toBe("");
    await zonesLoaded();
    // Only the primary forward zones, no reverse zone, no secondary or stub.
    expect(zoneChoices()).toEqual(["None: the zone of the domain name of the scope (option 15)", "example.test"]);
    await waitFor(() => expect(screen.getByTestId("ddns-server").textContent).toBe("The DDNS settings of the server: DDNS is off."));
    expect(screen.getByTestId("ddns-needs-dns").textContent).toContain("DNS module must be switched on");
    expect(screen.getByTestId("ddns-profile").dataset.key).toBe("home");
    expect(screen.queryByTestId("ddns-hardened-note")).toBeNull();
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("shows the settings the scope has, and the server's in words with the zone's name", async () => {
    lan().ddns = { enabled: true, forward_zone: DNS_IDS.zone.example, ttl: 600, conflict: "replace", client_may_update_a: true, legacy_clients: false, refuse_foreign: true, reverse: false };
    dhcpState().settings.ddns = { enabled: true, forward_zone: DNS_IDS.zone.example, ttl: 120 };
    open();
    await loaded();
    expect(checked("field-ddns-enabled")).toBe(true);
    expect(checked("field-ddns-reverse")).toBe(false);
    expect(value("field-ddns-ttl")).toBe("600");
    expect(value("field-ddns-conflict")).toBe("replace");
    expect(checked("field-ddns-client-a")).toBe(true);
    expect(checked("field-ddns-legacy")).toBe(false);
    expect(checked("field-ddns-foreign")).toBe(true);
    await waitFor(() => expect(value("field-ddns-zone")).toBe(DNS_IDS.zone.example));
    await waitFor(() =>
      expect(screen.getByTestId("ddns-server").textContent).toBe(
        "The DDNS settings of the server: DDNS is on with forward zone example.test, PTR records, TTL 120 s, names protected, and names for legacy clients.",
      ),
    );
    // The scope has settings of its own: it cannot go back to following the server.
    expect(screen.queryByTestId("ddns-follows")).toBeNull();
    expect(screen.getByTestId("ddns-inherit").parentElement?.textContent).toContain("cannot go back to following the server");
  });

  it("links to the tab from the line on the settings tab", async () => {
    open("settings");
    const link = await screen.findByTestId("scope-ddns-link");
    expect(link.getAttribute("href")).toBe(`/dhcp/scopes/${DHCP_IDS.lan}/ddns`);
    expect(screen.getByTestId("scope-ddns").textContent).toContain("Dynamic DNS updates are off for this scope.");
  });
});

describe("saving", () => {
  it("sends the settings with the revision, every switch explicit, and shows the saved scope", async () => {
    const writes = recordIfMatch();
    open();
    await loaded();
    await zonesLoaded();
    const revision = lan().revision;
    fireEvent.click(screen.getByTestId("field-ddns-enabled"));
    fireEvent.change(screen.getByTestId("field-ddns-zone"), { target: { value: DNS_IDS.zone.example } });
    fireEvent.input(screen.getByTestId("field-ddns-ttl"), { target: { value: "300" } });
    fireEvent.click(screen.getByTestId("field-ddns-client-a"));
    fireEvent.click(screen.getByTestId("ddns-save"));
    await waitFor(() => expect(lan().ddns?.enabled).toBe(true));
    const sent = writes().filter((w) => w.method === "PATCH");
    expect(sent).toHaveLength(1);
    expect(sent[0]?.ifMatch).toBe(`"${revision}"`);
    expect(sent[0]?.body).toEqual({
      ddns: { enabled: true, reverse: true, conflict: "protect", client_may_update_a: true, legacy_clients: true, refuse_foreign: false, forward_zone: DNS_IDS.zone.example, ttl: 300 },
    });
    // The settings tab reads the saved scope.
    fireEvent.click(screen.getByTestId("scope-tab-settings"));
    await screen.findByTestId("scope-ddns-link");
    expect(screen.getByTestId("scope-ddns").dataset.key).toBe("on");
  });

  it("sends nothing when nothing changed, also after a field was changed back", async () => {
    const writes = recordIfMatch();
    open();
    await loaded();
    fireEvent.click(screen.getByTestId("ddns-save"));
    fireEvent.click(screen.getByTestId("field-ddns-enabled"));
    fireEvent.click(screen.getByTestId("field-ddns-enabled"));
    fireEvent.input(screen.getByTestId("field-ddns-ttl"), { target: { value: " " } });
    fireEvent.click(screen.getByTestId("ddns-save"));
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(writes()).toHaveLength(0);
  });

  it("checks the TTL before it sends", async () => {
    const writes = recordIfMatch();
    open();
    await loaded();
    fireEvent.click(screen.getByTestId("field-ddns-enabled"));
    fireEvent.input(screen.getByTestId("field-ddns-ttl"), { target: { value: "0" } });
    fireEvent.click(screen.getByTestId("ddns-save"));
    const error = await screen.findByTestId("field-error");
    expect(error.dataset.field).toBe("ddns-ttl");
    expect(error.textContent).toContain("whole number of seconds from 1 to 2147483647");
    expect(screen.getByTestId("field-ddns-ttl").getAttribute("aria-invalid")).toBe("true");
    expect(writes()).toHaveLength(0);
  });

  it("shows the refusal of the server under the TTL", async () => {
    open();
    await loaded();
    fireEvent.click(screen.getByTestId("field-ddns-enabled"));
    // The form takes it; the server allows a week at most.
    fireEvent.input(screen.getByTestId("field-ddns-ttl"), { target: { value: "604801" } });
    fireEvent.click(screen.getByTestId("ddns-save"));
    const error = await screen.findByTestId("field-error");
    expect(error.dataset.field).toBe("ddns-ttl");
    expect(lan().ddns?.enabled).not.toBe(true);
  });
});

describe("the settings of the server", () => {
  it("copies them into the form without saving", async () => {
    const writes = recordIfMatch();
    dhcpState().settings.ddns = { enabled: true, ttl: 120, reverse: false, conflict: "replace" };
    open();
    await loaded();
    await waitFor(() => expect(screen.getByTestId("ddns-inherit")).toBeTruthy());
    fireEvent.click(screen.getByTestId("ddns-inherit"));
    expect(checked("field-ddns-enabled")).toBe(true);
    expect(checked("field-ddns-reverse")).toBe(false);
    expect(value("field-ddns-ttl")).toBe("120");
    expect(value("field-ddns-conflict")).toBe("replace");
    expect(writes()).toHaveLength(0);
    fireEvent.click(screen.getByTestId("ddns-save"));
    await waitFor(() => expect(lan().ddns?.ttl).toBe(120));
  });

  it("starts a scope that has none of its own from the settings of the server", async () => {
    dhcpState().settings.ddns = { enabled: true, ttl: 90 };
    delete lan().ddns;
    const writes = recordIfMatch();
    open();
    await loaded();
    await waitFor(() => expect(value("field-ddns-ttl")).toBe("90"));
    expect(checked("field-ddns-enabled")).toBe(true);
    expect(screen.getByTestId("ddns-follows")).toBeTruthy();
    // The form is what the scope has now: nothing changed, nothing sent.
    fireEvent.click(screen.getByTestId("ddns-save"));
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(writes()).toHaveLength(0);
    fireEvent.input(screen.getByTestId("field-ddns-ttl"), { target: { value: "45" } });
    fireEvent.click(screen.getByTestId("ddns-save"));
    await waitFor(() => expect(lan().ddns?.ttl).toBe(45));
  });
});

describe("the security profile", () => {
  it("says that Hardened protects names whatever the form says", async () => {
    open();
    await loaded();
    fireEvent.change(screen.getByTestId("field-ddns-conflict"), { target: { value: "replace" } });
    expect(screen.queryByTestId("ddns-hardened-note")).toBeNull();
    setProfile("hardened");
    const note = await screen.findByTestId("ddns-hardened-note");
    expect(note.textContent).toContain("Hardened profile always protects names: Replace is treated as Protect.");
    expect(screen.getByTestId("ddns-profile").dataset.key).toBe("hardened");
    expect(screen.getByTestId("ddns-profile").textContent).toContain("only when its update policy turns them on");
    fireEvent.change(screen.getByTestId("field-ddns-conflict"), { target: { value: "protect" } });
    await waitFor(() => expect(screen.queryByTestId("ddns-hardened-note")).toBeNull());
  });

  it("says whether the chosen zone takes DHCP updates, by its update policy and the profile", async () => {
    open();
    await loaded();
    await zonesLoaded();
    expect(screen.queryByTestId("ddns-zone-state")).toBeNull();
    fireEvent.change(screen.getByTestId("field-ddns-zone"), { target: { value: DNS_IDS.zone.example } });
    expect(screen.getByTestId("ddns-zone-state").dataset.key).toBe("profile_on");
    expect(screen.getByTestId("ddns-zone-state").textContent).toContain("Home profile lets it take DHCP updates");
    setProfile("standard");
    await waitFor(() => expect(screen.getByTestId("ddns-zone-state").dataset.key).toBe("profile_off"));
    expect(screen.getByTestId("ddns-zone-state").textContent).toContain("Standard profile does not let it take DHCP updates");
  });

  it("reads the update policy of the zone when it has one", async () => {
    dnsState().zones.find((z) => z.id === DNS_IDS.zone.example)!.update = { dhcp: false };
    open();
    await loaded();
    await zonesLoaded();
    fireEvent.change(screen.getByTestId("field-ddns-zone"), { target: { value: DNS_IDS.zone.example } });
    expect(screen.getByTestId("ddns-zone-state").dataset.key).toBe("off");
    expect(screen.getByTestId("ddns-zone-state").textContent).toContain("does not allow DHCP updates");
  });
});

describe("when the zones cannot be read", () => {
  it("says so and keeps the zone the scope has", async () => {
    lan().ddns = { enabled: true, forward_zone: DNS_IDS.zone.example };
    dnsSwitchedOff();
    const writes = recordIfMatch();
    open();
    await loaded();
    expect(await screen.findByTestId("ddns-zones-unavailable")).toBeTruthy();
    const zone = screen.getByTestId("field-ddns-zone") as HTMLSelectElement;
    expect(zone.disabled).toBe(true);
    await waitFor(() => expect(zone.value).toBe(DNS_IDS.zone.example));
    expect(zone.selectedOptions[0]?.textContent).toBe(`${DNS_IDS.zone.example} (not in the zone list)`);
    fireEvent.input(screen.getByTestId("field-ddns-ttl"), { target: { value: "200" } });
    fireEvent.click(screen.getByTestId("ddns-save"));
    await waitFor(() => expect(lan().ddns?.ttl).toBe(200));
    expect(writes().find((w) => w.method === "PATCH")?.body).toMatchObject({ ddns: { forward_zone: DNS_IDS.zone.example, ttl: 200 } });
    expect(lan().ddns?.forward_zone).toBe(DNS_IDS.zone.example);
  });
});

describe("who sees what", () => {
  it("gives a viewer the settings to read and nothing to change", async () => {
    await signInWithRoles(["viewer"]);
    open();
    await loaded();
    for (const id of ["field-ddns-enabled", "field-ddns-zone", "field-ddns-reverse", "field-ddns-ttl", "field-ddns-conflict", "field-ddns-client-a", "field-ddns-legacy", "field-ddns-foreign"]) {
      expect((screen.getByTestId(id) as HTMLInputElement).disabled).toBe(true);
    }
    expect(screen.queryByTestId("ddns-save")).toBeNull();
    expect(screen.queryByTestId("ddns-inherit")).toBeNull();
  });
});

describe("the language", () => {
  it("speaks Swedish", async () => {
    await setLocale("sv");
    open();
    await loaded();
    expect(screen.getByRole("heading", { level: 2 }).textContent).toBe("DDNS för 192.0.2.0/24");
    expect(screen.getByTestId("scope-tab-ddns").textContent).toBe("DDNS");
    await waitFor(() => expect(screen.getByTestId("ddns-server").textContent).toBe("Serverns DDNS-inställningar: DDNS är av."));
    fireEvent.change(screen.getByTestId("field-ddns-conflict"), { target: { value: "replace" } });
    setProfile("hardened");
    expect((await screen.findByTestId("ddns-hardened-note")).textContent).toContain("Ersätt behandlas som Skydda");
    expect(within(screen.getByTestId("ddns-fields")).getByText("Framåtzon")).toBeTruthy();
  });
});
