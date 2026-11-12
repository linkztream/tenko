// The DHCP server settings (/settings/dhcp): the lease times in human units, authoritative, conflict
// detection and the history retention with "follow the security profile" and the value in force,
// saved with the revision; the local checks; the server's refusal; the page for administrators
// only; the module-off state; the trusted relay agents (follow, list with links, checks, the Trust and Add link buttons, the any-link notice and
// the panel of the senders refused); the limits per client and per scope (follow, the five fields,
// the checks, the panel of the requests refused); Swedish.
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { server } from "../../api/mock/node";
import { dhcpState } from "../../api/mock/routes-dhcp";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { signInAlex } from "../../auth/account/testkit";
import { setSessionForTest } from "../../auth/session";
import { setLocale } from "../../i18n";
import { dhcpSwitchedOff, recordIfMatch } from "../testkit";
import DhcpSettingsPage from "./DhcpSettingsPage";
import { entryFor, holdsLink, MAX_RELAY_LINKS, MAX_TRUSTED_RELAYS, relayList, relayText, withLink } from "./relays";

beforeEach(async () => {
  await signInAlex();
});

afterEach(async () => {
  setSessionForTest(null);
  await setLocale("en");
});

const open = () => renderRoute(DhcpSettingsPage, { url: "/settings/dhcp", path: "/settings/dhcp" });
const loaded = () => screen.findByTestId("dhcp-settings-form");
const field = (id: string) => screen.getByTestId(id) as HTMLInputElement;

describe("the DHCP settings", () => {
  it("shows the lease times in human units and the values in force for what follows the profile", async () => {
    const view = open();
    await loaded();
    expect(screen.getByTestId("page-dhcp-settings")).toBeTruthy();
    expect([field("field-lease-default").value, (screen.getByTestId("field-lease-default-unit") as HTMLSelectElement).value]).toEqual(["1", "days"]);
    expect([field("field-lease-min").value, (screen.getByTestId("field-lease-min-unit") as HTMLSelectElement).value]).toEqual(["1", "hours"]);
    expect([field("field-lease-max").value, (screen.getByTestId("field-lease-max-unit") as HTMLSelectElement).value]).toEqual(["7", "days"]);
    expect(field("field-authoritative").checked).toBe(true);
    expect(field("field-conflict-follow").checked).toBe(true);
    expect(field("field-history-follow").checked).toBe(true);
    expect(screen.getByTestId("settings-effective-conflict").dataset.value).toBe("true");
    expect(screen.getByTestId("settings-effective-conflict").textContent).toBe("In force now: on.");
    expect(screen.getByTestId("settings-effective-history").textContent).toBe("In force now: 90 days.");
    expect(screen.queryByTestId("field-conflict")).toBeNull();
    expect(screen.getByTestId("settings-nav")).toBeTruthy();
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("saves with the revision read, setting what no longer follows the profile", async () => {
    const writes = recordIfMatch();
    open();
    await loaded();
    const revision = dhcpState().settings.revision;
    fireEvent.input(field("field-lease-default"), { target: { value: "12" } });
    fireEvent.change(screen.getByTestId("field-lease-default-unit"), { target: { value: "hours" } });
    fireEvent.click(field("field-authoritative"));
    fireEvent.click(field("field-conflict-follow"));
    fireEvent.click(await screen.findByTestId("field-conflict"));
    fireEvent.click(field("field-history-follow"));
    fireEvent.input(await screen.findByTestId("field-history_days"), { target: { value: "14" } });
    fireEvent.click(screen.getByTestId("dhcp-settings-save"));
    await waitFor(() => expect(dhcpState().settings.history_days).toBe(14));
    const sent = writes().find((w) => w.method === "PUT");
    expect(sent?.ifMatch).toBe(`"${revision}"`);
    expect(sent?.body).toEqual({
      authoritative: false,
      ddns: {},
      lease: { default_secs: 43_200, min_secs: 3600, max_secs: 604_800 },
      conflict_detection: false,
      history_days: 14,
    });
    expect(dhcpState().settings.conflict_detection).toBe(false);
    expect(await screen.findByText("DHCP settings saved")).toBeTruthy();
    // A second save uses the revision of the first.
    fireEvent.click(screen.getByTestId("dhcp-settings-save"));
    await waitFor(() => expect(writes().filter((w) => w.method === "PUT")).toHaveLength(2));
    expect(writes().filter((w) => w.method === "PUT")[1]?.ifMatch).toBe(`"${dhcpState().settings.revision}"`);
  });

  it("lets the profile decide again when the settings follow it", async () => {
    dhcpState().settings.history_days = 14;
    dhcpState().settings.conflict_detection = false;
    const writes = recordIfMatch();
    open();
    await loaded();
    expect(field("field-conflict-follow").checked).toBe(false);
    expect(field("field-history-follow").checked).toBe(false);
    fireEvent.click(field("field-conflict-follow"));
    fireEvent.click(field("field-history-follow"));
    fireEvent.click(screen.getByTestId("dhcp-settings-save"));
    await waitFor(() => expect(dhcpState().settings.history_days).toBeUndefined());
    expect(dhcpState().settings.conflict_detection).toBeUndefined();
    expect(writes().find((w) => w.method === "PUT")?.body).not.toHaveProperty("history_days");
  });

  it("checks the lease times and the days before it sends", async () => {
    const writes = recordIfMatch();
    open();
    await loaded();
    fireEvent.input(field("field-lease-min"), { target: { value: "3" } });
    fireEvent.change(screen.getByTestId("field-lease-min-unit"), { target: { value: "days" } });
    fireEvent.click(field("field-history-follow"));
    fireEvent.input(await screen.findByTestId("field-history_days"), { target: { value: "0" } });
    fireEvent.click(screen.getByTestId("dhcp-settings-save"));
    await waitFor(() => expect(screen.getAllByTestId("field-error").map((e) => e.dataset.field)).toEqual(["lease-min", "history_days"]));
    expect(screen.getAllByTestId("field-error")[0]?.textContent).toBe("The shortest time must not exceed the default, and the default must not exceed the longest.");
    expect(writes()).toHaveLength(0);
  });

  it("shows the refusal of a save over settings that changed meanwhile", async () => {
    open();
    await loaded();
    dhcpState().settings.revision += 4;
    fireEvent.click(screen.getByTestId("dhcp-settings-save"));
    const notice = await screen.findByTestId("error-notice");
    expect(notice.dataset.code).toBe("sys.store.precondition_failed");
  });

  it("says the module is switched off", async () => {
    dhcpSwitchedOff();
    open();
    expect(await screen.findByTestId("dhcp-off")).toBeTruthy();
    expect(screen.queryByTestId("dhcp-settings-form")).toBeNull();
  });

  it("speaks Swedish", async () => {
    await setLocale("sv");
    open();
    await loaded();
    expect(screen.getByRole("heading", { level: 1 }).textContent).toBe("DHCP-inställningar");
    expect(screen.getByTestId("settings-effective-history").textContent).toBe("Gäller nu: 90 dagar.");
    expect(within(screen.getByTestId("dhcp-settings-form")).getByTestId("dhcp-settings-save").textContent).toBe("Spara");
  });
});

describe("the trusted relay agents", () => {
  it("says which state is in force while the list follows the profile", async () => {
    open();
    await loaded();
    expect(field("field-relays-follow").checked).toBe(true);
    expect(screen.getByTestId("settings-relays-none").textContent).toBe("No relay agent is trusted: only clients on this server's own links are served.");
    expect(screen.queryByTestId("field-trusted_relays")).toBeNull();
  });

  it("warns that every sender is trusted under the Lab profile", async () => {
    dhcpState().settings.effective_trust_any_relay = true;
    open();
    await loaded();
    const notice = screen.getByTestId("settings-relays-trust-any");
    expect(notice.className).toContain("warn");
    expect(notice.textContent).toContain("every sender is trusted as a relay agent");
    expect(screen.queryByTestId("settings-relays-none")).toBeNull();
  });

  it("saves the list normalized, a bare address as a host prefix", async () => {
    const writes = recordIfMatch();
    open();
    await loaded();
    fireEvent.click(field("field-relays-follow"));
    const text = "192.0.2.9 = 203.0.113.0/24,198.51.100.0/24\n\n198.51.100.0/24 = 198.51.100.0/24\n2001:db8::1 = 2001:db8::/32\n192.0.2.9 = 198.51.100.0/24, 203.0.113.0/24";
    fireEvent.input(await screen.findByTestId("field-trusted_relays"), { target: { value: text } });
    fireEvent.click(screen.getByTestId("dhcp-settings-save"));
    await waitFor(() => expect(dhcpState().settings.trusted_relays).toBeDefined());
    const stored = [
      { relay: "192.0.2.9/32", links: ["198.51.100.0/24", "203.0.113.0/24"] },
      { relay: "198.51.100.0/24", links: ["198.51.100.0/24"] },
      { relay: "2001:db8::1/128", links: ["2001:db8::/32"] },
    ];
    expect(writes().find((w) => w.method === "PUT")?.body?.trusted_relays).toEqual(stored);
    expect(dhcpState().settings.trusted_relays).toEqual(stored);
  });

  it("refuses a line the parser refuses, with its line number, before it sends", async () => {
    const writes = recordIfMatch();
    open();
    await loaded();
    fireEvent.click(field("field-relays-follow"));
    const area = await screen.findByTestId("field-trusted_relays");
    const refused = async (value: string, message: string) => {
      fireEvent.input(area, { target: { value } });
      fireEvent.click(screen.getByTestId("dhcp-settings-save"));
      await waitFor(() => expect(screen.getByTestId("field-error").textContent).toBe(message));
      expect(screen.getByTestId("field-error").dataset.field).toBe("trusted_relays");
    };
    await refused("192.0.2.1 = 198.51.100.0/24\n192.0.2.1/24 = 198.51.100.0/24", "Line 2: 192.0.2.1/24 = 198.51.100.0/24 has host bits set. Write 192.0.2.1/32 for a single address, or give the network address of the prefix.");
    await refused("relay.example = 198.51.100.0/24", "Line 1: relay.example = 198.51.100.0/24 is not an IPv4 or IPv6 address or prefix.");
    await refused("192.0.2.1", "Line 1: 192.0.2.1 names no links. Write the relay agent, an equals sign and the links it may name, such as 192.0.2.1 = 198.51.100.0/24.");
    await refused("192.0.2.1 = 2001:db8::/32", "Line 1: 192.0.2.1 = 2001:db8::/32 has a link of the other address family than the relay agent.");
    await refused("192.0.2.1 = 198.51.100.0/24\n192.0.2.1 = 203.0.113.0/24", "Line 2: 192.0.2.1 = 203.0.113.0/24 is listed twice with different links. Put all of its links on one line.");
    expect(writes()).toHaveLength(0);
  });

  it("shows the server's refusal of a new relay for every link on the field", async () => {
    server.use(
      http.put("/api/v1/dhcp/settings", () =>
        HttpResponse.json(
          { type: "about:blank", status: 400, code: "dhcp.settings.relay_any_link", title: "Bad request", detail: "no", params: { field: "trusted_relays" }, errors: [{ field: "trusted_relays", code: "dhcp.settings.relay_any_link" }] },
          { status: 400, headers: { "content-type": "application/problem+json" } },
        ),
      ),
    );
    open();
    await loaded();
    fireEvent.click(field("field-relays-follow"));
    fireEvent.input(await screen.findByTestId("field-trusted_relays"), { target: { value: "192.0.2.1 = 0.0.0.0/0" } });
    fireEvent.click(screen.getByTestId("dhcp-settings-save"));
    const error = await screen.findByTestId("field-error");
    expect([error.dataset.field, error.textContent]).toEqual(["trusted_relays", "A new relay agent may not name every link under the Hardened profile. Give it the links it serves."]);
  });

  it("clears a stored list when the settings follow the profile again", async () => {
    dhcpState().settings.trusted_relays = [{ relay: "192.0.2.1/32", links: ["198.51.100.0/24"] }];
    const writes = recordIfMatch();
    open();
    await loaded();
    expect(field("field-relays-follow").checked).toBe(false);
    expect((screen.getByTestId("field-trusted_relays") as HTMLTextAreaElement).value).toBe("192.0.2.1/32 = 198.51.100.0/24");
    fireEvent.click(field("field-relays-follow"));
    fireEvent.click(screen.getByTestId("dhcp-settings-save"));
    await waitFor(() => expect(dhcpState().settings.trusted_relays).toBeUndefined());
    const body = writes().find((w) => w.method === "PUT")?.body;
    expect(body?.clear_trusted_relays).toBe(true);
    expect(body).not.toHaveProperty("trusted_relays");
  });

  it("sends neither field when nothing was stored and the settings follow the profile", async () => {
    const writes = recordIfMatch();
    open();
    await loaded();
    fireEvent.click(screen.getByTestId("dhcp-settings-save"));
    await waitFor(() => expect(writes().filter((w) => w.method === "PUT")).toHaveLength(1));
    const body = writes().find((w) => w.method === "PUT")?.body;
    expect(body).not.toHaveProperty("trusted_relays");
    expect(body).not.toHaveProperty("clear_trusted_relays");
  });

  it("lists the senders refused and the networks relayed, and trusts a sender for the link around the relay address it named", async () => {
    const writes = recordIfMatch();
    open();
    await loaded();
    const panel = await screen.findByTestId("settings-relays-seen");
    expect(within(panel).getByTestId("settings-relays-relayed").textContent).toContain("198.51.100.0/24 through 198.51.100.1");
    const row = within(panel).getAllByTestId("relay-refused").find((r) => r.dataset.source === "192.0.2.1")!;
    expect(within(row).getByTestId("relay-known").textContent).toBe("Known relay");
    fireEvent.click(within(row).getByTestId("relay-trust"));
    const entry = { relay: "192.0.2.1/32", links: ["192.0.2.1/32"] };
    await waitFor(() => expect(dhcpState().settings.trusted_relays).toEqual([entry]));
    const sent = writes().find((w) => w.method === "PUT");
    expect(sent?.body?.trusted_relays).toEqual([entry]);
    expect(sent?.ifMatch).not.toBeNull();
    expect(await screen.findByText("192.0.2.1 is now a trusted relay agent with its links")).toBeTruthy();
    await waitFor(() => expect((screen.getByTestId("field-trusted_relays") as HTMLTextAreaElement).value).toBe("192.0.2.1/32 = 192.0.2.1/32"));
    await waitFor(() => expect(screen.getAllByTestId("relay-refused").map((r) => r.dataset.source)).toEqual(["203.0.113.1"]));
  });

  it("shows the link a trusted relay was refused for, and its Add link button adds it to the relay's entry", async () => {
    dhcpState().settings.trusted_relays = [{ relay: "203.0.113.1/32", links: ["198.51.100.0/24"] }];
    const writes = recordIfMatch();
    open();
    await loaded();
    const panel = await screen.findByTestId("settings-relays-seen");
    expect(within(panel).getByRole("columnheader", { name: "Network outside its links" })).toBeTruthy();
    // The sender 192.0.2.1 is not listed and is still offered for trust; the listed relay shows the link.
    const row = within(panel).getAllByTestId("relay-refused").find((r) => r.dataset.source === "203.0.113.1")!;
    expect(within(row).getByText("203.0.113.0/24")).toBeTruthy();
    expect(within(row).queryByTestId("relay-trust")).toBeNull();
    fireEvent.click(within(row).getByTestId("relay-add-link"));
    const entry = { relay: "203.0.113.1/32", links: ["198.51.100.0/24", "203.0.113.0/24"] };
    await waitFor(() => expect(dhcpState().settings.trusted_relays).toEqual([entry]));
    expect(writes().find((w) => w.method === "PUT")?.body?.trusted_relays).toEqual([entry]);
    await waitFor(() => expect(screen.getAllByTestId("relay-refused").map((r) => r.dataset.source)).toEqual(["192.0.2.1"]));
  });

  it("hides a refusal the list handles already", async () => {
    dhcpState().settings.trusted_relays = [
      { relay: "192.0.2.0/24", links: ["198.51.100.0/24"] },
      { relay: "203.0.113.1/32", links: ["203.0.113.0/24"] },
    ];
    open();
    await loaded();
    await screen.findByTestId("settings-relays-any-link");
    await waitFor(() => expect(screen.queryAllByTestId("relay-refused")).toHaveLength(0));
  });

  it("warns about a relay that may name every link, and binds it to the networks the lease rows show", async () => {
    dhcpState().settings.trusted_relays = [{ relay: "198.51.100.1/32", links: ["0.0.0.0/0"] }];
    const writes = recordIfMatch();
    open();
    await loaded();
    const notice = await screen.findByTestId("settings-relays-any-link");
    expect(notice.className).toContain("warn");
    expect(notice.textContent).toContain("Give each relay agent the links it serves");
    const item = within(notice).getByTestId("relay-any-link");
    expect(item.textContent).toContain("198.51.100.1/32 served 198.51.100.0/24");
    fireEvent.click(within(item).getByTestId("relay-bind"));
    const entry = { relay: "198.51.100.1/32", links: ["198.51.100.0/24"] };
    await waitFor(() => expect(dhcpState().settings.trusted_relays).toEqual([entry]));
    expect(writes().find((w) => w.method === "PUT")?.body?.trusted_relays).toEqual([entry]);
  });

  it("hides the panel when the node cannot be read", async () => {
    server.use(http.get("/api/v1/nodes/:id/dhcp", () => HttpResponse.json({ type: "about:blank", status: 403, code: "sys.forbidden", title: "Forbidden", detail: "no", params: {} }, { status: 403, headers: { "content-type": "application/problem+json" } })));
    open();
    await loaded();
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(screen.queryByTestId("settings-relays-seen")).toBeNull();
    expect(screen.getByTestId("field-relays-follow")).toBeTruthy();
  });
});

describe("the limits per client and per scope", () => {
  const put = (writes: ReturnType<typeof recordIfMatch>) => writes().find((w) => w.method === "PUT");

  it("follows the profile and shows the values in force", async () => {
    open();
    await loaded();
    expect(field("field-limits-follow").checked).toBe(true);
    expect(screen.getByTestId("settings-effective-limits").textContent).toBe(
      "In force now: bindings per MAC address 16; addresses per DUID 16, prefixes per DUID 8; new clients a second per scope 100; renewal cache 25 %.",
    );
    expect(screen.queryByTestId("field-limits_leases_per_mac")).toBeNull();
  });

  it("reads a limit that is off as off", async () => {
    dhcpState().settings.limits = { leases_per_mac: 0 };
    open();
    await loaded();
    expect(screen.getByTestId("settings-effective-limits").textContent).toContain("bindings per MAC address off");
  });

  it("sends all five numbers once the settings stop following the profile", async () => {
    const writes = recordIfMatch();
    open();
    await loaded();
    fireEvent.click(field("field-limits-follow"));
    expect(["leases_per_mac", "addresses_per_duid", "prefixes_per_duid", "offers_per_second", "renew_cache_percent"].map((n) => field(`field-limits_${n}`).value)).toEqual(["16", "16", "8", "100", "25"]);
    fireEvent.input(field("field-limits_leases_per_mac"), { target: { value: "64" } });
    fireEvent.input(field("field-limits_offers_per_second"), { target: { value: "0" } });
    fireEvent.click(screen.getByTestId("dhcp-settings-save"));
    await waitFor(() => expect(dhcpState().settings.limits).toBeDefined());
    const limits = { leases_per_mac: 64, addresses_per_duid: 16, prefixes_per_duid: 8, offers_per_second: 0, renew_cache_percent: 25 };
    expect(put(writes)?.body?.limits).toEqual(limits);
    expect(dhcpState().settings.limits).toEqual(limits);
  });

  it("refuses a value out of range before it sends", async () => {
    const writes = recordIfMatch();
    open();
    await loaded();
    fireEvent.click(field("field-limits-follow"));
    fireEvent.input(field("field-limits_renew_cache_percent"), { target: { value: "51" } });
    fireEvent.input(field("field-limits_prefixes_per_duid"), { target: { value: "x" } });
    fireEvent.click(screen.getByTestId("dhcp-settings-save"));
    await waitFor(() => expect(screen.getAllByTestId("field-error").map((e) => e.dataset.field)).toEqual(["limits_prefixes_per_duid", "limits_renew_cache_percent"]));
    expect(screen.getAllByTestId("field-error")[1]?.textContent).toBe("Enter a whole number from 0 to 50.");
    expect(writes()).toHaveLength(0);
  });

  it("sends an empty object when the settings follow the profile again over stored limits", async () => {
    dhcpState().settings.limits = { leases_per_mac: 4 };
    const writes = recordIfMatch();
    open();
    await loaded();
    expect(field("field-limits-follow").checked).toBe(false);
    expect(field("field-limits_leases_per_mac").value).toBe("4");
    fireEvent.click(field("field-limits-follow"));
    fireEvent.click(screen.getByTestId("dhcp-settings-save"));
    await waitFor(() => expect(dhcpState().settings.limits).toBeUndefined());
    expect(put(writes)?.body?.limits).toEqual({});
  });

  it("sends nothing about limits when nothing was stored and the settings follow the profile", async () => {
    const writes = recordIfMatch();
    open();
    await loaded();
    fireEvent.click(screen.getByTestId("dhcp-settings-save"));
    await waitFor(() => expect(writes().filter((w) => w.method === "PUT")).toHaveLength(1));
    expect(put(writes)?.body).not.toHaveProperty("limits");
  });

  it("shows the refusal of the server beside the field it names", async () => {
    server.use(
      http.put("/api/v1/dhcp/settings", () =>
        HttpResponse.json({ type: "about:blank", status: 400, code: "dhcp.settings.invalid", title: "Invalid", detail: "x", params: { field: "limits.offers_per_second" } }, { status: 400, headers: { "content-type": "application/problem+json" } }),
      ),
    );
    open();
    await loaded();
    fireEvent.click(field("field-limits-follow"));
    fireEvent.click(screen.getByTestId("dhcp-settings-save"));
    const error = await screen.findByTestId("field-error");
    expect(error.dataset.field).toBe("limits_offers_per_second");
  });

  it("lists the requests the limits refused with the note on the offer rate", async () => {
    open();
    await loaded();
    const panel = await screen.findByTestId("settings-limits-refused");
    const rows = within(panel).getAllByTestId("limit-refused");
    expect(rows.map((r) => r.dataset.limit)).toEqual(["leases_per_mac", "offers_per_second"]);
    const cells = (row: HTMLElement) => within(row).getAllByRole("cell").map((c) => c.textContent);
    expect(cells(rows[0] as HTMLElement).slice(0, 5)).toEqual(["Bindings per MAC address", "00:00:5e:00:53:40", "192.0.2.0/24", "holds 16 of 16", "3"]);
    expect(cells(rows[1] as HTMLElement).slice(0, 5)).toEqual(["New clients per second", "\u2014", "198.51.100.0/24", "holds 100 of 100", "41"]);
    expect(within(panel).getByTestId("settings-limits-offer-note").textContent).toContain("New clients wait for the scope's offer rate");
    expect(within(panel).queryByTestId("settings-limits-unlogged")).toBeNull();
  });

  it("hides the panel when the node cannot be read", async () => {
    server.use(http.get("/api/v1/nodes/:id/dhcp", () => HttpResponse.json({ type: "about:blank", status: 403, code: "sys.forbidden", title: "Forbidden", detail: "no", params: {} }, { status: 403, headers: { "content-type": "application/problem+json" } })));
    open();
    await loaded();
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(screen.queryByTestId("settings-limits-refused")).toBeNull();
    expect(screen.getByTestId("field-limits-follow")).toBeTruthy();
  });
});

describe("the list of trusted relay agents as text", () => {
  const parsed = (text: string) => {
    const check = relayList(text);
    if (!check.ok) throw new Error(`refused: ${check.problem}`);
    return check.list;
  };
  const problem = (text: string) => {
    const check = relayList(text);
    return check.ok ? "ok" : `${check.problem}@${check.line ?? 0}`;
  };

  it("writes the same text back that it read, with bare addresses as host prefixes", () => {
    const text = "192.0.2.1/32 = 198.51.100.0/24, 203.0.113.0/24\n2001:db8::1/128 = 2001:db8::/32";
    expect(relayText(parsed(text))).toBe(text);
    expect(parsed("192.0.2.1=198.51.100.0/24,203.0.113.0/24\n2001:db8::1 = 2001:db8::2")).toEqual([
      { relay: "192.0.2.1/32", links: ["198.51.100.0/24", "203.0.113.0/24"] },
      { relay: "2001:db8::1/128", links: ["2001:db8::2/128"] },
    ]);
    expect(relayText([])).toBe("");
  });

  it("keeps identical lines once and sorts the links of a relay", () => {
    expect(parsed("192.0.2.1 = 203.0.113.0/24, 198.51.100.0/24, 203.0.113.0/24\n\n192.0.2.1 = 198.51.100.0/24, 203.0.113.0/24")).toEqual([
      { relay: "192.0.2.1/32", links: ["198.51.100.0/24", "203.0.113.0/24"] },
    ]);
  });

  it("names each problem with the line it is on", () => {
    expect(problem("192.0.2.1")).toBe("no_links@1");
    expect(problem("192.0.2.1 =")).toBe("no_links@1");
    expect(problem("192.0.2.1 = 198.51.100.0/24,")).toBe("format@1");
    expect(problem("nonsense = 198.51.100.0/24")).toBe("format@1");
    expect(problem("192.0.2.1/24 = 198.51.100.0/24")).toBe("host_bits@1");
    expect(problem("192.0.2.1 = 198.51.100.1/24")).toBe("host_bits@1");
    expect(problem("192.0.2.1 = 2001:db8::/32")).toBe("family@1");
    expect(problem("2001:db8::1 = 0.0.0.0/0")).toBe("family@1");
    expect(problem("192.0.2.1 = 198.51.100.0/24\n192.0.2.1 = 203.0.113.0/24")).toBe("twice@2");
    const links = Array.from({ length: MAX_RELAY_LINKS + 1 }, (_, i) => `10.${i}.0.0/16`).join(", ");
    expect(problem(`192.0.2.1 = ${links}`)).toBe("links_count@1");
    expect(problem("192.0.2.1 = 0.0.0.0/0")).toBe("ok");
    const many = Array.from({ length: MAX_TRUSTED_RELAYS + 1 }, (_, i) => `10.0.${Math.floor(i / 256)}.${i % 256} = 198.51.100.0/24`).join("\n");
    expect(problem(many)).toBe("count@0");
  });

  it("finds the entry that holds a sender, and whether its links reach a network", () => {
    const list = [{ relay: "192.0.2.0/24", links: ["198.51.100.0/24"] }];
    expect(entryFor(list, "192.0.2.77")).toBe(list[0]);
    expect(entryFor(list, "203.0.113.1")).toBeUndefined();
    // The most specific relay prefix decides, as on the server, whatever the order.
    const nested = [list[0]!, { relay: "192.0.2.9/32", links: ["203.0.113.128/25"] }];
    expect(entryFor(nested, "192.0.2.9")).toBe(nested[1]);
    expect(entryFor([...nested].reverse(), "192.0.2.9")).toBe(nested[1]);
    expect(entryFor(nested, "192.0.2.8")).toBe(nested[0]);
    expect(holdsLink(list[0]!, "198.51.100.0/25")).toBe(true);
    expect(holdsLink(list[0]!, "198.51.0.0/16")).toBe(true);
    expect(holdsLink(list[0]!, "203.0.113.0/24")).toBe(false);
  });

  it("adds a link to the entry of a listed sender and lists a new sender with that link", () => {
    const list = [{ relay: "192.0.2.1/32", links: ["198.51.100.0/24"] }];
    expect(withLink(list, "192.0.2.1", "203.0.113.0/24")).toEqual([{ relay: "192.0.2.1/32", links: ["198.51.100.0/24", "203.0.113.0/24"] }]);
    expect(withLink(list, "192.0.2.1", "198.51.100.0/24")).toEqual(list);
    expect(withLink(list, "192.0.2.9", "192.0.2.9/32")).toEqual([...list, { relay: "192.0.2.9/32", links: ["192.0.2.9/32"] }]);
  });
});
