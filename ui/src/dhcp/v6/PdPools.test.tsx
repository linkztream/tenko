// The delegation pools of a DHCPv6 scope (WP9.2): the section of the pools tab below the address
// pools (rows with the delegated length, the prefixes it holds and the prefixes bound, the empty
// state, no section for a DHCPv4 scope), the dialog that adds one (the local checks, the request,
// the refusals of the server under their fields), the delegated prefixes in the utilization, and
// who may add one.
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { DHCP_IDS } from "../../api/mock/dhcp-model";
import { IPAM_IDS, ipamState } from "../../api/mock/ipam/api";
import { server } from "../../api/mock/node";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { signInAlex } from "../../auth/account/testkit";
import { signInWithRoles } from "../../auth/scope-testkit";
import { setSessionForTest } from "../../auth/session";
import { setLocale } from "../../i18n";
import { applied, noteOf, recordWrites, typeInto } from "../../ipam/testkit";
import ScopePage from "../ScopePage";
import { UtilizationBar } from "../UtilizationBar";
import { cell, row, rows } from "../testkit";
import { checkPdDraft } from "./pdModel";

beforeEach(async () => {
  await signInAlex();
});

afterEach(async () => {
  setSessionForTest(null);
  await setLocale("en");
});

const open = (prefix: string, tab?: string) => renderRoute(ScopePage, { url: `/dhcp/scopes/${prefix}${tab ? `/${tab}` : ""}`, path: "/dhcp/scopes/:prefix/:tab?" });
const loaded = async () => screen.findByTestId("scope-name");
const POOL_KEY = "2001:db8:1:100::-2001:db8:1:1ff:ffff:ffff:ffff:ffff";
const pdRows = () => rows("dhcp-pd-pools");
const FIRST = "2001:db8:1:200::";
const LAST = "2001:db8:1:2ff:ffff:ffff:ffff:ffff";

describe("the checks of the add dialog", () => {
  const draft = { first: FIRST, last: LAST, len: "60" };
  const problems = (d: Partial<typeof draft>) => {
    const checked = checkPdDraft({ ...draft, ...d }, "2001:db8:1::/48");
    return checked.ok ? undefined : checked.problems;
  };

  it("accepts a pool on boundaries of the length and normalizes the addresses", () => {
    const checked = checkPdDraft({ first: "2001:DB8:1:200:0::", last: LAST, len: " 60 " }, "2001:db8:1::/48");
    expect(checked).toEqual({ ok: true, body: { first: "2001:db8:1:200::", last: LAST, delegated_len: 60 } });
  });

  it("names the field of every problem", () => {
    expect(problems({ first: "", last: "" })).toEqual({ first: "Enter an address.", last: "Enter an address." });
    expect(problems({ first: "nonsense" })?.first).toBe("This is not a valid IP address.");
    expect(problems({ first: "2001:db8:2::" })?.first).toBe("The range lies outside 2001:db8:1::/48.");
    expect(problems({ first: LAST, last: FIRST })?.last).toBe("The last address must not come before the first.");
    expect(problems({ len: "" })).toEqual({ delegated_len: "Enter the length of the delegated prefixes, for example 60." });
    expect(problems({ len: "x" })).toEqual({ delegated_len: "Enter a whole number, for example 60." });
    for (const len of ["48", "40", "65"]) expect(problems({ len })).toEqual({ delegated_len: "The length must be longer than /48 and at most /64." });
    expect(problems({ first: "2001:db8:1:208::" })).toEqual({ first: "The first address must be the first address of a /60 prefix." });
    expect(problems({ last: "2001:db8:1:2ff:ffff:ffff:ffff:fff0" })).toEqual({ last: "The last address must be the last address of a /60 prefix." });
  });
});

describe("the delegation pools section", () => {
  it("lists the delegation pool of a DHCPv6 scope with its length, prefixes, bound prefixes and lease time", async () => {
    const view = open(DHCP_IDS.pdV6, "pools");
    await loaded();
    expect(screen.getByTestId("pd-pools")).toBeTruthy();
    await waitFor(() => expect(pdRows()).toHaveLength(1));
    const pool = row("dhcp-pd-pools", POOL_KEY);
    expect(within(pool).getByTestId("pd-pool-row").dataset.key).toBe(POOL_KEY);
    expect(cell(pool, "len").textContent).toBe("/60");
    expect(within(pool).getByTestId("pd-pool-size").dataset.value).toBe("16");
    expect(within(pool).getByTestId("pd-pool-leased").dataset.value).toBe("1");
    expect(cell(pool, "lease").textContent).toBe("From the scope");
    // The delegation pool is not an address pool: the address list is empty.
    await waitFor(() => expect(screen.getByTestId("dhcp-pools-empty")).toBeTruthy());
    expect(rows("dhcp-pools")).toHaveLength(0);
    expect(screen.getByTestId("pools-address-title").textContent).toBe("Address pools");
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("keeps the address pools of a DHCPv6 scope in their own list and says there are no delegation pools", async () => {
    open(DHCP_IDS.lanV6, "pools");
    await loaded();
    await waitFor(() => expect(rows("dhcp-pools")).toHaveLength(1));
    expect(row("dhcp-pools", "2001:db8:0:10::100-2001:db8:0:10::1ff")).toBeTruthy();
    expect(await screen.findByTestId("pd-pools-empty")).toBeTruthy();
    expect(pdRows()).toHaveLength(0);
  });

  it("shows no delegation section for a DHCPv4 scope", async () => {
    open(DHCP_IDS.lan, "pools");
    await loaded();
    await waitFor(() => expect(rows("dhcp-pools")).toHaveLength(1));
    expect(screen.queryByTestId("pd-pools")).toBeNull();
    expect(screen.queryByTestId("pools-address-title")).toBeNull();
  });

  it("speaks Swedish", async () => {
    await setLocale("sv");
    open(DHCP_IDS.pdV6, "pools");
    await loaded();
    await waitFor(() => expect(pdRows()).toHaveLength(1));
    expect(within(screen.getByTestId("pd-pools")).getByRole("heading", { name: "Delegeringspooler" })).toBeTruthy();
    expect(screen.getByTestId("pd-pool-add").textContent).toContain("Lägg till en delegeringspool");
    expect(screen.getByTestId("pools-address-title").textContent).toBe("Adresspooler");
  });
});

describe("adding a delegation pool", () => {
  const dialog = () => screen.getByTestId("dialog-pd-pool-form");
  const openDialog = async () => {
    open(DHCP_IDS.pdV6, "pools");
    await loaded();
    await waitFor(() => expect(pdRows()).toHaveLength(1));
    fireEvent.click(screen.getByTestId("pd-pool-add"));
    await screen.findByTestId("dialog-pd-pool-form");
  };
  const fill = (first: string, last: string, len: string) => {
    typeInto("field-first", first);
    typeInto("field-last", last);
    typeInto("field-delegated_len", len);
  };
  const submit = () => fireEvent.click(within(dialog()).getByTestId("form-submit"));

  it("explains the length and checks the form before anything is sent", async () => {
    const writes = recordWrites();
    await openDialog();
    expect(noteOf("field-delegated_len")).toBe("The length of the prefixes handed to routers, for example 56 or 60. Longer than /48 and at most /64.");
    submit();
    expect(noteOf("field-first")).toBe("Enter an address.");
    expect(noteOf("field-delegated_len")).toBe("Enter the length of the delegated prefixes, for example 60.");
    fill(FIRST, LAST, "40");
    submit();
    expect(noteOf("field-delegated_len")).toBe("The length must be longer than /48 and at most /64.");
    expect(applied(writes())).toHaveLength(0);
    fill("2001:db8:1:208::", LAST, "60");
    submit();
    expect(noteOf("field-first")).toBe("The first address must be the first address of a /60 prefix.");
    expect(within(dialog()).getAllByTestId("field-error").map((e) => e.dataset.field)).toEqual(["first"]);
    expect(applied(writes())).toHaveLength(0);
  });

  it("makes the IPAM range with the role Delegation pool and lists it with its prefixes", async () => {
    const writes = recordWrites();
    await openDialog();
    fill(FIRST, LAST, "60");
    submit();
    await waitFor(() => expect(screen.queryByTestId("dialog-pd-pool-form")).toBeNull());
    const sent = applied(writes()).filter((w) => w.method === "POST");
    expect(sent).toHaveLength(1);
    expect(sent[0]?.url).toBe(`/api/v1/prefixes/${IPAM_IDS.prefix.pdV6}/ranges`);
    expect(sent[0]?.body).toEqual({ first: FIRST, last: LAST, delegated_len: 60, role: "dhcp_pd_pool" });
    const made = [...ipamState().data.range.values()].find((r) => r.first === FIRST);
    expect(made).toMatchObject({ role: "dhcp_pd_pool", delegated_len: 60, prefix: IPAM_IDS.prefix.pdV6 });
    await waitFor(() => expect(pdRows()).toHaveLength(2));
    const added = row("dhcp-pd-pools", `${FIRST}-${LAST}`);
    expect(cell(added, "len").textContent).toBe("/60");
    expect(within(added).getByTestId("pd-pool-size").dataset.value).toBe("16");
    expect(within(added).getByTestId("pd-pool-leased").dataset.value).toBe("0");
    expect(await screen.findByText(`Added the delegation pool ${FIRST} - ${LAST}`)).toBeTruthy();
  });

  it("shows what the server refuses under the fields it names", async () => {
    server.use(
      http.post("/api/v1/prefixes/:id/ranges", () =>
        HttpResponse.json(
          {
            type: "about:blank",
            title: "Bad Request",
            status: 400,
            code: "ipam.validation",
            detail: "refused",
            params: { field: "delegated_len" },
            errors: [{ field: "delegated_len", code: "ipam.validation" }],
          },
          { status: 400, headers: { "content-type": "application/problem+json" } },
        ),
      ),
    );
    await openDialog();
    fill(FIRST, LAST, "60");
    submit();
    await waitFor(() => expect(within(dialog()).getAllByTestId("field-error").map((e) => e.dataset.field)).toEqual(["delegated_len"]));
    expect(noteOf("field-delegated_len")).toBe("Some fields are not valid.");
    // The values stay and the dialog stays open.
    expect((screen.getByTestId("field-first") as HTMLInputElement).value).toBe(FIRST);
    expect(pdRows()).toHaveLength(1);
  });

  it("shows an overlap the server found under the first address", async () => {
    await openDialog();
    // The seeded pool covers 2001:db8:1:100:: to 2001:db8:1:1ff:ffff:ffff:ffff:ffff.
    fill("2001:db8:1:100::", "2001:db8:1:10f:ffff:ffff:ffff:ffff", "60");
    submit();
    await waitFor(() => expect(within(dialog()).getAllByTestId("field-error").map((e) => e.dataset.field)).toEqual(["first"]));
    expect(pdRows()).toHaveLength(1);
  });

  it("offers the button to an operator and not to a viewer", async () => {
    setSessionForTest(null);
    await signInWithRoles(["viewer"]);
    open(DHCP_IDS.pdV6, "pools");
    await loaded();
    await waitFor(() => expect(pdRows()).toHaveLength(1));
    expect(screen.queryByTestId("pd-pool-add")).toBeNull();
  });

  it("has no accessibility violations", async () => {
    await openDialog();
    expect(await axeViolations(dialog().closest("[role='dialog']") as HTMLElement)).toEqual([]);
    submit();
    expect(await axeViolations(dialog().closest("[role='dialog']") as HTMLElement)).toEqual([]);
  });
});

describe("the delegated prefixes in the utilization", () => {
  it("shows the prefixes bound of the prefixes the pools can hand out on the settings tab", async () => {
    open(DHCP_IDS.pdV6);
    await loaded();
    const figure = await screen.findByTestId("util-pd");
    expect(figure.textContent).toBe("1 of 16 bound");
    expect([figure.dataset.leased, figure.dataset.size, figure.dataset.value]).toEqual(["1", "16", "6"]);
    // The address figures leave the delegated prefixes out.
    expect(screen.getByTestId("util-pool_size").dataset.value).toBe("0");
    expect(screen.getByTestId("util-leased").dataset.value).toBe("0");
  });

  it("shows no such figure for a scope without delegation pools", async () => {
    open(DHCP_IDS.lanV6);
    await loaded();
    await waitFor(() => expect(screen.getByTestId("util-pool_size").dataset.value).toBe("256"));
    expect(screen.queryByTestId("util-pd")).toBeNull();
  });

  it("shows a bar and the words in the detail of the bar", async () => {
    renderRoute(() => <UtilizationBar prefix={DHCP_IDS.pdV6} detail />);
    const fact = await screen.findByText("1 of 16 bound");
    const pd = fact.closest("[data-key='pd']") as HTMLElement;
    expect([pd.dataset.leased, pd.dataset.size]).toEqual(["1", "16"]);
    expect(within(pd).getByTestId("scope-util-pd").dataset.key).toBe("6");
  });

  it("leaves the detail of an address scope as it was", async () => {
    renderRoute(() => <UtilizationBar prefix={DHCP_IDS.lan} detail />);
    await screen.findByTestId("util-facts");
    expect(screen.queryByTestId("scope-util-pd")).toBeNull();
    expect(screen.getAllByTestId("util-fact").map((f) => f.dataset.key)).toEqual(["leased", "reserved", "abandoned", "free", "pool_size"]);
  });
});
