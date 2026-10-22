import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { beforeEach, describe, expect, it } from "vitest";
import { DNS_IDS } from "../../api/mock/dns-model";
import { IPAM_IDS, ipamState } from "../../api/mock/ipam/api";
import { dnsState } from "../../api/mock/routes-dns";
import type { Site } from "../../api/types";
import { paths } from "../../app/paths";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { signInAlex } from "../../auth/account/testkit";
import { dnsSwitchedOff } from "../../dns/testkit";
import { applied, choose, recordWrites } from "../testkit";
import CustomFieldsView from "./CustomFieldsView";
import SitesView, { descendants, sitePath } from "./SitesView";
import TagsView from "./TagsView";
import TenancyView from "./TenancyView";
import VlansView from "./VlansView";

beforeEach(async () => {
  await signInAlex();
});

function rows(grid: HTMLElement): HTMLElement[] {
  return within(grid).queryAllByTestId("row");
}

function rowKeys(grid: HTMLElement): string[] {
  return rows(grid).map((r) => r.dataset.key ?? "");
}

async function confirmPlan() {
  const confirm = (await screen.findByTestId("plan-confirm")) as HTMLButtonElement;
  await waitFor(() => expect(confirm.disabled).toBe(false));
  fireEvent.click(confirm);
}

describe("site helpers", () => {
  const site = (id: string, name: string, parent: string | null): Site =>
    ({ id, name, parent, ad_site: null, meta: {} }) as unknown as Site;
  const sites = [site("a", "Home", null), site("b", "Garage", "a"), site("c", "Shelf", "b"), site("d", "Lab", null)];

  it("finds a site and everything below it", () => {
    expect([...descendants(sites, "a")].sort()).toEqual(["a", "b", "c"]);
    expect([...descendants(sites, "d")]).toEqual(["d"]);
  });

  it("writes the path of a site through its parents and stops on a cycle", () => {
    expect(sitePath(sites, sites[2]!)).toBe("Home / Garage / Shelf");
    const cyclic = [site("x", "X", "y"), site("y", "Y", "x")];
    expect(sitePath(cyclic, cyclic[0]!)).toBe("Y / X");
  });
});

describe("VLANs", () => {
  it("lists the VLANs in id order with the color chip and the id as text", async () => {
    renderRoute(VlansView, { url: "/ipam/vlans" });
    const grid = await screen.findByTestId("grid-vlans");
    await waitFor(() => expect(rows(grid).length).toBe(6));
    expect(rowKeys(grid)[0]).toMatch(/^10 /);
    expect(rows(grid)[0]!.textContent).toContain("LAN");
    expect(await axeViolations(screen.getByTestId("page-ipam-vlans"))).toEqual([]);
  });

  it("narrows the list with a status term", async () => {
    renderRoute(VlansView, { url: "/ipam/vlans" });
    const grid = await screen.findByTestId("grid-vlans");
    await waitFor(() => expect(rows(grid).length).toBe(6));
    fireEvent.input(within(screen.getByTestId("filterbar-vlans")).getByTestId("filter-input"), { target: { value: "status:planned" } });
    await waitFor(() => expect(rowKeys(grid)).toEqual(["50 Guest"]));
  });

  it("refuses an id outside 1 to 4094 and creates a valid VLAN through the plan", async () => {
    renderRoute(VlansView, { url: "/ipam/vlans" });
    const grid = await screen.findByTestId("grid-vlans");
    await waitFor(() => expect(rows(grid).length).toBe(6));
    fireEvent.click(screen.getByTestId("vlan-create"));
    const form = await screen.findByTestId("dialog-vlan-form");
    fireEvent.input(within(form).getByTestId("field-vid"), { target: { value: "5000" } });
    fireEvent.input(within(form).getByTestId("field-name"), { target: { value: "Cameras" } });
    fireEvent.click(within(form).getByTestId("form-submit"));
    expect(await within(form).findByText(/from 1 to 4094/)).toBeTruthy();
    fireEvent.input(within(form).getByTestId("field-vid"), { target: { value: "60" } });
    fireEvent.click(within(form).getByTestId("form-submit"));
    await confirmPlan();
    await waitFor(() => expect([...ipamState().data.vlan.values()].some((v) => v.vid === 60 && v.name === "Cameras")).toBe(true));
    await waitFor(() => expect(rowKeys(grid)).toContain("60 Cameras"));
  });
});

describe("sites", () => {
  it("shows nested sites by path and keeps a site out of its own parent choices", async () => {
    renderRoute(SitesView, { url: "/ipam/sites" });
    const grid = await screen.findByTestId("grid-sites");
    await waitFor(() => expect(rows(grid).length).toBe(3));
    await waitFor(() => expect(grid.textContent).toContain("Home / Garage"));
    const home = rows(grid).find((r) => r.dataset.id === IPAM_IDS.site.home)!;
    fireEvent.dblClick(home);
    const form = await screen.findByTestId("dialog-site-form");
    const options = [...(within(form).getByLabelText("Inside site") as HTMLSelectElement).options].map((o) => o.textContent);
    expect(options).toContain("Lab");
    expect(options).not.toContain("Home");
    expect(options).not.toContain("Home / Garage");
    expect(await axeViolations(form)).toEqual([]);
  });
});

describe("tenants and VRFs", () => {
  it("shows both grids and creates a tenant", async () => {
    renderRoute(TenancyView, { url: "/ipam/tenants" });
    const tenants = await screen.findByTestId("grid-tenants");
    const vrfs = await screen.findByTestId("grid-vrfs");
    await waitFor(() => expect(rows(tenants).length).toBe(2));
    await waitFor(() => expect(rows(vrfs).length).toBe(2));
    await waitFor(() => expect(vrfs.textContent).toContain("Workshop"));
    fireEvent.click(screen.getByTestId("tenant-create"));
    const form = await screen.findByTestId("dialog-tenant-form");
    fireEvent.click(within(form).getByTestId("form-submit"));
    expect(await within(form).findByText("Enter a name.")).toBeTruthy();
    fireEvent.input(within(form).getByTestId("field-name"), { target: { value: "Lab customer" } });
    fireEvent.click(within(form).getByTestId("form-submit"));
    await confirmPlan();
    await waitFor(() => expect(rowKeys(tenants)).toContain("Lab customer"));
    expect(await axeViolations(screen.getByTestId("page-ipam-tenancy"))).toEqual([]);
  });
});

describe("the default zone of a tenant", () => {
  async function editWorkshop() {
    renderRoute(TenancyView, { url: "/ipam/tenants" });
    const tenants = await screen.findByTestId("grid-tenants");
    await waitFor(() => expect(rows(tenants).length).toBe(2));
    fireEvent.dblClick(rows(tenants).find((r) => r.dataset.id === IPAM_IDS.tenant.workshop)!);
    return screen.findByTestId("dialog-tenant-form");
  }
  const zoneNamed = (name: string) => dnsState().zones.find((z) => z.name === name)!;

  it("lists the primary forward zones of the tenant and sends the one that is chosen", async () => {
    const writes = recordWrites();
    // A zone of another tenant is not offered; one of this tenant is.
    zoneNamed("lab.example.test").kind = "primary";
    zoneNamed("lab.example.test").tenant = IPAM_IDS.tenant.default;
    zoneNamed("corp.example.test").kind = "primary";
    zoneNamed("corp.example.test").tenant = IPAM_IDS.tenant.workshop;
    const form = await editWorkshop();
    const select = (await within(form).findByTestId("tenant-default-zone")) as HTMLSelectElement;
    expect([...select.options].map((o) => o.textContent)).toEqual(["None (the tenant's first forward zone)", "corp.example.test", "example.test"]);
    expect(select.value).toBe("");
    expect(within(form).getByText(/follow it when they change/)).toBeTruthy();
    expect((within(form).getByTestId("form-submit") as HTMLButtonElement).disabled).toBe(true);
    choose("tenant-default-zone", DNS_IDS.zone.example);
    fireEvent.click(within(form).getByTestId("form-submit"));
    await confirmPlan();
    await waitFor(() => expect(ipamState().data.tenant.get(IPAM_IDS.tenant.workshop)?.dns).toEqual({ default_zone: DNS_IDS.zone.example }));
    const sent = applied(writes());
    expect(sent[0]?.body).toEqual({ dns: { default_zone: DNS_IDS.zone.example } });
  });

  it("clears the default zone with an empty dns member", async () => {
    const writes = recordWrites();
    const tenant = ipamState().data.tenant.get(IPAM_IDS.tenant.workshop)!;
    tenant.dns = { default_zone: DNS_IDS.zone.example };
    const form = await editWorkshop();
    const select = (await within(form).findByTestId("tenant-default-zone")) as HTMLSelectElement;
    expect(select.value).toBe(DNS_IDS.zone.example);
    choose("tenant-default-zone", "");
    fireEvent.click(within(form).getByTestId("form-submit"));
    await confirmPlan();
    await waitFor(() => expect(ipamState().data.tenant.get(IPAM_IDS.tenant.workshop)?.dns).toBeUndefined());
    expect(applied(writes())[0]?.body).toEqual({ dns: {} });
  });

  it("shows the refusal of the server under the field, worded by the reason", async () => {
    const form = await editWorkshop();
    await within(form).findByTestId("tenant-default-zone");
    choose("tenant-default-zone", DNS_IDS.zone.example);
    // The zone is deleted meanwhile.
    dnsState().zones.splice(dnsState().zones.indexOf(zoneNamed("example.test")), 1);
    fireEvent.click(within(form).getByTestId("form-submit"));
    // The refusal brings the person back to the form, which is rendered anew.
    await waitFor(() => expect(screen.getByTestId("tenant-default-zone").getAttribute("aria-invalid")).toBe("true"));
    expect(screen.getByTestId("field-error").textContent).toBe("The zone no longer exists.");
    expect((screen.getByTestId("tenant-default-zone") as HTMLSelectElement).value).toBe(DNS_IDS.zone.example);
    expect(screen.queryByTestId("dialog-plan")).toBeNull();
  });

  it("does not offer the setting when the DNS service is off", async () => {
    dnsSwitchedOff();
    const form = await editWorkshop();
    await within(form).findByTestId("field-name");
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(within(form).queryByTestId("tenant-default-zone")).toBeNull();
  });

  it("does not offer it for a new tenant", async () => {
    renderRoute(TenancyView, { url: "/ipam/tenants" });
    await waitFor(() => expect(rows(screen.getByTestId("grid-tenants")).length).toBe(2));
    fireEvent.click(screen.getByTestId("tenant-create"));
    const form = await screen.findByTestId("dialog-tenant-form");
    expect(within(form).queryByTestId("tenant-default-zone")).toBeNull();
  });
});

describe("tags", () => {
  it("counts the live objects per tag and links to the hosts and addresses that carry it", async () => {
    renderRoute(TagsView, { url: "/ipam/tags" });
    const grid = await screen.findByTestId("grid-tags");
    await waitFor(() => expect(rowKeys(grid)).toContain("iot"));
    // The most used tag comes first.
    expect(rowKeys(grid)[0]).toBe("iot");
    const iot = rows(grid)[0]!;
    const links = within(iot).getAllByRole("link") as HTMLAnchorElement[];
    expect(links.map((a) => decodeURIComponent(a.getAttribute("href") ?? ""))).toEqual([paths.hosts({ q: "tag:iot" }), paths.addresses({ q: "tag:iot" })].map(decodeURIComponent));
    expect(await axeViolations(screen.getByTestId("page-ipam-tags"))).toEqual([]);
  });
});

describe("custom fields", () => {
  it("lists the definitions with their value type and kinds", async () => {
    renderRoute(CustomFieldsView, { url: "/ipam/custom-fields" });
    const grid = await screen.findByTestId("grid-custom-fields");
    await waitFor(() => expect(rowKeys(grid)).toEqual(["asset_tag", "rack", "warranty_until"]));
    expect(rows(grid)[1]!.textContent).toContain("A1, A2, B1");
    expect(await axeViolations(screen.getByTestId("page-ipam-custom-fields"))).toEqual([]);
  });

  it("checks the key and the choices, then creates a select field", async () => {
    renderRoute(CustomFieldsView, { url: "/ipam/custom-fields" });
    const grid = await screen.findByTestId("grid-custom-fields");
    await waitFor(() => expect(rows(grid).length).toBe(3));
    fireEvent.click(screen.getByTestId("custom-field-create"));
    const form = await screen.findByTestId("dialog-custom-field-form");
    fireEvent.input(within(form).getByTestId("field-key"), { target: { value: "Floor" } });
    fireEvent.change(within(form).getByTestId("field-type"), { target: { value: "select" } });
    fireEvent.click(within(form).getByTestId("form-submit"));
    expect(await within(form).findByText(/starting with a letter, at most 64/)).toBeTruthy();
    expect(within(form).getByText("Enter at least one choice.")).toBeTruthy();
    fireEvent.input(within(form).getByTestId("field-key"), { target: { value: "floor" } });
    fireEvent.input(within(form).getByLabelText("Choices"), { target: { value: "Ground\nFirst\n" } });
    fireEvent.click(within(form).getByTestId("form-submit"));
    await confirmPlan();
    await waitFor(() => expect(rowKeys(grid)).toContain("floor"));
    const def = [...ipamState().data.custom_field.values()].find((f) => f.key === "floor");
    expect(def?.kind).toEqual({ type: "select", options: ["Ground", "First"] });
    expect(def?.applies_to).toEqual(["host"]);
  });
});
