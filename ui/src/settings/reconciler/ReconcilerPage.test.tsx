import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { db } from "../../api/mock/db";
import { HOST_IDS, IPAM_IDS } from "../../api/mock/ipam/api";
import { nameAuthorityState } from "../../api/mock/name-authority";
import { server } from "../../api/mock/node";
import { reconcilerState } from "../../api/mock/routes-reconciler";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { recordWrites } from "../../ipam/testkit";
import { setSessionForTest } from "../../auth/session";
import { setLocale } from "../../i18n";
import { signInAs } from "../testkit";
import { body, displayOf, draftErrors, draftOf, FIELDS, secondsOf } from "./model";
import ReconcilerPage from "./ReconcilerPage";

const NO_SHELL = { disable: ["region"] } as const;

beforeEach(async () => {
  await setLocale("en");
  await signInAs();
});

afterEach(() => setSessionForTest(null));

async function openPage() {
  const view = renderRoute(ReconcilerPage, { url: "/settings/reconciler", path: "/settings/reconciler" });
  await screen.findByTestId("reconciler-form");
  return view;
}

const input = (id: string) => screen.getByTestId(`field-${id}`) as HTMLInputElement;
const type = (id: string, value: string) => fireEvent.input(input(id), { target: { value } });
const save = () => fireEvent.click(screen.getByTestId("form-submit"));

describe("the reconciler settings page", () => {
  it("shows the settings in human units with their limits", async () => {
    await openPage();
    expect(input("interval").value).toBe("300");
    expect(input("debounce").value).toBe("2");
    expect(input("refresh").value).toBe("15");
    expect(input("purge").value).toBe("1");
    expect(input("orphan").value).toBe("7");
    expect(input("retention").value).toBe("30");
    expect((screen.getByTestId("field-adopt") as HTMLInputElement).checked).toBe(true);
    expect(document.getElementById("rc-interval-limits")?.textContent).toBe("30 sec to 1 day, default 5 min");
    expect(document.getElementById("rc-orphan-limits")?.textContent).toBe("1 hr to 365 days, default 7 days");
  });

  it("saves changed values in seconds with the revision of the read", async () => {
    const revision = reconcilerState.revision;
    await openPage();
    type("interval", "120");
    type("orphan", "14");
    fireEvent.click(screen.getByTestId("field-adopt"));
    save();
    await waitFor(() => expect(reconcilerState.settings.interval_secs).toBe(120));
    expect(reconcilerState.settings.orphan_after_secs).toBe(14 * 86_400);
    expect(reconcilerState.settings.adopt).toBe(false);
    expect(reconcilerState.settings.refresh_secs).toBe(900);
    expect(reconcilerState.revision).not.toBe(revision);
    // The form starts again from the stored values.
    await waitFor(() => expect(input("interval").value).toBe("120"));
  });

  it("refuses values outside the limits before anything is sent", async () => {
    await openPage();
    type("interval", "10");
    expect(document.getElementById("rc-interval-limits")?.textContent).toBe("Use a value from 30 sec to 1 day.");
    expect(input("interval").getAttribute("aria-invalid")).toBe("true");
    save();
    expect(reconcilerState.settings.interval_secs).toBe(300);
    expect(screen.getAllByTestId("field-error")).toHaveLength(1);
    expect(screen.queryByTestId("error-notice")).toBeNull();
  });

  it("refuses a refresh interval that is not shorter than the retention", async () => {
    await openPage();
    type("retention", "1");
    type("refresh", "1440");
    expect(screen.getByTestId("field-error").getAttribute("data-field")).toBe("refresh");
    expect(screen.getByTestId("field-error").textContent).toContain("shorter than the retention (1 day)");
    save();
    expect(reconcilerState.settings.retention_secs).toBe(2_592_000);
  });

  it("reloads with a notice when someone else saved first", async () => {
    await openPage();
    reconcilerState.settings.interval_secs = 600;
    reconcilerState.revision = db.revision + 10;
    type("debounce", "5");
    save();
    expect(await screen.findByTestId("reconciler-reloaded")).toBeTruthy();
    await waitFor(() => expect(input("interval").value).toBe("600"));
    expect(reconcilerState.settings.debounce_secs).toBe(2);
    // Saving again now goes through.
    type("debounce", "5");
    save();
    await waitFor(() => expect(reconcilerState.settings.debounce_secs).toBe(5));
    await waitFor(() => expect(screen.queryByTestId("reconciler-reloaded")).toBeNull());
  });

  it("shows the refusal of a save by its code and field", async () => {
    await openPage();
    server.use(
      http.put("/api/v1/settings/reconciler", () =>
        HttpResponse.json(
          { type: "about:blank", status: 422, code: "ipam.reconciler.settings.invalid", title: "x", detail: "x", params: { field: "refresh_secs" } },
          { status: 422, headers: { "content-type": "application/problem+json" } },
        ),
      ),
    );
    save();
    const notice = await screen.findByTestId("error-notice");
    expect(notice.getAttribute("data-code")).toBe("ipam.reconciler.settings.invalid");
    expect(notice.textContent).toBe("The server refused the value of Refresh interval of a fact. Check the limits under the field.");
  });

  it("has no accessibility violations and works in Swedish", async () => {
    const view = await openPage();
    expect(await axeViolations(view.container, NO_SHELL)).toEqual([]);
    await setLocale("sv");
    await waitFor(() => expect(screen.getByTestId("page-reconciler").textContent).toContain("Körintervall"));
    expect(document.getElementById("rc-interval-limits")?.textContent).toBe("30 s till 1 d, standard 5 min");
  });
});

describe("the name authority", () => {
  const section = () => screen.getByTestId("name-authority");
  const global = () => screen.getByTestId("name-global");
  const orderOf = (id: string) =>
    within(screen.getByTestId(`${id}-order`))
      .queryAllByTestId("name-source")
      .map((li) => li.dataset.source);
  const rowOf = (id: string, source: string) =>
    within(screen.getByTestId(`${id}-order`))
      .getAllByTestId("name-source")
      .find((li) => li.dataset.source === source) as HTMLElement;
  const DEFAULT = ["proxmox", "home_assistant", "windows", "dns", "mdns", "llmnr", "unifi", "scan"];
  const HOME = IPAM_IDS.site.home;
  const by = { kind: "system", component: "ipam" } as never;

  async function openNames() {
    const view = await openPage();
    await screen.findByTestId("name-global");
    return view;
  }

  it("shows the default order, marked as the default, while no rule is stored", async () => {
    await openNames();
    expect(orderOf("name-global")).toEqual(DEFAULT);
    expect(global().textContent).toContain("Proxmox VE");
    expect(screen.getByTestId("default-tag").textContent).toBe("default");
    // Nothing to reset, and no site has a rule.
    expect(within(global()).queryByTestId("remove-rule")).toBeNull();
    expect(screen.getByTestId("name-sites-empty")).toBeTruthy();
    // The kinds that the default leaves out can be added.
    const add = within(global()).getByTestId("add-source") as HTMLSelectElement;
    expect([...add.options].map((o) => o.value)).toEqual(["", "dhcp", "other"]);
    expect(section().textContent).toContain("Kinds left out of a rule rank after the listed ones.");
  });

  it("moves a kind up and saves the new order with a PUT", async () => {
    await openNames();
    fireEvent.click(within(rowOf("name-global", "unifi")).getByRole("button", { name: "Move UniFi up" }));
    const moved = ["proxmox", "home_assistant", "windows", "dns", "mdns", "unifi", "llmnr", "scan"];
    expect(orderOf("name-global")).toEqual(moved);
    // The first and the last row cannot move out of the list.
    expect((within(rowOf("name-global", "proxmox")).getByRole("button", { name: "Move Proxmox VE up" }) as HTMLButtonElement).disabled).toBe(true);
    expect((within(rowOf("name-global", "scan")).getByRole("button", { name: "Move Scan down" }) as HTMLButtonElement).disabled).toBe(true);
    // Nothing is stored before Save.
    expect(nameAuthorityState().global).toBeNull();

    const writes = recordWrites();
    fireEvent.click(within(global()).getByTestId("save-rule"));
    await waitFor(() => expect(nameAuthorityState().global?.order).toEqual(moved));
    const put = writes().find((w) => w.method === "PUT" && w.url.endsWith("/api/v1/settings/reconciler/name-authority"));
    expect(put?.body).toEqual({ order: moved });
    expect(await screen.findByText("Name authority saved.")).toBeTruthy();
    // A stored rule is not the default any more, and can be reset.
    await waitFor(() => expect(screen.queryByTestId("default-tag")).toBeNull());
    expect(within(global()).getByTestId("remove-rule").textContent).toBe("Reset to default");
  });

  it("keeps the focus on the button that moved a kind", async () => {
    await openNames();
    const down = within(rowOf("name-global", "proxmox")).getByRole("button", { name: "Move Proxmox VE down" });
    down.focus();
    fireEvent.click(down);
    await waitFor(() => expect(orderOf("name-global").slice(0, 2)).toEqual(["home_assistant", "proxmox"]));
    await waitFor(() =>
      expect(document.activeElement).toBe(within(rowOf("name-global", "proxmox")).getByRole("button", { name: "Move Proxmox VE down" })),
    );
  });

  it("removes a kind and adds one that was not in the list", async () => {
    await openNames();
    fireEvent.click(within(rowOf("name-global", "windows")).getByRole("button", { name: "Remove Windows from the list" }));
    expect(orderOf("name-global")).toEqual(["proxmox", "home_assistant", "dns", "mdns", "llmnr", "unifi", "scan"]);
    // Choosing adds nothing; the button does.
    fireEvent.change(within(global()).getByTestId("add-source"), { target: { value: "dhcp" } });
    expect(orderOf("name-global")).not.toContain("dhcp");
    fireEvent.click(within(global()).getByTestId("add-source-button"));
    const next = ["proxmox", "home_assistant", "dns", "mdns", "llmnr", "unifi", "scan", "dhcp"];
    expect(orderOf("name-global")).toEqual(next);
    expect([...(within(global()).getByTestId("add-source") as HTMLSelectElement).options].map((o) => o.value)).toEqual(["", "windows", "other"]);

    fireEvent.click(within(global()).getByTestId("save-rule"));
    await waitFor(() => expect(nameAuthorityState().global?.order).toEqual(next));
  });

  it("does not save an empty order", async () => {
    await openNames();
    for (const source of DEFAULT) fireEvent.click(within(rowOf("name-global", source)).getByRole("button", { name: /^Remove / }));
    expect(orderOf("name-global")).toEqual([]);
    expect(screen.getByTestId("order-empty").textContent).toBe("The order needs at least one kind of source.");
    expect((within(global()).getByTestId("save-rule") as HTMLButtonElement).disabled).toBe(true);
  });

  it("resets to the default order with a DELETE", async () => {
    nameAuthorityState().global = { site: null, order: ["dns", "proxmox"], updated: { at: "2026-10-01T00:00:00Z", by }, revision: 1 };
    await openNames();
    expect(orderOf("name-global")).toEqual(["dns", "proxmox"]);
    expect(screen.queryByTestId("default-tag")).toBeNull();

    const writes = recordWrites();
    fireEvent.click(within(global()).getByTestId("remove-rule"));
    await waitFor(() => expect(nameAuthorityState().global).toBeNull());
    expect(writes().some((w) => w.method === "DELETE" && w.url.endsWith("/api/v1/settings/reconciler/name-authority"))).toBe(true);
    await waitFor(() => expect(orderOf("name-global")).toEqual(DEFAULT));
    expect(screen.getByTestId("default-tag")).toBeTruthy();
    expect(await screen.findByText("The default order applies again.")).toBeTruthy();
  });

  it("shows the refusal of the server the way the page shows its other errors", async () => {
    server.use(
      http.put("/api/v1/settings/reconciler/name-authority", () =>
        HttpResponse.json(
          { type: "about:blank", status: 422, code: "ipam.name_authority.invalid", title: "x", detail: "x", params: { field: "order" } },
          { status: 422, headers: { "content-type": "application/problem+json" } },
        ),
      ),
    );
    await openNames();
    fireEvent.click(within(global()).getByTestId("save-rule"));
    const notice = await within(global()).findByTestId("error-notice");
    expect(notice.getAttribute("data-code")).toBe("ipam.name_authority.invalid");
    expect(notice.textContent).toBe("The order must list one to ten kinds of source, each once.");
  });

  it("adds a rule for a site, saves it, and removes it again", async () => {
    await openNames();
    const pick = screen.getByTestId("add-site") as HTMLSelectElement;
    expect([...pick.options].map((o) => o.textContent)).toEqual(["Choose a site…", "Garage", "Home", "Lab"]);
    fireEvent.change(pick, { target: { value: HOME } });
    fireEvent.click(screen.getByTestId("add-site-button"));

    const id = `name-site-${HOME}`;
    const block = await screen.findByTestId(id);
    expect(block.textContent).toContain("Site Home");
    // It starts from the order in force and is not stored until it is saved.
    expect(orderOf(id)).toEqual(DEFAULT);
    expect(nameAuthorityState().sites.size).toBe(0);
    expect(within(block).getByTestId("cancel-rule")).toBeTruthy();
    // The site has its rule now, so it is not offered again.
    expect([...(screen.getByTestId("add-site") as HTMLSelectElement).options].map((o) => o.textContent)).toEqual(["Choose a site…", "Garage", "Lab"]);

    fireEvent.click(within(rowOf(id, "dns")).getByRole("button", { name: "Move DNS up" }));
    const writes = recordWrites();
    fireEvent.click(within(block).getByTestId("save-rule"));
    const moved = ["proxmox", "home_assistant", "dns", "windows", "mdns", "llmnr", "unifi", "scan"];
    await waitFor(() => expect(nameAuthorityState().sites.get(HOME)?.order).toEqual(moved));
    expect(writes().find((w) => w.method === "PUT" && w.url.endsWith(`/name-authority/sites/${HOME}`))?.body).toEqual({ order: moved });
    expect(await screen.findByText("The rule of site Home is saved.")).toBeTruthy();
    await waitFor(() => {
      const remove = within(screen.getByTestId(id)).getByTestId("remove-rule") as HTMLButtonElement;
      expect(remove.textContent).toBe("Remove rule");
      expect(remove.disabled).toBe(false);
    });

    fireEvent.click(within(screen.getByTestId(id)).getByTestId("remove-rule"));
    await waitFor(() => expect(nameAuthorityState().sites.size).toBe(0));
    await waitFor(() => expect(screen.queryByTestId(id)).toBeNull());
    expect(writes().some((w) => w.method === "DELETE" && w.url.endsWith(`/name-authority/sites/${HOME}`))).toBe(true);
  });

  it("drops a rule for a site that was not saved", async () => {
    await openNames();
    fireEvent.change(screen.getByTestId("add-site"), { target: { value: IPAM_IDS.site.lab } });
    fireEvent.click(screen.getByTestId("add-site-button"));
    const block = await screen.findByTestId(`name-site-${IPAM_IDS.site.lab}`);
    fireEvent.click(within(block).getByTestId("cancel-rule"));
    expect(screen.queryByTestId(`name-site-${IPAM_IDS.site.lab}`)).toBeNull();
    expect(nameAuthorityState().sites.size).toBe(0);
  });

  it("lists the stored rules of sites by the name of the site", async () => {
    nameAuthorityState().sites.set(IPAM_IDS.site.garage, { site: IPAM_IDS.site.garage, order: ["unifi", "dns"], updated: { at: "2026-10-01T00:00:00Z", by }, revision: 1 });
    await openNames();
    const block = await screen.findByTestId(`name-site-${IPAM_IDS.site.garage}`);
    expect(block.textContent).toContain("Site Garage");
    expect(orderOf(`name-site-${IPAM_IDS.site.garage}`)).toEqual(["unifi", "dns"]);
    expect(screen.queryByTestId("name-sites-empty")).toBeNull();
  });

  it("lists the hosts that prefer a source and forgets one", async () => {
    await openNames();
    const row = await screen.findByTestId("name-preference");
    expect(row.dataset.host).toBe(HOST_IDS["nas"]);
    expect(row.textContent).toContain("Proxmox VE");
    expect(within(row).getByRole("link", { name: "nas" }).getAttribute("href")).toContain("/ipam/hosts/nas");

    const writes = recordWrites();
    fireEvent.click(within(row).getByRole("button", { name: "Forget the preferred source of nas" }));
    await waitFor(() => expect(nameAuthorityState().preferences.size).toBe(0));
    expect(writes().some((w) => w.method === "DELETE" && w.url.endsWith(`/name-authority/hosts/${HOST_IDS["nas"]}`))).toBe(true);
    await waitFor(() => expect(screen.getByTestId("name-preferences-empty").textContent).toBe("No host prefers a source."));
    expect(await screen.findByText("The preferred source of nas is forgotten.")).toBeTruthy();
  });

  it("works in Swedish", async () => {
    await openNames();
    await setLocale("sv");
    await waitFor(() => expect(screen.getByTestId("name-authority").textContent).toContain("Namnauktoritet"));
    expect(screen.getByTestId("default-tag").textContent).toBe("standard");
    expect(within(rowOf("name-global", "scan")).getByRole("button", { name: "Flytta upp Skanning" })).toBeTruthy();
  });

  it("has no accessibility violations", async () => {
    const view = await openNames();
    await screen.findByTestId("name-preference");
    expect(await axeViolations(view.container, NO_SHELL)).toEqual([]);
  });
});

describe("the reconciler model", () => {
  const stored = {
    adopt: true,
    dns_actuator: true,
    dns_orphans: "remove" as const,
    debounce_secs: 2,
    interval_secs: 300,
    orphan_after_secs: 604_800,
    purge_interval_secs: 300,
    refresh_secs: 900,
    retention_secs: 2_592_000,
  };

  it("keeps a stored value that has no exact display unchanged when saved", () => {
    const draft = draftOf(stored);
    const purge = FIELDS.find((f) => f.id === "purge")!;
    expect(draft.text.purge).toBe(displayOf(purge, 300));
    expect(body(draft, stored)).toEqual(stored);
  });

  it("converts typed numbers to whole seconds and refuses fractions of a second", () => {
    const minute = FIELDS.find((f) => f.id === "refresh")!;
    expect(secondsOf(minute, "1.5", 900)).toBe(90);
    const second = FIELDS.find((f) => f.id === "interval")!;
    expect(secondsOf(second, "30.5", 300)).toBeNaN();
    expect(secondsOf(second, "", 300)).toBeNaN();
    expect(secondsOf(second, "abc", 300)).toBeNaN();
  });

  it("reports an error per field and none for the defaults", () => {
    expect(draftErrors(draftOf(stored), stored)).toEqual({});
    const draft = draftOf(stored);
    draft.text.debounce = "301";
    expect(Object.keys(draftErrors(draft, stored))).toEqual(["debounce"]);
  });
});
