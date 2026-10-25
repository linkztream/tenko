// The lifecycle on the host page: the Decommission action, the banner of a decommissioned host
// (when, by whom, why, what it released) and Reinstate with the addresses that did not come back.
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { beforeEach, describe, expect, it } from "vitest";
import { ADDRESS_IDS, applyCommands, HOST_IDS, ipamState } from "../api/mock/ipam/api";
import type { IpamCommand } from "../api/types";
import { paths } from "../app/paths";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { signInAlex } from "../auth/account/testkit";
import { applied, confirmPlan, recordWrites } from "../ipam/testkit";
import HostView from "./HostView";

beforeEach(async () => {
  await signInAlex();
});

async function openHost(name: string) {
  const view = renderRoute(HostView, { url: paths.host(name), path: "/ipam/hosts/:fqdn" });
  await screen.findByTestId("host-modes");
  return view;
}

const stored = (name: string) => ipamState().data.host.get(HOST_IDS[name] as string);

function decommission(name: string, reason: string | null = null, keepDns = false): void {
  applyCommands([{ op: "decommission_host", args: { host: HOST_IDS[name], reason, keep_dns: keepDns } }] as unknown as IpamCommand[]);
}

const gone = (testid: string) => waitFor(() => expect(screen.queryByTestId(testid)).toBeNull());

describe("the banner of a decommissioned host", () => {
  it("says when, by whom and why, what the host released and what became of the DNS names", async () => {
    decommission("laptop-ak", "Moved to the lab");
    await openHost("laptop-ak");
    const banner = await screen.findByTestId("host-decommissioned");
    expect(within(banner).getByText("This host is decommissioned")).toBeTruthy();
    expect(within(banner).getByTestId("decommission-when").textContent).toMatch(/by .*alex/i);
    expect(within(banner).getByTestId("decommission-reason-text").textContent).toBe("Moved to the lab");
    expect(within(banner).getByTestId("decommission-released").textContent).toBe("1 address was released. Their DNS names were removed.");
    expect(within(banner).getByTestId("host-reinstate")).toBeTruthy();
    // A decommissioned host is not decommissioned again.
    expect(screen.queryByTestId("host-decommission")).toBeNull();
    // The addresses it released are no longer listed.
    await waitFor(() => expect(screen.getByText("No address is assigned to this host.")).toBeTruthy());
  });

  it("says when no reason was given and when the DNS names were kept", async () => {
    decommission("laptop-ak", null, true);
    await openHost("laptop-ak");
    const banner = await screen.findByTestId("host-decommissioned");
    expect(within(banner).getByTestId("decommission-reason-text").textContent).toBe("No reason was given.");
    expect(within(banner).getByTestId("decommission-released").textContent).toBe("1 address was released. Their DNS names were kept.");
  });

  it("has no accessibility violations", async () => {
    decommission("laptop-ak", "Away");
    await openHost("laptop-ak");
    await screen.findByTestId("host-decommissioned");
    expect(await axeViolations(screen.getByTestId("page-host"))).toEqual([]);
  });

  it("is not there for an active host", async () => {
    await openHost("laptop-ak");
    expect(screen.queryByTestId("host-decommissioned")).toBeNull();
    expect(screen.getByTestId("host-decommission")).toBeTruthy();
  });
});

describe("decommissioning from the host page", () => {
  it("previews, applies at the revision of the host and shows the banner", async () => {
    const writes = recordWrites();
    await openHost("laptop-ak");
    const revision = stored("laptop-ak")?.meta.revision;
    fireEvent.click(screen.getByTestId("host-decommission"));
    const form = await screen.findByTestId("dialog-decommission");
    fireEvent.input(within(form).getByTestId("decommission-reason"), { target: { value: "Retired" } });
    fireEvent.click(within(form).getByTestId("form-submit"));

    const plan = await screen.findByTestId("dialog-decommission-plan");
    await within(plan).findByTestId("plan-preview");
    const preview = writes().find((w) => w.url.includes("/decommission"));
    expect(preview?.url).toContain("dry_run=true");
    expect(preview?.headers["If-Match"]).toBe(`"${revision}"`);
    expect(stored("laptop-ak")?.decommissioned).toBeUndefined();

    await confirmPlan({ dialog: "dialog-decommission-plan" });
    await gone("dialog-decommission-plan");
    const sent = applied(writes()).filter((w) => w.url.includes("/decommission"));
    expect(sent).toHaveLength(1);
    expect(sent[0]?.body).toEqual({ reason: "Retired", keep_dns: false });
    // The page found the host again although the default lists leave it out.
    const banner = await screen.findByTestId("host-decommissioned");
    expect(within(banner).getByTestId("decommission-reason-text").textContent).toBe("Retired");
    await waitFor(() => expect(screen.queryByTestId("host-decommission")).toBeNull());
  });

  it("shows an error from the server in the dialog", async () => {
    await openHost("laptop-ak");
    fireEvent.click(screen.getByTestId("host-decommission"));
    const form = await screen.findByTestId("dialog-decommission");
    // Somebody else decommissions the host while the dialog is open.
    decommission("laptop-ak");
    fireEvent.click(within(form).getByTestId("form-submit"));
    const plan = await screen.findByTestId("dialog-decommission-plan");
    const notice = await within(plan).findByTestId("error-notice");
    expect(notice.getAttribute("data-code") === "ipam.revision_mismatch" || notice.getAttribute("data-code") === "ipam.host.decommissioned").toBe(true);
  });
});

describe("reinstating from the banner", () => {
  it("binds the released addresses again and removes the banner", async () => {
    decommission("laptop-ak", "Away");
    const writes = recordWrites();
    await openHost("laptop-ak");
    const banner = await screen.findByTestId("host-decommissioned");
    fireEvent.click(within(banner).getByTestId("host-reinstate"));
    const dialog = await screen.findByTestId("dialog-reinstate");
    expect(within(dialog).getByRole("heading", { name: "Reinstate laptop-ak" })).toBeTruthy();
    await confirmPlan({ dialog: "dialog-reinstate" });
    await gone("dialog-reinstate");
    expect(applied(writes()).filter((w) => w.url.includes("/reinstate"))).toHaveLength(1);
    await waitFor(() => expect(screen.queryByTestId("host-decommissioned")).toBeNull());
    expect(stored("laptop-ak")?.decommissioned).toBeUndefined();
    expect(screen.queryByTestId("host-reinstate-skipped")).toBeNull();
    expect(screen.getByTestId("host-decommission")).toBeTruthy();
  });

  it("lists the addresses that did not come back, each with its cause", async () => {
    decommission("laptop-ak");
    const other = [...ipamState().data.interface.values()].find((i) => i.host === HOST_IDS["gw"]);
    applyCommands([{ op: "update_address", args: { id: ADDRESS_IDS["192.0.2.20"], patch: { interface: other?.id } } }] as unknown as IpamCommand[]);
    await openHost("laptop-ak");
    fireEvent.click(within(await screen.findByTestId("host-decommissioned")).getByTestId("host-reinstate"));
    await confirmPlan({ dialog: "dialog-reinstate" });
    await gone("dialog-reinstate");
    const note = await screen.findByTestId("host-reinstate-skipped");
    expect(within(note).getByText("1 address was not bound again")).toBeTruthy();
    const items = within(note).getAllByTestId("reinstate-skipped");
    expect(items.map((li) => li.dataset.cause)).toEqual(["assigned"]);
    expect(items[0]?.textContent).toBe("192.0.2.20 was not bound to the host again: the address is assigned to another host.");
    fireEvent.click(within(note).getByRole("button", { name: "Dismiss" }));
    expect(screen.queryByTestId("host-reinstate-skipped")).toBeNull();
  });
});
