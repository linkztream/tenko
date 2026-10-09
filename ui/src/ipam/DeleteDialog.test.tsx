import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../api/client";
import { ADDRESS_IDS, IPAM_IDS, ipamState } from "../api/mock/ipam/api";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { signInAlex } from "../auth/account/testkit";
import { DeleteDialog, RestoreDialog } from "./DeleteDialog";
import { applied, recordWrites } from "./testkit";

const lan = () => ipamState().data.prefix.get(IPAM_IDS.prefix.lan);
const live = (kind: "range" | "address", prefix: string) =>
  [...ipamState().data[kind].values()].filter((o) => o.prefix === prefix && !o.meta.deleted);

beforeEach(async () => {
  await signInAlex();
});

function deletePrefix(onDone = vi.fn(), cascade = true) {
  renderRoute(() => (
    <DeleteDialog
      collection="prefixes"
      id={IPAM_IDS.prefix.lan}
      kind="prefix"
      label="192.0.2.0/24"
      revision={lan()?.meta.revision}
      cascade={cascade}
      onDone={onDone}
      onClose={() => {}}
    />
  ));
  return onDone;
}

describe("delete dialog", () => {
  it("names the object in its title and confirm button", async () => {
    deletePrefix();
    const dialog = await screen.findByTestId("dialog-delete");
    expect(within(dialog).getByRole("heading", { name: "Delete prefix 192.0.2.0/24" })).toBeTruthy();
    expect(within(dialog).getByTestId("plan-confirm").textContent).toBe("Delete prefix 192.0.2.0/24");
    expect(within(dialog).getByTestId("plan-confirm").className).toContain("danger");
  });

  it("shows the refusal of the server when the prefix still holds things", async () => {
    const writes = recordWrites();
    deletePrefix();
    const dialog = await screen.findByTestId("dialog-delete");
    const alert = await within(dialog).findByRole("alert");
    expect(alert.textContent).toContain("still in use (2 references)");
    expect((within(dialog).getByTestId("plan-confirm") as HTMLButtonElement).disabled).toBe(true);
    expect(lan()?.meta.deleted).toBeFalsy();
    // The check box is off: the dry run did not ask for the dependants to go.
    const dry = writes().find((w) => w.method === "DELETE");
    expect(dry?.url).toContain("dry_run=true");
    expect(dry?.url).not.toContain("cascade");
  });

  it("previews the dependants with the check box and deletes them together", async () => {
    const writes = recordWrites();
    const onDone = deletePrefix();
    const dialog = await screen.findByTestId("dialog-delete");
    await within(dialog).findByRole("alert");
    fireEvent.click(within(dialog).getByTestId("delete-cascade"));
    // A new preview: the dialog is a new one and the box stays on.
    const again = await screen.findByTestId("dialog-delete");
    const summary = await within(again).findByTestId("plan-summary");
    expect(summary.textContent).toMatch(/Prefix: 1 deleted/);
    expect(summary.textContent).toMatch(/Ranges: 2 deleted/);
    expect(summary.textContent).toMatch(/Addresses: \d+ deleted/);
    expect((within(again).getByTestId("delete-cascade") as HTMLInputElement).checked).toBe(true);
    expect(within(again).queryByRole("alert")).toBeNull();
    // Nothing was deleted by the preview.
    expect(lan()?.meta.deleted).toBeFalsy();
    expect(live("range", IPAM_IDS.prefix.lan)).toHaveLength(2);

    const confirm = within(again).getByTestId("plan-confirm") as HTMLButtonElement;
    await waitFor(() => expect(confirm.disabled).toBe(false));
    fireEvent.click(confirm);
    await waitFor(() => expect(onDone).toHaveBeenCalledTimes(1));
    expect(lan()?.meta.deleted).toBeTruthy();
    expect(live("range", IPAM_IDS.prefix.lan)).toHaveLength(0);
    const sent = applied(writes().filter((w) => w.method === "DELETE"));
    expect(sent).toHaveLength(1);
    expect(sent[0]?.url).toContain("cascade=true");
    expect(sent[0]?.headers["If-Match"]).toMatch(/^"\d+"$/);
    expect(await screen.findByText("Deleted prefix 192.0.2.0/24")).toBeTruthy();
  });

  it("offers Undo in the toast, which restores what was deleted", async () => {
    const onDone = deletePrefix();
    const dialog = await screen.findByTestId("dialog-delete");
    await within(dialog).findByRole("alert");
    fireEvent.click(within(dialog).getByTestId("delete-cascade"));
    const again = await screen.findByTestId("dialog-delete");
    await within(again).findByTestId("plan-summary");
    const confirm = within(again).getByTestId("plan-confirm") as HTMLButtonElement;
    await waitFor(() => expect(confirm.disabled).toBe(false));
    fireEvent.click(confirm);
    await waitFor(() => expect(onDone).toHaveBeenCalledTimes(1));
    expect(await screen.findByRole("button", { name: "Open job" })).toBeTruthy();

    fireEvent.click(await screen.findByRole("button", { name: "Undo" }));
    await waitFor(() => expect(lan()?.meta.deleted).toBeFalsy());
    expect(live("range", IPAM_IDS.prefix.lan)).toHaveLength(2);
    expect(await screen.findByText("Restored prefix 192.0.2.0/24")).toBeTruthy();
    // The view is told once more, so it can show the restored object.
    await waitFor(() => expect(onDone).toHaveBeenCalledTimes(2));
  });

  it("tells when the undo does not work", async () => {
    const onDone = vi.fn();
    renderRoute(() => (
      <DeleteDialog
        collection="addresses"
        id={ADDRESS_IDS["192.0.2.30"] as string}
        kind="address"
        label="192.0.2.30"
        onDone={onDone}
        onClose={() => {}}
      />
    ));
    const dialog = await screen.findByTestId("dialog-delete");
    expect(within(dialog).queryByTestId("delete-cascade")).toBeNull();
    const confirm = within(dialog).getByTestId("plan-confirm") as HTMLButtonElement;
    await waitFor(() => expect(confirm.disabled).toBe(false));
    fireEvent.click(confirm);
    await waitFor(() => expect(onDone).toHaveBeenCalledTimes(1));
    expect(ipamState().data.address.get(ADDRESS_IDS["192.0.2.30"] as string)?.meta.deleted).toBeTruthy();
    expect(await screen.findByText("Deleted address 192.0.2.30")).toBeTruthy();
    // Someone else takes the address before the undo.
    await api.post("/api/v1/addresses", { body: { ip: "192.0.2.30", vrf: IPAM_IDS.vrf.default } });
    fireEvent.click(await screen.findByRole("button", { name: "Undo" }));
    expect(await screen.findByText("Could not restore address 192.0.2.30")).toBeTruthy();
    expect(onDone).toHaveBeenCalledTimes(1);
  });

  it("offers the check box only where a delete can take dependants along", async () => {
    renderRoute(() => (
      <DeleteDialog collection="ranges" id={IPAM_IDS.range.pool} kind="range" label="192.0.2.100 - 192.0.2.199" cascade onDone={() => {}} onClose={() => {}} />
    ));
    const dialog = await screen.findByTestId("dialog-delete");
    await within(dialog).findByTestId("plan-preview");
    expect(within(dialog).queryByTestId("delete-cascade")).toBeNull();
    expect(within(dialog).getByRole("heading", { name: "Delete range 192.0.2.100 - 192.0.2.199" })).toBeTruthy();
  });

  it("is refused when the object changed since the person looked at it", async () => {
    renderRoute(() => (
      <DeleteDialog collection="ranges" id={IPAM_IDS.range.pool} kind="range" label="192.0.2.100 - 192.0.2.199" revision={1} onDone={() => {}} onClose={() => {}} />
    ));
    const dialog = await screen.findByTestId("dialog-delete");
    const alert = await within(dialog).findByRole("alert");
    expect(alert.textContent).toMatch(/changed|revision/i);
  });

  it("has no accessibility violations", async () => {
    deletePrefix();
    const dialog = await screen.findByTestId("dialog-delete");
    await within(dialog).findByRole("alert");
    expect(await axeViolations(dialog.closest("[role='dialog']") as HTMLElement)).toEqual([]);
  });
});

describe("restore dialog", () => {
  it("restores a deleted object after a preview", async () => {
    const onDone = vi.fn();
    const id = IPAM_IDS.prefix.managementV6;
    renderRoute(() => (
      <RestoreDialog
        collection="prefixes"
        id={id}
        kind="prefix"
        label="2001:db8:0:99::/64"
        revision={ipamState().data.prefix.get(id)?.meta.revision}
        onDone={onDone}
        onClose={() => {}}
      />
    ));
    const dialog = await screen.findByTestId("dialog-restore");
    expect(within(dialog).getByRole("heading", { name: "Restore prefix 2001:db8:0:99::/64" })).toBeTruthy();
    const summary = await within(dialog).findByTestId("plan-summary");
    expect(summary.textContent).toMatch(/Prefix: 1 restored/);
    expect(ipamState().data.prefix.get(id)?.meta.deleted).toBeTruthy();
    const confirm = within(dialog).getByTestId("plan-confirm") as HTMLButtonElement;
    expect(confirm.textContent).toBe("Restore prefix 2001:db8:0:99::/64");
    await waitFor(() => expect(confirm.disabled).toBe(false));
    fireEvent.click(confirm);
    await waitFor(() => expect(onDone).toHaveBeenCalledTimes(1));
    expect(ipamState().data.prefix.get(id)?.meta.deleted).toBeFalsy();
    expect(await screen.findByText("Restored prefix 2001:db8:0:99::/64")).toBeTruthy();
  });
});
