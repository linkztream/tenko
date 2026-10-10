import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../../api/client";
import { events, type ApiEvent } from "../../api/events";
import { ADDRESS_IDS, HOST_IDS, IPAM_IDS, ipamState } from "../../api/mock/ipam/api";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { signInAlex } from "../../auth/account/testkit";
import { confirmPlan } from "../testkit";
import { HistoryDialog, HistoryPanel } from "./HistoryPanel";

beforeEach(async () => {
  await signInAlex();
});

const entries = () => screen.queryAllByTestId("history-entry");
const actions = () => entries().map((e) => e.getAttribute("data-action"));

describe("history panel", () => {
  it("shows the history of a host newest first, with the field changes", async () => {
    renderRoute(() => <HistoryPanel collection="hosts" id={HOST_IDS.nas as string} label="nas" revision={1} />);
    const panel = await screen.findByTestId("history-panel");
    await waitFor(() => expect(entries()).toHaveLength(2));
    // nas was a static host until three days ago, when it became a reservation.
    expect(actions()).toEqual(["update", "create"]);
    const [update, create] = entries() as [HTMLElement, HTMLElement];
    expect(within(update).getByText("Update")).toBeTruthy();
    const mode = update.querySelector('[data-field="mode"]');
    expect(mode?.textContent).toBe("mode: static → reserved");
    expect(within(update).getByText("ipam.apply").className).toContain("tag");
    expect(update.querySelector("time")?.getAttribute("datetime")).toBeTruthy();
    expect(update.textContent).toContain("(you)");
    expect(within(create).getByText("Create")).toBeTruthy();
    // A live object cannot be restored.
    expect(within(panel).queryByTestId("history-restore")).toBeNull();
    expect(within(panel).queryByTestId("history-more")).toBeNull();
  });

  it("restores a deleted host from its history and shows the restore", async () => {
    const id = HOST_IDS["old-printer"] as string;
    const onRestored = vi.fn();
    // The revision the page saw: the restore is a POST with If-Match, which the client now sends.
    const revision = ipamState().data.host.get(id)?.meta.revision;
    renderRoute(() => <HistoryPanel collection="hosts" id={id} label="old-printer" deleted revision={revision} onRestored={onRestored} />);
    await waitFor(() => expect(entries()).toHaveLength(2));
    expect(actions()).toEqual(["delete", "create"]);
    fireEvent.click(screen.getByTestId("history-restore"));
    const dialog = await screen.findByTestId("dialog-restore");
    expect(within(dialog).getByRole("heading", { name: "Restore host old-printer" })).toBeTruthy();
    await confirmPlan({ dialog: "dialog-restore" });
    await waitFor(() => expect(onRestored).toHaveBeenCalledTimes(1));
    expect(ipamState().data.host.get(id)?.meta.deleted).toBeFalsy();
    // The panel loads the history again: the restore is the newest entry.
    await waitFor(() => expect(actions()[0]).toBe("restore"));
    expect(screen.queryByTestId("dialog-restore")).toBeNull();
  });

  it("restores the deleted address 192.0.2.35 once the host it belonged to is back", async () => {
    const id = ADDRESS_IDS["192.0.2.35"] as string;
    const revision = ipamState().data.address.get(id)?.meta.revision;
    renderRoute(() => <HistoryPanel collection="addresses" id={id} label="192.0.2.35" deleted revision={revision} />);
    await waitFor(() => expect(actions()).toEqual(["delete", "create"]));
    expect(screen.getByTestId("history-restore").textContent).toBe("Restore");
    // The address belongs to the interface of the deleted old-printer: the server says so.
    fireEvent.click(screen.getByTestId("history-restore"));
    const dialog = await screen.findByTestId("dialog-restore");
    const alert = await within(dialog).findByRole("alert");
    expect(alert.textContent).toBe("The referenced interface is missing or deleted.");
    expect((within(dialog).getByTestId("plan-confirm") as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByTestId("dialog-restore")).toBeNull());
    // Restoring the host brings its interface and address back.
    await api.post("/api/v1/hosts/{id}/restore", { path: { id: HOST_IDS["old-printer"] as string } });
    expect(ipamState().data.address.get(id)?.meta.deleted).toBeFalsy();
  });

  it("restores a deleted address that has no host behind it", async () => {
    // A free-standing address, deleted and restored.
    const created = await api.post("/api/v1/addresses", { body: { ip: "192.0.2.77", vrf: IPAM_IDS.vrf.default } });
    const id = created.item?.id as string;
    await api.delete("/api/v1/addresses/{id}", { path: { id } });
    const onRestored = vi.fn();
    renderRoute(() => <HistoryPanel collection="addresses" id={id} label="192.0.2.77" deleted onRestored={onRestored} />);
    await waitFor(() => expect(actions()).toEqual(["delete", "create"]));
    fireEvent.click(screen.getByTestId("history-restore"));
    await screen.findByTestId("dialog-restore");
    await confirmPlan({ dialog: "dialog-restore" });
    await waitFor(() => expect(onRestored).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(actions()).toEqual(["restore", "delete", "create"]));
    expect(ipamState().data.address.get(id)?.meta.deleted).toBeFalsy();
  });

  it("loads more while the server has more", async () => {
    const id = IPAM_IDS.prefix.iot;
    const revision = () => ipamState().data.prefix.get(id)?.meta.revision;
    for (let i = 0; i < 104; i++) {
      await api.patch("/api/v1/prefixes/{id}", { path: { id }, body: { description: `Round ${i}` }, ifMatch: revision() });
    }
    renderRoute(() => <HistoryPanel collection="prefixes" id={id} label="198.51.100.0/24" />);
    await waitFor(() => expect(entries()).toHaveLength(100));
    const more = screen.getByTestId("history-more");
    expect(more.textContent).toBe("Load more");
    fireEvent.click(more);
    await waitFor(() => expect(entries()).toHaveLength(105));
    expect(screen.queryByTestId("history-more")).toBeNull();
    // Newest first, the creation last.
    expect(actions()[0]).toBe("update");
    expect(actions()[104]).toBe("create");
    expect(entries()[0]?.textContent).toContain("Round 103");
  });

  it("follows the live events that name the object", async () => {
    const handlers: ((event: ApiEvent) => void)[] = [];
    const off = vi.fn();
    vi.spyOn(events, "subscribe").mockImplementation((_topic, handler) => {
      handlers.push(handler);
      return off;
    });
    const id = IPAM_IDS.prefix.iot;
    const { unmount } = renderRoute(() => <HistoryPanel collection="prefixes" id={id} label="198.51.100.0/24" />);
    await waitFor(() => expect(entries()).toHaveLength(1));
    expect(handlers).toHaveLength(1);
    await api.patch("/api/v1/prefixes/{id}", { path: { id }, body: { description: "Changed" } });
    const event = (objects: { kind: string; id: string }[]): ApiEvent => ({ topic: "ipam", type: "ipam", objects, deleted: [], revision: 99, data: {} });
    // An event about another object changes nothing.
    handlers[0]?.(event([{ kind: "prefix", id: IPAM_IDS.prefix.lan }]));
    await new Promise((resolve) => setTimeout(resolve, 250));
    expect(entries()).toHaveLength(1);
    handlers[0]?.(event([{ kind: "prefix", id }]));
    await waitFor(() => expect(entries()).toHaveLength(2));
    expect(actions()[0]).toBe("update");
    unmount();
    expect(off).toHaveBeenCalled();
  });

  it("says what is wrong and tries again", async () => {
    renderRoute(() => <HistoryPanel collection="prefixes" id="0190d1c2-0000-7000-8000-00000000dead" label="nothing" />);
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toBeTruthy();
    expect(screen.getByRole("button", { name: "Try again" })).toBeTruthy();
    expect(entries()).toHaveLength(0);
  });

  it("has no accessibility violations", async () => {
    renderRoute(() => <HistoryPanel collection="hosts" id={HOST_IDS.nas as string} label="nas" />);
    const panel = await screen.findByTestId("history-panel");
    await waitFor(() => expect(entries()).toHaveLength(2));
    expect(await axeViolations(panel)).toEqual([]);
  });
});

describe("history dialog", () => {
  it("shows the history in a dialog that closes", async () => {
    const onClose = vi.fn();
    renderRoute(() => <HistoryDialog collection="hosts" id={HOST_IDS.nas as string} label="nas" onClose={onClose} />);
    const dialog = await screen.findByTestId("dialog-history");
    expect(within(dialog).getByRole("heading", { name: "History of nas" })).toBeTruthy();
    await waitFor(() => expect(entries()).toHaveLength(2));
    expect(await axeViolations(dialog.closest("[role='dialog']") as HTMLElement)).toEqual([]);
    fireEvent.click(within(dialog).getByRole("button", { name: "Close" }));
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});
