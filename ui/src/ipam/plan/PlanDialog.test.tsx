import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../../api/client";
import { IPAM_IDS, ipamState } from "../../api/mock/ipam/api";
import type { WriteResponse, Prefix } from "../../api/types";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { signInAlex } from "../../auth/account/testkit";
import { writeQuery } from "./describe";
import { PlanDialog, type SendOptions } from "./PlanDialog";

const create = (o: SendOptions) =>
  api.post("/api/v1/prefixes", {
    query: writeQuery(o.dryRun, o.acknowledge),
    body: { cidr: "2001:db8:0:40::/62", vrf: IPAM_IDS.vrf.default, description: "Lab v6" },
  }) as Promise<WriteResponse<Prefix>>;

beforeEach(async () => {
  await signInAlex();
});

describe("plan dialog", () => {
  it("previews first, blocks on a warning that needs an acknowledgement, then applies", async () => {
    const done = vi.fn();
    renderRoute(() => <PlanDialog title="Create prefix 2001:db8:0:40::/62" confirmLabel="Create prefix" send={create} onDone={done} onClose={() => {}} />);
    const dialog = await screen.findByRole("dialog", { name: "Create prefix 2001:db8:0:40::/62" });
    const blocking = await within(dialog).findByTestId("plan-blocking");
    expect(blocking.textContent).toMatch(/nibble boundary/);
    expect(within(dialog).getByTestId("plan-summary").textContent).toMatch(/Prefix: 1 created/);
    const confirm = within(dialog).getByTestId("plan-confirm") as HTMLButtonElement;
    expect(confirm.disabled).toBe(true);
    // Nothing was written by the preview.
    expect([...ipamState().data.prefix.values()].some((p) => p.cidr === "2001:db8:0:40::/62")).toBe(false);
    fireEvent.click(within(blocking).getByTestId("plan-ack"));
    expect(confirm.disabled).toBe(false);
    expect(await axeViolations(dialog)).toEqual([]);
    fireEvent.click(confirm);
    await waitFor(() => expect(done).toHaveBeenCalledTimes(1));
    const result = done.mock.calls[0]?.[0] as WriteResponse<Prefix>;
    expect(result.item?.cidr).toBe("2001:db8:0:40::/62");
    expect(result.job_id).toBeTruthy();
  });

  it("shows a refused preview as a translated error", async () => {
    const send = (o: SendOptions) =>
      api.post("/api/v1/prefixes", {
        query: writeQuery(o.dryRun, o.acknowledge),
        body: { cidr: "192.0.2.1/24", vrf: IPAM_IDS.vrf.default },
      }) as Promise<WriteResponse<Prefix>>;
    renderRoute(() => <PlanDialog title="Create prefix" confirmLabel="Create prefix" send={send} onDone={() => {}} onClose={() => {}} />);
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toMatch(/host bits/);
    expect((screen.getByTestId("plan-confirm") as HTMLButtonElement).disabled).toBe(true);
  });
});
