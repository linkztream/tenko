// The column widths of the hosts list: a header handle resizes a column, the width is kept for
// the signed-in user and comes back with the list, and the column menu resets it.
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { paths } from "../app/paths";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { signInAlex } from "../auth/account/testkit";
import { session } from "../auth/session";
import { widthsKey } from "../grid/widths";
import HostsView from "./HostsView";

beforeEach(async () => {
  await signInAlex();
});

afterEach(() => {
  localStorage.clear();
});

async function renderList() {
  const view = renderRoute(HostsView, { url: paths.hosts(), path: "/ipam/hosts" });
  await waitFor(() => expect(screen.queryAllByTestId("row").length).toBeGreaterThan(0));
  return view;
}

const grid = () => screen.getByRole("grid");
const nameCol = () => grid().querySelectorAll("col")[1] as HTMLElement;
const key = () => widthsKey("hosts", session()?.user.id);

describe("the hosts list's column widths", () => {
  it("resizes a column on its header handle, keeps it for the user and resets it from the column menu", async () => {
    const first = await renderList();
    expect(nameCol().style.width).toBe("220px");
    const handle = within(grid()).getByRole("separator", { name: "Resize column Name" });
    fireEvent.pointerDown(handle, { clientX: 300, pointerId: 1, pointerType: "mouse", button: 0 });
    fireEvent.pointerMove(handle, { clientX: 380, pointerId: 1, pointerType: "mouse" });
    fireEvent.pointerUp(handle, { clientX: 380, pointerId: 1, pointerType: "mouse" });
    expect(nameCol().style.width).toBe("300px");
    expect(key()).toContain(session()?.user.id ?? "missing");
    expect(JSON.parse(localStorage.getItem(key()) ?? "{}")).toMatchObject({ name: 300 });
    expect(await axeViolations(screen.getByTestId("grid-hosts"), { disable: ["region"] })).toEqual([]);

    // The list comes back with the width.
    first.unmount();
    await renderList();
    expect(nameCol().style.width).toBe("300px");
    // The list has a column menu, so the reset is there and not under the list.
    expect(screen.queryByTestId("grid-reset-widths")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Choose columns" }));
    fireEvent.click(screen.getByTestId("reset-column-widths"));
    expect(nameCol().style.width).toBe("220px");
    expect(localStorage.getItem(key())).toBeNull();
  });
});
