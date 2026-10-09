import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { createSignal } from "solid-js";
import { afterEach, describe, expect, it } from "vitest";
import { mockUpdates } from "../api/mock/routes-updates";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { setSessionForTest } from "../auth/session";
import { signInAdmin } from "./testkit";
import WhatsNew from "./WhatsNew";

afterEach(() => setSessionForTest(null));

function Harness() {
  const [open, setOpen] = createSignal(false);
  return (
    <>
      <button type="button" onClick={() => setOpen(true)}>
        Reopen the notes
      </button>
      <WhatsNew open={open()} onClose={() => setOpen(false)} />
    </>
  );
}

function mount() {
  return renderRoute(Harness, { url: "/", path: "/" });
}

async function settle() {
  await new Promise((resolve) => setTimeout(resolve, 80));
}

describe("what is new", () => {
  it("opens a dialog with the notes since the last version the user saw, and posts seen when it closes", async () => {
    await signInAdmin();
    mockUpdates.running = "0.2.0";
    mockUpdates.lastSeen = "0.0.9";
    mount();
    const dialog = await screen.findByTestId("dialog-whats-new");
    expect(within(dialog).getByRole("heading", { name: "What is new in 0.2.0" })).toBeTruthy();
    expect(dialog.textContent).toContain("Changes since version 0.0.9");

    // Newest first, with the marks of each release.
    const cards = within(dialog).getAllByTestId("update-release");
    expect(cards.map((c) => c.getAttribute("data-key"))).toEqual(["0.2.0", "0.1.1", "0.1.0-dev"]);
    expect(within(cards[0]!).getByText("Action required")).toBeTruthy();
    expect(within(cards[0]!).getByTestId("update-action").textContent).toContain("Make a backup of the data directory.");
    expect(within(cards[1]!).getByText("Security fixes")).toBeTruthy();
    expect(mockUpdates.seenPosts).toBe(0);
    expect(await axeViolations(dialog)).toEqual([]);

    fireEvent.click(within(dialog).getByTestId("whats-new-close"));
    await waitFor(() => expect(screen.queryByTestId("dialog-whats-new")).toBeNull());
    await waitFor(() => expect(mockUpdates.seenPosts).toBe(1));
    expect(mockUpdates.lastSeen).toBe("0.2.0");
  });

  it("closes with Escape and still posts seen", async () => {
    await signInAdmin();
    mockUpdates.lastSeen = "0.0.9";
    mount();
    const dialog = await screen.findByTestId("dialog-whats-new");
    fireEvent.keyDown(dialog, { key: "Escape" });
    await waitFor(() => expect(screen.queryByTestId("dialog-whats-new")).toBeNull());
    await waitFor(() => expect(mockUpdates.seenPosts).toBe(1));
  });

  it("is shown once in a session, however often the shell mounts", async () => {
    await signInAdmin();
    mockUpdates.lastSeen = "0.0.9";
    const first = mount();
    fireEvent.click(within(await screen.findByTestId("dialog-whats-new")).getByTestId("whats-new-close"));
    await waitFor(() => expect(mockUpdates.seenPosts).toBe(1));
    first.unmount();

    // The server would still say "show" (as if the post had been lost): the session has seen it.
    mockUpdates.lastSeen = "0.0.9";
    mount();
    await settle();
    expect(screen.queryByTestId("dialog-whats-new")).toBeNull();
    expect(mockUpdates.seenPosts).toBe(1);
  });

  it("starts a new user from the running version without a dialog", async () => {
    await signInAdmin();
    mockUpdates.lastSeen = null;
    mount();
    await waitFor(() => expect(mockUpdates.seenPosts).toBe(1));
    expect(screen.queryByTestId("dialog-whats-new")).toBeNull();
    expect(mockUpdates.lastSeen).toBe("0.1.0-dev");
  });

  it("does nothing for a user who saw the running version", async () => {
    await signInAdmin();
    mockUpdates.lastSeen = "0.1.0-dev";
    mount();
    await settle();
    expect(screen.queryByTestId("dialog-whats-new")).toBeNull();
    expect(mockUpdates.seenPosts).toBe(0);
  });

  it("stays quiet when the server has no update service", async () => {
    await signInAdmin();
    mockUpdates.unavailable = true;
    mount();
    await settle();
    expect(screen.queryByTestId("dialog-whats-new")).toBeNull();
    expect(mockUpdates.seenPosts).toBe(0);
  });

  it("opens the same notes again on request, without posting seen a second time", async () => {
    await signInAdmin();
    mockUpdates.lastSeen = "0.0.9";
    mount();
    fireEvent.click(within(await screen.findByTestId("dialog-whats-new")).getByTestId("whats-new-close"));
    await waitFor(() => expect(mockUpdates.seenPosts).toBe(1));

    fireEvent.click(screen.getByRole("button", { name: "Reopen the notes" }));
    const dialog = await screen.findByTestId("dialog-whats-new");
    expect(within(dialog).getByText("Notes of the running version, shown after an upgrade.")).toBeTruthy();
    fireEvent.click(within(dialog).getByTestId("whats-new-close"));
    await waitFor(() => expect(screen.queryByTestId("dialog-whats-new")).toBeNull());
    expect(mockUpdates.seenPosts).toBe(1);
  });

  it("says that there is nothing to show when it is asked for before any notes were shown", async () => {
    await signInAdmin();
    mockUpdates.lastSeen = "0.1.0-dev";
    mount();
    await settle();
    fireEvent.click(screen.getByRole("button", { name: "Reopen the notes" }));
    const dialog = await screen.findByTestId("dialog-whats-new");
    expect(within(dialog).getByTestId("whats-new-empty").textContent).toBe("There are no release notes to show for version 0.1.0-dev.");
  });
});
