// The dialog panel against the viewport: the panel is capped to the viewport's height and
// scrolls as a whole, the title stays pinned at its top and the actions at its bottom, so
// the buttons are in reach however tall the content. The styles come from the real
// stylesheet (jsdom resolves the cascade, not the layout); the focus and aria behaviour of
// the panel is checked alongside, since the fix must leave it alone.
import { cleanup, fireEvent, render, screen } from "@solidjs/testing-library";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import appCss from "../app/styles/app.css?raw";
import { ConfirmDialog, Dialog } from "./Dialog";

beforeAll(() => {
  // Vitest serves stylesheets as empty modules, this one excepted (vite.config.ts); jsdom
  // resolves the cascade from it, not the layout.
  expect(appCss.length).toBeGreaterThan(0);
  const style = document.createElement("style");
  style.textContent = appCss;
  document.head.append(style);
});

afterEach(() => {
  cleanup();
});

function mountForm() {
  const onClose = vi.fn();
  render(() => (
    <Dialog label="Tall form" onClose={onClose} class="dialog connector-dialog" testid="dialog-tall">
      <form class="connector-form">
        <h2 class="dialog-title">Tall form</h2>
        <div data-testid="body">
          <label>
            First <input data-testid="first" />
          </label>
          <label>
            Second <input data-testid="second" />
          </label>
        </div>
        <div class="dialog-actions">
          <button type="button" data-testid="cancel">
            Cancel
          </button>
          <button type="submit" data-testid="submit">
            Save
          </button>
        </div>
      </form>
    </Dialog>
  ));
  return { onClose, panel: screen.getByTestId("dialog-tall") };
}

describe("the panel against the viewport", () => {
  it("is capped to the dynamic viewport less its offset and the gutter, and scrolls as a whole", () => {
    const { panel } = mountForm();
    const style = getComputedStyle(panel);
    expect(style.overflow).toBe("auto");
    expect(style.maxHeight).toBe("calc(100dvh - var(--dialog-top) - var(--dialog-gutter))");
    expect(style.getPropertyValue("--dialog-top")).toBe("16dvh");
    expect(style.getPropertyValue("inset-block-start")).toBe("var(--dialog-top)");
    // The domain stylesheet of the connectors sets the width and nothing of the height.
    expect(style.getPropertyValue("--dialog-gutter")).toBe("var(--sp-6)");
  });

  it("pins the title at the top and the actions at the bottom, the body between them", () => {
    const { panel } = mountForm();
    const title = panel.querySelector(".dialog-title")!;
    const actions = panel.querySelector(".dialog-actions")!;
    const body = screen.getByTestId("body");
    expect(getComputedStyle(title).position).toBe("sticky");
    expect(getComputedStyle(title).getPropertyValue("inset-block-start")).toBe("var(--sp-7)");
    expect(getComputedStyle(actions).position).toBe("sticky");
    expect(getComputedStyle(actions).getPropertyValue("inset-block-end")).toBe("var(--sp-7)");
    expect(getComputedStyle(body).position).not.toBe("sticky");
    // Both sit at any depth inside the scrolling panel: here inside the form, in document
    // order title, body, actions, with the actions last so that they take the bottom band.
    expect(panel.contains(title) && panel.contains(actions)).toBe(true);
    expect(title.compareDocumentPosition(body) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(body.compareDocumentPosition(actions) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(actions.parentElement!.lastElementChild).toBe(actions);
  });

  it("applies to a confirmation too, whose actions are direct children of the panel", () => {
    render(() => (
      <ConfirmDialog title="Delete it?" confirmLabel="Delete" cancelLabel="Keep" danger onConfirm={() => {}} onClose={() => {}} />
    ));
    const panel = screen.getByTestId("dialog-confirm");
    expect(getComputedStyle(panel).overflow).toBe("auto");
    expect(getComputedStyle(panel.querySelector(".dialog-title")!).position).toBe("sticky");
    expect(getComputedStyle(panel.querySelector(".dialog-actions")!).position).toBe("sticky");
    expect(panel.lastElementChild).toBe(panel.querySelector(".dialog-actions"));
  });
});

describe("focus and aria stay as they were", () => {
  it("names the panel, marks it modal, moves focus in, wraps Tab and closes on Escape", async () => {
    const { panel, onClose } = mountForm();
    expect(panel.getAttribute("role")).toBe("dialog");
    expect(panel.getAttribute("aria-modal")).toBe("true");
    expect(panel.getAttribute("aria-label")).toBe("Tall form");
    await Promise.resolve();
    expect(document.activeElement).toBe(screen.getByTestId("first"));
    screen.getByTestId("submit").focus();
    fireEvent.keyDown(panel, { key: "Tab" });
    expect(document.activeElement).toBe(screen.getByTestId("first"));
    fireEvent.keyDown(panel, { key: "Tab", shiftKey: true });
    expect(document.activeElement).toBe(screen.getByTestId("submit"));
    fireEvent.keyDown(panel, { key: "Escape" });
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});
