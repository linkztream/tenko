// The page header: the title as the page's h1 with the subtitle as a line of its own, the info
// button that opens the view's explanation in a popover (focus into it, Esc and a click outside
// close it, the focus returns to the button), the actions on the right and the tabs under it.
import { fireEvent, render, screen, waitFor } from "@solidjs/testing-library";
import { afterEach, describe, expect, it } from "vitest";
import { axeViolations } from "../app/testing/axe";
import { setLocale } from "../i18n";
import { PageHeader } from "./PageHeader";

afterEach(async () => {
  await setLocale("en");
});

function infoButton(): HTMLButtonElement {
  return screen.getByRole("button", { name: "About Jobs" });
}

function mount() {
  return render(() => (
    <main>
      <PageHeader
        title="Jobs"
        info={<span>Every change runs as a job.</span>}
        sub={<span>3 jobs wait for you</span>}
        actions={<button type="button">New job</button>}
        tabs={<nav data-testid="tabs">Tabs</nav>}
      />
      <button type="button" data-testid="outside">
        Outside
      </button>
    </main>
  ));
}

async function open(): Promise<HTMLElement> {
  fireEvent.click(infoButton());
  const popover = await screen.findByTestId("page-info-popover");
  await waitFor(() => expect(document.activeElement).toBe(popover));
  return popover;
}

describe("the title and the subtitle", () => {
  it("sets the title as the h1 and the subtitle as a separate line outside the heading", () => {
    mount();
    const heading = screen.getByRole("heading", { level: 1, name: "Jobs" });
    expect(heading.textContent).toBe("Jobs");
    const sub = screen.getByTestId("page-sub");
    expect(sub.classList.contains("page-sub")).toBe(true);
    expect(sub.textContent).toBe("3 jobs wait for you");
    expect(heading.contains(sub)).toBe(false);
    expect(heading.textContent).not.toContain("3 jobs");
  });

  it("has no subtitle line without a subtitle", () => {
    render(() => <PageHeader title="Jobs" />);
    expect(screen.queryByTestId("page-sub")).toBeNull();
  });

  it("offers no info button without an explanation", () => {
    render(() => <PageHeader title="Jobs" sub="Nothing waits" />);
    expect(screen.queryByTestId("page-info")).toBeNull();
    expect(screen.queryByRole("button", { name: /About/ })).toBeNull();
  });
});

describe("the actions and the tabs", () => {
  it("renders the actions in the actions block and the tabs after the header", () => {
    mount();
    const header = screen.getByTestId("page-header");
    const actions = header.querySelector(".actions");
    expect(actions).not.toBeNull();
    expect(actions?.contains(screen.getByRole("button", { name: "New job" }))).toBe(true);
    const tabs = screen.getByTestId("tabs");
    expect(header.contains(tabs)).toBe(false);
    expect(header.compareDocumentPosition(tabs) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it("renders no actions block without actions", () => {
    render(() => <PageHeader title="Jobs" />);
    expect(screen.getByTestId("page-header").querySelector(".actions")).toBeNull();
  });
});

describe("the info button", () => {
  it("is a native button named by the title and in the tab order", () => {
    mount();
    const button = infoButton();
    expect(button.tagName).toBe("BUTTON");
    expect(button.getAttribute("type")).toBe("button");
    expect(button.tabIndex).toBe(0);
    expect(button.hasAttribute("disabled")).toBe(false);
    expect(button.getAttribute("aria-haspopup")).toBe("dialog");
    button.focus();
    expect(document.activeElement).toBe(button);
    expect(button.getAttribute("aria-expanded")).toBe("false");
    expect(button.hasAttribute("aria-controls")).toBe(false);
  });

  it("opens the explanation in a dialog named by the title that takes the focus", async () => {
    mount();
    const button = infoButton();
    fireEvent.click(button);
    const popover = await screen.findByTestId("page-info-popover");
    expect(button.getAttribute("aria-expanded")).toBe("true");
    expect(popover.getAttribute("role")).toBe("dialog");
    expect(popover.getAttribute("aria-label")).toBe("Jobs");
    expect(screen.getByRole("dialog", { name: "Jobs" })).toBe(popover);
    expect(popover.classList.contains("page-info")).toBe(true);
    expect(popover.textContent).toContain("Every change runs as a job.");
    expect(popover.id).not.toBe("");
    expect(button.getAttribute("aria-controls")).toBe(popover.id);
    await waitFor(() => expect(document.activeElement).toBe(popover));
  });

  it("closes on a second click", async () => {
    mount();
    const button = infoButton();
    await open();
    fireEvent.click(button);
    expect(screen.queryByTestId("page-info-popover")).toBeNull();
    expect(button.getAttribute("aria-expanded")).toBe("false");
    expect(button.hasAttribute("aria-controls")).toBe(false);
  });

  // Defect in Popover: its Esc handler reads `props.anchor` after `onClose()`. In PageHeader the
  // anchor is the accessor of a <Show> that the close has just unmounted, so the read throws
  // ("stale value from <Show>") and the focus is not returned to the button.
  it("closes on Esc and returns the focus to the button", async () => {
    const errors: unknown[] = [];
    const trap = (e: ErrorEvent) => {
      errors.push(e.error);
      e.preventDefault();
    };
    window.addEventListener("error", trap);
    try {
      mount();
      const popover = await open();
      fireEvent.keyDown(popover, { key: "Escape" });
      expect(screen.queryByTestId("page-info-popover")).toBeNull();
      expect(infoButton().getAttribute("aria-expanded")).toBe("false");
      expect(errors).toEqual([]);
      expect(document.activeElement).toBe(infoButton());
    } finally {
      window.removeEventListener("error", trap);
    }
  });

  it("closes on a mouse press outside, and stays open on a press inside or on the button", async () => {
    mount();
    const popover = await open();
    fireEvent.mouseDown(popover);
    expect(screen.getByTestId("page-info-popover")).toBe(popover);
    fireEvent.mouseDown(infoButton());
    expect(screen.getByTestId("page-info-popover")).toBe(popover);
    fireEvent.mouseDown(screen.getByTestId("outside"));
    expect(screen.queryByTestId("page-info-popover")).toBeNull();
    expect(infoButton().getAttribute("aria-expanded")).toBe("false");
  });
});

describe("accessibility", () => {
  it("has no axe violations with the popover open", async () => {
    mount();
    await open();
    expect(await axeViolations()).toEqual([]);
  });
});
