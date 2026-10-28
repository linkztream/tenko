// The filter bar: the live query field ("/" focuses it, Esc clears it), a bar that applies on
// Enter as a search form, the message beside an unusable value, the row density, the actions
// of the list at the end, and the toggle chips with their counts.
import { fireEvent, render, screen } from "@solidjs/testing-library";
import { createSignal } from "solid-js";
import { afterEach, describe, expect, it, vi } from "vitest";
import { axeViolations } from "../app/testing/axe";
import { setLocale } from "../i18n";
import { FilterBar, ToggleChip } from "./FilterBar";

afterEach(async () => {
  await setLocale("en");
});

function query(): HTMLInputElement {
  return screen.getByTestId("filter-input") as HTMLInputElement;
}

/** A live bar whose value follows what is typed, as in a list. */
function Live(props: { onInput?: (value: string) => void; initial?: string; slashFocus?: boolean }) {
  const [value, setValue] = createSignal(props.initial ?? "");
  return (
    <main>
      <FilterBar
        label="Filter addresses"
        value={value()}
        onInput={(v) => {
          setValue(v);
          props.onInput?.(v);
        }}
        {...(props.slashFocus === undefined ? {} : { slashFocus: props.slashFocus })}
      />
      <input aria-label="Other field" data-testid="other" />
    </main>
  );
}

describe("the live query field", () => {
  it("is named by the label and calls onInput as the person types", () => {
    const onInput = vi.fn();
    render(() => <Live onInput={onInput} />);
    const field = screen.getByRole("textbox", { name: "Filter addresses" });
    expect(field).toBe(query());
    fireEvent.input(field, { target: { value: "nas" } });
    expect(onInput).toHaveBeenLastCalledWith("nas");
    expect(query().value).toBe("nas");
  });

  it("is in a toolbar named by the label", () => {
    render(() => <Live />);
    const bar = screen.getByRole("toolbar", { name: "Filter addresses" });
    expect(bar.getAttribute("data-testid")).toBe("filterbar");
    expect(bar.tagName).toBe("DIV");
  });

  it("clears on Esc, only when there is something to clear", () => {
    const onInput = vi.fn();
    render(() => <Live initial="nas" onInput={onInput} />);
    expect(query().value).toBe("nas");
    fireEvent.keyDown(query(), { key: "Escape" });
    expect(onInput).toHaveBeenCalledTimes(1);
    expect(onInput).toHaveBeenLastCalledWith("");
    expect(query().value).toBe("");
    fireEvent.keyDown(query(), { key: "Escape" });
    expect(onInput).toHaveBeenCalledTimes(1);
  });

  it("is focused by the slash key, and not while typing in another field", () => {
    render(() => <Live />);
    const other = screen.getByTestId("other") as HTMLInputElement;
    other.focus();
    fireEvent.keyDown(other, { key: "/" });
    expect(document.activeElement).toBe(other);

    other.blur();
    expect(fireEvent.keyDown(document.body, { key: "/" })).toBe(false);
    expect(document.activeElement).toBe(query());
  });

  it("leaves the slash key alone with slashFocus off", () => {
    render(() => <Live slashFocus={false} />);
    fireEvent.keyDown(document.body, { key: "/" });
    expect(document.activeElement).not.toBe(query());
  });

  it("does not take the slash key from a modal dialog", () => {
    render(() => <Live />);
    const modal = document.createElement("div");
    modal.setAttribute("aria-modal", "true");
    document.body.append(modal);
    try {
      fireEvent.keyDown(document.body, { key: "/" });
      expect(document.activeElement).not.toBe(query());
    } finally {
      modal.remove();
    }
  });

  it("ignores the slash key with a modifier", () => {
    render(() => <Live />);
    fireEvent.keyDown(document.body, { key: "/", ctrlKey: true });
    expect(document.activeElement).not.toBe(query());
  });
});

describe("a bar without a query field", () => {
  it("has none when neither onInput nor onSubmit is passed", () => {
    render(() => (
      <FilterBar label="Filter the log">
        <button type="button">Chip</button>
      </FilterBar>
    ));
    expect(screen.queryByTestId("filter-input")).toBeNull();
    expect(screen.queryByRole("textbox")).toBeNull();
    expect(screen.getByRole("toolbar", { name: "Filter the log" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Chip" })).toBeTruthy();
  });

  it("takes the role group for a bar of labelled fields", () => {
    render(() => <FilterBar label="Filter the log" role="group" />);
    expect(screen.getByRole("group", { name: "Filter the log" })).toBeTruthy();
    expect(screen.queryByRole("toolbar")).toBeNull();
  });
});

describe("a bar that applies on Enter", () => {
  it("is a search form named by the label", () => {
    render(() => <FilterBar label="Filter the cache" onSubmit={() => {}} />);
    const form = screen.getByRole("search", { name: "Filter the cache" });
    expect(form.tagName).toBe("FORM");
    expect(screen.getByRole("textbox", { name: "Filter the cache" })).toBe(query());
  });

  it("calls onSubmit once on Enter in the field", () => {
    const onSubmit = vi.fn();
    render(() => <FilterBar label="Filter the cache" onSubmit={onSubmit} />);
    // jsdom does not turn Enter into an implicit submission; the form's own event stands for it.
    fireEvent.submit(screen.getByRole("search"));
    expect(onSubmit).toHaveBeenCalledTimes(1);
  });

  it("calls onSubmit once from a submit button among the children, without navigating", () => {
    const onSubmit = vi.fn();
    render(() => (
      <FilterBar label="Filter the cache" onSubmit={onSubmit}>
        <button type="submit">Read</button>
      </FilterBar>
    ));
    const submitted = fireEvent.click(screen.getByRole("button", { name: "Read" }));
    expect(onSubmit).toHaveBeenCalledTimes(1);
    // The default of the submit event is prevented, so the page does not reload.
    expect(submitted).toBe(true);
  });

  it("does not clear on Esc without onInput", () => {
    render(() => <FilterBar label="Filter the cache" value="a.example" onSubmit={() => {}} />);
    const stop = fireEvent.keyDown(query(), { key: "Escape" });
    expect(stop).toBe(true);
    expect(query().value).toBe("a.example");
  });
});

describe("an unusable value", () => {
  it("shows the message beside the field and marks the field invalid", () => {
    render(() => (
      <FilterBar label="Filter the cache" onSubmit={() => {}} invalid="Not a name" invalidField="suffix" value="??" />
    ));
    const error = screen.getByTestId("field-error");
    expect(error.textContent).toBe("Not a name");
    expect(error.getAttribute("data-field")).toBe("suffix");
    expect(error.getAttribute("role")).toBe("status");
    expect(query().getAttribute("aria-invalid")).toBe("true");
    expect(query().closest("label")?.classList.contains("bad")).toBe(true);
  });

  it("shows no message and no aria-invalid for a usable value", () => {
    render(() => <FilterBar label="Filter the cache" onSubmit={() => {}} />);
    expect(screen.queryByTestId("field-error")).toBeNull();
    expect(query().hasAttribute("aria-invalid")).toBe(false);
  });
});

describe("the density and the actions", () => {
  it("offers the row density by default", () => {
    render(() => <Live />);
    const density = screen.getByRole("group", { name: "Row density" });
    expect(density.querySelectorAll("button").length).toBe(3);
    expect(density.closest(".right")).not.toBeNull();
  });

  it("hides the row density with density off", () => {
    render(() => <FilterBar label="Filter the log" density={false} />);
    expect(screen.queryByRole("group", { name: "Row density" })).toBeNull();
  });

  it("renders the actions inside the right block, before the density", () => {
    render(() => (
      <FilterBar label="Filter the log" actions={<button type="button">Export</button>}>
        <button type="button">Chip</button>
      </FilterBar>
    ));
    const right = screen.getByTestId("filterbar").querySelector(".right");
    expect(right).not.toBeNull();
    const exportButton = screen.getByRole("button", { name: "Export" });
    expect(right?.contains(exportButton)).toBe(true);
    expect(right?.contains(screen.getByRole("button", { name: "Chip" }))).toBe(false);
    const density = screen.getByRole("group", { name: "Row density" });
    expect(exportButton.compareDocumentPosition(density) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });
});

describe("the toggle chip", () => {
  it("shows its count in the chip", () => {
    render(() => (
      <ToggleChip pressed={false} onToggle={() => {}} count={1234}>
        Needs you
      </ToggleChip>
    ));
    expect(screen.getByTestId("chip-count").textContent).toBe("1,234");
    expect(screen.getByRole("button", { name: /Needs you/ })).toBeTruthy();
  });

  it("shows a count of zero, and none when the count is unknown", () => {
    render(() => (
      <>
        <ToggleChip pressed={false} onToggle={() => {}} count={0} testid="zero">
          Zero
        </ToggleChip>
        <ToggleChip pressed={false} onToggle={() => {}} testid="unknown">
          Unknown
        </ToggleChip>
      </>
    ));
    expect(screen.getByTestId("zero").querySelector("[data-testid='chip-count']")?.textContent).toBe("0");
    expect(screen.getByTestId("unknown").querySelector("[data-testid='chip-count']")).toBeNull();
  });

  it("shows the count with a plus when more rows exist", () => {
    render(() => (
      <ToggleChip pressed={false} onToggle={() => {}} count={200} more>
        Needs you
      </ToggleChip>
    ));
    expect(screen.getByTestId("chip-count").textContent).toBe("200+");
  });

  it("follows pressed in aria-pressed and calls onToggle on a click", () => {
    const onToggle = vi.fn();
    const [pressed, setPressed] = createSignal(false);
    render(() => (
      <ToggleChip
        pressed={pressed()}
        onToggle={() => {
          onToggle();
          setPressed((p) => !p);
        }}
        testid="chip"
      >
        Show free
      </ToggleChip>
    ));
    const chip = screen.getByTestId("chip");
    expect(chip.getAttribute("aria-pressed")).toBe("false");
    fireEvent.click(chip);
    expect(onToggle).toHaveBeenCalledTimes(1);
    expect(chip.getAttribute("aria-pressed")).toBe("true");
    fireEvent.click(chip);
    expect(chip.getAttribute("aria-pressed")).toBe("false");
  });

  it("adds the class of its tone", () => {
    render(() => (
      <>
        <ToggleChip pressed={false} onToggle={() => {}} tone="conflict" testid="conflict">
          Conflicts
        </ToggleChip>
        <ToggleChip pressed={false} onToggle={() => {}} tone="proposal" testid="proposal">
          Proposals
        </ToggleChip>
        <ToggleChip pressed={false} onToggle={() => {}} testid="plain">
          Plain
        </ToggleChip>
      </>
    ));
    expect(screen.getByTestId("conflict").className).toBe("chip conflict");
    expect(screen.getByTestId("proposal").className).toBe("chip proposal");
    expect(screen.getByTestId("plain").className).toBe("chip");
  });
});

describe("accessibility", () => {
  it("has no axe violations for a live bar with chips and a message", async () => {
    render(() => (
      <main>
        <FilterBar label="Filter addresses" onInput={() => {}} invalid="Not a name" invalidField="suffix" actions={<button type="button">Export</button>}>
          <ToggleChip pressed={true} onToggle={() => {}} count={3} tone="conflict">
            Conflicts
          </ToggleChip>
          <ToggleChip pressed={false} onToggle={() => {}} count={200} more>
            Free
          </ToggleChip>
        </FilterBar>
      </main>
    ));
    expect(await axeViolations()).toEqual([]);
  });

  it("has no axe violations for a search form", async () => {
    render(() => (
      <main>
        <FilterBar label="Filter the cache" onSubmit={() => {}}>
          <button type="submit">Read</button>
        </FilterBar>
      </main>
    ));
    expect(await axeViolations()).toEqual([]);
  });
});
