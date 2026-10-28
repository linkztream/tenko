import { fireEvent, render, screen } from "@solidjs/testing-library";
import { describe, expect, it, vi } from "vitest";
import { HiddenLine, type HiddenItem } from "./HiddenLine";

const ITEMS: HiddenItem[] = [
  { key: "host", text: "host CPU and memory (not read on this host)" },
  { key: "dns", text: "DNS (this node does not serve it)" },
  { key: "dhcp", text: "DHCP (this node does not serve it)" },
];

function mount(items: readonly HiddenItem[], shown = false, onToggle: (shown: boolean) => void = () => undefined) {
  return render(() => <HiddenLine label="Hidden:" items={items} show="Show all metrics" hide="Hide again" shown={shown} onToggle={onToggle} />);
}

describe("the hidden line", () => {
  it("is not drawn without items while the toggle is off", () => {
    mount([], false);
    expect(screen.queryByTestId("hidden-line")).toBeNull();
    expect(screen.queryByTestId("hidden-line-toggle")).toBeNull();
  });

  it("joins the items with a middle dot and gives each its key", () => {
    mount(ITEMS);
    const items = screen.getAllByTestId("hidden-line-item");
    expect(items.map((el) => el.getAttribute("data-item"))).toEqual(["host", "dns", "dhcp"]);
    expect(items.map((el) => el.textContent)).toEqual(ITEMS.map((i) => i.text));
    const paragraph = screen.getByTestId("hidden-line").querySelector("p");
    expect(paragraph?.textContent).toBe(`Hidden: ${ITEMS[0]?.text} · ${ITEMS[1]?.text} · ${ITEMS[2]?.text}`);
  });

  it("puts no separator before the first item or after the last", () => {
    mount([{ key: "host", text: "host" }]);
    expect(screen.getByTestId("hidden-line").querySelector("p")?.textContent).toBe("Hidden: host");
  });

  it("states the number of items as data-count", () => {
    mount(ITEMS);
    expect(screen.getByTestId("hidden-line").getAttribute("data-count")).toBe("3");
  });

  it("offers the show text and is not pressed while the toggle is off", () => {
    mount(ITEMS, false);
    const toggle = screen.getByTestId("hidden-line-toggle");
    expect(toggle.textContent).toBe("Show all metrics");
    expect(toggle.getAttribute("aria-pressed")).toBe("false");
    expect(toggle.tagName).toBe("BUTTON");
  });

  it("offers the hide text and is pressed while the toggle is on", () => {
    mount(ITEMS, true);
    const toggle = screen.getByTestId("hidden-line-toggle");
    expect(toggle.textContent).toBe("Hide again");
    expect(toggle.getAttribute("aria-pressed")).toBe("true");
  });

  it("calls onToggle with the negation of the state when the button is clicked", () => {
    const off = vi.fn();
    const first = mount(ITEMS, false, off);
    fireEvent.click(screen.getByTestId("hidden-line-toggle"));
    expect(off).toHaveBeenCalledExactlyOnceWith(true);
    first.unmount();
    const on = vi.fn();
    mount(ITEMS, true, on);
    fireEvent.click(screen.getByTestId("hidden-line-toggle"));
    expect(on).toHaveBeenCalledExactlyOnceWith(false);
  });

  it("draws the line and the toggle without items while the toggle is on, so it can be turned off", () => {
    mount([], true);
    const line = screen.getByTestId("hidden-line");
    expect(line.getAttribute("data-count")).toBe("0");
    expect(line.querySelector("p")).toBeNull();
    expect(screen.queryAllByTestId("hidden-line-item")).toHaveLength(0);
    expect(screen.getByTestId("hidden-line-toggle").textContent).toBe("Hide again");
  });
});
