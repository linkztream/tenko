import { screen } from "@solidjs/testing-library";
import { describe, expect, it } from "vitest";
import { renderRoute } from "../app/testing/render";
import { Metric } from "./Metric";

function mount(props: Parameters<typeof Metric>[0]) {
  return renderRoute(() => <Metric testid="m" {...props} />, { url: "/" });
}

describe("the metric block", () => {
  it("draws the label, the value with an SI suffix, the unit and the context", () => {
    mount({ label: "Queries", value: 1234, unit: "qps", context: <span>peak 2.0K</span> });
    const block = screen.getByTestId("m");
    expect(block.querySelector(".metric-label")?.textContent).toBe("Queries");
    expect(block.querySelector(".metric-value .num")?.textContent).toBe("1.2K");
    expect(block.querySelector(".metric-unit")?.textContent?.trim()).toBe("qps");
    expect(block.querySelector(".metric-context")?.textContent).toBe("peak 2.0K");
  });

  it("puts the exact number in the tooltip of the value", () => {
    mount({ label: "Queries", value: 1234 });
    expect(screen.getByTestId("m").querySelector(".num")?.getAttribute("title")).toBe("1,234");
  });

  it("carries the raw number as data-value for a number", () => {
    mount({ label: "Queries", value: 1234 });
    expect(screen.getByTestId("m").getAttribute("data-value")).toBe("1234");
  });

  it("draws a text value as it is and carries the number given as data", () => {
    mount({ label: "Nodes", value: "2/2", data: 2 });
    const block = screen.getByTestId("m");
    expect(block.querySelector(".metric-value .num")?.textContent).toBe("2/2");
    expect(block.getAttribute("data-value")).toBe("2");
  });

  it("has no data-value for a text value without data", () => {
    mount({ label: "Nodes", value: "2/2" });
    expect(screen.getByTestId("m").hasAttribute("data-value")).toBe(false);
  });

  it("draws a dash and no unit for an unknown value, and has no data-value", () => {
    mount({ label: "Queries", value: null, unit: "qps" });
    const block = screen.getByTestId("m");
    expect(block.querySelector(".metric-value .num")?.textContent).toBe("–");
    expect(block.querySelector(".metric-unit")).toBeNull();
    expect(block.hasAttribute("data-value")).toBe(false);
  });

  it("draws a zero as a value, with data-value 0", () => {
    mount({ label: "Queries", value: 0 });
    const block = screen.getByTestId("m");
    expect(block.querySelector(".num")?.textContent).toBe("0");
    expect(block.getAttribute("data-value")).toBe("0");
  });

  it("draws no context line and no unit without them", () => {
    mount({ label: "Queries", value: 5 });
    const block = screen.getByTestId("m");
    expect(block.querySelector(".metric-context")).toBeNull();
    expect(block.querySelector(".metric-unit")).toBeNull();
  });

  it("is plain text, not a link, without a destination", () => {
    mount({ label: "Queries", value: 5 });
    expect(screen.queryByRole("link")).toBeNull();
    expect(screen.getByTestId("m").tagName).toBe("DIV");
  });

  it("is a link to its destination with one", () => {
    mount({ label: "Queries", value: 5, href: "/dns" });
    const link = screen.getByRole("link");
    expect(link.getAttribute("href")).toBe("/dns");
    expect(link.getAttribute("data-testid")).toBe("m");
    expect(link.classList.contains("metric")).toBe(true);
    expect(link.getAttribute("data-value")).toBe("5");
    expect(link.querySelector(".metric-label")?.textContent).toBe("Queries");
  });

  it("colors the context only for the act tone", () => {
    mount({ label: "Findings", value: 3, context: "3 to act on", tone: "act" });
    expect(screen.getByTestId("m").querySelector(".metric-context")?.classList.contains("act")).toBe(true);
  });

  it("leaves the context uncolored without a tone", () => {
    mount({ label: "Findings", value: 3, context: "3 to review" });
    expect(screen.getByTestId("m").querySelector(".metric-context")?.classList.contains("act")).toBe(false);
  });
});
