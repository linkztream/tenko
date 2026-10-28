import { screen } from "@solidjs/testing-library";
import { describe, expect, it } from "vitest";
import { renderRoute } from "../app/testing/render";
import { EmptyState } from "./EmptyState";

describe("the empty state", () => {
  it("says what is missing in one sentence", () => {
    renderRoute(() => <EmptyState testid="empty" text="No DNS zone is set up yet." />);
    const block = screen.getByTestId("empty");
    expect(block.querySelector("p")?.textContent).toBe("No DNS zone is set up yet.");
  });

  it("offers the action as a link with its address and test id", () => {
    renderRoute(() => <EmptyState testid="empty" text="No DNS zone is set up yet." action={{ label: "Add a zone", href: "/dns", testid: "empty-action" }} />);
    const link = screen.getByRole("link", { name: "Add a zone" });
    expect(link.getAttribute("href")).toBe("/dns");
    expect(link.getAttribute("data-testid")).toBe("empty-action");
    expect(screen.getByTestId("empty").contains(link)).toBe(true);
  });

  it("draws no link without an action", () => {
    renderRoute(() => <EmptyState testid="empty" text="Nothing to show." />);
    expect(screen.queryByRole("link")).toBeNull();
  });
});
