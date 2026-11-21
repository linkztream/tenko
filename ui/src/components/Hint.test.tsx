import { screen } from "@solidjs/testing-library";
import { describe, expect, it } from "vitest";
import { renderRoute } from "../app/testing/render";
import { Hint } from "./Hint";

describe("the hint", () => {
  it("is a button the keyboard reaches, described by its text", () => {
    renderRoute(() => <Hint label="Why?" text="Because." testid="h" />, { url: "/" });
    const button = screen.getByTestId("h");
    expect(button.tagName).toBe("BUTTON");
    expect(button.getAttribute("aria-label")).toBe("Why?");
    expect(document.getElementById(button.getAttribute("aria-describedby") ?? "")?.textContent).toBe("Because.");
  });
});
