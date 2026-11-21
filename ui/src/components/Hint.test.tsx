import { fireEvent, screen } from "@solidjs/testing-library";
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

  it("hides on the first Esc without letting it reach a dialog, and shows again on re-entry", () => {
    let reached = 0;
    renderRoute(() => <div onKeyDown={() => reached++}><Hint label="Why?" text="Because." testid="h" /></div>, { url: "/" });
    const button = screen.getByTestId("h");
    const hint = button.parentElement as HTMLElement;
    fireEvent.keyDown(button, { key: "Escape" });
    expect(hint.classList.contains("hint-off")).toBe(true);
    expect(reached).toBe(0);
    fireEvent.keyDown(button, { key: "Escape" });
    expect(reached).toBe(1);
    fireEvent.mouseEnter(hint);
    expect(hint.classList.contains("hint-off")).toBe(false);
  });
});
