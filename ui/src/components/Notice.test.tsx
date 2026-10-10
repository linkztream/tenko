import { render, screen } from "@solidjs/testing-library";
import { describe, expect, it } from "vitest";
import { ApiError } from "../api/problem";
import { ErrorNotice, Notice } from "./Notice";

describe("ErrorNotice", () => {
  it("is error-notice and carries the problem code of an API error", () => {
    const error = new ApiError({ status: 409, code: "ipam.some.new_code", title: "Server title", detail: "" });
    render(() => <ErrorNotice error={error} />);
    const note = screen.getByTestId("error-notice");
    expect(note.getAttribute("data-code")).toBe("ipam.some.new_code");
    expect(note.getAttribute("role")).toBe("alert");
    expect(note.textContent).toContain("Server title");
  });

  it("has no data-code for an error that is not an API error", () => {
    render(() => <ErrorNotice error={new Error("boom")} />);
    const note = screen.getByTestId("error-notice");
    expect(note.hasAttribute("data-code")).toBe(false);
    expect(note.textContent).toContain("Something unexpected happened");
  });

  it("renders nothing without an error", () => {
    render(() => <ErrorNotice error={undefined} />);
    expect(screen.queryByTestId("error-notice")).toBeNull();
  });
});

describe("Notice", () => {
  it("keeps its own test id and has no data-code unless it is given one", () => {
    render(() => (
      <Notice kind="warn" testid="my-note">
        Careful
      </Notice>
    ));
    const note = screen.getByTestId("my-note");
    expect(note.hasAttribute("data-code")).toBe(false);
    expect(note.textContent).toContain("Careful");
  });
});
