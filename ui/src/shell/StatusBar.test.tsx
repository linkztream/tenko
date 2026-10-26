import { screen } from "@solidjs/testing-library";
import { afterEach, describe, expect, it } from "vitest";
import { renderRoute } from "../app/testing/render";
import { setSessionForTest } from "../auth/session";
import { signInAdmin, viewerOnly } from "../updates/testkit";
import { StatusBar } from "./StatusBar";

afterEach(() => {
  setSessionForTest(null);
});

function show() {
  return renderRoute(() => <StatusBar jobs={null} version="0.1.0-dev" />, { url: "/", path: "/" });
}

describe("the version in the status bar", () => {
  it("links an administrator to the updates page", async () => {
    await signInAdmin();
    show();
    const link = await screen.findByTestId("status-version");
    expect(link.tagName).toBe("A");
    expect(link.getAttribute("href")).toBe("/updates");
    expect(link.textContent).toBe("Tenko DDI 0.1.0-dev");
    expect(link.getAttribute("aria-label")).toBe("Tenko DDI 0.1.0-dev. Open the updates page.");
  });

  it("stays plain text for an account that may not open the updates page", async () => {
    await signInAdmin(viewerOnly);
    show();
    await screen.findByText("Tenko DDI 0.1.0-dev");
    expect(screen.queryByTestId("status-version")).toBeNull();
    expect(document.querySelector("footer.statusbar a[href='/updates']")).toBeNull();
  });
});
