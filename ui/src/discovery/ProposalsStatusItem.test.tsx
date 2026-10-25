import { screen, waitFor } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { bridgeMockEvents } from "../audit/testkit";
import { server } from "../api/mock/node";
import { RECONCILE_IDS } from "../api/mock/reconcile-store";
import { paths } from "../app/paths";
import { renderRoute } from "../app/testing/render";
import { signInAlex } from "../auth/account/testkit";
import { setSessionForTest } from "../auth/session";
import { rejectProposal } from "./api";
import ProposalsStatusItem from "./ProposalsStatusItem";

let stopBridge: (() => void) | undefined;

beforeEach(async () => {
  await signInAlex();
});

afterEach(() => {
  stopBridge?.();
  stopBridge = undefined;
  setSessionForTest(null);
});

const render = () => renderRoute(ProposalsStatusItem, { url: "/", path: "/" });

describe("the open proposals in the status bar", () => {
  it("counts the open proposals and links to the inbox", async () => {
    render();
    const item = await screen.findByTestId("status-proposals");
    expect(item.textContent).toContain("7 open proposals");
    expect(item.getAttribute("href")).toBe(paths.discovery());
  });

  it("follows a decision without a reload", async () => {
    stopBridge = bridgeMockEvents();
    render();
    await screen.findByText("7 open proposals");
    await rejectProposal({ id: RECONCILE_IDS.proposal.mediaPc, revision: undefined }, "");
    await waitFor(() => expect(screen.getByTestId("status-proposals").textContent).toContain("6 open proposals"));
  });

  it("shows nothing while no proposal is open", async () => {
    server.use(http.get("*/api/v1/proposals", () => HttpResponse.json({ items: [], next_cursor: null, revision: 1 })));
    const { container } = render();
    await waitFor(() => expect(container.querySelector("[data-testid='status-proposals']")).toBeNull());
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(screen.queryByTestId("status-proposals")).toBeNull();
  });

  it("shows nothing when the read fails", async () => {
    server.use(http.get("*/api/v1/proposals", () => HttpResponse.json({ type: "about:blank", title: "Forbidden", status: 403, code: "auth.forbidden" }, { status: 403 })));
    render();
    await new Promise((resolve) => setTimeout(resolve, 100));
    expect(screen.queryByTestId("status-proposals")).toBeNull();
  });
});
