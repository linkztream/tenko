// The side panel of a finding that is not a proposal: a disk short of room shows its sentence in
// the language of the UI, not the server's figures.
import { screen, within } from "@solidjs/testing-library";
import { afterEach, describe, expect, it } from "vitest";
import type { components } from "../api/generated/schema";
import { renderRoute } from "../app/testing/render";
import { setLocale } from "../i18n";
import { FindingPanel } from "./FindingPanel";

afterEach(async () => {
  await setLocale("en");
});

const disk: components["schemas"]["Finding"] = {
  id: "health:d1",
  kind: "health",
  severity: "act",
  area: "nodes",
  subject: { kind: "node", label: "node.disk.low", objects: [] },
  summary: "low disk space (available 9663676416, bytes 2100000000, cause hour, seconds_left 18000)",
  code: "node.disk.low",
  params: { severity: "act", cause: "hour", seconds_left: "18000", bytes: "2100000000", free: "14600000000", margin: "2000000000" },
  evidence: { id: "node.disk.low", path: "/system/status" },
  action: "none",
  since: "2026-11-23T08:00:00Z",
  source: "health",
};

describe("the panel of a disk short of room", () => {
  it("says the sentence in Swedish, without the server's figures", async () => {
    await setLocale("sv");
    renderRoute(() => <FindingPanel finding={disk} onClose={() => undefined} />, { url: "/discovery" });
    const panel = await screen.findByTestId("finding-panel");
    const text = within(panel).getByText(/avvisas ändringar/).textContent ?? "";
    expect(text).toContain("Med den senaste timmens takt");
    expect(text).toContain("Ta aldrig bort något under store/.");
    expect(panel.textContent).not.toMatch(/seconds_left|low disk space|available \d/);
  });
});
