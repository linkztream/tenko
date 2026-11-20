// WP14.1: a mirrored source's card goes stale and fresh again (E73; ADR 0033, docs/MIGRATION.md
// section "Windows DHCP"). The mirror is created through the API with the longest interval the
// server allows (3,600 s, stale after three hours), so that a slow runner cannot see it stale
// before the test asks for it; its token pushes the fixture snapshot of
// crates/tenko-core/tests/fixtures/mirror from a request context of its own, as the exporter
// would. The card shows the push as fresh; the interval is then shortened to 10 s (stale 30 s
// after the push) and the card turns stale while the page stays open; the interval back at
// 3,600 s and a second push make it fresh again. The same token reads nothing else.
//
// Arrangement: documentation data only (the fixture: 192.0.2.0/24, names under
// corp.example.test).

import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { request as playwrightRequest } from "@playwright/test";
import type { Schemas } from "./support/api";
import { expect, test } from "./support/fixtures";

const FIXTURE = fileURLToPath(new URL("../../crates/tenko-core/tests/fixtures/mirror/snapshot.json", import.meta.url));

test("a mirror's card goes stale and fresh again", async ({ server, api, page, signedIn }) => {
  void signedIn;
  const created = await api.post<Schemas["MirrorCreated"]>("/migrate/mirrors", { name: "dc1", kind: "windows-dhcp", interval_secs: 3600 });
  const id = created.mirror.id;
  const fixture = await readFile(FIXTURE, "utf8");
  const exporter = await playwrightRequest.newContext({ ignoreHTTPSErrors: true });
  const push = (sequence: number) =>
    exporter.put(`${server.url}/api/v1/migrate/mirrors/${id}/snapshot`, {
      headers: { Authorization: `Bearer ${created.token}`, "Content-Type": "application/json" },
      data: fixture.replace('"sequence": 1,', `"sequence": ${sequence},`),
    });
  const interval = (secs: number) => api.patch<Schemas["MirrorItem"]>(`/migrate/mirrors/${id}`, { interval_secs: secs });
  try {
    const first = await push(1);
    expect(first.status()).toBe(200);
    expect(await first.json()).toEqual({ sequence: 1, changed: true });
    const refused = await exporter.get(`${server.url}/api/v1/migrate/mirrors/${id}`, { headers: { Authorization: `Bearer ${created.token}` } });
    expect(refused.status()).toBe(403);

    await page.goto("/connectors");
    const card = page.getByTestId("mirror-card").filter({ hasText: "dc1" });
    await expect(card).toHaveAttribute("data-state", "fresh");
    await expect(card).toContainText("dc1.corp.example.test");
    await expect(card.getByTestId("mirror-losses-open")).toHaveText("4");

    // Three intervals of 10 s without a push: the card turns stale while the page stays open.
    await interval(10);
    await expect(card).toHaveAttribute("data-state", "stale", { timeout: 60_000 });
    const status = await api.get<Schemas["SystemStatus"]>("/system/status");
    expect(status.warnings.map((warning) => warning.code)).toContain("migrate.mirror.stale");

    // The long interval again and a push: fresh, however long the runner takes from here.
    await interval(3600);
    expect((await push(2)).status()).toBe(200);
    await expect(card).toHaveAttribute("data-state", "fresh", { timeout: 30_000 });
  } finally {
    await exporter.dispose();
  }
});
