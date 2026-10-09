// Helpers of the IPAM scenario: finishing the plan dialog, the row menu of a grid and short
// reads of the public API (lists, one object, the history of an object). Locators follow
// the `data-testid` convention of ui/README.md.

import { expect, type Locator, type Page } from "@playwright/test";
import type { Api, Schemas } from "./api";
import { cell, withKey } from "./ui";

export type Prefix = Schemas["Prefix"];
export type Host = Schemas["Host"];
export type Interface = Schemas["Interface"];
export type Address = Schemas["Address"];
export type HistoryEntry = Schemas["HistoryEntry"];

/**
 * Applies the write the plan dialog previews: waits until the preview is there and nothing
 * blocks the confirm button, presses it, and waits until the dialog is gone.
 */
export async function confirmPlan(page: Page): Promise<void> {
  const confirm = page.getByTestId("plan-confirm");
  await expect(page.getByTestId("plan-preview")).toBeVisible();
  await expect(confirm).toBeEnabled();
  await confirm.click();
  await expect(confirm).toHaveCount(0);
}

/** The repeated item `testid` that is number `index` (`data-index`, counted from 0). */
export function withIndex(scope: Page | Locator, testid: string, index: number): Locator {
  return scope.locator(`[data-testid="${testid}"][data-index="${index}"]`);
}

/** The changes of the previewed plan for one kind of object and one action (`data-kind`, `data-action`). */
export function planChange(page: Page, kind: string, action: string): Locator {
  return page.locator(`[data-testid="plan-change"][data-kind="${kind}"][data-action="${action}"]`);
}

/**
 * The item `id` of the row menu that is open (`menu-item` with the action id as
 * `data-key`: `open`, `history`, `restore`, `delete`).
 */
export function rowMenuItem(page: Page, id: string): Locator {
  return withKey(page.getByTestId("row-menu"), "menu-item", id);
}

/**
 * Opens the row menu of a grid row from the keyboard (the context-menu key): a click on a
 * cell without a link puts the focus on the row, the key opens its menu.
 */
export async function openRowMenu(page: Page, row: Locator, plainCol: string): Promise<void> {
  await cell(row, plainCol).click();
  await page.keyboard.press("ContextMenu");
  await expect(page.getByTestId("row-menu")).toBeVisible();
}

/** The live prefixes of the default VRF, by CIDR. */
export async function prefixByCidr(api: Api, cidr: string): Promise<Prefix | undefined> {
  const page = await api.get<Schemas["Page_Prefix"]>("/prefixes", { within: cidr, limit: 200 });
  return page.items.find((p) => p.cidr === cidr);
}

/** The host called `name` (deleted ones included), or undefined. */
export async function hostByName(api: Api, name: string): Promise<Host | undefined> {
  const page = await api.get<Schemas["Page_Host"]>("/hosts", { q: name, deleted: "include", limit: 50 });
  return page.items.find((h) => h.name === name);
}

/** The actions in the history of an object, oldest first. */
export async function historyActions(api: Api, collection: "hosts" | "addresses" | "prefixes", id: string): Promise<string[]> {
  const page = await api.get<Schemas["Page_HistoryEntry"]>(`/${collection}/${id}/history`, { limit: 100 });
  return [...page.items].reverse().map((entry) => entry.action);
}

/** The `data-action` of every history entry in `entries`, in the order shown (newest first). */
export async function actionsOf(entries: Locator): Promise<Array<string | null>> {
  return entries.evaluateAll((els) => els.map((el) => el.getAttribute("data-action")));
}
