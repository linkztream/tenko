// Small helpers over the `data-testid` convention of ui/README.md. Tests locate elements
// by their test id and, for repeated items, by the documented `data-key` and `data-id`
// attributes; never by text or CSS classes, so translations and layout changes do not
// break them.

import { expect, type Locator, type Page } from "@playwright/test";

type Scope = Page | Locator;

/** The repeated item `testid` whose `data-key` is `key` (a CIDR, a name, an IP). */
export function withKey(scope: Scope, testid: string, key: string): Locator {
  return scope.locator(`[data-testid="${testid}"][data-key="${key}"]`);
}

/** The repeated item `testid` whose `data-id` is `id` (an object identifier). */
export function withId(scope: Scope, testid: string, id: string): Locator {
  return scope.locator(`[data-testid="${testid}"][data-id="${id}"]`);
}

/** The cell of column `col` in a grid row. */
export function cell(row: Locator, col: string): Locator {
  return row.locator(`[data-col="${col}"]`);
}

/** The row of grid `grid` with readable key `key`. */
export function gridRow(page: Page, grid: string, key: string): Locator {
  return withKey(page.getByTestId(`grid-${grid}`), "row", key);
}

/** Opens the account menu of the top bar. */
export async function openAccountMenu(page: Page): Promise<Locator> {
  await page.getByTestId("account-menu").click();
  const menu = page.getByTestId("dialog-account");
  await expect(menu).toBeVisible();
  return menu;
}

/** Signs out through the account menu and waits for the sign-in page. */
export async function signOut(page: Page): Promise<void> {
  const menu = await openAccountMenu(page);
  await menu.getByTestId("account-sign-out").click();
  await expect(page.getByTestId("page-signin")).toBeVisible();
}

/** Confirms that recovery codes were saved and closes the dialog that shows them. */
export async function acknowledgeRecoveryCodes(page: Page): Promise<string[]> {
  const dialog = page.getByTestId("dialog-recovery-codes");
  await expect(dialog).toBeVisible();
  const codes = (await dialog.getByTestId("recovery-codes").innerText()).split(/\s+/).filter(Boolean);
  await dialog.getByTestId("recovery-saved").check();
  await dialog.getByTestId("recovery-close").click();
  await expect(dialog).toHaveCount(0);
  return codes;
}
