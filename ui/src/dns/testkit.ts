// Helpers of the DNS view tests: the grid rows by their readable key, a row's action menu, the
// 501 answer of the server before WP4.2, the switched-off module, and the writes the views sent.
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { expect, vi } from "vitest";
import { server } from "../api/mock/node";
import { dnsStubs } from "../api/mock/routes-dns";

/** The rows of grid `grid`. */
export function rows(grid: string): HTMLElement[] {
  return within(screen.getByTestId(`grid-${grid}`)).queryAllByTestId("row");
}

/** The row of grid `grid` whose `data-key` is `key`. */
export function row(grid: string, key: string): HTMLElement {
  const found = rows(grid).find((r) => r.dataset.key === key);
  if (!found) throw new Error(`no row ${key} in grid-${grid}: ${rows(grid).map((r) => r.dataset.key).join(", ")}`);
  return found;
}

/** The cell of column `col` in a row. */
export function cell(r: HTMLElement, col: string): HTMLElement {
  const found = r.querySelector<HTMLElement>(`td[data-col="${col}"]`);
  if (!found) throw new Error(`no cell ${col}`);
  return found;
}

/** Opens the action menu of a row and runs the item `id`. */
export async function rowAction(r: HTMLElement, id: string): Promise<void> {
  fireEvent.click(within(r).getByRole("button", { name: /^Actions for/ }));
  const menu = await screen.findByTestId("row-menu");
  const item = within(menu)
    .queryAllByTestId("menu-item")
    .find((i) => i.dataset.key === id);
  if (!item) throw new Error(`no action ${id}`);
  fireEvent.click(item);
}

/** The action ids a row's menu offers. */
export async function rowActions(r: HTMLElement): Promise<string[]> {
  fireEvent.click(within(r).getByRole("button", { name: /^Actions for/ }));
  const menu = await screen.findByTestId("row-menu");
  const ids = within(menu)
    .queryAllByTestId("menu-item")
    .map((i) => i.dataset.key ?? "");
  fireEvent.keyDown(menu, { key: "Escape" });
  await waitFor(() => expect(screen.queryByTestId("row-menu")).toBeNull());
  return ids;
}

/** Every DNS route answers 501, as the server does until WP4.2 lands. */
export function dnsNotBuilt(): void {
  server.use(...dnsStubs);
}

/** Every DNS route answers 404 `sys.route_not_found`, as with the module switched off. */
export function dnsSwitchedOff(): void {
  server.use(
    http.all("/api/v1/dns/*", () =>
      HttpResponse.json(
        { type: "about:blank", status: 404, code: "sys.route_not_found", title: "Not Found", detail: "no such route", params: {} },
        { status: 404, headers: { "content-type": "application/problem+json" } },
      ),
    ),
  );
}

export interface SentRequest {
  url: string;
  method: string;
  body: Record<string, unknown> | undefined;
}

/** Records the writes (every request but GET) the views send. */
export function recordWrites(): () => SentRequest[] {
  const spy = vi.spyOn(globalThis, "fetch");
  return () =>
    spy.mock.calls
      .map(([url, init]) => ({
        url: String(url),
        method: String(init?.method ?? "GET"),
        body: typeof init?.body === "string" ? (JSON.parse(init.body) as Record<string, unknown>) : undefined,
      }))
      .filter((call) => call.method !== "GET");
}
