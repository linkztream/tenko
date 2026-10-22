// Helpers of the DHCP view tests: the grid rows and their menus (as in the DNS tests), the 501
// answer of a server without the service, the switched-off module, and the writes a view sent.
import { http, HttpResponse } from "msw";
import { vi } from "vitest";
import { server } from "../api/mock/node";
import { dhcpStubs } from "../api/mock/routes-dhcp";

export { cell, recordWrites, row, rowAction, rowActions, rows, type SentRequest } from "../dns/testkit";

export interface SentWrite {
  url: string;
  method: string;
  body: Record<string, unknown> | undefined;
  /** The `If-Match` header of the write, as sent. */
  ifMatch: string | null;
}

/** Records the writes the views send, with their `If-Match`. */
export function recordIfMatch(): () => SentWrite[] {
  const spy = vi.spyOn(globalThis, "fetch");
  return () =>
    spy.mock.calls
      .map(([url, init]) => ({
        url: String(url),
        method: String(init?.method ?? "GET"),
        body: typeof init?.body === "string" ? (JSON.parse(init.body) as Record<string, unknown>) : undefined,
        ifMatch: new Headers(init?.headers).get("if-match"),
      }))
      .filter((call) => call.method !== "GET");
}

/** Every DHCP route answers 501, as a server without the service does. */
export function dhcpNotBuilt(): void {
  server.use(...dhcpStubs);
}

/** Every DHCP route answers 404 `sys.route_not_found`, as with the module switched off. */
export function dhcpSwitchedOff(): void {
  server.use(
    http.all("/api/v1/dhcp/*", () =>
      HttpResponse.json(
        { type: "about:blank", status: 404, code: "sys.route_not_found", title: "Not Found", detail: "no such route", params: {} },
        { status: 404, headers: { "content-type": "application/problem+json" } },
      ),
    ),
  );
}

/** Every DHCP route answers 409 `dhcp.module.disabled`, as a server that runs no configuration service does. */
export function dhcpNoService(): void {
  server.use(
    http.all("/api/v1/dhcp/*", () =>
      HttpResponse.json(
        { type: "about:blank", status: 409, code: "dhcp.module.disabled", title: "Conflict", detail: "the DHCP module is off", params: {} },
        { status: 409, headers: { "content-type": "application/problem+json" } },
      ),
    ),
  );
}
