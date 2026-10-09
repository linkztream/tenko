// Helpers of the IPAM form tests: type into a field by its test id, take the plan through its
// preview and confirm, and read the writes the UI sent to the (mock) API.
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { expect, vi } from "vitest";

/** Sets the value of a field and fires the input event, like typing. */
export function typeInto(testid: string, value: string): void {
  fireEvent.input(screen.getByTestId(testid), { target: { value } });
}

/** Chooses an option of a select by its value. */
export function choose(testid: string, value: string): void {
  fireEvent.change(screen.getByTestId(testid), { target: { value } });
}

/** Presses the submit button of the open form. */
export function submitForm(): void {
  fireEvent.click(screen.getByTestId("form-submit"));
}

/** The message under a field: the element its `aria-describedby` points to. */
export function noteOf(testid: string): string | undefined {
  const id = screen.getByTestId(testid).getAttribute("aria-describedby");
  return id ? (document.getElementById(id)?.textContent ?? undefined) : undefined;
}

/**
 * Waits for the preview of the open plan dialog, acknowledges the warnings when asked, and
 * confirms. `dialog` is the test id of the dialog (the plan dialog of the forms by default).
 * Returns the dialog (it is gone once the write was applied).
 */
export async function confirmPlan(options: { acknowledge?: boolean; dialog?: string } = {}): Promise<HTMLElement> {
  const plan = await screen.findByTestId(options.dialog ?? "dialog-plan");
  const confirm = within(plan).getByTestId("plan-confirm") as HTMLButtonElement;
  await within(plan).findByTestId("plan-preview");
  if (options.acknowledge) {
    for (const box of within(plan).queryAllByTestId("plan-ack")) fireEvent.click(box);
  }
  await waitFor(() => expect(confirm.disabled).toBe(false));
  fireEvent.click(confirm);
  return plan;
}

export interface SentRequest {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: Record<string, unknown> | undefined;
}

/** Records the requests that go to the API; call the returned function for the writes so far. */
export function recordWrites(): () => SentRequest[] {
  const spy = vi.spyOn(globalThis, "fetch");
  return () =>
    spy.mock.calls
      .map(([url, init]) => ({
        url: String(url),
        method: String(init?.method ?? "GET"),
        headers: (init?.headers ?? {}) as Record<string, string>,
        body: typeof init?.body === "string" ? (JSON.parse(init.body) as Record<string, unknown>) : undefined,
      }))
      .filter((call) => call.method !== "GET");
}

/** The writes that applied (not the dry runs). */
export function applied(calls: SentRequest[]): SentRequest[] {
  return calls.filter((call) => !new URL(call.url, "http://localhost").searchParams.has("dry_run"));
}
