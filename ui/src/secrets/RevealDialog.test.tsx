import { fireEvent, render, screen, waitFor } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { server } from "../api/mock/node";
import { axeViolations } from "../app/testing/axe";
import { signInAlex } from "../auth/account/testkit";
import { session, setSessionForTest } from "../auth/session";
import { clearNow } from "./clipboard";
import { RevealDialog } from "./RevealDialog";

const SECRET = "0190d1c2-0000-7000-8000-00000000a001";
const HOST = "0190d1c2-0000-7000-8000-00000000b001";
const VALUE = "example-reveal-value";

interface Seen {
  body: unknown;
}

/** Answers the reveal with the value, or with the problems in `refusals` first. */
function revealAnswers(refusals: { status: number; code: string; params?: Record<string, string> }[] = []): Seen[] {
  const seen: Seen[] = [];
  server.use(
    http.post("/api/v1/secrets/:id/reveal", async ({ request }) => {
      const text = await request.text();
      seen.push({ body: text ? (JSON.parse(text) as unknown) : null });
      const refusal = refusals.shift();
      if (refusal) {
        return HttpResponse.json(
          { type: "about:blank", title: "Refused", status: refusal.status, code: refusal.code, detail: "", params: refusal.params ?? {} },
          { status: refusal.status, headers: { "content-type": "application/problem+json" } },
        );
      }
      return HttpResponse.json(
        {
          id: SECRET,
          value: VALUE,
          username: "admin",
          kind: "password",
          revealed_at: "2026-10-10T08:00:00Z",
          clear_after_secs: 30,
        },
        { headers: { "cache-control": "no-store" } },
      );
    }),
  );
  return seen;
}

function fakeClipboard(writable = true) {
  const state = { text: "" };
  Object.defineProperty(navigator, "clipboard", {
    configurable: true,
    value: {
      writeText: vi.fn((text: string) => {
        if (!writable) return Promise.reject(new DOMException("denied", "NotAllowedError"));
        state.text = text;
        return Promise.resolve();
      }),
      readText: vi.fn(() => Promise.resolve(state.text)),
    },
  });
  return state;
}

function open(host?: string, reason?: string) {
  const onClose = vi.fn();
  const view = render(() => (
    <RevealDialog target={{ id: SECRET, name: "nas admin", host }} reason={reason} onClose={onClose} />
  ));
  return { ...view, onClose };
}

const status = () => screen.getByTestId("reveal-status");

describe("the reveal dialog", () => {
  beforeEach(async () => {
    await signInAlex();
  });

  afterEach(async () => {
    await clearNow();
    Reflect.deleteProperty(navigator, "clipboard");
    setSessionForTest(null);
  });

  it("copies the value, counts down, names the audit record and never renders the value unasked", async () => {
    const clipboard = fakeClipboard();
    const seen = revealAnswers();
    open(HOST, "maintenance");
    await waitFor(() => expect(status().dataset.state).toBe("copied"));
    expect(clipboard.text).toBe(VALUE);
    expect(seen[0]?.body).toEqual({ host: HOST, reason: "maintenance" });
    expect(screen.getByTestId("reveal-countdown").dataset.seconds).toBe("30");
    expect(screen.getByTestId("reveal-username").textContent).toBe("admin");
    expect(screen.getByTestId("reveal-audit").textContent).toContain("alex");
    expect(document.body.textContent).not.toContain(VALUE);
    expect(screen.queryByTestId("reveal-value")).toBeNull();
    expect(await axeViolations(screen.getByTestId("dialog-reveal"))).toEqual([]);
  });

  it("shows the value on request and drops it when the dialog closes", async () => {
    fakeClipboard();
    revealAnswers();
    const view = open();
    await waitFor(() => expect(status().dataset.state).toBe("copied"));
    fireEvent.click(screen.getByTestId("reveal-show"));
    expect(screen.getByTestId("reveal-value").textContent).toBe(VALUE);
    fireEvent.click(screen.getByTestId("reveal-show"));
    expect(screen.queryByTestId("reveal-value")).toBeNull();
    fireEvent.click(screen.getByTestId("reveal-show"));
    fireEvent.click(screen.getByTestId("reveal-close"));
    expect(view.onClose).toHaveBeenCalled();
    view.unmount();
    expect(document.body.textContent).not.toContain(VALUE);
  });

  it("clears the clipboard after the countdown", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      const clipboard = fakeClipboard();
      revealAnswers();
      open();
      await waitFor(() => expect(status().dataset.state).toBe("copied"));
      await vi.advanceTimersByTimeAsync(30_000);
      await waitFor(() => expect(status().dataset.state).toBe("cleared"));
      expect(clipboard.text).toBe("");
      // The dialog forgets the value with the clipboard.
      expect(screen.queryByTestId("reveal-show")).toBeNull();
    } finally {
      vi.useRealTimers();
    }
  });

  it("offers a second copy when the browser refuses the first one", async () => {
    fakeClipboard(false);
    revealAnswers();
    open();
    await waitFor(() => expect(status().dataset.state).toBe("blocked"));
    expect(screen.getByTestId("reveal-copy")).toBeTruthy();
    const clipboard = fakeClipboard();
    fireEvent.click(screen.getByTestId("reveal-copy"));
    await waitFor(() => expect(status().dataset.state).toBe("copied"));
    expect(clipboard.text).toBe(VALUE);
  });

  it("asks for a fresh sign-in in place, ends the old session and reveals", async () => {
    fakeClipboard();
    const seen = revealAnswers([{ status: 403, code: "auth.step_up_required", params: { required: "fresh" } }]);
    const before = session()?.session_id;
    const ended: string[] = [];
    const fresh = { ...session(), session_id: "0190d1c2-0000-7000-8000-00000000c001" };
    const logins: unknown[] = [];
    server.use(
      http.post("/api/v1/auth/login/password", async ({ request }) => {
        logins.push(await request.json());
        return HttpResponse.json({ status: "authenticated", session: fresh });
      }),
      http.delete("/api/v1/auth/sessions/:id", ({ params }) => {
        ended.push(String(params.id));
        return new HttpResponse(null, { status: 204 });
      }),
    );
    open();
    const stepUp = await screen.findByTestId("reveal-stepup");
    expect(stepUp.dataset.required).toBe("fresh");
    fireEvent.input(screen.getByTestId("field-stepup-password"), { target: { value: "correct horse battery staple" } });
    fireEvent.click(screen.getByTestId("form-submit"));
    await waitFor(() => expect(status().dataset.state).toBe("copied"));
    expect(seen).toHaveLength(2);
    expect(logins).toEqual([{ user_name: "alex", password: "correct horse battery staple" }]);
    expect(session()?.session_id).toBe(fresh.session_id);
    expect(ended).toEqual([before]);
  });

  it("asks for a passkey only when the policy wants one", async () => {
    fakeClipboard();
    revealAnswers([{ status: 403, code: "auth.step_up_required", params: { required: "passkey" } }]);
    open(HOST);
    const stepUp = await screen.findByTestId("reveal-stepup");
    expect(stepUp.dataset.required).toBe("passkey");
    expect(screen.queryByTestId("field-stepup-password")).toBeNull();
  });

  it("shows a refusal of the policy in words and offers a retry", async () => {
    fakeClipboard();
    revealAnswers([{ status: 403, code: "vault.reveal.host_required" }]);
    open();
    await waitFor(() => expect(status().dataset.state).toBe("failed"));
    expect(status().textContent).toContain("only on the page of a host");
    fireEvent.click(screen.getByTestId("reveal-retry"));
    await waitFor(() => expect(status().dataset.state).toBe("copied"));
  });
});
