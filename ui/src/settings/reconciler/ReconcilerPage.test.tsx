import { fireEvent, screen, waitFor } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { db } from "../../api/mock/db";
import { server } from "../../api/mock/node";
import { reconcilerState } from "../../api/mock/routes-reconciler";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { setSessionForTest } from "../../auth/session";
import { setLocale } from "../../i18n";
import { signInAs } from "../testkit";
import { body, displayOf, draftErrors, draftOf, FIELDS, secondsOf } from "./model";
import ReconcilerPage from "./ReconcilerPage";

const NO_SHELL = { disable: ["region"] } as const;

beforeEach(async () => {
  await setLocale("en");
  await signInAs();
});

afterEach(() => setSessionForTest(null));

async function openPage() {
  const view = renderRoute(ReconcilerPage, { url: "/settings/reconciler", path: "/settings/reconciler" });
  await screen.findByTestId("reconciler-form");
  return view;
}

const input = (id: string) => screen.getByTestId(`field-${id}`) as HTMLInputElement;
const type = (id: string, value: string) => fireEvent.input(input(id), { target: { value } });
const save = () => fireEvent.click(screen.getByTestId("form-submit"));

describe("the reconciler settings page", () => {
  it("shows the settings in human units with their limits", async () => {
    await openPage();
    expect(input("interval").value).toBe("300");
    expect(input("debounce").value).toBe("2");
    expect(input("refresh").value).toBe("15");
    expect(input("purge").value).toBe("1");
    expect(input("orphan").value).toBe("7");
    expect(input("retention").value).toBe("30");
    expect((screen.getByTestId("field-adopt") as HTMLInputElement).checked).toBe(true);
    expect(document.getElementById("rc-interval-limits")?.textContent).toBe("30 sec to 1 day, default 5 min");
    expect(document.getElementById("rc-orphan-limits")?.textContent).toBe("1 hr to 365 days, default 7 days");
  });

  it("saves changed values in seconds with the revision of the read", async () => {
    const revision = reconcilerState.revision;
    await openPage();
    type("interval", "120");
    type("orphan", "14");
    fireEvent.click(screen.getByTestId("field-adopt"));
    save();
    await waitFor(() => expect(reconcilerState.settings.interval_secs).toBe(120));
    expect(reconcilerState.settings.orphan_after_secs).toBe(14 * 86_400);
    expect(reconcilerState.settings.adopt).toBe(false);
    expect(reconcilerState.settings.refresh_secs).toBe(900);
    expect(reconcilerState.revision).not.toBe(revision);
    // The form starts again from the stored values.
    await waitFor(() => expect(input("interval").value).toBe("120"));
  });

  it("refuses values outside the limits before anything is sent", async () => {
    await openPage();
    type("interval", "10");
    expect(document.getElementById("rc-interval-limits")?.textContent).toBe("Use a value from 30 sec to 1 day.");
    expect(input("interval").getAttribute("aria-invalid")).toBe("true");
    save();
    expect(reconcilerState.settings.interval_secs).toBe(300);
    expect(screen.getAllByTestId("field-error")).toHaveLength(1);
    expect(screen.queryByTestId("error-notice")).toBeNull();
  });

  it("refuses a refresh interval that is not shorter than the retention", async () => {
    await openPage();
    type("retention", "1");
    type("refresh", "1440");
    expect(screen.getByTestId("field-error").getAttribute("data-field")).toBe("refresh");
    expect(screen.getByTestId("field-error").textContent).toContain("shorter than the retention (1 day)");
    save();
    expect(reconcilerState.settings.retention_secs).toBe(2_592_000);
  });

  it("reloads with a notice when someone else saved first", async () => {
    await openPage();
    reconcilerState.settings.interval_secs = 600;
    reconcilerState.revision = db.revision + 10;
    type("debounce", "5");
    save();
    expect(await screen.findByTestId("reconciler-reloaded")).toBeTruthy();
    await waitFor(() => expect(input("interval").value).toBe("600"));
    expect(reconcilerState.settings.debounce_secs).toBe(2);
    // Saving again now goes through.
    type("debounce", "5");
    save();
    await waitFor(() => expect(reconcilerState.settings.debounce_secs).toBe(5));
    await waitFor(() => expect(screen.queryByTestId("reconciler-reloaded")).toBeNull());
  });

  it("shows the refusal of a save by its code and field", async () => {
    await openPage();
    server.use(
      http.put("/api/v1/settings/reconciler", () =>
        HttpResponse.json(
          { type: "about:blank", status: 422, code: "ipam.reconciler.settings.invalid", title: "x", detail: "x", params: { field: "refresh_secs" } },
          { status: 422, headers: { "content-type": "application/problem+json" } },
        ),
      ),
    );
    save();
    const notice = await screen.findByTestId("error-notice");
    expect(notice.getAttribute("data-code")).toBe("ipam.reconciler.settings.invalid");
    expect(notice.textContent).toBe("The server refused the value of Refresh interval of a fact. Check the limits under the field.");
  });

  it("has no accessibility violations and works in Swedish", async () => {
    const view = await openPage();
    expect(await axeViolations(view.container, NO_SHELL)).toEqual([]);
    await setLocale("sv");
    await waitFor(() => expect(screen.getByTestId("page-reconciler").textContent).toContain("Körintervall"));
    expect(document.getElementById("rc-interval-limits")?.textContent).toBe("30 s till 1 d, standard 5 min");
  });
});

describe("the reconciler model", () => {
  const stored = {
    adopt: true,
    dns_actuator: true,
    dns_orphans: "remove" as const,
    debounce_secs: 2,
    interval_secs: 300,
    orphan_after_secs: 604_800,
    purge_interval_secs: 300,
    refresh_secs: 900,
    retention_secs: 2_592_000,
  };

  it("keeps a stored value that has no exact display unchanged when saved", () => {
    const draft = draftOf(stored);
    const purge = FIELDS.find((f) => f.id === "purge")!;
    expect(draft.text.purge).toBe(displayOf(purge, 300));
    expect(body(draft, stored)).toEqual(stored);
  });

  it("converts typed numbers to whole seconds and refuses fractions of a second", () => {
    const minute = FIELDS.find((f) => f.id === "refresh")!;
    expect(secondsOf(minute, "1.5", 900)).toBe(90);
    const second = FIELDS.find((f) => f.id === "interval")!;
    expect(secondsOf(second, "30.5", 300)).toBeNaN();
    expect(secondsOf(second, "", 300)).toBeNaN();
    expect(secondsOf(second, "abc", 300)).toBeNaN();
  });

  it("reports an error per field and none for the defaults", () => {
    expect(draftErrors(draftOf(stored), stored)).toEqual({});
    const draft = draftOf(stored);
    draft.text.debounce = "301";
    expect(Object.keys(draftErrors(draft, stored))).toEqual(["debounce"]);
  });
});
