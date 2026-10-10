import { fireEvent, render, screen, waitFor, within } from "@solidjs/testing-library";
import { createSignal } from "solid-js";
import { describe, expect, it, vi } from "vitest";
import { axeViolations } from "../app/testing/axe";
import { checkSettings, initialSettings, settingsForm, type JsonSchema, type Settings } from "./schema";
import { SchemaForm } from "./SchemaForm";

/** A schema with every kind of field the form renders, and two it does not. */
const RICH: JsonSchema = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  type: "object",
  title: "Wireless controller",
  description: "Settings of one controller instance.",
  properties: {
    url: {
      type: "string",
      format: "uri",
      title: "Address",
      description: "Base URL of the controller API.",
      examples: ["https://controller.example.net:8443"],
    },
    site: { type: "string", title: "Site code", minLength: 2, maxLength: 8, pattern: "^[a-z][a-z0-9-]*$" },
    mode: { type: "string", title: "Mode", enum: ["poll", "push", "both"], default: "poll" },
    interval: { type: "integer", title: "Interval", enum: [30, 60, 300] },
    page_size: { type: "integer", title: "Page size", minimum: 1, maximum: 500, default: 100 },
    ratio: { type: "number", title: "Sample ratio", minimum: 0, maximum: 1, examples: [0.5] },
    verify_tls: { type: "boolean", title: "Verify the TLS certificate", default: true },
    debug: { type: "boolean", title: "Debug output" },
    gateway: { type: "string", format: "ipv4", title: "Gateway" },
    domain: { type: "string", format: "hostname", title: "Domain" },
    vlans: { type: "array", title: "VLANs", items: { type: "integer", minimum: 1, maximum: 4094 }, uniqueItems: true, maxItems: 3 },
    ssids: {
      type: "array",
      title: "SSIDs",
      description: "Only these networks are reported.",
      items: { type: "string", minLength: 1, maxLength: 32 },
      minItems: 1,
    },
    auth: {
      type: "object",
      title: "Authentication",
      properties: {
        user: { type: "string", title: "User name", minLength: 1 },
        realm: { type: "string", title: "Realm", format: "hostname" },
        options: { type: "object", properties: { deep: { type: "string" } } },
      },
      required: ["user"],
    },
    legacy: { type: "null", title: "Legacy" },
  },
  required: ["url"],
  additionalProperties: false,
};

interface Mounted {
  form: ReturnType<typeof settingsForm>;
  /** Every object `onChange` received, in order. */
  calls: Settings[];
  /** The values the form shows now. */
  values: () => Settings;
  setValues: (values: Settings) => void;
  setErrors: (errors: Record<string, string>) => void;
  setDisabled: (disabled: boolean) => void;
  container: HTMLElement;
}

interface MountOptions {
  schema?: JsonSchema | null;
  initial?: Settings;
  errors?: Record<string, string>;
  disabled?: boolean;
  idPrefix?: string;
}

/** Renders the form with a small wrapper that keeps the values in a signal, like a dialog does. */
function mount(options: MountOptions = {}): Mounted {
  const form = settingsForm(options.schema === undefined ? RICH : options.schema);
  const [values, setValues] = createSignal<Settings>(options.initial ?? initialSettings(form));
  const [errors, setErrors] = createSignal<Record<string, string>>(options.errors ?? {});
  const [disabled, setDisabled] = createSignal(options.disabled ?? false);
  const calls: Settings[] = [];
  // The landmark is the page around the form (axe wants all content in one).
  const view = render(() => (
    <main>
      <SchemaForm
        form={form}
        values={values()}
        errors={errors()}
        disabled={disabled()}
        idPrefix={options.idPrefix}
        onChange={(next) => {
          calls.push(next);
          setValues(next);
        }}
      />
    </main>
  ));
  return { form, calls, values, setValues: (v) => setValues(v), setErrors: (e) => setErrors(e), setDisabled, container: view.container };
}

const control = (testid: string) => screen.getByTestId(testid);
const input = (testid: string) => screen.getByTestId(testid) as HTMLInputElement;
const select = (testid: string) => screen.getByTestId(testid) as HTMLSelectElement;

function type(testid: string, value: string): void {
  fireEvent.input(control(testid), { target: { value } });
}

function pick(testid: string, value: string): void {
  fireEvent.change(control(testid), { target: { value } });
}

/**
 * Fires an input event for text that jsdom would sanitize away from a number input (a browser
 * keeps what the person typed until the input event has been handled).
 */
function typeUnsanitized(element: HTMLInputElement, raw: string): void {
  Object.defineProperty(element, "value", { configurable: true, get: () => raw, set: () => {} });
  fireEvent.input(element);
}

/** The text of the element that `aria-describedby` points to. */
function noteOf(element: HTMLElement): string | undefined {
  const id = element.getAttribute("aria-describedby");
  return id ? (document.getElementById(id)?.textContent ?? undefined) : undefined;
}

/** The label element of a control. */
function labelOf(element: HTMLElement): HTMLLabelElement | null {
  return document.querySelector<HTMLLabelElement>(`label[for="${element.id}"]`);
}

const items = (field: string) => screen.queryAllByTestId("settings-item").filter((el) => el.getAttribute("data-field") === field) as HTMLInputElement[];
const removeButtons = (field: string) => screen.queryAllByTestId("settings-item-remove").filter((el) => el.getAttribute("data-field") === field);
const addButton = (field: string) => screen.getAllByTestId("settings-item-add").find((el) => el.getAttribute("data-field") === field) as HTMLButtonElement;
const optionValues = (el: HTMLSelectElement) => Array.from(el.options).map((o) => o.value);

describe("SchemaForm: structure", () => {
  it("shows a muted line for a form without fields", () => {
    for (const schema of [null, { type: "object" }]) {
      const { container } = mount({ schema });
      const empty = screen.getByTestId("settings-empty");
      expect(empty.textContent).toBe("This plugin has no settings.");
      expect(empty.className).toContain("muted");
      expect(container.querySelector("input, select, button")).toBeNull();
      expect(screen.queryByTestId("settings-form")).toBeNull();
      document.body.innerHTML = "";
    }
  });

  it("renders the fields in order and leaves out the title and the description of the form", () => {
    const { container } = mount();
    const ids = Array.from(container.querySelectorAll("[data-testid^='field-']")).map((el) => el.getAttribute("data-testid"));
    expect(ids).toEqual([
      "field-settings-url",
      "field-settings-site",
      "field-settings-mode",
      "field-settings-interval",
      "field-settings-page_size",
      "field-settings-ratio",
      "field-settings-verify_tls",
      "field-settings-debug",
      "field-settings-gateway",
      "field-settings-domain",
      "field-settings-vlans",
      "field-settings-ssids",
      "field-settings-auth",
      "field-settings-auth-user",
      "field-settings-auth-realm",
      "field-settings-auth-options",
      "field-settings-legacy",
    ]);
    expect(container.textContent).not.toContain("Wireless controller");
    expect(container.textContent).not.toContain("Settings of one controller instance.");
  });

  it("labels each control with the title, or the name when there is none", () => {
    mount({ schema: { type: "object", properties: { plain_name: { type: "string" }, other: { type: "string", title: "Other thing" } } } });
    expect(labelOf(input("field-settings-plain_name"))?.textContent).toBe("plain_name");
    expect(screen.getByLabelText("Other thing")).toBe(input("field-settings-other"));
    expect(screen.getByLabelText("plain_name")).toBe(input("field-settings-plain_name"));
  });

  it("ties every control to its label", () => {
    mount();
    expect(screen.getByLabelText("Address")).toBe(input("field-settings-url"));
    expect(screen.getByLabelText("Mode")).toBe(select("field-settings-mode"));
    expect(screen.getByLabelText("Page size")).toBe(input("field-settings-page_size"));
    expect(screen.getByLabelText("Verify the TLS certificate")).toBe(input("field-settings-verify_tls"));
    expect(screen.getByRole("group", { name: "VLANs" })).toBe(control("field-settings-vlans"));
    expect(screen.getByRole("group", { name: "SSIDs" })).toBe(control("field-settings-ssids"));
    expect(screen.getByRole("group", { name: "Authentication" })).toBe(control("field-settings-auth"));
    expect(screen.getByLabelText("User name")).toBe(input("field-settings-auth-user"));
  });

  it("marks required settings: the label class and aria-required", () => {
    mount({
      schema: {
        type: "object",
        properties: {
          url: { type: "string", title: "Address" },
          note: { type: "string", title: "Note" },
          mode: { type: "string", title: "Mode", enum: ["a", "b"] },
          names: { type: "array", title: "Names", items: { type: "string" } },
          auth: { type: "object", title: "Login", properties: { user: { type: "string", title: "User name" } }, required: ["user"] },
        },
        required: ["url", "mode", "names"],
      },
    });
    expect(labelOf(input("field-settings-url"))?.classList.contains("required")).toBe(true);
    expect(input("field-settings-url").getAttribute("aria-required")).toBe("true");
    expect(labelOf(input("field-settings-note"))?.classList.contains("required")).toBe(false);
    expect(input("field-settings-note").hasAttribute("aria-required")).toBe(false);
    expect(labelOf(select("field-settings-mode"))?.classList.contains("required")).toBe(true);
    expect(select("field-settings-mode").getAttribute("aria-required")).toBe("true");
    // A list is named by its legend.
    expect(screen.getByText("Names").classList.contains("required")).toBe(true);
    // The group is optional, its member is not.
    expect(screen.getByText("Login").classList.contains("required")).toBe(false);
    expect(labelOf(input("field-settings-auth-user"))?.classList.contains("required")).toBe(true);
  });

  it("marks a required boolean on its label", () => {
    mount({ schema: { type: "object", properties: { agree: { type: "boolean", title: "Agree" } }, required: ["agree"] } });
    expect(screen.getByText("Agree").closest("label")?.classList.contains("required")).toBe(true);
  });

  it("does not collide with a second form when the prefix differs", () => {
    const { container } = mount({ idPrefix: "one" });
    const second = render(() => (
      <SchemaForm form={settingsForm(RICH)} values={{}} errors={{}} idPrefix="two" onChange={() => {}} />
    ));
    const ids = Array.from(document.querySelectorAll("[id]")).map((el) => el.id);
    expect(new Set(ids).size).toBe(ids.length);
    expect(container.querySelector("#one-settings-url")).not.toBeNull();
    expect(second.container.querySelector("#two-settings-url")).not.toBeNull();
  });

  it("uses the default prefix when none is given", () => {
    mount();
    expect(input("field-settings-url").id).toBe("sf-settings-url");
  });
});

describe("SchemaForm: help lines", () => {
  it("shows the description and the first example under a string, and the example as the placeholder", () => {
    mount();
    const url = input("field-settings-url");
    expect(noteOf(url)).toBe("Base URL of the controller API. For example https://controller.example.net:8443");
    expect(url.placeholder).toBe("https://controller.example.net:8443");
  });

  it("shows the default of a string, a number and a boolean", () => {
    mount({ initial: {} });
    expect(noteOf(select("field-settings-mode"))).toBe("Default: poll");
    expect(noteOf(input("field-settings-page_size"))).toBe("Default: 100");
    expect(noteOf(input("field-settings-verify_tls"))).toBe("Default: On");
  });

  it("has no note when there is nothing to say", () => {
    mount();
    expect(input("field-settings-site").hasAttribute("aria-describedby")).toBe(false);
    // A boolean whose default is off says nothing: the box is unchecked.
    expect(input("field-settings-debug").hasAttribute("aria-describedby")).toBe(false);
  });

  it("shows a numeric example for a number", () => {
    mount();
    const ratio = input("field-settings-ratio");
    expect(noteOf(ratio)).toBe("For example 0.5");
    expect(ratio.placeholder).toBe("0.5");
  });

  it("shows the description of a list below the list and an example only when it is text or a number", () => {
    mount({
      schema: {
        type: "object",
        properties: {
          names: { type: "array", title: "Names", description: "Some names.", items: { type: "string" }, examples: [["a", "b"], "first", 7] },
          plain: { type: "string", title: "Plain", examples: [{ a: 1 }] },
        },
      },
    });
    expect(noteOf(control("field-settings-names"))).toBe("Some names. For example first");
    expect(input("field-settings-plain").placeholder).toBe("");
    expect(input("field-settings-plain").hasAttribute("aria-describedby")).toBe(false);
  });
});

describe("SchemaForm: strings", () => {
  it("is a text input without spell checking or autocomplete", () => {
    mount();
    const site = input("field-settings-site");
    expect(site.tagName).toBe("INPUT");
    expect(site.type).toBe("text");
    expect(site.className).toBe("input");
    expect(site.getAttribute("spellcheck")).toBe("false");
    expect(site.getAttribute("autocomplete")).toBe("off");
  });

  it("uses the mono class for identifier formats only", () => {
    mount();
    for (const id of ["field-settings-url", "field-settings-gateway", "field-settings-domain", "field-settings-auth-realm"]) {
      expect(input(id).className).toBe("input mono");
    }
    expect(input("field-settings-site").className).toBe("input");
    mount({ schema: { type: "object", properties: { addr6: { type: "string", format: "ipv6" } } }, idPrefix: "b" });
    expect(input("field-settings-addr6").className).toBe("input mono");
  });

  it("sends the typed text and undefined for empty text, without touching the old object", () => {
    const m = mount({ initial: { site: "lab-1", gateway: "192.0.2.1" } });
    const before = m.values();
    const snapshot = structuredClone(before);
    type("field-settings-site", "lab-22");
    expect(m.calls).toHaveLength(1);
    expect(m.calls[0]).toEqual({ site: "lab-22", gateway: "192.0.2.1" });
    expect(m.calls[0]).not.toBe(before);
    expect(before).toEqual(snapshot);
    expect(input("field-settings-site").value).toBe("lab-22");

    type("field-settings-site", "");
    expect(m.calls[1]?.site).toBeUndefined();
    expect(m.calls[1]?.gateway).toBe("192.0.2.1");
    expect(input("field-settings-site").value).toBe("");
  });

  it("shows the stored value, whatever its type", () => {
    mount({ initial: { site: 42, domain: { a: 1 } } });
    expect(input("field-settings-site").value).toBe("42");
    expect(input("field-settings-domain").value).toBe('{"a":1}');
  });

  it("follows values that change from outside", () => {
    const m = mount({ initial: { site: "one" } });
    m.setValues({ site: "two" });
    expect(input("field-settings-site").value).toBe("two");
  });
});

describe("SchemaForm: enums", () => {
  it("is a select with a first option for not set when the setting is optional", () => {
    const m = mount({ initial: { mode: "poll" } });
    const mode = select("field-settings-mode");
    expect(mode.tagName).toBe("SELECT");
    expect(mode.className).toBe("select");
    expect(optionValues(mode)).toEqual(["", "poll", "push", "both"]);
    expect(mode.options[0]?.textContent).toBe("Not set");
    expect(mode.value).toBe("poll");

    pick("field-settings-mode", "push");
    expect(m.calls.at(-1)).toEqual({ mode: "push" });
    expect(mode.value).toBe("push");

    pick("field-settings-mode", "");
    expect(m.calls.at(-1)?.mode).toBeUndefined();
    expect(mode.value).toBe("");
  });

  it("converts the value of an integer enum back to a number", () => {
    const m = mount({ initial: { interval: 60 } });
    const interval = select("field-settings-interval");
    expect(optionValues(interval)).toEqual(["", "30", "60", "300"]);
    expect(interval.value).toBe("60");
    pick("field-settings-interval", "300");
    expect(m.calls.at(-1)).toEqual({ interval: 300 });
    expect(m.calls.at(-1)?.interval).toBe(300);
    pick("field-settings-interval", "");
    expect(m.calls.at(-1)?.interval).toBeUndefined();
  });

  it("offers not set to a required enum only while it has no value", () => {
    const schema: JsonSchema = { type: "object", properties: { region: { type: "string", title: "Region", enum: ["eu", "us"] } }, required: ["region"] };
    const m = mount({ schema, initial: {} });
    const region = select("field-settings-region");
    expect(optionValues(region)).toEqual(["", "eu", "us"]);
    expect(region.value).toBe("");
    pick("field-settings-region", "us");
    expect(m.calls.at(-1)).toEqual({ region: "us" });
    expect(optionValues(region)).toEqual(["eu", "us"]);
    expect(region.value).toBe("us");
  });

  it("keeps a stored value outside the enum selectable, so the select never shows another one", () => {
    mount({ initial: { mode: "legacy", interval: 45 } });
    expect(optionValues(select("field-settings-mode"))).toEqual(["", "poll", "push", "both", "legacy"]);
    expect(select("field-settings-mode").value).toBe("legacy");
    expect(optionValues(select("field-settings-interval"))).toEqual(["", "30", "60", "300", "45"]);
    expect(select("field-settings-interval").value).toBe("45");
  });
});

describe("SchemaForm: numbers", () => {
  it("is a number input with the bounds and the step of its type", () => {
    mount();
    const size = input("field-settings-page_size");
    expect(size.type).toBe("number");
    expect(size.className).toBe("input num");
    expect(size.min).toBe("1");
    expect(size.max).toBe("500");
    expect(size.step).toBe("1");
    const ratio = input("field-settings-ratio");
    expect(ratio.min).toBe("0");
    expect(ratio.max).toBe("1");
    expect(ratio.step).toBe("any");
  });

  it("sends numbers, and undefined for an empty input", () => {
    const m = mount({ initial: {} });
    type("field-settings-page_size", "250");
    expect(m.calls.at(-1)).toEqual({ page_size: 250 });
    expect(m.calls.at(-1)?.page_size).toBe(250);
    type("field-settings-ratio", "0.25");
    expect(m.calls.at(-1)?.ratio).toBe(0.25);
    type("field-settings-ratio", "-0.5");
    expect(m.calls.at(-1)?.ratio).toBe(-0.5);
    type("field-settings-page_size", "");
    expect(m.calls.at(-1)?.page_size).toBeUndefined();
    expect(input("field-settings-page_size").value).toBe("");
  });

  it("keeps text that is not a finite number as the raw string, so the type problem is reported", () => {
    const m = mount({ initial: {} });
    // A number that is not an integer is a number; the type problem comes from the check.
    type("field-settings-page_size", "1.5");
    expect(m.calls.at(-1)?.page_size).toBe(1.5);
    typeUnsanitized(input("field-settings-page_size"), "1e999");
    expect(m.calls.at(-1)?.page_size).toBe("1e999");
    expect(checkSettings(m.form, { url: "https://c.example.net", ...m.values() })).toContainEqual({
      path: "settings.page_size",
      kind: "type",
      params: { type: "integer" },
    });
  });

  it("keeps text the browser cannot read as a number as a string: an empty input that reports bad input", () => {
    const m = mount({ initial: { page_size: 100 } });
    const size = input("field-settings-page_size");
    Object.defineProperty(size, "validity", { configurable: true, value: { badInput: true } });
    fireEvent.input(size, { target: { value: "" } });
    const sent = m.calls.at(-1)?.page_size;
    expect(typeof sent).toBe("string");
    expect(checkSettings(m.form, { url: "https://c.example.net", ...m.values() })).toContainEqual({
      path: "settings.page_size",
      kind: "type",
      params: { type: "integer" },
    });
  });

  it("shows the stored number and does not rewrite what is being typed", () => {
    const m = mount({ initial: { ratio: 0.5 } });
    const ratio = input("field-settings-ratio");
    expect(ratio.value).toBe("0.5");
    // "0.50" and 0.5 are the same number: the input keeps the text the person typed.
    type("field-settings-ratio", "0.50");
    expect(m.calls.at(-1)?.ratio).toBe(0.5);
    expect(ratio.value).toBe("0.50");
    // A value that changes from outside is shown.
    m.setValues({ ratio: 0.75 });
    expect(ratio.value).toBe("0.75");
    m.setValues({});
    expect(ratio.value).toBe("");
  });
});

describe("SchemaForm: booleans", () => {
  it("is a checkbox inside its label", () => {
    mount();
    const box = input("field-settings-verify_tls");
    expect(box.type).toBe("checkbox");
    expect(box.className).toBe("cb");
    expect(box.closest("label")?.textContent).toBe("Verify the TLS certificate");
  });

  it("shows the default without calling onChange until the person clicks", () => {
    const m = mount({ initial: {} });
    expect(input("field-settings-verify_tls").checked).toBe(true);
    expect(input("field-settings-debug").checked).toBe(false);
    expect(m.calls).toHaveLength(0);

    fireEvent.click(input("field-settings-verify_tls"));
    expect(m.calls).toHaveLength(1);
    expect(m.calls[0]).toEqual({ verify_tls: false });
    expect(input("field-settings-verify_tls").checked).toBe(false);

    fireEvent.click(input("field-settings-debug"));
    expect(m.calls.at(-1)).toEqual({ verify_tls: false, debug: true });
    fireEvent.click(input("field-settings-verify_tls"));
    expect(m.calls.at(-1)?.verify_tls).toBe(true);
  });

  it("shows the stored value over the default", () => {
    mount({ initial: { verify_tls: false, debug: true } });
    expect(input("field-settings-verify_tls").checked).toBe(false);
    expect(input("field-settings-debug").checked).toBe(true);
  });
});

describe("SchemaForm: lists", () => {
  it("is a fieldset named by its legend, with a muted line and an Add button while empty", () => {
    mount();
    const ssids = control("field-settings-ssids");
    expect(ssids.tagName).toBe("FIELDSET");
    expect(ssids.querySelector("legend")?.textContent).toBe("SSIDs");
    expect(within(ssids).getByText("None yet.").className).toContain("muted");
    expect(items("ssids")).toHaveLength(0);
    const add = within(ssids).getByRole("button", { name: "Add to SSIDs" });
    expect(add).toBe(addButton("ssids"));
    expect(add.textContent?.trim()).toBe("Add");
    expect(add.className).toBe("btn sm");
    expect(add.getAttribute("type")).toBe("button");
  });

  it("adds an empty item and moves the focus to it", async () => {
    const m = mount();
    fireEvent.click(addButton("ssids"));
    expect(m.calls.at(-1)?.ssids).toEqual([""]);
    expect(within(control("field-settings-ssids")).queryByText("None yet.")).toBeNull();
    const [first] = items("ssids");
    expect(first).toBeDefined();
    await waitFor(() => expect(document.activeElement).toBe(first));
    expect(first?.getAttribute("data-index")).toBe("0");
    expect(first?.getAttribute("data-field")).toBe("ssids");
    expect(first?.getAttribute("aria-label")).toBe("SSIDs, item 1");
    expect(screen.getByLabelText("SSIDs, item 1")).toBe(first);
  });

  it("edits the items one by one and keeps the focus in the item being typed in", async () => {
    const m = mount();
    fireEvent.click(addButton("ssids"));
    fireEvent.click(addButton("ssids"));
    expect(m.calls.at(-1)?.ssids).toEqual(["", ""]);
    const second = items("ssids")[1] as HTMLInputElement;
    await waitFor(() => expect(document.activeElement).toBe(second));
    expect(second.getAttribute("aria-label")).toBe("SSIDs, item 2");

    fireEvent.input(second, { target: { value: "iot" } });
    expect(m.calls.at(-1)?.ssids).toEqual(["", "iot"]);
    // The row stays in the document while it is edited, so the focus stays too.
    expect(items("ssids")[1]).toBe(second);
    expect(document.activeElement).toBe(second);
    fireEvent.input(items("ssids")[0] as HTMLInputElement, { target: { value: "guest" } });
    expect(m.calls.at(-1)?.ssids).toEqual(["guest", "iot"]);
    // Clearing an item leaves an empty text in the list: there is no undefined in JSON.
    fireEvent.input(second, { target: { value: "" } });
    expect(m.calls.at(-1)?.ssids).toEqual(["guest", ""]);
  });

  it("removes an item with its button, which names the item, and moves the focus on", async () => {
    const m = mount({ initial: { ssids: ["guest", "iot", "lab"] } });
    expect(items("ssids").map((el) => el.value)).toEqual(["guest", "iot", "lab"]);
    const remove = screen.getByRole("button", { name: "Remove item 2 of SSIDs" });
    expect(remove).toBe(removeButtons("ssids")[1]);
    expect(remove.getAttribute("type")).toBe("button");
    expect(remove.className).toBe("icon-btn");
    expect(remove.getAttribute("data-index")).toBe("1");

    fireEvent.click(remove);
    expect(m.calls.at(-1)?.ssids).toEqual(["guest", "lab"]);
    expect(items("ssids").map((el) => el.value)).toEqual(["guest", "lab"]);
    expect(removeButtons("ssids")).toHaveLength(2);
    await waitFor(() => expect(document.activeElement).toBe(items("ssids")[1]));

    // Removing the last item moves the focus to the one before it.
    fireEvent.click(removeButtons("ssids")[1] as HTMLElement);
    expect(m.calls.at(-1)?.ssids).toEqual(["guest"]);
    await waitFor(() => expect(document.activeElement).toBe(items("ssids")[0]));

    // Removing the only item moves the focus to the Add button.
    fireEvent.click(removeButtons("ssids")[0] as HTMLElement);
    expect(m.calls.at(-1)?.ssids).toEqual([]);
    expect(within(control("field-settings-ssids")).getByText("None yet.")).toBeTruthy();
    await waitFor(() => expect(document.activeElement).toBe(addButton("ssids")));
  });

  it("shows the values of the items that move up after a removal", () => {
    mount({ initial: { vlans: [10, 20, 30] } });
    fireEvent.click(removeButtons("vlans")[0] as HTMLElement);
    expect(items("vlans").map((el) => el.value)).toEqual(["20", "30"]);
  });

  it("edits integer items as numbers and keeps unreadable text as the raw string", () => {
    const m = mount();
    fireEvent.click(addButton("vlans"));
    const [first] = items("vlans");
    expect(first?.type).toBe("number");
    expect(first?.className).toBe("input num");
    expect(first?.min).toBe("1");
    expect(first?.max).toBe("4094");
    expect(first?.step).toBe("1");
    expect(first?.getAttribute("aria-label")).toBe("VLANs, item 1");
    fireEvent.input(first as HTMLInputElement, { target: { value: "10" } });
    expect(m.calls.at(-1)?.vlans).toEqual([10]);
    expect(m.calls.at(-1)?.vlans).not.toEqual(["10"]);
    // An empty number item stays in the list as an empty text.
    fireEvent.input(first as HTMLInputElement, { target: { value: "" } });
    expect(m.calls.at(-1)?.vlans).toEqual([""]);
    typeUnsanitized(first as HTMLInputElement, "1e999");
    expect(m.calls.at(-1)?.vlans).toEqual(["1e999"]);
    expect(checkSettings(m.form, { url: "https://c.example.net", ...m.values() })).toContainEqual({
      path: "settings.vlans[0]",
      kind: "type",
      params: { type: "integer" },
    });
  });

  it("disables Add when the maximum is reached", () => {
    const m = mount({ initial: { vlans: [1, 2] } });
    const add = addButton("vlans");
    expect(add.disabled).toBe(false);
    fireEvent.click(add);
    expect(m.calls.at(-1)?.vlans).toEqual([1, 2, ""]);
    expect(add.disabled).toBe(true);
    fireEvent.click(add);
    expect(m.calls.at(-1)?.vlans).toEqual([1, 2, ""]);
    // Removing one makes room again.
    fireEvent.click(removeButtons("vlans")[2] as HTMLElement);
    expect(add.disabled).toBe(false);
  });

  it("renders a stored value that is not a list as an empty one", () => {
    mount({ initial: { ssids: "guest" } });
    expect(items("ssids")).toHaveLength(0);
    expect(within(control("field-settings-ssids")).getByText("None yet.")).toBeTruthy();
  });

  it("does not submit a form around it when its buttons are pressed", () => {
    const submit = vi.fn((e: Event) => e.preventDefault());
    const [values, setValues] = createSignal<Settings>({ ssids: ["guest"] });
    render(() => (
      <form onSubmit={submit}>
        <SchemaForm form={settingsForm(RICH)} values={values()} errors={{}} onChange={setValues} />
      </form>
    ));
    fireEvent.click(addButton("ssids"));
    fireEvent.click(removeButtons("ssids")[0] as HTMLElement);
    expect(submit).not.toHaveBeenCalled();
    expect(Array.from(document.querySelectorAll("button")).every((b) => b.type === "button")).toBe(true);
  });

  it("uses a select for the items of an enum", () => {
    const schema: JsonSchema = {
      type: "object",
      properties: {
        roles: { type: "array", title: "Roles", items: { type: "string", enum: ["admin", "viewer"] } },
        levels: { type: "array", title: "Levels", items: { type: "integer", enum: [1, 2, 3] } },
      },
    };
    const m = mount({ schema, initial: { roles: ["viewer"], levels: [2] } });
    const [role] = items("roles");
    expect(role?.tagName).toBe("SELECT");
    expect(optionValues(role as unknown as HTMLSelectElement)).toEqual(["", "admin", "viewer"]);
    expect((role as unknown as HTMLSelectElement).value).toBe("viewer");
    fireEvent.change(role as HTMLElement, { target: { value: "admin" } });
    expect(m.calls.at(-1)?.roles).toEqual(["admin"]);
    const [level] = items("levels");
    fireEvent.change(level as HTMLElement, { target: { value: "3" } });
    expect(m.calls.at(-1)?.levels).toEqual([3]);
  });
});

describe("SchemaForm: groups", () => {
  it("is a fieldset with its legend and nested controls", () => {
    mount();
    const auth = control("field-settings-auth");
    expect(auth.tagName).toBe("FIELDSET");
    expect(auth.querySelector("legend")?.textContent).toBe("Authentication");
    expect(within(auth).getByLabelText("User name")).toBe(input("field-settings-auth-user"));
    expect(within(auth).getByLabelText("Realm")).toBe(input("field-settings-auth-realm"));
  });

  it("reads and writes the nested object and leaves the rest alone", () => {
    const m = mount({ initial: { url: "https://c.example.net", auth: { user: "svc", realm: "example.com" } } });
    const before = m.values();
    const snapshot = structuredClone(before);
    expect(input("field-settings-auth-user").value).toBe("svc");
    expect(input("field-settings-auth-realm").value).toBe("example.com");

    type("field-settings-auth-user", "admin");
    expect(m.calls).toHaveLength(1);
    expect(m.calls[0]).toEqual({ url: "https://c.example.net", auth: { user: "admin", realm: "example.com" } });
    expect(m.calls[0]?.auth).not.toBe(before.auth);
    expect(before).toEqual(snapshot);

    type("field-settings-auth-realm", "");
    expect((m.calls.at(-1)?.auth as Settings).realm).toBeUndefined();
    expect((m.calls.at(-1)?.auth as Settings).user).toBe("admin");
  });

  it("creates the nested object on the first edit when the group has no value", () => {
    const m = mount({ initial: { url: "https://c.example.net" } });
    type("field-settings-auth-user", "svc");
    expect(m.calls.at(-1)).toEqual({ url: "https://c.example.net", auth: { user: "svc" } });
  });
});

describe("SchemaForm: unsupported settings", () => {
  it("shows the label, the value as JSON and a note, and keeps the value when other settings change", () => {
    const legacy = { kept: [1, 2] };
    const m = mount({ initial: { url: "https://c.example.net", legacy } });
    const code = control("field-settings-legacy");
    expect(code.tagName).toBe("CODE");
    expect(code.textContent).toBe('{"kept":[1,2]}');
    const group = screen.getByRole("group", { name: "Legacy" });
    expect(within(group).getByText("The form cannot edit this setting; it keeps its value.")).toBeTruthy();
    expect(group.querySelector("input, select, textarea, button")).toBeNull();

    type("field-settings-site", "lab-1");
    expect(m.calls.at(-1)?.legacy).toBe(legacy);
  });

  it("shows a dash when there is no value, also for a nested setting", () => {
    mount();
    expect(control("field-settings-legacy").textContent).toBe("—");
    expect(control("field-settings-auth-options").textContent).toBe("—");
  });
});

describe("SchemaForm: errors", () => {
  it("shows a message under its field and sets aria-invalid", () => {
    mount({ errors: { "settings.url": "Enter a URI.", "settings.page_size": "Out of range." } });
    const url = input("field-settings-url");
    expect(url.getAttribute("aria-invalid")).toBe("true");
    expect(noteOf(url)).toBe("Enter a URI.");
    const note = document.getElementById(url.getAttribute("aria-describedby") ?? "") as HTMLElement;
    expect(note.getAttribute("role")).toBe("alert");
    expect(note.className).toContain("bad");
    // The error replaces the help line.
    expect(note.textContent).not.toContain("Base URL");
    expect(input("field-settings-page_size").getAttribute("aria-invalid")).toBe("true");
    expect(noteOf(input("field-settings-page_size"))).toBe("Out of range.");
    // Other fields are untouched.
    expect(input("field-settings-site").hasAttribute("aria-invalid")).toBe(false);
    expect(noteOf(input("field-settings-ratio"))).toBe("For example 0.5");
  });

  it("follows the errors as they come and go, and brings the help back", () => {
    const m = mount();
    const url = input("field-settings-url");
    expect(url.hasAttribute("aria-invalid")).toBe(false);
    expect(noteOf(url)).toMatch(/^Base URL/);
    m.setErrors({ "settings.url": "Enter a URI." });
    expect(url.getAttribute("aria-invalid")).toBe("true");
    expect(noteOf(url)).toBe("Enter a URI.");
    m.setErrors({});
    expect(url.hasAttribute("aria-invalid")).toBe(false);
    expect(noteOf(url)).toMatch(/^Base URL/);
  });

  it("shows an error under a select, a checkbox and a number", () => {
    mount({ errors: { "settings.mode": "Pick one.", "settings.verify_tls": "Must be on.", "settings.ratio": "Not a number." } });
    expect(select("field-settings-mode").getAttribute("aria-invalid")).toBe("true");
    expect(noteOf(select("field-settings-mode"))).toBe("Pick one.");
    expect(input("field-settings-verify_tls").getAttribute("aria-invalid")).toBe("true");
    expect(noteOf(input("field-settings-verify_tls"))).toBe("Must be on.");
    expect(noteOf(input("field-settings-ratio"))).toBe("Not a number.");
  });

  it("shows the error of an item under that item", () => {
    mount({ initial: { ssids: ["guest", "x".repeat(40), "lab"] }, errors: { "settings.ssids[1]": "At most 32 characters." } });
    const [first, second, third] = items("ssids");
    expect(second?.getAttribute("aria-invalid")).toBe("true");
    expect(noteOf(second as HTMLElement)).toBe("At most 32 characters.");
    expect(first?.hasAttribute("aria-invalid")).toBe(false);
    expect(first?.hasAttribute("aria-describedby")).toBe(false);
    expect(third?.hasAttribute("aria-invalid")).toBe(false);
    // The note sits in the row of the item, not under the whole list.
    const note = document.getElementById(second?.getAttribute("aria-describedby") ?? "") as HTMLElement;
    expect(note.closest("li")).toBe(second?.closest("li"));
    // The list itself has no error.
    expect(noteOf(control("field-settings-ssids"))).toBe("Only these networks are reported.");
  });

  it("shows the error of the list under the whole list", () => {
    mount({ initial: { ssids: ["guest"] }, errors: { "settings.ssids": "Add at least 2." } });
    const ssids = control("field-settings-ssids");
    expect(noteOf(ssids)).toBe("Add at least 2.");
    const note = document.getElementById(ssids.getAttribute("aria-describedby") ?? "") as HTMLElement;
    expect(note.getAttribute("role")).toBe("alert");
    // After the items and the Add button.
    expect(note.compareDocumentPosition(addButton("ssids")) & Node.DOCUMENT_POSITION_PRECEDING).toBeTruthy();
    expect(items("ssids")[0]?.hasAttribute("aria-invalid")).toBe(false);
  });

  it("shows the error of a field inside a group, and of the group", () => {
    mount({ errors: { "settings.auth.user": "Required.", "settings.auth": "Check the login." } });
    expect(input("field-settings-auth-user").getAttribute("aria-invalid")).toBe("true");
    expect(noteOf(input("field-settings-auth-user"))).toBe("Required.");
    expect(noteOf(control("field-settings-auth"))).toBe("Check the login.");
    expect(input("field-settings-auth-realm").hasAttribute("aria-invalid")).toBe(false);
  });

  it("shows the problems of checkSettings on the fields they belong to", () => {
    const form = settingsForm(RICH);
    const values: Settings = { ...initialSettings(form), url: "nope", ssids: ["guest", ""], vlans: [10, 5000], auth: { user: "" } };
    const errors: Record<string, string> = {};
    for (const p of checkSettings(form, values)) errors[p.path] = p.kind;
    mount({ initial: values, errors });
    expect(noteOf(input("field-settings-url"))).toBe("format");
    expect(noteOf(items("ssids")[1] as HTMLElement)).toBe("length");
    expect(noteOf(items("vlans")[1] as HTMLElement)).toBe("range");
    expect(noteOf(input("field-settings-auth-user"))).toBe("required");
  });

  it("shows an error under an unsupported setting in place of its note", () => {
    mount({ errors: { "settings.legacy": "Not allowed." } });
    const group = screen.getByRole("group", { name: "Legacy" });
    expect(within(group).getByText("Not allowed.")).toBeTruthy();
    expect(within(group).queryByText("The form cannot edit this setting; it keeps its value.")).toBeNull();
  });
});

describe("SchemaForm: disabled", () => {
  it("disables every control, buttons included", () => {
    const m = mount({ initial: { ssids: ["guest"], vlans: [10], auth: { user: "svc" } }, disabled: true });
    const controls = Array.from(m.container.querySelectorAll<HTMLInputElement | HTMLSelectElement | HTMLButtonElement>("input, select, button"));
    expect(controls.length).toBeGreaterThan(15);
    for (const c of controls) expect(c.disabled, c.getAttribute("data-testid") ?? c.tagName).toBe(true);
    // Nothing is sent from a disabled form.
    fireEvent.click(addButton("ssids"));
    expect(m.calls).toHaveLength(0);
  });

  it("enables the controls again", () => {
    const m = mount({ initial: { ssids: ["guest"] }, disabled: true });
    m.setDisabled(false);
    const controls = Array.from(m.container.querySelectorAll<HTMLInputElement | HTMLSelectElement | HTMLButtonElement>("input, select, button"));
    expect(controls.some((c) => c.disabled)).toBe(false);
  });

  it("keeps Add disabled at the maximum even when the form is enabled", () => {
    mount({ initial: { vlans: [1, 2, 3] } });
    expect(addButton("vlans").disabled).toBe(true);
  });
});

describe("SchemaForm: keyboard", () => {
  it("leaves every control in the tab order", () => {
    const m = mount({ initial: { ssids: ["guest"], vlans: [10] } });
    const controls = Array.from(m.container.querySelectorAll<HTMLElement>("input, select, button"));
    expect(controls.length).toBeGreaterThan(15);
    for (const c of controls) expect(c.tabIndex, c.getAttribute("data-testid") ?? c.tagName).toBeGreaterThanOrEqual(0);
  });
});

describe("SchemaForm: accessibility", () => {
  it("has no axe violations with values", async () => {
    mount({ initial: { ...initialSettings(settingsForm(RICH)), url: "https://c.example.net", ssids: ["guest", "iot"], vlans: [10], auth: { user: "svc" } } });
    expect(await axeViolations()).toEqual([]);
  });

  it("has no axe violations when empty or with errors on every kind of field", async () => {
    const errors = {
      "settings.url": "Enter a URI.",
      "settings.mode": "Pick one.",
      "settings.page_size": "Out of range.",
      "settings.verify_tls": "Must be on.",
      "settings.ssids": "Add at least 2.",
      "settings.ssids[1]": "At most 32 characters.",
      "settings.auth": "Check the login.",
      "settings.auth.user": "Required.",
      "settings.legacy": "Not allowed.",
    };
    mount({ initial: { ssids: ["guest", "x"] }, errors });
    expect(await axeViolations()).toEqual([]);
  });

  it("has no axe violations when disabled, and none for the empty form", async () => {
    mount({ disabled: true, initial: { ssids: ["guest"] } });
    expect(await axeViolations()).toEqual([]);
    document.body.innerHTML = "";
    mount({ schema: null });
    expect(await axeViolations()).toEqual([]);
  });
});
