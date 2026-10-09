import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { createSignal } from "solid-js";
import { beforeEach, describe, expect, it } from "vitest";
import { api } from "../../api/client";
import type { CustomFieldInput, CustomValue } from "../../api/types";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { signInAlex } from "../../auth/account/testkit";
import { choose, typeInto } from "../testkit";
import { CustomFieldsEditor, customPatch, CustomValues, TagsInput, useCustomFields } from "./CustomFieldsEditor";

beforeEach(async () => {
  await signInAlex();
});

async function define(def: CustomFieldInput): Promise<void> {
  await api.post("/api/v1/custom-fields", { body: def });
}

describe("tags input", () => {
  function Harness(props: { initial?: string[]; onChange?: (tags: string[]) => void }) {
    const [tags, setTags] = createSignal<string[]>(props.initial ?? []);
    return (
      <form data-testid="form" onSubmit={(e) => e.preventDefault()}>
        <TagsInput
          label="Tags"
          value={tags()}
          onChange={(next) => {
            setTags(next);
            props.onChange?.(next);
          }}
        />
        <output data-testid="tags">{JSON.stringify(tags())}</output>
      </form>
    );
  }
  const current = () => JSON.parse(screen.getByTestId("tags").textContent ?? "[]") as string[];

  it("splits at commas, trims and keeps each tag once", () => {
    renderRoute(() => <Harness />);
    typeInto("field-tags", "iot, camera ,iot,  ,garage,");
    expect(current()).toEqual(["iot", "camera", "garage"]);
    expect((screen.getByTestId("field-tags") as HTMLInputElement).value).toBe("");
    const chips = within(screen.getByTestId("tags-chips")).getAllByRole("listitem");
    expect(chips.map((c) => c.getAttribute("data-tag"))).toEqual(["iot", "camera", "garage"]);
  });

  it("keeps the text after the last comma for the next tag and takes it on Enter or when the input is left", () => {
    renderRoute(() => <Harness />);
    const input = screen.getByTestId("field-tags") as HTMLInputElement;
    typeInto("field-tags", "a,b");
    expect(current()).toEqual(["a"]);
    expect(input.value).toBe("b");
    const enter = new KeyboardEvent("keydown", { key: "Enter", bubbles: true, cancelable: true });
    input.dispatchEvent(enter);
    expect(enter.defaultPrevented).toBe(true);
    expect(current()).toEqual(["a", "b"]);
    typeInto("field-tags", "c");
    fireEvent.blur(input);
    expect(current()).toEqual(["a", "b", "c"]);
    // Enter on an empty input is left to the form: it submits.
    const again = new KeyboardEvent("keydown", { key: "Enter", bubbles: true, cancelable: true });
    input.dispatchEvent(again);
    expect(again.defaultPrevented).toBe(false);
  });

  it("removes a tag with its button and the last one with Backspace", () => {
    renderRoute(() => <Harness initial={["x", "y", "z"]} />);
    fireEvent.click(screen.getByRole("button", { name: "Remove tag y" }));
    expect(current()).toEqual(["x", "z"]);
    fireEvent.keyDown(screen.getByTestId("field-tags"), { key: "Backspace" });
    expect(current()).toEqual(["x"]);
  });

  it("refuses a tag that is too long and says so", () => {
    renderRoute(() => <Harness />);
    const input = screen.getByTestId("field-tags") as HTMLInputElement;
    typeInto("field-tags", `${"x".repeat(65)},`);
    expect(current()).toEqual([]);
    expect(input.getAttribute("aria-invalid")).toBe("true");
    expect(document.getElementById(input.getAttribute("aria-describedby") ?? "")?.textContent).toBe("A tag has 1 to 64 characters.");
    typeInto("field-tags", `${"x".repeat(64)},`);
    expect(current()).toEqual(["x".repeat(64)]);
    expect(input.getAttribute("aria-invalid")).toBeNull();
  });

  it("has no accessibility violations", async () => {
    renderRoute(() => <Harness initial={["a", "b"]} />);
    expect(await axeViolations(screen.getByTestId("form"))).toEqual([]);
  });
});

describe("custom field inputs", () => {
  function Harness(props: { kind?: string; initial?: Record<string, CustomValue>; showRequired?: boolean }) {
    const [values, setValues] = createSignal<Record<string, CustomValue>>(props.initial ?? {});
    const [problems, setProblems] = createSignal<Record<string, string>>({});
    return (
      <div data-testid="editor">
        <CustomFieldsEditor
          kind={props.kind ?? "prefix"}
          values={values()}
          onChange={setValues}
          showRequired={props.showRequired}
          onProblems={setProblems}
        />
        <output data-testid="values">{JSON.stringify(values())}</output>
        <output data-testid="problems">{JSON.stringify(problems())}</output>
      </div>
    );
  }
  const values = () => JSON.parse(screen.getByTestId("values").textContent ?? "{}") as Record<string, CustomValue>;
  const problems = () => JSON.parse(screen.getByTestId("problems").textContent ?? "{}") as Record<string, string>;

  async function defineAll() {
    await define({ key: "note", kind: { type: "text" }, applies_to: ["prefix"], required: false });
    await define({ key: "ports", kind: { type: "integer" }, applies_to: ["prefix"], required: false });
    await define({ key: "managed", kind: { type: "boolean" }, applies_to: ["prefix"], required: false });
    await define({ key: "audited", kind: { type: "date" }, applies_to: ["prefix"], required: false });
    await define({ key: "wiki", kind: { type: "url" }, applies_to: ["prefix"], required: false });
    await define({ key: "owner", kind: { type: "text" }, applies_to: ["prefix"], required: true });
  }

  it("lists the definitions of a kind", async () => {
    let list: () => string[] = () => [];
    renderRoute(() => {
      const defs = useCustomFields(() => "prefix");
      list = () => defs().map((d) => d.key);
      return <p data-testid="keys">{list().join(",")}</p>;
    });
    await waitFor(() => expect(screen.getByTestId("keys").textContent).toBe("rack"));
  });

  it("draws one input per definition, by its type", async () => {
    await defineAll();
    renderRoute(() => <Harness />);
    await screen.findByTestId("custom-fields");
    const attr = (name: string, a: string) => screen.getByTestId(`field-custom-${name}`).getAttribute(a);
    expect(screen.getByTestId("field-custom-note").tagName).toBe("INPUT");
    expect(attr("note", "type")).toBe("text");
    expect(attr("ports", "type")).toBe("number");
    expect(attr("ports", "step")).toBe("1");
    expect(attr("managed", "type")).toBe("checkbox");
    expect(attr("audited", "type")).toBe("date");
    expect(attr("wiki", "type")).toBe("url");
    const rack = screen.getByTestId("field-custom-rack") as HTMLSelectElement;
    expect(rack.tagName).toBe("SELECT");
    expect([...rack.options].map((o) => o.value)).toEqual(["", "A1", "A2", "B1"]);
    // Required ones are marked.
    expect(attr("owner", "aria-required")).toBe("true");
    expect(attr("note", "aria-required")).toBeNull();
    expect(screen.getByText("owner").className).toContain("required");
  });

  it("turns input into typed values and removes a value that is emptied", async () => {
    await defineAll();
    renderRoute(() => <Harness />);
    await screen.findByTestId("custom-fields");
    typeInto("field-custom-note", "  hello ");
    typeInto("field-custom-ports", "48");
    fireEvent.click(screen.getByTestId("field-custom-managed"));
    typeInto("field-custom-audited", "2026-03-01");
    typeInto("field-custom-wiki", "https://example.com/wiki");
    choose("field-custom-rack", "B1");
    expect(values()).toMatchObject({
      note: { type: "text", value: "hello" },
      ports: { type: "integer", value: 48 },
      managed: { type: "boolean", value: true },
      audited: { type: "date", value: "2026-03-01" },
      wiki: { type: "url", value: "https://example.com/wiki" },
      rack: { type: "select", value: "B1" },
    });
    typeInto("field-custom-note", "");
    choose("field-custom-rack", "");
    fireEvent.click(screen.getByTestId("field-custom-managed"));
    expect(values().note).toBeUndefined();
    expect(values().rack).toBeUndefined();
    expect(values().managed).toEqual({ type: "boolean", value: false });
  });

  it("reports a number that is not whole and a web address that is not one", async () => {
    await defineAll();
    renderRoute(() => <Harness />);
    await screen.findByTestId("custom-fields");
    typeInto("field-custom-ports", "1.5");
    typeInto("field-custom-wiki", "not a url");
    const ports = screen.getByTestId("field-custom-ports");
    expect(ports.getAttribute("aria-invalid")).toBe("true");
    expect(document.getElementById(ports.getAttribute("aria-describedby") ?? "")?.textContent).toBe("Enter a whole number.");
    expect(screen.getByTestId("field-custom-wiki").getAttribute("aria-invalid")).toBe("true");
    expect(values().ports).toBeUndefined();
    expect(Object.keys(problems())).toEqual(expect.arrayContaining(["ports", "wiki"]));
    typeInto("field-custom-ports", "2");
    expect(ports.getAttribute("aria-invalid")).toBeNull();
    expect(problems().ports).toBeUndefined();
  });

  it("reports a missing required value only once asked, but always as a problem", async () => {
    await defineAll();
    const [show, setShow] = createSignal(false);
    renderRoute(() => (
      <>
        <Harness showRequired={show()} />
        <button type="button" data-testid="show" onClick={() => setShow(true)} />
      </>
    ));
    await screen.findByTestId("custom-fields");
    expect(problems().owner).toBe("This field is required.");
    expect(screen.getByTestId("field-custom-owner").getAttribute("aria-invalid")).toBeNull();
    fireEvent.click(screen.getByTestId("show"));
    expect(screen.getByTestId("field-custom-owner").getAttribute("aria-invalid")).toBe("true");
    typeInto("field-custom-owner", "alex");
    expect(problems().owner).toBeUndefined();
  });

  it("starts a required check box unchecked, as a value", async () => {
    await define({ key: "approved", kind: { type: "boolean" }, applies_to: ["prefix"], required: true });
    renderRoute(() => <Harness />);
    await screen.findByTestId("custom-fields");
    await waitFor(() => expect(values().approved).toEqual({ type: "boolean", value: false }));
    expect(problems().approved).toBeUndefined();
  });

  it("shows the values it is given", async () => {
    renderRoute(() => <Harness initial={{ rack: { type: "select", value: "A2" } }} />);
    await screen.findByTestId("custom-fields");
    expect((screen.getByTestId("field-custom-rack") as HTMLSelectElement).value).toBe("A2");
  });

  it("draws nothing for a kind without definitions", async () => {
    renderRoute(() => <Harness kind="address" />);
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(screen.queryByTestId("custom-fields")).toBeNull();
  });

  it("has no accessibility violations", async () => {
    await defineAll();
    renderRoute(() => <Harness />);
    await screen.findByTestId("custom-fields");
    expect(await axeViolations(screen.getByTestId("editor"))).toEqual([]);
  });
});

describe("custom values", () => {
  it("lists key and value, formatted by type", () => {
    renderRoute(() => (
      <CustomValues
        values={{
          note: { type: "text", value: "spare" },
          ports: { type: "integer", value: 1234 },
          managed: { type: "boolean", value: true },
          audited: { type: "date", value: "2026-03-01" },
          wiki: { type: "url", value: "https://example.com/wiki" },
          rack: { type: "select", value: "A1" },
        }}
      />
    ));
    const list = screen.getByTestId("custom-values");
    const cell = (key: string) => list.querySelector(`dd[data-key="${key}"]`) as HTMLElement;
    expect(cell("note").textContent).toBe("spare");
    expect(cell("ports").textContent).toBe("1,234");
    expect(cell("managed").textContent).toBe("Yes");
    expect(cell("audited").textContent).toBe("Mar 1, 2026");
    expect(cell("rack").textContent).toBe("A1");
    const link = cell("wiki").querySelector("a");
    expect(link?.getAttribute("href")).toBe("https://example.com/wiki");
    expect(link?.getAttribute("rel")).toBe("noopener noreferrer");
    expect([...list.querySelectorAll("dt")].map((d) => d.textContent)).toEqual(["audited", "managed", "note", "ports", "rack", "wiki"]);
  });

  it("shows an address that is not a web address as text, never as a link", () => {
    renderRoute(() => <CustomValues values={{ wiki: { type: "url", value: "javascript:alert(1)" } }} />);
    expect(screen.getByTestId("custom-values").querySelector("a")).toBeNull();
    expect(screen.getByTestId("custom-values").textContent).toContain("javascript:alert(1)");
  });

  it("renders nothing when there are no values", () => {
    renderRoute(() => (
      <>
        <CustomValues values={{}} />
        <CustomValues values={null} />
        <CustomValues />
      </>
    ));
    expect(screen.queryByTestId("custom-values")).toBeNull();
  });
});

describe("custom patch", () => {
  const text = (value: string): CustomValue => ({ type: "text", value });
  it("keeps what is new or changed and nulls what was removed", () => {
    expect(customPatch({ a: text("1"), b: text("2"), c: text("3") }, { a: text("1"), b: text("9"), d: text("4") })).toEqual({
      b: text("9"),
      c: null,
      d: text("4"),
    });
  });
  it("is undefined when nothing changed", () => {
    expect(customPatch({ a: text("1") }, { a: text("1") })).toBeUndefined();
    expect(customPatch({}, {})).toBeUndefined();
  });
});
