import { render, screen } from "@solidjs/testing-library";
import { createSignal } from "solid-js";
import { describe, expect, it } from "vitest";
import { VLAN_SHAPES, type VlanStyle } from "./palette";
import { VlanChip } from "./VlanChip";

function styleOf(shape: VlanStyle["shape"], hex = "#3A7BCB"): VlanStyle {
  return { vid: 20, hex, hue: 255, contrast: 4.31, shape };
}

function chip(vid: number): HTMLElement {
  const el = document.querySelector<HTMLElement>(`[data-vid="${vid}"]`);
  if (!el) throw new Error(`no chip for VLAN ${vid}`);
  return el;
}

describe("VlanChip", () => {
  it("shows the VLAN id as text", () => {
    render(() => <VlanChip vid={20} />);
    expect(screen.getByText("20")).toBeTruthy();
    expect(chip(20).querySelector(".id")?.textContent).toBe("20");
  });

  it("shows the name next to the id", () => {
    render(() => <VlanChip vid={20} name="servers.example.test" />);
    expect(screen.getByText("servers.example.test")).toBeTruthy();
    expect(chip(20).querySelector(".name")?.textContent).toBe("servers.example.test");
  });

  it("leaves the name out when there is none", () => {
    const { unmount } = render(() => <VlanChip vid={20} />);
    expect(chip(20).querySelector(".name")).toBeNull();
    unmount();
    render(() => <VlanChip vid={21} name={null} />);
    expect(chip(21).querySelector(".name")).toBeNull();
    expect(chip(21).querySelector(".id")?.textContent).toBe("21");
  });

  it("carries the VLAN id in a data attribute", () => {
    render(() => <VlanChip vid={4094} />);
    expect(chip(4094).dataset.vid).toBe("4094");
  });

  it("is a .vlan chip", () => {
    render(() => <VlanChip vid={20} />);
    expect(chip(20).classList.contains("vlan")).toBe(true);
  });

  it("sets the swatch color as the --vlan custom property", () => {
    render(() => <VlanChip vid={20} style={styleOf("square")} />);
    expect(chip(20).style.getPropertyValue("--vlan")).toBe("#3A7BCB");
  });

  it("sets the shape class from the style", () => {
    for (const shape of VLAN_SHAPES) {
      const { unmount } = render(() => <VlanChip vid={20} style={styleOf(shape)} />);
      const classes = [...chip(20).classList];
      expect(classes, shape).toContain("vlan");
      expect(classes, shape).toContain(`vlan-shape-${shape}`);
      expect(classes.filter((c) => c.startsWith("vlan-shape-")), shape).toHaveLength(1);
      unmount();
    }
  });

  it("has no shape class and no --vlan without a style, so the default gray applies", () => {
    render(() => <VlanChip vid={20} />);
    const el = chip(20);
    expect([...el.classList].some((c) => c.startsWith("vlan-shape-"))).toBe(false);
    expect(el.style.getPropertyValue("--vlan")).toBe("");
    expect(el.getAttribute("style")).toBeNull();
  });

  it("accepts an explicit undefined style", () => {
    render(() => <VlanChip vid={20} style={undefined} />);
    expect(chip(20).style.getPropertyValue("--vlan")).toBe("");
  });

  it("adds the class from the props", () => {
    render(() => <VlanChip vid={20} class="lan" style={styleOf("circle")} />);
    const classes = [...chip(20).classList];
    expect(classes).toEqual(expect.arrayContaining(["vlan", "vlan-shape-circle", "lan"]));
  });

  it("follows a style that changes", () => {
    const [style, setStyle] = createSignal<VlanStyle | undefined>(styleOf("square", "#3A7BCB"));
    render(() => <VlanChip vid={20} style={style()} />);
    expect(chip(20).style.getPropertyValue("--vlan")).toBe("#3A7BCB");
    expect(chip(20).classList.contains("vlan-shape-square")).toBe(true);

    setStyle(styleOf("ring", "#B2548D"));
    expect(chip(20).style.getPropertyValue("--vlan")).toBe("#B2548D");
    expect(chip(20).classList.contains("vlan-shape-ring")).toBe(true);
    expect(chip(20).classList.contains("vlan-shape-square")).toBe(false);

    setStyle(undefined);
    expect(chip(20).style.getPropertyValue("--vlan")).toBe("");
    expect([...chip(20).classList].some((c) => c.startsWith("vlan-shape-"))).toBe(false);
  });
});
