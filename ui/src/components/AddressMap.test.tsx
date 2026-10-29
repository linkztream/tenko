// The address map: the cell counts of the plan's acceptance (a /24 draws 256 cells, a /22
// 1,024, a /23 512, a /16 256 block cells, an IPv6 /120 256), the states and the digits of the
// cells, color only where a finding sits, and hover, focus, the arrows and Enter.
import { fireEvent, render, screen, within } from "@solidjs/testing-library";
import { beforeAll, describe, expect, it, vi } from "vitest";
import { axeViolations } from "../app/testing/axe";
import { loadPacks, setLocale } from "../i18n";
import AddressMap from "./AddressMap";
import { addressCells, blockCells, cellDigits, mapLayout } from "./addressMapCells";
import { parseCidr } from "../ipam/ip";

beforeAll(async () => {
  await setLocale("en");
  await loadPacks(["ipam"]);
});

describe("the layout of the map", () => {
  it.each([
    ["192.0.2.0/24", "addresses", 256, 16],
    ["198.51.100.0/22", "addresses", 1024, 32],
    ["198.51.100.0/23", "addresses", 512, 32],
    ["192.0.2.128/25", "addresses", 128, 16],
    ["192.0.2.8/30", "addresses", 4, 4],
    ["2001:db8::/120", "addresses", 256, 16],
    ["2001:db8::/118", "addresses", 1024, 32],
    ["198.18.0.0/21", "blocks", 8, 8],
    ["198.18.0.0/16", "blocks", 256, 16],
    ["198.18.0.0/15", "blocks", 512, 32],
    ["2001:db8::/110", "blocks", 1024, 32],
    ["2001:db8::/112", "blocks", 256, 16],
  ] as const)("%s draws %s, %d cells, %d per row", (cidr, mode, count, columns) => {
    expect(mapLayout(cidr)).toMatchObject({ mode, count, columns });
  });

  it("draws nothing for a prefix of more than 1,024 blocks", () => {
    expect(mapLayout("2001:db8::/109").mode).toBe("none");
    expect(mapLayout("2001:db8::/64").mode).toBe("none");
    expect(mapLayout("not a prefix").mode).toBe("none");
  });

  it("shows the last octet, or the last digits of the last hextet", () => {
    const v4 = parseCidr("192.0.2.0/24")!;
    expect([0, 17, 255].map((i) => cellDigits(v4, i))).toEqual(["0", "17", "255"]);
    const v6 = parseCidr("2001:db8::ab00/120")!;
    expect([0, 10, 255].map((i) => cellDigits(v6, i))).toEqual(["00", "0a", "ff"]);
    const wide = parseCidr("2001:db8::/118")!;
    expect(cellDigits(wide, 1023)).toBe("3ff");
  });
});

describe("the cells", () => {
  const addresses = [{ ip: "192.0.2.10", name: "host-01.example.test" }, { ip: "192.0.2.11" }, { ip: "198.51.100.1" }];
  const ranges = [{ first: "192.0.2.100", last: "192.0.2.109", role: "dhcp_pool" }];
  const findings = [
    { ip: "192.0.2.11", severity: "review" as const, label: "Unknown device" },
    { ip: "192.0.2.11", severity: "act" as const, label: "Conflict" },
    { ip: "192.0.2.50", severity: "info" as const, label: "Ghost" },
  ];

  it("marks the edges, the addresses in use, the range and the worst finding of an address", () => {
    const cells = addressCells("192.0.2.0/24", addresses, ranges, findings);
    expect(cells).toHaveLength(256);
    expect(cells[0]).toMatchObject({ ip: "192.0.2.0", state: "edge" });
    expect(cells[255]).toMatchObject({ ip: "192.0.2.255", state: "edge" });
    expect(cells[10]).toMatchObject({ state: "used", name: "host-01.example.test", severity: undefined });
    expect(cells[11]).toMatchObject({ state: "used", severity: "act" });
    expect(cells[11]?.findings).toHaveLength(2);
    expect(cells[50]).toMatchObject({ state: "free", severity: "info" });
    expect(cells.filter((c) => c.state === "held")).toHaveLength(10);
    expect(cells.filter((c) => c.state === "free")).toHaveLength(256 - 2 - 2 - 10);
    // A supernet has no edge addresses; an IPv6 network loses only its first.
    expect(addressCells("192.0.2.0/24", [], [], [], { network: false })[0]?.state).toBe("free");
    const v6 = addressCells("2001:db8::/120", [], [], []);
    expect(v6[0]?.state).toBe("edge");
    expect(v6[255]?.state).toBe("free");
    // /31 and /32 keep every address.
    expect(addressCells("192.0.2.0/31", [], [], []).map((c) => c.state)).toEqual(["free", "free"]);
  });

  it("counts the addresses in use per block of 256 and keeps each address once", () => {
    const blocks = blockCells(
      "198.18.0.0/16",
      [{ ip: "198.18.2.10" }, { ip: "198.18.2.10" }, { ip: "198.18.2.101" }, { ip: "198.18.3.1" }],
      [{ first: "198.18.2.100", last: "198.18.2.109" }],
      [{ ip: "198.18.3.1", severity: "review", label: "Unknown device" }],
    );
    expect(blocks).toHaveLength(256);
    expect(blocks[2]).toMatchObject({ cidr: "198.18.2.0/24", inUse: 11, findings: 0 });
    expect(blocks[3]).toMatchObject({ cidr: "198.18.3.0/24", inUse: 1, severity: "review", findings: 1 });
    expect(blocks[0]?.inUse).toBe(0);
  });
});

describe("the component", () => {
  const props = {
    cidr: "192.0.2.0/24",
    addresses: [{ ip: "192.0.2.10", name: "host-01.example.test" }],
    ranges: [],
    findings: [{ ip: "192.0.2.20", severity: "act" as const, label: "Conflict" }],
  };

  it("draws a cell per address with its digits, colored only where a finding sits", async () => {
    render(() => <AddressMap {...props} />);
    const grid = screen.getByRole("grid", { name: "Address map of 192.0.2.0/24, 256 addresses, 16 per row" });
    const cells = within(grid).getAllByRole("gridcell");
    expect(cells).toHaveLength(256);
    expect(cells[10]?.textContent).toBe("10");
    expect(cells[10]?.dataset.state).toBe("used");
    expect(cells.filter((c) => c.dataset.severity)).toHaveLength(1);
    expect(cells[20]?.className).toContain("sev-act");
    expect(cells[20]?.getAttribute("aria-label")).toBe("192.0.2.20, Free, Act now");
    expect(await axeViolations(screen.getByTestId("address-map"), { disable: ["region"] })).toEqual([]);
  });

  it("says the address and its state on hover and focus, moves with the arrows and opens on Enter", () => {
    const onOpen = vi.fn();
    render(() => <AddressMap {...props} onOpen={onOpen} />);
    const cells = screen.getAllByRole("gridcell");
    const readout = screen.getByTestId("address-map-readout");
    // One tab stop.
    expect(cells.filter((c) => c.tabIndex === 0)).toHaveLength(1);
    fireEvent.mouseEnter(cells[10]!);
    expect(readout.textContent).toContain("192.0.2.10");
    expect(readout.textContent).toContain("In use");
    expect(readout.textContent).toContain("host-01.example.test");
    fireEvent.focus(cells[0]!);
    expect(readout.textContent).toContain("192.0.2.0");
    expect(readout.textContent).toContain("Not usable");
    fireEvent.keyDown(cells[0]!, { key: "ArrowDown" });
    expect(document.activeElement).toBe(cells[16]);
    fireEvent.keyDown(cells[16]!, { key: "ArrowRight" });
    fireEvent.keyDown(cells[17]!, { key: "ArrowRight" });
    fireEvent.keyDown(cells[18]!, { key: "ArrowRight" });
    fireEvent.keyDown(cells[19]!, { key: "ArrowRight" });
    expect(document.activeElement).toBe(cells[20]);
    expect(readout.textContent).toContain("Conflict");
    fireEvent.keyDown(cells[20]!, { key: "Enter" });
    expect(onOpen).toHaveBeenCalledWith("192.0.2.20");
    fireEvent.keyDown(cells[20]!, { key: "End", ctrlKey: true });
    expect(document.activeElement).toBe(cells[255]);
  });

  it("draws block cells with their in-use count and opens a block's addresses", () => {
    const onOpenBlock = vi.fn();
    render(() => <AddressMap cidr="198.18.0.0/16" addresses={[{ ip: "198.18.5.1" }, { ip: "198.18.5.2" }]} ranges={[]} findings={[]} onOpenBlock={onOpenBlock} />);
    const cells = screen.getAllByRole("gridcell");
    expect(cells).toHaveLength(256);
    expect(cells[5]?.textContent).toBe("2");
    expect(cells[5]?.getAttribute("aria-label")).toBe("198.18.5.0/24, 2 of 256 in use, 0 findings");
    fireEvent.click(cells[5]!);
    expect(onOpenBlock).toHaveBeenCalledWith("198.18.5.0/24");
  });

  it("says so when a prefix is too large for a map", () => {
    render(() => <AddressMap cidr="2001:db8::/64" addresses={[]} ranges={[]} findings={[]} />);
    expect(screen.getByTestId("address-map-none")).toBeTruthy();
    expect(screen.queryByRole("grid")).toBeNull();
  });
});
