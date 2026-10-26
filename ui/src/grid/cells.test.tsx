import { render } from "@solidjs/testing-library";
import { createSignal } from "solid-js";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { AlarmLevel, AssignmentMode, Status, TreeNode } from "../api/types";
import { formatDateTime, setLocale } from "../i18n";
import { allocationWords } from "../ipam/words";
import {
  AlarmFlag,
  Count,
  DeletedTag,
  DnsName,
  Kind,
  LockFlag,
  ModeBadge,
  StatusBadge,
  Tags,
  TimeAgo,
  UtilizationMeter,
} from "./cells";

beforeEach(async () => {
  await setLocale("en");
});

afterEach(async () => {
  await setLocale("en");
});

function first(container: HTMLElement, selector: string): HTMLElement {
  const el = container.querySelector<HTMLElement>(selector);
  if (!el) throw new Error(`nothing matches ${selector} in ${container.innerHTML}`);
  return el;
}

function iconOf(el: HTMLElement): string | null | undefined {
  return el.querySelector("svg use")?.getAttribute("href");
}

describe("StatusBadge", () => {
  const WORDS: readonly [Status, string][] = [
    ["planned", "Planned"],
    ["active", "Active"],
    ["reserved", "Reserved"],
    ["deprecated", "Deprecated"],
  ];

  it.each(WORDS)("shows %s as a word with its own class", (status, word) => {
    const { container } = render(() => <StatusBadge status={status} />);
    const badge = first(container, "span");
    expect(badge.textContent).toBe(word);
    expect(badge.classList.contains("status-badge")).toBe(true);
    expect(badge.classList.contains(status)).toBe(true);
    expect(badge.dataset.status).toBe(status);
  });

  it("has exactly one status class", () => {
    const { container } = render(() => <StatusBadge status="planned" />);
    expect([...first(container, "span").classList].sort()).toEqual(["planned", "status-badge"]);
  });

  it("follows a status that changes and a language switch", async () => {
    const [status, setStatus] = createSignal<Status>("active");
    const { container } = render(() => <StatusBadge status={status()} />);
    const badge = first(container, "span");
    expect(badge.textContent).toBe("Active");
    setStatus("deprecated");
    expect(badge.textContent).toBe("Deprecated");
    expect(badge.classList.contains("deprecated")).toBe(true);
    expect(badge.classList.contains("active")).toBe(false);
    await setLocale("sv");
    expect(badge.textContent).toBe("Utfasad");
  });
});

describe("ModeBadge", () => {
  const MODES: readonly AssignmentMode[] = ["reserved", "static", "dynamic", "unmanaged"];

  it.each(MODES)("renders the design's mode markup for %s", (mode) => {
    const { container } = render(() => <ModeBadge mode={mode} />);
    const el = first(container, ".mode");
    expect(el.classList.contains(mode)).toBe(true);
    expect(el.textContent).toBe(mode);
    expect(el.title.length).toBeGreaterThan(10);
  });

  it("explains the behavior in the title", () => {
    const { container } = render(() => <ModeBadge mode="reserved" />);
    expect(first(container, ".mode").title).toBe("An address change moves the DHCP reservation and updates DNS.");
  });

  it("leaves the hint out by default", () => {
    const { container } = render(() => <ModeBadge mode="static" />);
    expect(container.querySelector(".muted")).toBeNull();
  });

  it("spells the hint out after the mode with showHint", () => {
    const { container } = render(() => <ModeBadge mode="static" showHint />);
    const hint = first(container, ".muted");
    expect(hint.textContent).toBe("Only DNS follows. The device itself is configured by hand.");
    expect(first(container, ".mode").nextElementSibling).toBe(hint);
  });

  it("follows a mode that changes", () => {
    const [mode, setMode] = createSignal<AssignmentMode>("dynamic");
    const { container } = render(() => <ModeBadge mode={mode()} showHint />);
    expect(first(container, ".muted").textContent).toBe("Tenko only observes this host.");
    setMode("unmanaged");
    expect(first(container, ".mode").textContent).toBe("unmanaged");
    expect(first(container, ".muted").textContent).toBe("Tenko never touches this host.");
  });
});

describe("LockFlag", () => {
  it("renders nothing when the host is not locked", () => {
    for (const locked of [false, null, undefined]) {
      const { container, unmount } = render(() => <LockFlag locked={locked} />);
      expect(container.innerHTML, String(locked)).toBe("");
      unmount();
    }
    const { container } = render(() => <LockFlag />);
    expect(container.innerHTML).toBe("");
  });

  it("shows the lock icon, the word and what it means", () => {
    const { container } = render(() => <LockFlag locked />);
    const flag = first(container, ".flag.locked");
    expect(flag.textContent).toBe("Locked");
    expect(flag.title).toBe("Automation is stopped for this host.");
    expect(iconOf(flag)).toBe("#i-lock");
    expect(flag.querySelector("svg")?.getAttribute("aria-hidden")).toBe("true");
  });

  it("appears and disappears with the flag", () => {
    const [locked, setLocked] = createSignal(false);
    const { container } = render(() => <LockFlag locked={locked()} />);
    expect(container.querySelector(".flag")).toBeNull();
    setLocked(true);
    expect(container.querySelector(".flag.locked")).not.toBeNull();
    setLocked(false);
    expect(container.querySelector(".flag")).toBeNull();
  });
});

describe("Tags", () => {
  const FIVE = ["core", "lab", "iot", "printer", "camera"];

  function chips(container: HTMLElement): string[] {
    return [...container.querySelectorAll(".tag")].map((el) => el.textContent ?? "");
  }

  it("renders nothing without tags", () => {
    for (const tags of [undefined, null, []] as const) {
      const { container, unmount } = render(() => <Tags tags={tags} />);
      expect(container.innerHTML).toBe("");
      unmount();
    }
  });

  it("shows every tag when there are no more than the maximum", () => {
    const { container } = render(() => <Tags tags={["core", "lab", "iot"]} />);
    expect(chips(container)).toEqual(["core", "lab", "iot"]);
    expect(container.querySelector(".more")).toBeNull();
  });

  it("shows three tags and +2 for five tags with the default maximum", () => {
    const { container } = render(() => <Tags tags={FIVE} />);
    expect(chips(container)).toEqual(["core", "lab", "iot", "+2"]);
    expect(first(container, ".tag.more").title).toBe("printer, camera");
  });

  it("honors a given maximum", () => {
    const { container } = render(() => <Tags tags={FIVE} max={1} />);
    expect(chips(container)).toEqual(["core", "+4"]);
    expect(first(container, ".tag.more").title).toBe("lab, iot, printer, camera");
  });

  it("shows only the count with a maximum of zero", () => {
    const { container } = render(() => <Tags tags={["core", "lab"]} max={0} />);
    expect(chips(container)).toEqual(["+2"]);
  });

  it("shows all tags when the maximum is large", () => {
    const { container } = render(() => <Tags tags={FIVE} max={10} />);
    expect(chips(container)).toEqual(FIVE);
  });

  it("keeps the tag text as data", () => {
    const { container } = render(() => <Tags tags={["Rack A", "vlan:20"]} />);
    expect(chips(container)).toEqual(["Rack A", "vlan:20"]);
  });
});

describe("UtilizationMeter", () => {
  it("draws a neutral bar and the percentage", () => {
    const { container } = render(() => <UtilizationMeter percent={52} />);
    const meter = first(container, ".meter");
    expect([...meter.classList]).toEqual(["meter"]);
    expect(meter.style.getPropertyValue("--v")).toBe("52%");
    expect(first(container, ".bar > i")).toBeTruthy();
    expect(first(container, ".val").textContent).toBe("52%");
    expect(container.querySelector(".sr-only")).toBeNull();
    expect(container.querySelector("svg")).toBeNull();
  });

  it("shows at most one decimal", () => {
    const { container, unmount } = render(() => <UtilizationMeter percent={44.1} />);
    expect(first(container, ".val").textContent).toBe("44.1%");
    unmount();
    const second = render(() => <UtilizationMeter percent={44.149} />);
    expect(first(second.container, ".val").textContent).toBe("44.1%");
    second.unmount();
    const third = render(() => <UtilizationMeter percent={99.96} />);
    expect(first(third.container, ".val").textContent).toBe("100%");
  });

  it("marks a warning with the warn class, an alert icon and the level as text", () => {
    const { container } = render(() => <UtilizationMeter percent={84} level="warning" />);
    const meter = first(container, ".meter");
    expect(meter.classList.contains("warn")).toBe(true);
    expect(meter.classList.contains("crit")).toBe(false);
    expect(first(container, ".sr-only").textContent).toBe("Warning");
    expect(iconOf(meter)).toBe("#i-alert");
    expect(meter.dataset.level).toBe("warning");
  });

  it("marks a critical level with the crit class, an alert icon and the level as text", () => {
    const { container } = render(() => <UtilizationMeter percent={100} level="critical" />);
    const meter = first(container, ".meter");
    expect(meter.classList.contains("crit")).toBe(true);
    expect(meter.classList.contains("warn")).toBe(false);
    expect(first(container, ".sr-only").textContent).toBe("Critical");
    expect(iconOf(meter)).toBe("#i-alert");
    expect(first(container, ".val").textContent).toBe("100%");
  });

  it("stays neutral for the normal level", () => {
    const { container } = render(() => <UtilizationMeter percent={10} level="normal" />);
    const meter = first(container, ".meter");
    expect([...meter.classList]).toEqual(["meter"]);
    expect(container.querySelector(".sr-only")).toBeNull();
    expect(container.querySelector("svg")).toBeNull();
  });

  it("explains the numbers in the title with compact counts", () => {
    const { container } = render(() => <UtilizationMeter percent={44.1} used="112" capacity="254" />);
    expect(first(container, ".meter").title).toBe("112 of 254 usable addresses in use");
    const big = render(() => <UtilizationMeter percent={29} used="1234" capacity="18446744073709551616" />);
    expect(first(big.container, ".meter").title).toBe("1.2K of 2^64 usable addresses in use");
  });

  it("puts a supernet's allocation on a line of its own in the title, never in the bar", () => {
    const node = { role: "supernet" as const, children: 13, utilization: { covered: "3328", size: "65536" } as TreeNode["utilization"] };
    const note = allocationWords(node);
    expect(note).toBe("3.3K of 66K allocated to 13 prefixes");
    const { container } = render(() => <UtilizationMeter percent={0.2} used="150" capacity="65510" note={note} />);
    const meter = first(container, ".meter");
    expect(meter.title).toBe("150 of 66K usable addresses in use\n3.3K of 66K allocated to 13 prefixes");
    expect(first(container, ".val").textContent).toBe("0.2%");
    expect(meter.style.getPropertyValue("--v")).toBe("0.2%");
    expect(allocationWords({ ...node, role: "network" })).toBeUndefined();
    expect(allocationWords({ ...node, children: 1 })).toBe("3.3K of 66K allocated to 1 prefix");
  });

  it("has no title without both counts", () => {
    const { container, unmount } = render(() => <UtilizationMeter percent={44} />);
    expect(first(container, ".meter").getAttribute("title")).toBeNull();
    unmount();
    const half = render(() => <UtilizationMeter percent={44} used="112" />);
    expect(first(half.container, ".meter").getAttribute("title")).toBeNull();
  });

  it("can be compact", () => {
    const { container } = render(() => <UtilizationMeter percent={20} compact level="warning" />);
    const meter = first(container, ".meter");
    expect(meter.classList.contains("compact")).toBe(true);
    expect(meter.classList.contains("warn")).toBe(true);
  });

  it("keeps the bar between 0 and 100 percent", () => {
    const over = render(() => <UtilizationMeter percent={140} />);
    expect(first(over.container, ".meter").style.getPropertyValue("--v")).toBe("100%");
    over.unmount();
    const under = render(() => <UtilizationMeter percent={-5} />);
    expect(first(under.container, ".meter").style.getPropertyValue("--v")).toBe("0%");
    under.unmount();
    const nan = render(() => <UtilizationMeter percent={Number.NaN} />);
    expect(first(nan.container, ".meter").style.getPropertyValue("--v")).toBe("0%");
    expect(first(nan.container, ".val").textContent).toBe("0%");
  });

  it("is not a gauge or a dial", () => {
    const { container } = render(() => <UtilizationMeter percent={50} />);
    expect(container.querySelector("canvas, svg circle, [role='meter'], progress, meter")).toBeNull();
  });

  it("follows the percentage and the level", () => {
    const [percent, setPercent] = createSignal(70);
    const [level, setLevel] = createSignal<AlarmLevel>("normal");
    const { container } = render(() => <UtilizationMeter percent={percent()} level={level()} />);
    const meter = first(container, ".meter");
    expect(first(container, ".val").textContent).toBe("70%");
    setPercent(91.5);
    setLevel("critical");
    expect(meter.style.getPropertyValue("--v")).toBe("91.5%");
    expect(first(container, ".val").textContent).toBe("91.5%");
    expect(meter.classList.contains("crit")).toBe(true);
    expect(first(container, ".sr-only").textContent).toBe("Critical");
    setLevel("normal");
    expect(meter.classList.contains("crit")).toBe(false);
    expect(container.querySelector(".sr-only")).toBeNull();
  });

  it("writes the value and the level in Swedish", async () => {
    await setLocale("sv");
    const { container } = render(() => <UtilizationMeter percent={44.1} level="warning" used="112" capacity="254" />);
    expect(first(container, ".val").textContent).toBe("44,1 %");
    expect(first(container, ".sr-only").textContent).toBe("Varning");
    expect(first(container, ".meter").title).toBe("112 av 254 användbara adresser används");
  });
});

describe("AlarmFlag", () => {
  it("renders nothing for the normal level", () => {
    const { container } = render(() => <AlarmFlag level="normal" />);
    expect(container.innerHTML).toBe("");
  });

  it("shows a warning in the warning ink with an alert icon and a word", () => {
    const { container } = render(() => <AlarmFlag level="warning" />);
    const flag = first(container, ".flag.alarm-warning");
    expect(flag.textContent).toBe("Warning");
    expect(iconOf(flag)).toBe("#i-alert");
  });

  it("shows a critical level in the danger ink with an alert icon and a word", () => {
    const { container } = render(() => <AlarmFlag level="critical" />);
    const flag = first(container, ".flag.alarm-critical");
    expect(flag.textContent).toBe("Critical");
    expect(iconOf(flag)).toBe("#i-alert");
  });

  it("follows the level", () => {
    const [level, setLevel] = createSignal<AlarmLevel>("normal");
    const { container } = render(() => <AlarmFlag level={level()} />);
    expect(container.querySelector(".flag")).toBeNull();
    setLevel("warning");
    expect(first(container, ".flag").classList.contains("alarm-warning")).toBe(true);
    setLevel("critical");
    expect(first(container, ".flag").classList.contains("alarm-critical")).toBe(true);
    expect(first(container, ".flag").classList.contains("alarm-warning")).toBe(false);
  });
});

describe("TimeAgo", () => {
  it("shows the relative time with the exact time as the title", () => {
    const at = new Date(Date.now() - 5 * 60_000).toISOString();
    const { container } = render(() => <TimeAgo at={at} />);
    const time = first(container, "time");
    expect(time.textContent).toBe("5 minutes ago");
    expect(time.getAttribute("datetime")).toBe(at);
    expect(time.title).toBe(formatDateTime(at));
    expect(time.title).not.toBe("");
  });

  it("counts in larger units", () => {
    const at = new Date(Date.now() - 3 * 3_600_000).toISOString();
    const { container } = render(() => <TimeAgo at={at} />);
    expect(first(container, "time").textContent).toBe("3 hours ago");
  });

  it("shows a dash when there is no time", () => {
    for (const at of [null, undefined, ""]) {
      const { container, unmount } = render(() => <TimeAgo at={at} />);
      expect(container.textContent, String(at)).toBe("–");
      expect(container.querySelector("time")).toBeNull();
      unmount();
    }
  });

  it("follows the time and the language", async () => {
    const [at, setAt] = createSignal<string | null>(null);
    const { container } = render(() => <TimeAgo at={at()} />);
    expect(container.textContent).toBe("–");
    setAt(new Date(Date.now() - 3 * 86_400_000).toISOString());
    expect(first(container, "time").textContent).toBe("3 days ago");
    await setLocale("sv");
    expect(first(container, "time").textContent).toBe("för 3 dagar sedan");
  });
});

describe("DeletedTag", () => {
  it("renders nothing when the object is not deleted", () => {
    for (const deleted of [null, undefined]) {
      const { container, unmount } = render(() => <DeletedTag deleted={deleted} />);
      expect(container.innerHTML).toBe("");
      unmount();
    }
    const { container } = render(() => <DeletedTag />);
    expect(container.innerHTML).toBe("");
  });

  it("shows a dashed tag with the date as the title", () => {
    const at = "2026-03-14T09:30:00Z";
    const { container } = render(() => <DeletedTag deleted={{ at }} />);
    const tag = first(container, ".tag.deleted");
    expect(tag.textContent).toBe("Deleted");
    expect(tag.title).toBe(formatDateTime(at));
    expect(tag.title).toMatch(/2026/);
  });

  it("accepts the stamp the API sends", () => {
    const stamp = { at: "2026-03-14T09:30:00Z", by: { kind: "user", id: "u1", name: "alex" } };
    const { container } = render(() => <DeletedTag deleted={stamp} />);
    expect(container.querySelector(".tag.deleted")).not.toBeNull();
  });
});

describe("DnsName", () => {
  it("renders nothing for an empty name", () => {
    for (const name of [undefined, null, "", "   "]) {
      const { container, unmount } = render(() => <DnsName name={name} />);
      expect(container.innerHTML, String(name)).toBe("");
      unmount();
    }
  });

  it("puts the first label in ink and the rest in the domain", () => {
    const { container } = render(() => <DnsName name="gw.example.test" />);
    const name = first(container, ".hostname");
    expect(name.textContent).toBe("gw.example.test");
    expect(first(container, ".domain").textContent).toBe(".example.test");
    expect(name.firstChild?.textContent).toBe("gw");
  });

  it("keeps a trailing dot in the domain", () => {
    const { container } = render(() => <DnsName name="printer-2.example.org." />);
    expect(first(container, ".domain").textContent).toBe(".example.org.");
    expect(first(container, ".hostname").firstChild?.textContent).toBe("printer-2");
  });

  it("shows a bare label without a domain", () => {
    const { container } = render(() => <DnsName name="gw" />);
    expect(first(container, ".hostname").textContent).toBe("gw");
    expect(container.querySelector(".domain")).toBeNull();
  });

  it("splits a wildcard name at the first dot", () => {
    const { container } = render(() => <DnsName name="*.apps.example.net" />);
    expect(first(container, ".hostname").firstChild?.textContent).toBe("*");
    expect(first(container, ".domain").textContent).toBe(".apps.example.net");
  });

  it("follows a name that changes", () => {
    const [name, setName] = createSignal<string | null>("gw");
    const { container } = render(() => <DnsName name={name()} />);
    expect(container.querySelector(".domain")).toBeNull();
    setName("gw.example.test");
    expect(first(container, ".domain").textContent).toBe(".example.test");
    setName(null);
    expect(container.innerHTML).toBe("");
  });
});

describe("Count", () => {
  it("shows the compact form with the exact value as the title", () => {
    const { container } = render(() => <Count value="1234" />);
    const el = first(container, "span");
    expect(el.textContent).toBe("1.2K");
    expect(el.title).toBe("1,234");
    expect([...el.classList]).toEqual(["num"]);
  });

  it("shows small counts as they are", () => {
    const { container } = render(() => <Count value={982} />);
    expect(first(container, "span").textContent).toBe("982");
    expect(first(container, "span").title).toBe("982");
  });

  it("writes an IPv6 size as a power of two", () => {
    const { container } = render(() => <Count value="18446744073709551616" />);
    const el = first(container, "span");
    expect(el.textContent).toBe("2^64");
    expect(el.title).toBe("18,446,744,073,709,551,616");
  });

  it("writes other huge counts in exponent form", () => {
    const { container } = render(() => <Count value="30000000000000000000" />);
    expect(first(container, "span").textContent).toBe("3.0e19");
    expect(first(container, "span").title).toBe("30,000,000,000,000,000,000");
  });

  it("takes bigints", () => {
    const { container } = render(() => <Count value={2n ** 128n} />);
    expect(first(container, "span").textContent).toBe("2^128");
  });

  it("adds a class next to num", () => {
    const { container } = render(() => <Count value={5} class="strong" />);
    expect([...first(container, "span").classList]).toEqual(["num", "strong"]);
  });

  it("follows the language", async () => {
    const { container } = render(() => <Count value="1234" />);
    await setLocale("sv");
    expect(first(container, "span").textContent).toBe("1,2K");
    expect(first(container, "span").title.replace(/\s/g, " ")).toBe("1 234");
  });
});

describe("Kind", () => {
  it("shows the singular by default", () => {
    const { container } = render(() => <Kind kind="prefix" />);
    expect(container.textContent).toBe("prefix");
  });

  it("shows the plural for any other count", () => {
    const { container, unmount } = render(() => <Kind kind="prefix" count={3} />);
    expect(container.textContent).toBe("prefixes");
    unmount();
    const one = render(() => <Kind kind="custom_field" count={1} />);
    expect(one.container.textContent).toBe("custom field");
    one.unmount();
    const zero = render(() => <Kind kind="vlan" count={0} />);
    expect(zero.container.textContent).toBe("VLANs");
  });

  it("shows an unknown kind as it is", () => {
    const { container } = render(() => <Kind kind="session" count={2} />);
    expect(container.textContent).toBe("session");
  });

  it("follows the language", async () => {
    const { container } = render(() => <Kind kind="host" count={2} />);
    expect(container.textContent).toBe("hosts");
    await setLocale("sv");
    expect(container.textContent).toBe("värdar");
  });
});
