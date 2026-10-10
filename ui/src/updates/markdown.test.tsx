import { render } from "@solidjs/testing-library";
import { describe, expect, it } from "vitest";
import { axeViolations } from "../app/testing/axe";
import { Markdown, parseMarkdown, safeUrl } from "./markdown";

function html(source: string, top?: number): HTMLElement {
  const { container } = render(() => <Markdown source={source} {...(top === undefined ? {} : { top })} />);
  return container.querySelector(".md") as HTMLElement;
}

describe("Markdown blocks", () => {
  it("reads headings, paragraphs and lists", () => {
    const blocks = parseMarkdown("### Added\n- one\n- two\n\nSome text\nover two lines.\n\n#### Fixed\n1. first\n2. second");
    expect(blocks.map((b) => b.kind)).toEqual(["heading", "list", "paragraph", "heading", "list"]);
    expect(blocks[0]).toEqual({ kind: "heading", level: 3, text: "Added" });
    expect(blocks[2]).toEqual({ kind: "paragraph", text: "Some text over two lines." });
    const bullets = blocks[1];
    expect(bullets?.kind === "list" && bullets.ordered).toBe(false);
    const numbers = blocks[4];
    expect(numbers?.kind === "list" && numbers.ordered).toBe(true);
  });

  it("nests a list by two spaces of indent", () => {
    const [list] = parseMarkdown("- parent\n  - child\n  - other child\n- second");
    expect(list?.kind).toBe("list");
    if (list?.kind !== "list") return;
    expect(list.items).toHaveLength(2);
    expect(list.items[0]?.children?.items.map((i) => i.text)).toEqual(["child", "other child"]);
    expect(list.items[1]?.children).toBeNull();
  });

  it("keeps a continuation line with its item and understands CRLF", () => {
    const [list] = parseMarkdown("- first line\r\n  continues here\r\n- next");
    expect(list?.kind === "list" && list.items.map((i) => i.text)).toEqual(["first line continues here", "next"]);
  });

  it("reads a fenced block as code", () => {
    const [code] = parseMarkdown("```\ntenko upgrade check\n- not a list\n```");
    expect(code).toEqual({ kind: "code", text: "tenko upgrade check\n- not a list" });
  });
});

describe("Markdown rendering", () => {
  it("renders headings below the page heading, lists, emphasis and code", () => {
    const root = html("### Added\n- **bold** and *italic* and `code`\n- plain\n\n#### Detail\nText");
    expect(root.querySelector("h4")?.textContent).toBe("Added");
    expect(root.querySelector("h5")?.textContent).toBe("Detail");
    expect(root.querySelectorAll("ul > li")).toHaveLength(2);
    expect(root.querySelector("li strong")?.textContent).toBe("bold");
    expect(root.querySelector("li em")?.textContent).toBe("italic");
    expect(root.querySelector("li code")?.textContent).toBe("code");
    expect(root.querySelector("p")?.textContent).toBe("Text");
  });

  it("gives every element a generic test id", () => {
    const root = html(
      [
        "### Added",
        "- **bold** and *italic* and `code` and [a link](https://example.org/)",
        "- plain",
        "",
        "#### Detail",
        "Text",
        "",
        "1. one",
        "2. two",
        "   - nested",
        "",
        "```",
        "fenced",
        "```",
      ].join("\n"),
    );
    const all = (id: string) => Array.from(root.querySelectorAll(`[data-testid="${id}"]`));
    expect(all("md-heading").map((h) => [h.tagName, h.getAttribute("data-level"), h.textContent])).toEqual([
      ["H4", "4", "Added"],
      ["H5", "5", "Detail"],
    ]);
    expect(all("md-paragraph").map((p) => p.textContent)).toEqual(["Text"]);
    expect(all("md-list").map((l) => [l.tagName, l.getAttribute("data-ordered")])).toEqual([
      ["UL", "false"],
      ["OL", "true"],
      ["UL", "false"],
    ]);
    expect(all("md-item")).toHaveLength(5);
    expect(all("md-strong").map((e) => e.textContent)).toEqual(["bold"]);
    expect(all("md-em").map((e) => e.textContent)).toEqual(["italic"]);
    expect(all("md-code").map((e) => e.textContent)).toEqual(["code"]);
    expect(all("md-pre").map((e) => e.textContent)).toEqual(["fenced"]);
    const links = all("md-link");
    expect(links.map((a) => [a.tagName, a.getAttribute("href"), a.textContent])).toEqual([["A", "https://example.org/", "a link"]]);
  });

  it("gives the heading level of the element in data-level", () => {
    expect(html("### Added", 3).querySelector('[data-testid="md-heading"]')?.getAttribute("data-level")).toBe("3");
    expect(html("###### Deep", 5).querySelector('[data-testid="md-heading"]')?.getAttribute("data-level")).toBe("6");
  });

  it("starts the headings at the level the page asks for", () => {
    expect(html("### Added", 3).querySelector("h3")?.textContent).toBe("Added");
    expect(html("###### Deep", 5).querySelector("h6")?.textContent).toBe("Deep");
  });

  it("renders nested and numbered lists", () => {
    const root = html("1. one\n2. two\n   - nested\n");
    expect(root.querySelectorAll("ol > li")).toHaveLength(2);
    expect(root.querySelector("ol li ul li")?.textContent).toBe("nested");
  });

  it("links http and https URLs and opens them safely", () => {
    const root = html("See [the advisory](https://example.org/a?b=1) and [plain](http://example.net/x).");
    const links = Array.from(root.querySelectorAll("a"));
    expect(links.map((a) => a.getAttribute("href"))).toEqual(["https://example.org/a?b=1", "http://example.net/x"]);
    for (const a of links) {
      expect(a.getAttribute("rel")).toBe("noopener noreferrer");
      expect(a.getAttribute("target")).toBe("_blank");
    }
    expect(links[0]?.textContent).toBe("the advisory");
  });

  it("keeps a script tag as text", () => {
    const root = html("Before <script>window.hacked = true</script> after");
    expect(root.querySelector("script")).toBeNull();
    expect(root.textContent).toBe("Before <script>window.hacked = true</script> after");
    expect((window as unknown as { hacked?: boolean }).hacked).toBeUndefined();
  });

  it("keeps an image with an error handler as text", () => {
    const root = html('<img src="x" onerror="window.hacked = true">');
    expect(root.querySelector("img")).toBeNull();
    expect(root.textContent).toContain('<img src="x" onerror="window.hacked = true">');
    expect((window as unknown as { hacked?: boolean }).hacked).toBeUndefined();
  });

  it("does not turn a javascript, data or other scheme into a link", () => {
    const root = html(
      "[a](javascript:alert(1)) [b](JaVaScRiPt:alert(1)) [c](data:text/html;base64,AAAA) [d](ftp://example.org/x) [e](//example.org/x) [f](/relative)",
    );
    expect(root.querySelector("a")).toBeNull();
    expect(root.querySelector('[data-testid="md-link"]')).toBeNull();
    expect(root.textContent).toContain("[a](javascript:alert(1)");
    expect(root.textContent).toContain("[c](data:text/html;base64,AAAA)");
  });

  it("keeps HTML entities as they are written", () => {
    const root = html("Fish &amp; chips &lt;b&gt;bold&lt;/b&gt; &#60;i&#62;");
    expect(root.textContent).toBe("Fish &amp; chips &lt;b&gt;bold&lt;/b&gt; &#60;i&#62;");
    expect(root.querySelector("b, i")).toBeNull();
  });

  it("does not let an HTML tag inside a link text or a heading become markup", () => {
    const root = html("### <u>Title</u>\n[<img src=x onerror=alert(1)>](https://example.org/)");
    expect(root.querySelector("u, img")).toBeNull();
    expect(root.querySelector('[data-testid="md-heading"]')?.textContent).toBe("<u>Title</u>");
    expect(root.querySelector("a")?.textContent).toBe("<img src=x onerror=alert(1)>");
  });

  it("lets a backslash keep a character literal", () => {
    const root = html("\\*not italic\\* and \\`not code\\`");
    expect(root.querySelector("em, code")).toBeNull();
    expect(root.querySelector('[data-testid="md-em"], [data-testid="md-code"]')).toBeNull();
    expect(root.textContent).toBe("*not italic* and `not code`");
  });

  it("leaves an unclosed marker as text", () => {
    const root = html("a **bold never ends and a `code never ends");
    expect(root.querySelector("strong, code")).toBeNull();
    expect(root.querySelector('[data-testid="md-strong"], [data-testid="md-code"]')).toBeNull();
    expect(root.textContent).toBe("a **bold never ends and a `code never ends");
  });

  it("is accessible", async () => {
    html("### Added\n- one\n- [link](https://example.org/)\n\n```\ncode\n```");
    // The fragment is rendered alone, without the landmarks of a page.
    expect(await axeViolations(document.body, { disable: ["region"] })).toEqual([]);
  });
});

describe("safeUrl", () => {
  it("accepts only http and https URLs", () => {
    expect(safeUrl("https://example.org/path")).toBe("https://example.org/path");
    expect(safeUrl("http://example.org")).toBe("http://example.org/");
    expect(safeUrl("javascript:alert(1)")).toBeNull();
    expect(safeUrl("https://example.org/a b")).toBeNull();
    expect(safeUrl('https://example.org/"onmouseover="x')).toBeNull();
    expect(safeUrl("")).toBeNull();
  });
});
