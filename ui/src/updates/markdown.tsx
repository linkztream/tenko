// A small, safe Markdown renderer for release notes and the action text of a release.
// Release notes come from a manifest an administrator fetched or uploaded, so they are
// data, never markup: everything is built as Solid elements and text nodes (no innerHTML),
// so `<script>`, `<img onerror=...>` and HTML entities stay inert text. The subset:
//
//   # to ###### headings, paragraphs, fenced code blocks,
//   "-", "*" and "1." lists (nested by two spaces of indent),
//   **bold**, *italic*, `code`, and [text](url) for http: and https: URLs only.
//
// Anything else is plain text, and so is a link whose URL is not http: or https:.
//
// Every element it builds has a generic test id (ui/README.md): `md-heading` (`data-level`,
// the level of the element), `md-paragraph`, `md-list` (`data-ordered`), `md-item`,
// `md-strong`, `md-em`, `md-code` (inline), `md-pre` (fenced) and `md-link`.
import { For, Match, Show, Switch, type JSX } from "solid-js";

// ---------------------------------------------------------------------------------
// Blocks

export interface ListItem {
  text: string;
  children: ListBlock | null;
}

export interface ListBlock {
  kind: "list";
  ordered: boolean;
  items: ListItem[];
}

export type Block =
  | { kind: "heading"; level: number; text: string }
  | { kind: "paragraph"; text: string }
  | { kind: "code"; text: string }
  | ListBlock;

const HEADING = /^(#{1,6})\s+(.+?)\s*#*\s*$/;
const BULLET = /^(\s*)[-*+]\s+(.*)$/;
const NUMBERED = /^(\s*)\d{1,9}[.)]\s+(.*)$/;
const FENCE = /^\s*```/;
const MAX_DEPTH = 3;

interface Marker {
  indent: number;
  ordered: boolean;
  text: string;
}

function listMarker(line: string): Marker | null {
  const bullet = BULLET.exec(line);
  if (bullet) return { indent: (bullet[1] ?? "").replace(/\t/g, "  ").length, ordered: false, text: bullet[2] ?? "" };
  const numbered = NUMBERED.exec(line);
  if (numbered) return { indent: (numbered[1] ?? "").replace(/\t/g, "  ").length, ordered: true, text: numbered[2] ?? "" };
  return null;
}

/** Reads the lines of a list (starting at `start`) into nested lists; returns where it stopped. */
function readList(lines: readonly string[], start: number): { block: ListBlock; next: number } {
  const root: ListBlock = { kind: "list", ordered: listMarker(lines[start] ?? "")?.ordered ?? false, items: [] };
  // The lists open at each depth, innermost last.
  const stack: ListBlock[] = [root];
  let i = start;
  let last: ListItem | null = null;
  for (; i < lines.length; i += 1) {
    const line = lines[i] ?? "";
    if (line.trim() === "" || FENCE.test(line) || HEADING.test(line)) break;
    const marker = listMarker(line);
    if (!marker) {
      // A continuation of the last item: more text of the same item.
      if (last && /^\s+\S/.test(line)) {
        last.text = `${last.text} ${line.trim()}`;
        continue;
      }
      break;
    }
    // One level deeper than the open lists at most.
    const depth = Math.min(MAX_DEPTH, Math.floor(marker.indent / 2), stack.length);
    while (stack.length > depth + 1) stack.pop();
    if (depth >= stack.length && last) {
      const inner: ListBlock = { kind: "list", ordered: marker.ordered, items: [] };
      last.children = inner;
      stack.push(inner);
    }
    const item: ListItem = { text: marker.text, children: null };
    stack[stack.length - 1]?.items.push(item);
    last = item;
  }
  return { block: root, next: i };
}

/** Splits Markdown into blocks. Line ends of any kind; blank lines separate paragraphs. */
export function parseMarkdown(source: string): Block[] {
  const lines = source.replace(/\r\n?/g, "\n").split("\n");
  const blocks: Block[] = [];
  let paragraph: string[] = [];
  const flush = () => {
    if (paragraph.length > 0) blocks.push({ kind: "paragraph", text: paragraph.join(" ") });
    paragraph = [];
  };
  for (let i = 0; i < lines.length; ) {
    const line = lines[i] ?? "";
    if (line.trim() === "") {
      flush();
      i += 1;
    } else if (FENCE.test(line)) {
      flush();
      const body: string[] = [];
      i += 1;
      while (i < lines.length && !FENCE.test(lines[i] ?? "")) {
        body.push(lines[i] ?? "");
        i += 1;
      }
      i += 1;
      blocks.push({ kind: "code", text: body.join("\n") });
    } else if (HEADING.test(line)) {
      flush();
      const match = HEADING.exec(line);
      blocks.push({ kind: "heading", level: match?.[1]?.length ?? 3, text: match?.[2] ?? "" });
      i += 1;
    } else if (listMarker(line)) {
      flush();
      const { block, next } = readList(lines, i);
      blocks.push(block);
      i = next;
    } else {
      paragraph.push(line.trim());
      i += 1;
    }
  }
  flush();
  return blocks;
}

// ---------------------------------------------------------------------------------
// Inline text

/** The URL of a link, when it is an http: or https: URL without anything odd in it. */
export function safeUrl(raw: string): string | null {
  const text = raw.trim();
  if (!/^https?:\/\/[^\s<>"'`\\]+$/i.test(text)) return null;
  try {
    const url = new URL(text);
    return url.protocol === "https:" || url.protocol === "http:" ? url.href : null;
  } catch {
    return null;
  }
}

const LINK = /^\[([^\]\n]*)\]\(([^)\s]*)\)/;
const ESCAPABLE = /[\\`*_[\](){}#+\-.!<>]/;

/** Inline text to text nodes and elements. Unknown or unsafe syntax stays as written. */
export function renderInline(text: string): JSX.Element[] {
  const out: JSX.Element[] = [];
  let buffer = "";
  const flush = () => {
    if (buffer !== "") out.push(buffer);
    buffer = "";
  };
  let i = 0;
  while (i < text.length) {
    const c = text.charAt(i);
    if (c === "\\" && i + 1 < text.length && ESCAPABLE.test(text.charAt(i + 1))) {
      buffer += text.charAt(i + 1);
      i += 2;
      continue;
    }
    if (c === "`") {
      const end = text.indexOf("`", i + 1);
      if (end > i + 1) {
        flush();
        out.push(<code data-testid="md-code">{text.slice(i + 1, end)}</code>);
        i = end + 1;
        continue;
      }
    }
    if (c === "*" && text.charAt(i + 1) === "*") {
      const end = text.indexOf("**", i + 2);
      if (end > i + 2) {
        flush();
        out.push(<strong data-testid="md-strong">{renderInline(text.slice(i + 2, end))}</strong>);
        i = end + 2;
        continue;
      }
    }
    if (c === "*" && text.charAt(i + 1) !== " " && text.charAt(i + 1) !== "*") {
      const end = text.indexOf("*", i + 1);
      if (end > i + 1 && text.charAt(end - 1) !== " ") {
        flush();
        out.push(<em data-testid="md-em">{renderInline(text.slice(i + 1, end))}</em>);
        i = end + 1;
        continue;
      }
    }
    if (c === "[") {
      const match = LINK.exec(text.slice(i));
      if (match) {
        const href = safeUrl(match[2] ?? "");
        if (href) {
          flush();
          out.push(
            <a href={href} target="_blank" rel="noopener noreferrer" data-testid="md-link">
              {renderInline(match[1] ?? "")}
            </a>,
          );
        } else {
          // Not a link this page follows: the whole thing is text.
          buffer += match[0];
        }
        i += match[0].length;
        continue;
      }
    }
    buffer += c;
    i += 1;
  }
  flush();
  return out;
}

// ---------------------------------------------------------------------------------
// Rendering

function ListView(props: { list: ListBlock }): JSX.Element {
  const items = () => (
    <For each={props.list.items}>
      {(item) => (
        <li data-testid="md-item">
          {renderInline(item.text)}
          <Show when={item.children}>{(inner) => <ListView list={inner()} />}</Show>
        </li>
      )}
    </For>
  );
  return (
    <Show
      when={props.list.ordered}
      fallback={
        <ul data-testid="md-list" data-ordered="false">
          {items()}
        </ul>
      }
    >
      <ol data-testid="md-list" data-ordered="true">
        {items()}
      </ol>
    </Show>
  );
}

function Heading(props: { level: number; text: string }): JSX.Element {
  const inner = () => renderInline(props.text);
  return (
    <Switch
      fallback={
        <h6 data-testid="md-heading" data-level="6">
          {inner()}
        </h6>
      }
    >
      <Match when={props.level === 1}>
        <h1 data-testid="md-heading" data-level="1">
          {inner()}
        </h1>
      </Match>
      <Match when={props.level === 2}>
        <h2 data-testid="md-heading" data-level="2">
          {inner()}
        </h2>
      </Match>
      <Match when={props.level === 3}>
        <h3 data-testid="md-heading" data-level="3">
          {inner()}
        </h3>
      </Match>
      <Match when={props.level === 4}>
        <h4 data-testid="md-heading" data-level="4">
          {inner()}
        </h4>
      </Match>
      <Match when={props.level === 5}>
        <h5 data-testid="md-heading" data-level="5">
          {inner()}
        </h5>
      </Match>
    </Switch>
  );
}

/**
 * Release notes as elements. A release lists its changes under `###` and `####`; they
 * become `top` (default `h4`) and the next level, so the notes sit below the heading of the
 * release (`h3`). A `#` or `##` takes the level of `###`.
 */
export function Markdown(props: { source: string; top?: number; class?: string }): JSX.Element {
  const blocks = () => parseMarkdown(props.source);
  const level = (n: number) => Math.min(6, (props.top ?? 4) + Math.max(0, n - 3));
  return (
    <div class={props.class ? `md ${props.class}` : "md"}>
      <For each={blocks()}>
        {(block) => (
          <Switch>
            <Match when={block.kind === "heading" && block}>
              {(b) => <Heading level={level(b().level)} text={b().text} />}
            </Match>
            <Match when={block.kind === "paragraph" && block}>{(b) => <p data-testid="md-paragraph">{renderInline(b().text)}</p>}</Match>
            <Match when={block.kind === "code" && block}>
              {(b) => (
                <pre data-testid="md-pre">
                  <code>{b().text}</code>
                </pre>
              )}
            </Match>
            <Match when={block.kind === "list" && block}>{(b) => <ListView list={b() as ListBlock} />}</Match>
          </Switch>
        )}
      </For>
    </div>
  );
}
