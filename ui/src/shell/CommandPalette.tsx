import { useNavigate } from "@solidjs/router";
import { createEffect, createMemo, createSignal, For, onCleanup, Show } from "solid-js";
import { api } from "../api/client";
import type { SearchHit } from "../api/types";
import { paths } from "../app/paths";
import { hitHref, hitIcon, hitSubtitle, hitTitle } from "./searchHits";
import { Dialog } from "../components/Dialog";
import { Icon, type IconName } from "../components/Icon";
import { Kbd } from "../components/Kbd";
import { t, type MessageKey } from "../i18n";
import { moduleRunning } from "../updates/modules";
import { activeCommands, matchCommand, type Command, type CommandGroup } from "./commands";

const GROUP_LABEL: Record<CommandGroup, MessageKey> = {
  actions: "shell.palette.group.actions",
  goto: "shell.palette.group.goto",
  preferences: "shell.palette.group.preferences",
};
const GROUP_ORDER: readonly CommandGroup[] = ["actions", "goto", "preferences"];
const IDENTIFIER = /^[0-9a-f:.\-/]+$/i;

interface Item {
  id: string;
  group: string;
  icon: IconName;
  title: string;
  mono: boolean;
  sub?: string | undefined;
  keys?: readonly string[] | undefined;
  run: () => void;
}

/** Ctrl+K: one field for addresses, hosts, MACs, prefixes and commands; `>` limits to commands. */
export function CommandPalette(props: { onClose: () => void; initial?: string }) {
  const navigate = useNavigate();
  const [query, setQuery] = createSignal(props.initial ?? "");
  const [selected, setSelected] = createSignal(0);
  const [hits, setHits] = createSignal<SearchHit[]>([]);
  const [searching, setSearching] = createSignal(false);
  let input!: HTMLInputElement;
  let list!: HTMLDivElement;

  const commandsOnly = () => query().startsWith(">");
  const text = () => (commandsOnly() ? query().slice(1) : query()).trim();

  // Search the inventory as the user types (debounced); a stub server simply finds nothing.
  let timer: ReturnType<typeof setTimeout> | undefined;
  let controller: AbortController | undefined;
  createEffect(() => {
    const q = text();
    // The inventory search belongs to IPAM; without that module there is nothing to search.
    const skip = commandsOnly() || q.length < 2 || !moduleRunning("ipam");
    clearTimeout(timer);
    controller?.abort();
    if (skip) {
      setHits([]);
      setSearching(false);
      return;
    }
    setSearching(true);
    timer = setTimeout(async () => {
      controller = new AbortController();
      try {
        const page = await api.get("/api/v1/search", { query: { q, limit: 8 }, signal: controller.signal });
        setHits(page.items.slice(0, 8));
      } catch {
        setHits([]);
      } finally {
        setSearching(false);
      }
    }, 150);
  });
  onCleanup(() => {
    clearTimeout(timer);
    controller?.abort();
  });

  const go = (href: string) => {
    props.onClose();
    navigate(href);
  };
  const runCommand = (c: Command) => {
    props.onClose();
    c.run();
  };

  const items = createMemo<Item[]>(() => {
    const q = text();
    const out: Item[] = [];
    if (!commandsOnly() && moduleRunning("ipam")) {
      for (const hit of hits()) {
        const title = hitTitle(hit);
        out.push({
          id: `hit:${hit.object.kind}:${hit.object.id}`,
          group: t("shell.palette.group.search"),
          icon: hitIcon(hit),
          title,
          mono: IDENTIFIER.test(title),
          sub: hitSubtitle(hit),
          run: () => go(hitHref(hit)),
        });
      }
      if (q.length >= 2) {
        out.push({
          id: "search-all",
          group: t("shell.palette.group.search"),
          icon: "search",
          title: t("shell.palette.search_all", { query: q }),
          mono: false,
          run: () => go(paths.search(q)),
        });
      }
    }
    const commands = activeCommands().filter((c) => matchCommand(c, q));
    for (const group of GROUP_ORDER) {
      for (const c of commands.filter((x) => x.group === group)) {
        out.push({
          id: c.id,
          group: t(GROUP_LABEL[group]),
          icon: c.icon,
          title: c.label(),
          mono: false,
          sub: c.hint?.(),
          keys: c.keys,
          run: () => runCommand(c),
        });
      }
    }
    return out;
  });

  createEffect(() => {
    items();
    setSelected(0);
  });

  const move = (delta: number) => {
    const n = items().length;
    if (n === 0) return;
    setSelected((i) => Math.min(n - 1, Math.max(0, i + delta)));
    list.querySelector(`[data-index="${selected()}"]`)?.scrollIntoView({ block: "nearest" });
  };

  const onKeyDown = (e: KeyboardEvent) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      move(1);
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      move(-1);
    } else if (e.key === "Enter") {
      e.preventDefault();
      items()[selected()]?.run();
    }
  };

  const optionId = (i: number) => `palette-option-${i}`;

  return (
    <Dialog label={t("shell.palette.label")} onClose={props.onClose} class="palette" initialFocus={() => input}>
      <div class="pin">
        <Icon name="search" />
        <input
          ref={input}
          value={query()}
          onInput={(e) => setQuery(e.currentTarget.value)}
          onKeyDown={onKeyDown}
          placeholder={t("shell.palette.placeholder")}
          aria-label={t("shell.palette.search_label")}
          role="combobox"
          aria-expanded="true"
          aria-controls="palette-list"
          aria-activedescendant={items().length ? optionId(selected()) : undefined}
          autocomplete="off"
          spellcheck={false}
        />
        <Kbd keys={["Esc"]} />
      </div>
      <div class="groups" id="palette-list" role="listbox" ref={list} aria-label={t("shell.palette.label")}>
        <For each={items()}>
          {(item, i) => (
            <>
              <Show when={i() === 0 || items()[i() - 1]?.group !== item.group}>
                <div class="gh" role="presentation">
                  {item.group}
                </div>
              </Show>
              <div
                class="it"
                id={optionId(i())}
                data-index={i()}
                role="option"
                aria-selected={i() === selected()}
                onMouseMove={() => setSelected(i())}
                onClick={() => item.run()}
              >
                <Icon name={item.icon} />
                <span class={item.mono ? "mono" : undefined}>{item.title}</span>
                <Show when={item.sub}>
                  <span class="s">{item.sub}</span>
                </Show>
                <Show when={item.keys}>
                  <span class="r">
                    <Kbd keys={item.keys ?? []} />
                  </span>
                </Show>
              </div>
            </>
          )}
        </For>
        <Show when={items().length === 0 && !searching()}>
          <div class="empty palette-empty">
            <h3>{t("shell.palette.no_match", { query: text() })}</h3>
            <p>{t("shell.palette.no_match_hint")}</p>
          </div>
        </Show>
        <Show when={items().length === 0 && searching()}>
          <div class="empty palette-empty">
            <p>{t("shell.palette.searching")}</p>
          </div>
        </Show>
      </div>
      <div class="foot">
        <span>
          <Kbd keys={["↑", "↓"]} /> {t("shell.palette.foot.move")}
        </span>
        <span>
          <Kbd keys={["Enter"]} /> {t("shell.palette.foot.open")}
        </span>
        <span>
          <Kbd keys={[">"]} /> {t("shell.palette.foot.commands")}
        </span>
      </div>
    </Dialog>
  );
}
