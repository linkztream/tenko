// Toasts: the result of an action, with Undo or Open job where they apply. They
// auto-dismiss unless they report a failure (design/README.md, component inventory).
import { createSignal, For, Show } from "solid-js";
import { t } from "../i18n";
import { Icon } from "./Icon";

export type ToastKind = "info" | "ok" | "bad";

export interface ToastAction {
  label: string;
  primary?: boolean;
  run: () => void;
}

export interface ToastOptions {
  title: string;
  body?: string | undefined;
  kind?: ToastKind;
  actions?: ToastAction[];
  /** Keep it until dismissed. Failures always stay. */
  sticky?: boolean;
  /** Auto-dismiss delay in milliseconds (default 7 s). */
  ms?: number;
}

interface ToastEntry extends ToastOptions {
  id: number;
}

const [toasts, setToasts] = createSignal<ToastEntry[]>([]);
let nextId = 1;

export function dismissToast(id: number): void {
  setToasts((list) => list.filter((x) => x.id !== id));
}

/** Shows a toast and returns its id. */
export function toast(options: ToastOptions): number {
  const id = nextId++;
  setToasts((list) => [...list, { ...options, id }]);
  if (options.kind !== "bad" && !options.sticky) setTimeout(() => dismissToast(id), options.ms ?? 7000);
  return id;
}

const ICON = { info: "info", ok: "check", bad: "alert" } as const;

/** The toast stack; rendered once at the root. */
export function Toasts() {
  return (
    <div class="toasts" role="status" aria-live="polite">
      <For each={toasts()}>
        {(item) => (
          <div class={`toast ${item.kind ?? "info"}`} data-testid="toast" data-key={item.kind ?? "info"}>
            <span class={`toast-icon ${item.kind ?? "info"}`}>
              <Icon name={ICON[item.kind ?? "info"]} />
            </span>
            <div>
              <div class="t">{item.title}</div>
            </div>
            <button type="button" class="icon-btn toast-close" aria-label={t("common.action.dismiss")} onClick={() => dismissToast(item.id)}>
              <Icon name="x" size="xs" />
            </button>
            <Show when={item.body}>
              <div class="b">{item.body}</div>
            </Show>
            <Show when={item.actions?.length}>
              <div class="acts">
                <For each={item.actions}>
                  {(a, i) => (
                    <button
                      type="button"
                      class={a.primary ? "btn sm primary" : "btn sm"}
                      data-testid="toast-action"
                      data-index={i()}
                      onClick={() => {
                        a.run();
                        dismissToast(item.id);
                      }}
                    >
                      {a.label}
                    </button>
                  )}
                </For>
              </div>
            </Show>
          </div>
        )}
      </For>
    </div>
  );
}
