// Steps 4 and 5: the apply job runs (progress from the `jobs` topic), then the result with
// links to what was created. A failed import was rolled back; the person can go back to the
// preview and try again.
import { A } from "@solidjs/router";
import { createMemo, For, Show } from "solid-js";
import type { JobDetail } from "../../api/types";
import { paths } from "../../app/paths";
import { Icon } from "../../components/Icon";
import { Notice } from "../../components/Notice";
import { t, tDynamic } from "../../i18n";
import { kindWord } from "../../ipam/words";
import type { ItemKey } from "../api";
import type { WizardState } from "../model";
import { itemLabel } from "./PreviewStep";

/** Where a created item can be seen. */
function itemHref(key: ItemKey): string | undefined {
  switch (key.kind) {
    case "prefix":
      return paths.prefix(key.cidr);
    case "address":
      return paths.address(key.ip);
    case "host":
      return paths.host(key.name);
    case "interface":
    case "credential":
      return paths.host(key.host);
    default:
      return undefined;
  }
}

const LINKS_SHOWN = 50;

export function ResultStep(props: { state: WizardState; job: JobDetail | null; onAgain: () => void; onBack: () => void }) {
  const job = () => props.job?.job;
  const done = () => job()?.steps.filter((s) => s.state.state === "done" || s.state.state === "skipped").length ?? 0;
  const total = () => job()?.steps.length ?? 0;
  const pct = () => (total() ? Math.round((done() / total()) * 100) : 0);

  const created = createMemo(() => {
    const seen = new Map<string, ItemKey>();
    for (const row of props.state.preview?.rows ?? []) {
      for (const item of row.items) {
        if (item.action === "create" && item.key.kind !== "credential") seen.set(`${item.key.kind}:${itemLabel(item.key)}`, item.key);
      }
    }
    return [...seen.values()];
  });

  return (
    <section class="import-card import-result" data-testid="import-result" aria-live="polite">
      <Show when={props.state.step === "apply"}>
        <h2>{t("import.result.running")}</h2>
        <div class="meter progress" aria-hidden="true">
          <span class="bar">
            <i style={{ "--v": `${pct()}%` }} />
          </span>
        </div>
        <p class="muted" role="status">
          {t("import.result.progress", { done: done(), total: total() })}
        </p>
      </Show>
      <Show when={props.state.step === "done" && props.state.succeeded}>
        <h2>
          <Icon name="check" /> {t("import.result.done")}
        </h2>
        <ul class="plain-list">
          <For each={props.state.preview?.summary.counts.filter((c) => c.action === "create" || c.action === "update") ?? []}>
            {(c) => <li>{t("import.result.count", { kind: kindWord(c.kind, c.count), action: t(`import.action.${c.action}`), count: c.count })}</li>}
          </For>
        </ul>
        <Show when={created().length > 0}>
          <h3>{t("import.result.created")}</h3>
          <ul class="import-links" data-testid="import-created">
            <For each={created().slice(0, LINKS_SHOWN)}>
              {(key) => (
                <li>
                  <Show when={itemHref(key)} fallback={<span class="mono">{itemLabel(key)}</span>}>
                    {(href) => (
                      <A href={href()} class="mono">
                        {itemLabel(key)}
                      </A>
                    )}
                  </Show>
                </li>
              )}
            </For>
          </ul>
          <Show when={created().length > LINKS_SHOWN}>
            <p class="muted">{t("import.result.more", { count: created().length - LINKS_SHOWN })}</p>
          </Show>
        </Show>
      </Show>
      <Show when={props.state.step === "done" && props.state.succeeded === false}>
        <Notice kind="bad" role="alert" title={t("import.result.failed")}>
          {job()?.error ? (tDynamic(`errors.${job()!.error!.code}`, job()!.error!.params ?? {}) ?? job()!.error!.detail) : t("import.result.rolled_back")}
        </Notice>
      </Show>
      <div class="import-actions">
        <Show when={props.state.jobId}>
          {(id) => (
            <A class="btn" href={paths.job(id())} data-testid="import-open-job">
              {t("ipam.plan.open_job")}
            </A>
          )}
        </Show>
        <Show when={props.state.step === "done" && props.state.succeeded === false}>
          <button type="button" class="btn" onClick={() => props.onBack()}>
            {t("import.result.back")}
          </button>
        </Show>
        <Show when={props.state.step === "done"}>
          <button type="button" class="btn primary" onClick={() => props.onAgain()} data-testid="import-again">
            {t("import.result.again")}
          </button>
        </Show>
      </div>
    </section>
  );
}
