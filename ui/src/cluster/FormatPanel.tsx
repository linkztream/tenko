// The data format of the cluster (docs/upgrades.md, sections 3 and 7.7): the format of the
// replicated data and of this binary, and while a migration waits, the format it targets and the
// voters whose binary does not know it yet, with the status warning as a banner.
import { For, Show } from "solid-js";
import type { SystemStatus } from "../api/types";
import { Notice } from "../components/Notice";
import { t } from "../i18n";
import { memberName, migrationWarning, type MemberView } from "./model";

export function FormatPanel(props: { status: SystemStatus; members: readonly MemberView[] }) {
  const format = () => props.status.data_format;
  const warning = () => migrationWarning(props.status.warnings);
  const nameOf = (node: number) => {
    const found = props.members.find((m) => m.node === node);
    return found ? memberName(found) : t("cluster.member.unnamed", { id: node });
  };
  return (
    <Show when={format()}>
      {(f) => (
        <section class="page-section" aria-labelledby="cluster-format-title" data-testid="cluster-format" data-state={f().pending ? "pending" : "current"}>
          <h2 id="cluster-format-title">{t("cluster.format.title")}</h2>
          <Show when={warning()}>
            {(w) => (
              <Notice kind="warn" role="status" testid="cluster-warning" code={w().code}>
                {t("cluster.warning.migration_blocked", {
                  stored: w().params?.["stored"] ?? "",
                  target: w().params?.["target"] ?? "",
                  nodes: w().params?.["nodes"] ?? "",
                })}
              </Notice>
            )}
          </Show>
          <dl class="cluster-facts">
            <div>
              <dt>{t("cluster.format.stored")}</dt>
              <dd class="num" data-testid="format-stored">{f().stored}</dd>
            </div>
            <div>
              <dt>{t("cluster.format.binary")}</dt>
              <dd class="num" data-testid="format-binary">{f().binary}</dd>
            </div>
            <Show when={f().pending}>
              {(p) => (
                <div>
                  <dt>{t("cluster.format.target")}</dt>
                  <dd class="num" data-testid="format-target">{p().target}</dd>
                </div>
              )}
            </Show>
          </dl>
          <Show when={!f().pending}>
            <p class="muted" data-testid="format-current">{t("cluster.format.current")}</p>
          </Show>
          <Show when={f().pending}>
            {(p) => (
              <>
                <p>{p().blocked_by.length > 0 ? t("cluster.format.blocked") : t("cluster.format.waiting")}</p>
                <Show when={p().blocked_by.length > 0}>
                  <ul class="cluster-list" data-testid="format-blockers">
                    <For each={p().blocked_by}>
                      {(b) => (
                        <li data-testid="format-blocker" data-node={b.node}>
                          <span class="mono">{nameOf(b.node)}</span>
                          {": "}
                          {b.data_format == null ? t("cluster.format.not_reported") : t("cluster.format.knows", { format: b.data_format })}
                        </li>
                      )}
                    </For>
                  </ul>
                  <p class="muted" data-testid="format-advice">
                    {t("cluster.format.advice")}
                  </p>
                </Show>
              </>
            )}
          </Show>
        </section>
      )}
    </Show>
  );
}
