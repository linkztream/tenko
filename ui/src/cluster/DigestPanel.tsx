// The digest check of the cluster page (docs/cluster.md, section 12.7): asks every member for a
// SHA-256 over its tables at one revision and shows whether they agree. Nothing runs until the
// person asks, and a new answer replaces the old one.
import { createSignal, For, Show } from "solid-js";
import { ApiError, errorMessage, hasErrorMessage } from "../api/problem";
import { ErrorNotice, Notice } from "../components/Notice";
import { Icon } from "../components/Icon";
import { formatNumber, t } from "../i18n";
import { digests } from "./api";
import { digestState, memberName, shortDigest, type DigestReport, type DigestState, type MemberDigest, type MemberView } from "./model";

const STATE_ICON = { agrees: "check", differs: "alert", missing: "pause" } as const;

/** Why a member gave no digest: the words of its error code when the UI has them. */
function missingText(member: MemberDigest): string {
  const code = member.error;
  if (!code) return "–";
  return hasErrorMessage(code) ? errorMessage(new ApiError({ status: 500, code, title: "", detail: "" })) : code;
}

export function DigestPanel(props: { members: () => readonly MemberView[] }) {
  const [report, setReport] = createSignal<DigestReport | null>(null);
  const [error, setError] = createSignal<unknown>(null);
  const [busy, setBusy] = createSignal(false);

  const nameOf = (node: number) => {
    const found = props.members().find((m) => m.node === node);
    return found ? memberName(found) : t("cluster.member.unnamed", { id: node });
  };

  const check = async () => {
    if (busy()) return;
    setBusy(true);
    setError(null);
    try {
      setReport(await digests());
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  const stateWord = (state: DigestState) => t(`cluster.digests.state.${state}`);

  return (
    <section class="page-section" aria-labelledby="cluster-digests-title" data-testid="cluster-digests">
      <h2 id="cluster-digests-title">
        {t("cluster.digests.title")}
        <span class="aside">
          <button type="button" class="btn sm" disabled={busy()} data-testid="cluster-check-digests" onClick={() => void check()}>
            <Icon name="refresh" size="sm" />
            {t("cluster.action.check_digests")}
          </button>
        </span>
      </h2>
      <p>{t("cluster.digests.intro")}</p>
      <ErrorNotice error={error()} />
      <Show when={report()}>
        {(r) => (
          <>
            <Notice kind={r().agree ? "ok" : "warn"} role="status" testid="digests-result">
              <span data-state={r().agree ? "agree" : "differ"} data-testid="digests-overall">
                {r().agree
                  ? t("cluster.digests.agree", { count: r().members.length, revision: formatNumber(r().revision) })
                  : t("cluster.digests.differ", { revision: formatNumber(r().revision) })}
              </span>
            </Notice>
            <div class="table-wrap">
              <table class="plain" aria-label={t("cluster.digests.title")}>
                <thead>
                  <tr>
                    <th scope="col">{t("cluster.digests.col.member")}</th>
                    <th scope="col" class="r">
                      {t("cluster.digests.col.revision")}
                    </th>
                    <th scope="col">{t("cluster.digests.col.digest")}</th>
                    <th scope="col" class="r">
                      {t("cluster.digests.col.tables")}
                    </th>
                    <th scope="col" class="r">
                      {t("cluster.digests.col.entries")}
                    </th>
                    <th scope="col">{t("cluster.digests.col.state")}</th>
                  </tr>
                </thead>
                <tbody>
                  <For each={r().members}>
                    {(m) => {
                      const state = () => digestState(r(), m);
                      return (
                        <tr data-testid={`digest-row-${m.node}`} data-state={state()} data-id={m.node}>
                          <td>{nameOf(m.node)}</td>
                          <td class="r num">{m.revision != null ? formatNumber(m.revision) : "–"}</td>
                          <td class="mono" title={m.sha256 ?? undefined} data-testid="digest-value">
                            {shortDigest(m.sha256)}
                          </td>
                          <td class="r num">{m.tables != null ? formatNumber(m.tables) : "–"}</td>
                          <td class="r num">{m.entries != null ? formatNumber(m.entries) : "–"}</td>
                          <td>
                            <span class={`tag cluster-digest ${state()}`} data-state={state()} data-testid="digest-state">
                              <Icon name={STATE_ICON[state()]} size="xs" />
                              {stateWord(state())}
                            </span>
                            <Show when={state() === "missing" && m.error}>
                              {" "}
                              <span class="muted">{missingText(m)}</span>
                            </Show>
                          </td>
                        </tr>
                      );
                    }}
                  </For>
                </tbody>
              </table>
            </div>
          </>
        )}
      </Show>
    </section>
  );
}
