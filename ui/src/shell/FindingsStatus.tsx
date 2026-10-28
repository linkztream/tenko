// The open findings in the status bar (ui-plan section 3): one count per severity, each a link to
// the Discovery list filtered by it. Act now and Review are counted; Info is listed in plain ink
// and never counted as a problem. A severity without findings shows nothing. Loaded after the
// shell is up, like the status items before it, so the first page load stays small; the counts
// arrive after the first page anyway.
import { Show } from "solid-js";
import { paths } from "../app/paths";
import { FindingChip } from "../components/Finding";
import { t } from "../i18n";
import type { FindingCounts } from "./findings";

export default function FindingsStatus(props: { counts: FindingCounts | null }) {
  const total = () => props.counts?.total;
  return (
    <Show when={total()}>
      {(levels) => (
        <span class="status-findings" data-testid="status-findings">
          <Show when={levels().act > 0}>
            <FindingChip
              level="act"
              text={t("shell.status.findings.act", { count: levels().act })}
              title={t("shell.status.findings.act_title")}
              href={paths.discovery({ severity: "act" })}
              testid="status-findings-act"
            />
          </Show>
          <Show when={levels().review > 0}>
            <FindingChip
              level="review"
              text={t("shell.status.findings.review", { count: levels().review })}
              title={t("shell.status.findings.review_title")}
              href={paths.discovery({ severity: "review" })}
              testid="status-findings-review"
            />
          </Show>
          {/* Info is listed without a link for now: `severity=info` of the Discovery list is the
              proposal severity, and no open proposal is information (U4 makes the list carry
              every finding). */}
          <Show when={levels().info > 0}>
            <span class="finding-chip info" title={t("shell.status.findings.info_title")} data-testid="status-findings-info">
              {t("shell.status.findings.info", { count: levels().info })}
            </span>
          </Show>
        </span>
      )}
    </Show>
  );
}
