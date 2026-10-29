// Columns of the reconciliation view (U4): the address, the four truths on one line each with the
// check glyph on the truth that wins, the outcome in words (said once in the header when every row
// shares it), the last sighting and the default action of the row's finding. The OS field, the
// vendors and the rule are hidden by default and one click away in the column menu; the side panel
// shows them all.
import { A } from "@solidjs/router";
import { Show } from "solid-js";
import { paths } from "../../app/paths";
import { Addr } from "../../components/Addr";
import { FindingAction } from "../../discovery/FindingAction";
import type { Finding } from "../../discovery/findings";
import { TimeAgo } from "../../grid/cells";
import type { Column } from "../../grid/types";
import { formatList, t } from "../../i18n";
import { RULE_TEXT, TRUTH_WORD, TRUTHS, type ReconcileRow } from "./model";
import { OsGuess } from "./OsGuess";
import { outcomeWord, TruthLine, truthText } from "./truths";

export function reconcileColumns(options: {
  /** The finding of a row, for its default action. */
  finding: (row: ReconcileRow) => Finding | undefined;
  onPanel: (finding: Finding) => void;
  onDone: () => void;
}): Column<ReconcileRow>[] {
  return [
    {
      id: "address",
      header: () => t("ipam.reconcile.col.address"),
      width: 140,
      fixed: true,
      text: (r) => r.address,
      render: (r) => (
        <A href={paths.address(r.address, r.vrf ?? undefined)} class="mono" data-testid="reconcile-address">
          <Addr value={r.address} />
        </A>
      ),
    },
    ...TRUTHS.map(
      (truth): Column<ReconcileRow> => ({
        id: truth,
        header: () => t(TRUTH_WORD[truth]),
        width: truth === "intent" || truth === "dns" ? 200 : 150,
        text: (r) => truthText(r, truth),
        render: (r) => <TruthLine row={r} truth={truth} />,
      }),
    ),
    {
      id: "outcome",
      header: () => t("ipam.reconcile.col.outcome"),
      width: 140,
      text: (r) => outcomeWord(r),
      majority: (r) => outcomeWord(r),
      render: (r) => (
        <span class="reconcile-outcome" classList={{ conflict: !r.winner && r.kind === "conflict" }} data-testid="reconcile-winner" data-winner={r.winner ?? "none"}>
          {outcomeWord(r)}
        </span>
      ),
    },
    {
      id: "rule",
      header: () => t("ipam.reconcile.col.rule"),
      width: 260,
      hidden: true,
      text: (r) => t(RULE_TEXT[r.rule_id]),
      majority: (r) => t(RULE_TEXT[r.rule_id]),
      render: (r) => (
        <span class="muted" title={t(RULE_TEXT[r.rule_id])} data-testid="reconcile-rule">
          {t(RULE_TEXT[r.rule_id])}
        </span>
      ),
    },
    {
      id: "os",
      header: () => t("ipam.reconcile.col.os"),
      width: 220,
      hidden: true,
      render: (r) => (
        <Show when={r.os} fallback={<span class="muted">–</span>}>
          {(os) => <OsGuess os={os()} />}
        </Show>
      ),
    },
    {
      id: "vendors",
      header: () => t("ipam.reconcile.col.vendors"),
      width: 160,
      hidden: true,
      render: (r) => <span data-testid="reconcile-vendors">{formatList(r.vendors ?? [])}</span>,
    },
    {
      id: "last_seen",
      header: () => t("ipam.reconcile.col.last_seen"),
      width: 110,
      render: (r) => (
        <Show when={r.last_seen} fallback={<span class="muted">–</span>}>
          <TimeAgo at={r.last_seen} />
        </Show>
      ),
    },
    {
      id: "action",
      header: () => t("ipam.reconcile.col.action"),
      width: 150,
      render: (r) => <Show when={options.finding(r)}>{(f) => <FindingAction finding={f()} onPanel={options.onPanel} onDone={options.onDone} />}</Show>,
    },
  ];
}
