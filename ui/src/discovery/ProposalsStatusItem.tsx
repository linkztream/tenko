// The number of open proposals in the status bar, as a link to the proposal inbox: loaded
// lazily after the shell, like the utilization alarms. Nothing shows while there are none,
// before the first answer, or when the read fails (an account that may not read proposals).
import { A } from "@solidjs/router";
import { Show } from "solid-js";
import { createLiveQuery } from "../api/live";
import { paths } from "../app/paths";
import { Icon } from "../components/Icon";
import { t } from "../i18n";
import { listProposals } from "./api";
import { isProposalEvent } from "./model";

export default function ProposalsStatusItem() {
  const live = createLiveQuery<number>({
    topics: ["ipam"],
    relevant: isProposalEvent,
    fetch: async (signal) => ({ value: (await listProposals({ state: ["open"] }, signal)).length }),
  });
  const count = () => live.latest() ?? 0;
  return (
    <Show when={count() > 0}>
      <A class="status-jobs" href={paths.discovery()} data-testid="status-proposals">
        <Icon name="proposal" size="sm" />
        {t("shell.status.proposals", { count: count() })}
      </A>
    </Show>
  );
}
