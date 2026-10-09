import { A, useSearchParams } from "@solidjs/router";
import { createResource, For, Show } from "solid-js";
import { api } from "../../api/client";
import { ErrorNotice } from "../../components/Notice";
import { PageHead } from "../../components/PageHead";
import { t } from "../../i18n";
import { hitHref, hitSubtitle, hitTitle } from "../searchHits";

/** Results of the global search (`/search?q=`), reached from the command palette. */
export default function Search() {
  const [params] = useSearchParams();
  const q = () => (typeof params.q === "string" ? params.q.trim() : "");
  const [result] = createResource(q, (query) =>
    query.length >= 2 ? api.get("/api/v1/search", { query: { q: query, limit: 200 } }) : Promise.resolve(null),
  );
  return (
    <div class="page">
      <PageHead title={t("shell.search.title")} sub={q() ? `“${q()}”` : undefined} />
      <div class="page-body">
        <Show when={q().length >= 2} fallback={<p class="muted">{t("shell.search.empty")}</p>}>
          <Show when={!result.error} fallback={<ErrorNotice error={result.error} />}>
            <Show when={result()}>
              {(page) => (
                <>
                  <p class="muted">{t("shell.search.results", { count: page().items.length, query: q() })}</p>
                  <ul class="list">
                    <For each={page().items}>
                      {(hit) => (
                        <li>
                          <A href={hitHref(hit)} class="mono">
                            {hitTitle(hit)}
                          </A>
                          <span class="muted"> {hitSubtitle(hit)}</span>
                        </li>
                      )}
                    </For>
                  </ul>
                </>
              )}
            </Show>
          </Show>
        </Show>
      </div>
    </div>
  );
}
