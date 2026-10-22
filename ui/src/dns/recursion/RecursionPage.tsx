// The recursion section of the DNS area (/dns/recursion), WP10.0: a placeholder until the
// recursive resolver is built. It says so, and reads the trust anchors (GET /dns/trust-anchors):
// the server answers 501 `sys.not_implemented` until WP10.2, which is shown as an empty state
// and never as an error. Any other failure of the read is shown as the error it is.
import { createResource, Match, Show, Switch } from "solid-js";
import { api } from "../../api/client";
import { ApiError } from "../../api/problem";
import { ErrorNotice } from "../../components/Notice";
import { PageHead } from "../../components/PageHead";
import { t } from "../../i18n";
import { DnsNav } from "../DnsNav";
import { DnsProblem, moduleOff } from "../Parts";
import "../dns.css";

/** The server has not built the operation yet (`sys.not_implemented`). */
export function notAvailableYet(err: unknown): boolean {
  return err instanceof ApiError && err.status === 501;
}

/** The zones that have a trust anchor, or `null` while the server cannot list them yet. */
async function readTrustAnchors(): Promise<string[] | null> {
  try {
    const page = await api.get("/api/v1/dns/trust-anchors");
    return page.items.map((anchor) => anchor.zone);
  } catch (err) {
    if (notAvailableYet(err)) return null;
    throw err;
  }
}

export default function RecursionPage() {
  const [anchors] = createResource(readTrustAnchors);
  return (
    <div class="page" data-testid="page-dns-recursion">
      <DnsNav />
      <PageHead title={t("dns.recursion.title")} />
      <div class="empty" data-testid="dns-recursion-coming">
        <h2>{t("dns.recursion.coming.title")}</h2>
        <p>{t("dns.recursion.coming.body")}</p>
      </div>
      <section class="page-section" aria-labelledby="dns-recursion-anchors-title" data-testid="dns-recursion-anchors">
        <h2 id="dns-recursion-anchors-title">{t("dns.recursion.trust_anchors.title")}</h2>
        <Switch>
          <Match when={anchors.error}>
            <Show when={moduleOff(anchors.error)} fallback={<ErrorNotice error={anchors.error} />}>
              <DnsProblem error={anchors.error} />
            </Show>
          </Match>
          <Match when={anchors() === null}>
            <p class="muted" data-testid="dns-recursion-anchors-unavailable" data-state="unavailable">
              {t("dns.recursion.trust_anchors.unavailable")}
            </p>
          </Match>
          <Match when={anchors()}>
            {(zones) => (
              <p class="muted" data-testid="dns-recursion-anchors-count" data-state={zones().length === 0 ? "none" : "listed"}>
                {zones().length === 0 ? t("dns.recursion.trust_anchors.none") : t("dns.recursion.trust_anchors.count", { count: zones().length })}
              </p>
            )}
          </Match>
        </Switch>
      </section>
    </div>
  );
}
