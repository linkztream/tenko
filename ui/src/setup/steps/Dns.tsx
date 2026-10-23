// Step 7: how names are resolved and the DNS upstreams (P2-Q5, REC-Q2, REC-Q5). WP10.4: the step
// first asks whether the node resolves names itself (recursion, the default) or forwards them to a
// resolver of the person's choice, with the privacy sentence of the recursion plan's section 2.8;
// the upstreams below are asked for the second choice only. No resolver is preset: the person enters the upstreams,
// starting with the resolvers the network uses now (the browser cannot read them, so the hint
// says where to look). When every address typed belongs to a well-known public resolver that
// offers DNS over TLS, DoT with its certificate name is offered. The Home preset sets the
// switches: the cache on with the profile's bound, DoT and DoH served off, the query log off.
// The upstreams become the root forwarding rule after setup, and the result step shows the
// `[dns]` section for `tenko.toml`. When DNS is not part of the installation, the step says so.
import { createMemo, For, Show } from "solid-js";
import type { DnsResolve } from "../controller";
import { t } from "../../i18n";
import { knownResolver, needsTlsName, splitUpstreams, TRANSPORTS } from "../../dns/forwarders/model";
import { dnsChecklist } from "../checklist";
import { dnsPreset, profileCacheEntries, useWizard } from "../controller";
import { FOCUS } from "../gates";
import { ProblemNotice } from "../parts";

export function Dns() {
  const w = useWizard();
  const dns = () => w.state.dns;
  const known = createMemo(() => (dns().transport === "plain" ? knownResolver(splitUpstreams(dns().upstreams)) : undefined));
  const presetOn = () => {
    const home = dnsPreset("home");
    const d = dns();
    return d.cache === home.cache && d.cacheEntries === home.cacheEntries && d.dot === home.dot && d.doh === home.doh && d.log === home.log;
  };

  return (
    <div data-testid="setup-dns" data-state={w.dnsWanted() ? "wanted" : "skipped"}>
      <Show
        when={w.dnsWanted()}
        fallback={
          <>
            <p class="wz-lede">{t("setup.dns.skipped")}</p>
            <ProblemNotice step={6} />
          </>
        }
      >
        <p class="wz-lede">{t("setup.dns.lede")}</p>
        <ProblemNotice step={6} />

        {/* WP10.4: resolve names yourself, or forward them to a resolver of your choice. */}
        <div class="wz-blk">
          <h2 id="wz-dns-resolve">{t("setup.dns.resolve")}</h2>
          <div role="radiogroup" aria-labelledby="wz-dns-resolve" aria-describedby="wz-dns-privacy">
            <For each={["recurse", "forward"] as const satisfies readonly DnsResolve[]}>
              {(mode) => (
                <label class="wz-choice">
                  <input
                    type="radio"
                    name="wz-dns-resolve"
                    class="rb"
                    checked={dns().resolve === mode}
                    data-testid="setup-dns-resolve"
                    data-key={mode}
                    onChange={() => w.setDns("resolve", mode)}
                  />
                  <span>
                    <span class="t">{t(`setup.dns.resolve.${mode}`)}</span>
                    <span class="d">{t(`setup.dns.resolve.${mode}_description`)}</span>
                  </span>
                </label>
              )}
            </For>
          </div>
          <p class="wz-help" id="wz-dns-privacy" data-testid="setup-dns-privacy">
            {t("setup.dns.privacy")}
          </p>
        </div>

        <Show when={dns().resolve === "forward"}>
          <div class="wz-blk">
            <h2>
              <label for={FOCUS.dnsUpstreams}>{t("setup.dns.upstreams")}</label>
            </h2>
            <textarea
              id={FOCUS.dnsUpstreams}
              class="input mono wz-dns-upstreams"
              rows={3}
              spellcheck={false}
              value={dns().upstreams}
              aria-describedby="wz-dns-upstreams-help"
              data-testid="field-dns-upstreams"
              onInput={(e) => w.setDns("upstreams", e.currentTarget.value)}
            />
            <p class="wz-help" id="wz-dns-upstreams-help">
              {t("setup.dns.upstreams_help")}
            </p>
            <p class="wz-help">{t("setup.dns.upstreams_none")}</p>
          </div>

          <div class="wz-blk">
            <h2 id="wz-dns-transport">{t("setup.dns.transport")}</h2>
            <div role="radiogroup" aria-labelledby="wz-dns-transport">
              <For each={TRANSPORTS}>
                {(tr) => (
                  <label class="wz-choice">
                    <input
                      type="radio"
                      name="wz-dns-transport"
                      class="rb"
                      checked={dns().transport === tr}
                      data-testid="setup-dns-transport"
                      data-key={tr}
                      onChange={() => w.setDns("transport", tr)}
                    />
                    <span>
                      <span class="t">{t(`setup.dns.transport.${tr}`)}</span>
                      <span class="d">{t(`setup.dns.transport.${tr}_description`)}</span>
                    </span>
                  </label>
                )}
              </For>
            </div>
            <Show when={known()}>
              {(resolver) => (
                <div class="note info wz-dns-known" data-testid="setup-dns-known" data-key={resolver().tlsName}>
                  <span class="grow">{t("setup.dns.known", { name: resolver().name, tls: resolver().tlsName })}</span>
                  <button
                    type="button"
                    class="btn sm"
                    data-testid="setup-dns-use-dot"
                    onClick={() => {
                      // Read the resolver first: switching to DoT ends the offer and its accessor.
                      const name = resolver().tlsName;
                      w.setDns("tlsName", name);
                      w.setDns("transport", "dot");
                    }}
                  >
                    {t("setup.dns.use_dot")}
                  </button>
                </div>
              )}
            </Show>
            <Show when={needsTlsName(dns().transport)}>
              <div class="field wz-dns-tls">
                <label for={FOCUS.dnsTlsName}>{t("setup.dns.tls_name")}</label>
                <input
                  id={FOCUS.dnsTlsName}
                  class="input mono"
                  spellcheck={false}
                  autocomplete="off"
                  value={dns().tlsName}
                  aria-describedby="wz-dns-tls-help"
                  data-testid="field-dns-tls-name"
                  onInput={(e) => w.setDns("tlsName", e.currentTarget.value)}
                />
                <span class="wz-help" id="wz-dns-tls-help">
                  {t("setup.dns.tls_name_help")}
                </span>
              </div>
            </Show>
          </div>
        </Show>
        {/* WP10.4: end. */}

        <div class="wz-blk">
          <h2>
            <span>{t("setup.dns.preset")}</span>
            <span class="aside">{presetOn() ? t("setup.dns.preset_on") : ""}</span>
          </h2>
          <p class="wz-help">{t("setup.dns.preset_help")}</p>
          <div class="form-row">
            <button type="button" class="btn sm" data-testid="setup-dns-preset" disabled={presetOn()} onClick={() => w.applyDnsPreset()}>
              {t("setup.dns.preset_apply")}
            </button>
          </div>
          <label class="wz-choice multi">
            <input type="checkbox" class="cb" checked={dns().cache} data-testid="setup-dns-switch" data-key="cache" onChange={(e) => w.setDns("cache", e.currentTarget.checked)} />
            <span>
              <span class="t">{t("setup.dns.cache")}</span>
              <span class="d">{t("setup.dns.cache_description", { entries: profileCacheEntries(w.state.profile) })}</span>
            </span>
          </label>
          <Show when={dns().cache}>
            <div class="field wz-dns-entries">
              <label for={FOCUS.dnsEntries}>{t("setup.dns.entries")}</label>
              <input
                id={FOCUS.dnsEntries}
                class="input num"
                inputmode="numeric"
                value={dns().cacheEntries}
                data-testid="field-dns-entries"
                onInput={(e) => w.setDns("cacheEntries", e.currentTarget.value)}
              />
            </div>
          </Show>
          <For each={["dot", "doh", "log"] as const}>
            {(key) => (
              <label class="wz-choice multi">
                <input type="checkbox" class="cb" checked={dns()[key]} data-testid="setup-dns-switch" data-key={key} onChange={(e) => w.setDns(key, e.currentTarget.checked)} />
                <span>
                  <span class="t">{t(`setup.dns.${key}`)}</span>
                  <span class="d">{t(`setup.dns.${key}_description`)}</span>
                </span>
              </label>
            )}
          </For>
        </div>

        <div class="wz-blk tight">
          <h2>{t("setup.dns.checklist")}</h2>
          <ul class="wz-dns-checklist" data-testid="setup-dns-checklist">
            <For each={dnsChecklist(dns())}>
              {(id) => (
                <li data-testid="setup-dns-check" data-key={id}>
                  {t(`setup.dns.check.${id}`)}
                </li>
              )}
            </For>
          </ul>
        </div>
      </Show>
    </div>
  );
}
