// The certificates page (/settings/certificates, administrators; OPS-22, TGL-08): what the
// listener of this node serves and where it comes from. Which mode runs (the internal CA, imported
// files, a reverse proxy or plain HTTP), the served certificate with its names, validity, days left,
// chain length and fingerprint, then what belongs to the mode: the CA root with its download, the
// files and the switch for a certificate replaced from outside, or the proxies. A newer
// certificate on disk that this profile does not load while the node runs is shown as pending
// until the next restart. The page reads when it opens and when Refresh is pressed, never on
// its own; the settings live in tenko.toml, so there is nothing to save here.
import { createResource, For, Show } from "solid-js";
import { api } from "../../api/client";
import { latest } from "../../api/live";
import { CaRootLink } from "../../components/CaRootLink";
import { Icon } from "../../components/Icon";
import { ErrorNotice, Notice } from "../../components/Notice";
import { PageHead } from "../../components/PageHead";
import { formatDateTime, formatList, t } from "../../i18n";
import { SettingsNav } from "../SettingsNav";
import {
  EXPIRY_WARNING,
  groupedFingerprint,
  MODE_HELP,
  MODE_NAME,
  noticeKind,
  PENDING_WARNING,
  profileRule,
  stateClass,
  warningOf,
  type Loaded,
  type TlsCertificate,
  type TlsDetails,
} from "./model";
import "../settings.css";
import "./certificates.css";

async function load(): Promise<Loaded> {
  // The profile only words the sentence on what is allowed: a failed read leaves it out.
  const [tls, status, security] = await Promise.all([
    api.get("/api/v1/system/tls"),
    api.get("/api/v1/system/status"),
    api.get("/api/v1/settings/security").catch(() => null),
  ]);
  return { tls, warnings: status.warnings, profile: security?.settings.profile ?? null, readAt: Date.now() };
}

export default function CertificatesPage() {
  const [loaded, { refetch }] = createResource(load);

  return (
    <div class="page" data-testid="page-certificates">
      <PageHead title={t("certificates.title")} />
      <SettingsNav />
      <div class="page-body">
        <p class="muted">{t("certificates.lede")}</p>
        <div class="cert-bar">
          <button type="button" class="btn" data-testid="certificates-refresh" disabled={loaded.loading} onClick={() => void refetch()}>
            <Icon name="refresh" size="sm" />
            {t("certificates.refresh")}
          </button>
          <Show when={latest(loaded)}>
            {(current) => (
              <span class="muted" data-testid="certificates-read-at">
                {t("certificates.read_at", { time: formatDateTime(current().readAt) })}
              </span>
            )}
          </Show>
        </div>
        <ErrorNotice error={loaded.error} />
        <Show when={latest(loaded)} fallback={<Show when={!loaded.error}><p class="muted" role="status">{t("common.loading")}</p></Show>} keyed>
          {(current) => <Certificates loaded={current} />}
        </Show>
      </div>
    </div>
  );
}

function Certificates(props: { loaded: Loaded }) {
  const tls = () => props.loaded.tls;
  const expiry = () => warningOf(props.loaded, EXPIRY_WARNING);
  const pendingWarning = () => warningOf(props.loaded, PENDING_WARNING);
  return (
    <>
      <div class="cert-notices">
        <Show when={tls().certificate}>
          {(cert) => (
            <Show when={expiry()}>
              <Notice kind={noticeKind(cert().state)} role="status" testid="certificates-expiring" code={EXPIRY_WARNING}>
                {expiryText(cert())}
              </Notice>
            </Show>
          )}
        </Show>
        <Show when={tls().pending || pendingWarning()}>
          <Notice kind="warn" role="status" testid="certificates-pending-notice" code={PENDING_WARNING}>
            {t("certificates.pending.notice")}
          </Notice>
        </Show>
        <Show when={tls().last_error}>
          {(error) => (
            <Notice kind="bad" role="alert" testid="certificates-error">
              {t("certificates.error", { error: error() })}
            </Notice>
          )}
        </Show>
        <Show when={(tls().mode === "internal_ca" || tls().mode === "imported") && !tls().certificate}>
          <Notice kind="bad" role="alert" testid="certificates-none">
            {t("certificates.none")}
          </Notice>
        </Show>
      </div>

      <section class="page-section" aria-labelledby="cert-mode" data-testid="certificates-mode" data-mode={tls().mode}>
        <h2 id="cert-mode">{t("certificates.mode.heading")}</h2>
        <div class="card facts">
          <dl class="kv wide">
            <dt>{t("certificates.mode.label")}</dt>
            <dd data-testid="certificates-mode-name">
              <strong>{t(MODE_NAME[tls().mode])}</strong>
              <span class="muted"> {t(MODE_HELP[tls().mode])}</span>
            </dd>
            <Show when={tls().min_version}>
              {(version) => (
                <>
                  <dt>{t("certificates.min_version")}</dt>
                  <dd data-testid="certificates-min-version">{t("certificates.min_version.value", { version: version() })}</dd>
                </>
              )}
            </Show>
            <dt>{t("certificates.hsts")}</dt>
            <dd data-testid="certificates-hsts">{tls().hsts ? t("certificates.on") : t("certificates.off")}</dd>
          </dl>
        </div>
        <Show when={tls().mode === "plain"}>
          <Notice kind="warn" testid="certificates-plain">
            {t("certificates.plain.notice")}
          </Notice>
        </Show>
      </section>

      <Show when={tls().certificate}>
        {(cert) => (
          <section class="page-section" aria-labelledby="cert-served" data-testid="certificates-served">
            <h2 id="cert-served">{t("certificates.served.heading")}</h2>
            <CertificateFacts cert={cert()} prefix="cert" loadedAt={tls().loaded_at} />
          </section>
        )}
      </Show>

      <Show when={tls().pending}>
        {(pending) => (
          <section class="page-section" aria-labelledby="cert-pending" data-testid="certificates-pending">
            <h2 id="cert-pending">{t("certificates.pending.heading")}</h2>
            <p class="muted">{t("certificates.pending.detected", { time: formatDateTime(pending().detected_at) })}</p>
            <CertificateFacts cert={pending().certificate} prefix="pending" loadedAt={null} />
          </section>
        )}
      </Show>

      <Show when={tls().imported}>{(imported) => <ImportedSection imported={imported()} profile={props.loaded.profile} />}</Show>
      <Show when={tls().internal_ca}>{(ca) => <InternalCaSection ca={ca()} />}</Show>
      <Show when={tls().reverse_proxy}>{(proxy) => <ProxySection proxy={proxy()} />}</Show>
    </>
  );
}

function expiryText(cert: TlsCertificate): string {
  switch (cert.state) {
    case "expired":
      return t("certificates.expiry.expired", { date: formatDateTime(cert.not_after) });
    case "not_yet_valid":
      return t("certificates.expiry.not_yet_valid", { date: formatDateTime(cert.not_before) });
    default:
      return t("certificates.expiry.soon", { days: cert.days_left, date: formatDateTime(cert.not_after) });
  }
}

function CertificateFacts(props: { cert: TlsCertificate; prefix: string; loadedAt: string | null | undefined }) {
  const c = () => props.cert;
  const id = (name: string) => `${props.prefix}-${name}`;
  return (
    <div class="card facts" data-testid={id("facts")}>
      <dl class="kv wide">
        <dt>{t("certificates.subject")}</dt>
        <dd class="mono" data-testid={id("subject")}>{c().subject}</dd>
        <dt>{t("certificates.names")}</dt>
        <dd class="mono" data-testid={id("names")}>
          <Show when={c().dns_names.length + c().ip_addresses.length > 0} fallback={<span class="muted">{t("certificates.names.none")}</span>}>
            {formatList([...c().dns_names, ...c().ip_addresses])}
          </Show>
        </dd>
        <dt>{t("certificates.issuer")}</dt>
        <dd class="mono" data-testid={id("issuer")}>{c().issuer}</dd>
        <dt>{t("certificates.valid_from")}</dt>
        <dd data-testid={id("not-before")}>{formatDateTime(c().not_before)}</dd>
        <dt>{t("certificates.valid_until")}</dt>
        <dd data-testid={id("not-after")}>{formatDateTime(c().not_after)}</dd>
        <dt>{t("certificates.days_left")}</dt>
        <dd>
          <span class="tag" classList={{ [stateClass(c().state)]: stateClass(c().state) !== "" }} data-testid={id("days")} data-state={c().state}>
            {t("certificates.days", { days: c().days_left })}
          </span>
        </dd>
        <dt>{t("certificates.chain")}</dt>
        <dd data-testid={id("chain")}>{t("certificates.chain_len", { count: c().chain_len })}</dd>
        <dt>{t("certificates.fingerprint")}</dt>
        <dd class="mono" data-testid={id("fingerprint")}>{groupedFingerprint(c().sha256)}</dd>
        <Show when={props.loadedAt}>
          {(at) => (
            <>
              <dt>{t("certificates.loaded_at")}</dt>
              <dd data-testid={id("loaded")}>{formatDateTime(at())}</dd>
            </>
          )}
        </Show>
      </dl>
    </div>
  );
}

function ImportedSection(props: { imported: NonNullable<TlsDetails["imported"]>; profile: Loaded["profile"] }) {
  const i = () => props.imported;
  return (
    <section class="page-section" aria-labelledby="cert-imported" data-testid="certificates-imported">
      <h2 id="cert-imported">{t("certificates.imported.heading")}</h2>
      <div class="card facts">
        <dl class="kv wide">
          <dt>{t("certificates.imported.cert_path")}</dt>
          <dd class="mono" data-testid="imported-cert-path">{i().cert_path}</dd>
          <dt>{t("certificates.imported.key_path")}</dt>
          <dd class="mono" data-testid="imported-key-path">{i().key_path}</dd>
          <dt>{t("certificates.imported.interval")}</dt>
          <dd data-testid="imported-interval">
            <Show when={i().watch_interval_secs != null} fallback={<span class="muted">{t("certificates.unknown")}</span>}>
              {t("certificates.imported.interval.value", { seconds: i().watch_interval_secs ?? 0 })}
            </Show>
          </dd>
          <dt>{t("certificates.accept.label")}</dt>
          <dd>
            <span class="tag" classList={{ discrepancy: !i().accept_external_replacement }} data-testid="imported-accept" data-accepted={String(i().accept_external_replacement)}>
              {i().accept_external_replacement ? t("certificates.accept.on") : t("certificates.accept.off")}
            </span>
          </dd>
        </dl>
      </div>
      <p class="muted" data-testid="imported-rule">
        <Show when={props.profile} fallback={t("certificates.rule.unknown")}>
          {(profile) => <>{t(profileRule(profile()))}</>}
        </Show>
      </p>
      <p class="muted">{t("certificates.accept.where")}</p>
    </section>
  );
}

function InternalCaSection(props: { ca: NonNullable<TlsDetails["internal_ca"]> }) {
  const ca = () => props.ca;
  return (
    <section class="page-section" aria-labelledby="cert-ca" data-testid="certificates-ca">
      <h2 id="cert-ca">{t("certificates.ca.heading")}</h2>
      <div class="card facts">
        <dl class="kv wide">
          <dt>{t("certificates.subject")}</dt>
          <dd class="mono" data-testid="ca-subject">{ca().root_subject ?? t("certificates.unknown")}</dd>
          <dt>{t("certificates.valid_until")}</dt>
          <dd data-testid="ca-not-after">{ca().root_not_after ? formatDateTime(ca().root_not_after ?? "") : t("certificates.unknown")}</dd>
          <dt>{t("certificates.fingerprint")}</dt>
          <dd class="mono" data-testid="ca-fingerprint">{ca().root_sha256 ? groupedFingerprint(ca().root_sha256 ?? "") : t("certificates.unknown")}</dd>
        </dl>
      </div>
      <CaRootLink mode="internal_ca" withHelp />
    </section>
  );
}

function ProxySection(props: { proxy: NonNullable<TlsDetails["reverse_proxy"]> }) {
  const p = () => props.proxy;
  return (
    <section class="page-section" aria-labelledby="cert-proxy" data-testid="certificates-proxy">
      <h2 id="cert-proxy">{t("certificates.proxy.heading")}</h2>
      <p class="muted">{t("certificates.proxy.note")}</p>
      <div class="card facts">
        <dl class="kv wide">
          <dt>{t("certificates.proxy.host")}</dt>
          <dd class="mono" data-testid="proxy-host">{p().public_host}</dd>
          <dt>{t("certificates.proxy.trusted")}</dt>
          <dd data-testid="proxy-trusted">
            <ul class="cert-list">
              <For each={p().trusted_proxies}>{(network) => <li class="mono">{network}</li>}</For>
            </ul>
          </dd>
          <dt>{t("certificates.proxy.protocol")}</dt>
          <dd data-testid="proxy-protocol">{p().proxy_protocol ? t("certificates.on") : t("certificates.off")}</dd>
        </dl>
      </div>
    </section>
  );
}
