import { A } from "@solidjs/router";
import { errorMessage } from "../../api/problem";
import { For, Show } from "solid-js";
import { paths } from "../../app/paths";
import { session } from "../../auth/session";
import { webauthnAvailable } from "../../auth/webauthn";
import { Icon } from "../../components/Icon";
import { ErrorNotice, Notice } from "../../components/Notice";
import { RecoveryCodes } from "../../components/RecoveryCodes";
import { toast } from "../../components/toast";
import { t } from "../../i18n";
import { fingerprintRows, fingerprintText } from "../format";
import { CaRootLink } from "../../components/CaRootLink";
import { FOCUS } from "../gates";
import { dnsChoice, useWizard } from "../controller";
import { dnsChecklist } from "../checklist";
import { generateDnsConfig } from "../generate";
// WP8.6: the DHCP block.
import { dhcpPaths } from "../../dhcp/paths";
import { generateDhcpConfig } from "../dhcp";

/**
 * After the request succeeded: recovery codes, the passkey, the CA fingerprint, the DNS upstreams
 * (stored as the root forwarding rule or not) with the `[dns]` section for `tenko.toml` and the
 * DNS checklist, what to do next.
 */
export function Result() {
  const w = useWizard();
  const needsPasskey = () => session()?.strength === "pin" && w.after.passkey.status !== "added";
  const passkeyTag = () =>
    w.state.profile === "hardened" ? t("common.required") : w.state.profile === "standard" ? t("common.recommended") : t("common.optional");

  const copyFingerprint = async () => {
    try {
      await navigator.clipboard.writeText(fingerprintText(w.after.caFingerprint ?? ""));
      toast({ title: t("setup.result.ca.copied"), kind: "ok" });
    } catch {
      toast({ title: t("setup.result.ca.copy_failed"), kind: "bad" });
    }
  };

  const connect = (which: "unifi" | "proxmox") =>
    w.open(() => {
      if (needsPasskey()) {
        toast({
          title: t("setup.result.next.passkey_first"),
          body: t(which === "unifi" ? "setup.result.next.passkey_first_unifi" : "setup.result.next.passkey_first_proxmox"),
          kind: "info",
          actions: [{ label: t("setup.result.passkey.add"), primary: true, run: () => document.getElementById(FOCUS.passkey)?.focus() }],
        });
        return;
      }
      toast({
        title: t(which === "unifi" ? "setup.result.next.unifi" : "setup.result.next.proxmox"),
        body: t("setup.result.next.connector_later"),
        kind: "info",
      });
    });

  const dnsConfig = () => generateDnsConfig(dnsChoice(w.state.dns, w.state.profile));
  const copyDns = async () => {
    try {
      await navigator.clipboard.writeText(dnsConfig());
      toast({ title: t("setup.result.dns.copied"), kind: "ok" });
    } catch {
      toast({ title: t("setup.result.dns.copy_failed"), kind: "bad" });
    }
  };

  // WP8.6: the `[dhcp]` section for the listener of the DHCP step.
  const dhcpConfig = () => generateDhcpConfig(w.dhcpPlan());
  const copyDhcp = async () => {
    try {
      await navigator.clipboard.writeText(dhcpConfig());
      toast({ title: t("setup.result.dhcp.copied"), kind: "ok" });
    } catch {
      toast({ title: t("setup.result.dns.copy_failed"), kind: "bad" });
    }
  };

  /** Leaving through a link would skip the recovery codes: ask for them first. */
  const guard = (e: MouseEvent) => {
    if (w.openGate()) {
      e.preventDefault();
      w.open();
    }
  };

  return (
    <div>
      <p class="wz-lede">{t("setup.result.lede")}</p>

      <div class="wz-blk tight">
        <h2>{t("setup.result.codes.title")}</h2>
        <div class="wz-codes" id={FOCUS.codesAck}>
          <Show when={w.after.codes.status === "loading"}>
            <p class="wz-help wz-loading" role="status">
              {t("setup.result.codes.loading")}
            </p>
          </Show>
          <Show when={w.after.codes.status === "ready"}>
            <p class="wz-lede">{t("setup.result.codes.lede", { user: w.state.userName.trim() })}</p>
            <RecoveryCodes
              codes={w.after.codes.codes}
              fileBase={w.state.hostName.trim()}
              saved={w.after.codesSaved}
              onSavedChange={(saved) => w.setCodesSaved(saved)}
            />
          </Show>
          <Show when={w.after.codes.status === "deferred"}>
            <Notice kind="info">{t("setup.result.codes.deferred")}</Notice>
          </Show>
          <Show when={w.after.codes.status === "error"}>
            <ErrorNotice error={w.after.codes.error} />
            <div class="form-row">
              <button type="button" class="btn sm" onClick={() => void w.loadCodes()}>
                {t("common.action.retry")}
              </button>
            </div>
          </Show>
        </div>
      </div>

      <div class="wz-blk">
        <h2>
          {t("setup.result.passkey.title")} <span class="tag" classList={{ accent: w.state.profile === "hardened" }}>{passkeyTag()}</span>
        </h2>
        <div class="wz-pk">
          <div class="info">
            <p class="wz-help ink">{t(`setup.result.passkey.help.${w.state.profile}`)}</p>
            <Show when={!webauthnAvailable()}>
              <p class="wz-help gap">{t("setup.result.passkey.unavailable")}</p>
            </Show>
            <Show when={w.after.passkey.error}>
              {(message) => (
                <p class="err" role="alert">
                  {message()}
                </p>
              )}
            </Show>
          </div>
          <div class="act">
            <Show
              when={w.after.passkey.status !== "added"}
              fallback={
                <span class="added" role="status">
                  <Icon name="check" size="sm" />
                  {t("setup.result.passkey.added")}
                </span>
              }
            >
              <button
                type="button"
                id={FOCUS.passkey}
                data-testid="setup-passkey-add"
                class="btn"
                aria-disabled={w.after.passkey.status === "waiting"}
                onClick={() => void w.addPasskey()}
              >
                <Icon name="key" size="sm" />
                {w.after.passkey.status === "waiting" ? t("setup.result.passkey.waiting") : t("setup.result.passkey.add")}
              </button>
            </Show>
          </div>
        </div>
      </div>

      <Show when={w.after.caFingerprint}>
        {(fp) => (
          <div class="wz-blk">
            <h2 id="wz-ca-title">{t("setup.result.ca.title")}</h2>
            <div class="wz-fp">
              <div class="grow">
                <div class="wz-help ink">{t("setup.result.ca.help")}</div>
                <div class="hex" role="group" aria-labelledby="wz-ca-title" data-testid="setup-ca-fingerprint">
                  <For each={fingerprintRows(fp())}>
                    {(row) => (
                      <div>
                        <For each={row}>{(pair, i) => <>{i() > 0 ? " " : ""}<span>{pair}</span></>}</For>
                      </div>
                    )}
                  </For>
                </div>
              </div>
              <button type="button" class="btn sm" onClick={() => void copyFingerprint()}>
                <Icon name="copy" size="sm" />
                {t("setup.result.ca.copy")}
              </button>
            </div>
            <CaRootLink mode="internal_ca" withHelp />
            <p class="wz-help">{t("setup.result.ca.compare")}</p>
          </div>
        )}
      </Show>

      <Show when={w.dnsWanted()}>
        <div class="wz-blk" data-testid="setup-result-dns" data-state={w.after.dns.status}>
          <h2 id="wz-dns-config-title">{t("setup.result.dns.title")}</h2>
          <Show when={w.after.dns.status === "saved"}>
            <Notice kind="ok" role="status" testid="setup-dns-saved">
              {t("setup.result.dns.saved")}
            </Notice>
          </Show>
          <Show when={w.after.dns.status === "failed" ? w.after.dns : undefined}>
            {(failed) => (
              <Notice kind="warn" role="status" testid="setup-dns-failed">
                {t("setup.result.dns.failed", { reason: errorMessage(failed().error) })}
              </Notice>
            )}
          </Show>
          <Show when={w.after.dns.status === "none"}>
            <p class="wz-help ink">{t("setup.result.dns.none")}</p>
          </Show>
          <p class="wz-help ink">{t("setup.result.dns.config_help")}</p>
          <pre class="wz-dns-config mono" aria-labelledby="wz-dns-config-title" data-testid="setup-dns-config">
            {dnsConfig()}
          </pre>
          <div class="form-row">
            <button type="button" class="btn sm" data-testid="setup-dns-copy" onClick={() => void copyDns()}>
              <Icon name="copy" size="sm" />
              {t("setup.result.dns.copy")}
            </button>
          </div>
          <ul class="wz-dns-checklist" data-testid="setup-dns-checklist">
            <For each={dnsChecklist(w.state.dns)}>
              {(id) => (
                <li data-testid="setup-dns-check" data-key={id}>
                  {t(`setup.dns.check.${id}`)}
                </li>
              )}
            </For>
          </ul>
        </div>
      </Show>

      {/* WP8.6: the first DHCP scope and the `[dhcp]` section of tenko.toml. */}
      <Show when={w.dhcpWanted()}>
        <div class="wz-blk" data-testid="setup-result-dhcp" data-state={w.after.dhcp.status}>
          <h2 id="wz-dhcp-config-title">{t("setup.result.dhcp.title")}</h2>
          <Show when={w.after.dhcp.status === "saved" ? w.after.dhcp : undefined}>
            {(saved) => (
              <Notice kind="ok" role="status" testid="setup-dhcp-saved">
                {t("setup.result.dhcp.saved", { network: w.dhcpPlan()?.network ?? "" })}{" "}
                <A href={dhcpPaths.scope(saved().prefix)} data-testid="setup-dhcp-scope-link" onClick={guard}>
                  {t("setup.result.dhcp.open_scope")}
                </A>
              </Notice>
            )}
          </Show>
          <Show when={w.after.dhcp.status === "failed" ? w.after.dhcp : undefined}>
            {(failed) => (
              <Notice kind="warn" role="status" testid="setup-dhcp-failed">
                {t(`setup.result.dhcp.failed.${failed().step}`, { reason: errorMessage(failed().error) })}
              </Notice>
            )}
          </Show>
          <Show when={w.after.dhcp.status === "none"}>
            <p class="wz-help ink">{t("setup.result.dhcp.none")}</p>
          </Show>
          <p class="wz-help ink">{t("setup.result.dhcp.config_help")}</p>
          <pre class="wz-dns-config mono" aria-labelledby="wz-dhcp-config-title" data-testid="setup-dhcp-config">
            {dhcpConfig()}
          </pre>
          <div class="form-row">
            <button type="button" class="btn sm" data-testid="setup-dhcp-copy" onClick={() => void copyDhcp()}>
              <Icon name="copy" size="sm" />
              {t("setup.result.dhcp.copy")}
            </button>
          </div>
          <p class="wz-help ink" data-testid="setup-dhcp-reminder">
            {t("setup.dhcp.safety")}
          </p>
        </div>
      </Show>

      <div class="wz-blk">
        <h2>{t("setup.result.next.title")}</h2>
        <div class="wz-nexts">
          <A class="wz-next" href={paths.ipam()} onClick={guard}>
            <Icon name="ipam" />
            <span>
              <span class="t">{t("setup.result.next.ipam")}</span>
              <span class="d">{t("setup.result.next.ipam_description")}</span>
            </span>
          </A>
          <A class="wz-next" href={paths.imports()} onClick={guard}>
            <Icon name="folder" />
            <span>
              <span class="t">{t("setup.result.next.import")}</span>
              <span class="d">{t("setup.result.next.import_description")}</span>
            </span>
          </A>
          <button type="button" class="wz-next" onClick={() => connect("unifi")}>
            <Icon name="wifi" />
            <span>
              <span class="t">
                {t("setup.result.next.unifi")}
                <Show when={needsPasskey()}>
                  <span class="tag discrepancy">{t("setup.result.next.passkey_first")}</span>
                </Show>
              </span>
              <span class="d">{t("setup.result.next.unifi_description")}</span>
            </span>
          </button>
          <button type="button" class="wz-next" onClick={() => connect("proxmox")}>
            <Icon name="vm" />
            <span>
              <span class="t">
                {t("setup.result.next.proxmox")}
                <Show when={needsPasskey()}>
                  <span class="tag discrepancy">{t("setup.result.next.passkey_first")}</span>
                </Show>
              </span>
              <span class="d">{t("setup.result.next.proxmox_description")}</span>
            </span>
          </button>
        </div>
      </div>
    </div>
  );
}
