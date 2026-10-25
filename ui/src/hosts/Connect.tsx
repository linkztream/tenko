// Remote access hand-off (API-11) from the ports the probe saw open: an RDP and an SSH button
// next to each scanned address of the host, and a link to its web interface.
//
// What is open comes from the `services` facts of the address (docs/scanning.md, section 3):
// a button is enabled only for a port that was seen open, is disabled with the time of the last
// scan for a port that was not, and is left out for an address no scan has reached. The server
// builds the `.rdp` file and the `ssh://` URI (`GET /hosts/{id}/remote`) with the target, the
// port and the user name of the bound credential; neither carries a secret. The password
// reaches the clipboard only through the audited reveal of the credentials section
// (credentials.tsx). A user name and ports typed here override the server's choice and are
// remembered per host in this browser. The port fields start with the open ports found.
import { A } from "@solidjs/router";
import { createEffect, createMemo, createSignal, For, on, Show, untrack } from "solid-js";
import { createLiveQuery } from "../api/live";
import { errorMessage } from "../api/problem";
import type { Address, Host } from "../api/types";
import { paths } from "../app/paths";
import { Addr } from "../components/Addr";
import { Icon } from "../components/Icon";
import { toast } from "../components/toast";
import { getSubject } from "../discovery/api";
import { formatDateTime, formatRelative, t } from "../i18n";
import { parseIp } from "../ipam/ip";
import { remoteRdp, remoteSsh } from "../secrets/api";
import { isValidPort, RDP_MIME, rdpFileName, saveTextFile } from "./handoff";
import { defaultPort, RDP_ALTERNATIVES, RDP_PORT, type Scanned, type Services, servicesOf, SSH_ALTERNATIVES, SSH_PORT, type WebLink, webLinks } from "./ports";

interface Remembered {
  rdpPort: number;
  sshPort: number;
  user: string;
}

const KEY = "tenko-connect:";

function read(hostId: string): Partial<Remembered> {
  try {
    const value: unknown = JSON.parse(localStorage.getItem(KEY + hostId) ?? "{}");
    // Anything but an object (a damaged entry, the JSON text null) starts from the defaults.
    return typeof value === "object" && value !== null ? (value as Partial<Remembered>) : {};
  } catch {
    return {};
  }
}

function remember(hostId: string, value: Remembered): void {
  try {
    localStorage.setItem(KEY + hostId, JSON.stringify(value));
  } catch {
    // Storage unavailable: the choice lasts for this page only.
  }
}

/** One place to connect to: an address of the host (by its DNS name when it has one), or the host name. */
export interface ConnectTarget {
  /** What the server gets as `address`; absent for the host name. */
  address?: string | undefined;
  /** The IP address shown. */
  ip?: string | undefined;
  /** What the row shows as the name. */
  label: string;
}

/** The targets of a host: its live addresses, IPv4 first, or the host name when it has none. */
export function connectTargets(host: Host, addresses: readonly Address[]): ConnectTarget[] {
  const live = addresses.filter((a) => !a.meta.deleted);
  const v4 = live.filter((a) => parseIp(a.ip)?.version === 4);
  const v6 = live.filter((a) => parseIp(a.ip)?.version === 6);
  const rows = [...v4, ...v6].map((a) => ({ address: a.dns_name ?? a.ip, ip: a.ip, label: a.dns_name ?? a.ip }));
  return rows.length > 0 ? rows : [{ label: host.name }];
}

/** Opens a URI with the operating system's handler through a temporary link. */
function openUri(uri: string): void {
  const a = document.createElement("a");
  a.href = uri;
  a.rel = "noopener";
  document.body.appendChild(a);
  try {
    a.click();
  } finally {
    a.remove();
  }
}

/** The open ports of one address, each with the TLS mark, in one compact line. */
function PortsLine(props: { services: Services }) {
  const when = () => formatRelative(props.services.at);
  return (
    <p class="muted connect-ports" data-testid="connect-ports" title={formatDateTime(props.services.at)}>
      {props.services.open.length > 0 ? t("hosts.connect.ports", { time: when() }) : t("hosts.connect.ports_none", { time: when() })}
      <Show when={props.services.open.length > 0}>
        {": "}
        <For each={props.services.open}>
          {(port, index) => (
            <>
              {index() > 0 ? ", " : null}
              <span class="mono" data-port={port} data-tls={props.services.tls.includes(port) ? "true" : undefined}>
                {port}
                {props.services.tls.includes(port) ? ` ${t("hosts.connect.tls")}` : ""}
              </span>
            </>
          )}
        </For>
      </Show>
    </p>
  );
}

/** A link to a web interface, in a new tab. */
function WebAnchor(props: { link: WebLink; class?: string; testid: string; children: string }) {
  return (
    <a
      class={props.class}
      href={props.link.url}
      target="_blank"
      rel="noopener noreferrer"
      title={t("hosts.connect.web_open", { url: props.link.url })}
      data-testid={props.testid}
      data-port={props.link.port}
      data-scheme={props.link.scheme}
    >
      {props.children}
    </a>
  );
}

export function Connect(props: { host: Host; addresses: readonly Address[]; loading?: boolean }) {
  const saved = untrack(() => read(props.host.id));
  const [rdpPort, setRdpPort] = createSignal(saved.rdpPort ?? RDP_PORT);
  const [sshPort, setSshPort] = createSignal(saved.sshPort ?? SSH_PORT);
  const [user, setUser] = createSignal(saved.user ?? "");
  const [busy, setBusy] = createSignal<string | null>(null);
  const store = () => remember(props.host.id, { rdpPort: rdpPort(), sshPort: sshPort(), user: user() });

  const targets = createMemo(() => connectTargets(props.host, props.addresses));
  const ips = createMemo(() => targets().flatMap((target) => (target.ip ? [target.ip] : [])), undefined, {
    equals: (a, b) => a.length === b.length && a.every((x, i) => x === b[i]),
  });

  // The services facts of each address; the live query follows the discovery topic.
  const live = createLiveQuery<Map<string, Services | null>>({
    topics: ["discovery"],
    debounceMs: 400,
    fetch: async (signal) => {
      const list = ips();
      const pictures = await Promise.all(list.map((ip) => getSubject(ip, signal)));
      return { value: new Map(list.map((ip, index) => [ip, servicesOf(pictures[index]?.facts ?? [])])) };
    },
  });
  createEffect(on(ips, () => live.refetch(), { defer: true }));

  const known = () => live.latest();
  // Reading until the open ports of every address are in (a new address is read when it appears).
  const reading = () => props.loading === true || (!live.value.error && !ips().every((ip) => known()?.has(ip)));
  const entries = createMemo((): Scanned[] => targets().map((target) => ({ target, services: (target.ip ? known()?.get(target.ip) : null) ?? null })));
  const anyScanned = () => entries().some((entry) => entry.services !== null);
  const web = createMemo(() => webLinks(entries()));

  // The port fields start with the open ports found, until the operator or a remembered choice sets them.
  let rdpSet = saved.rdpPort !== undefined;
  let sshSet = saved.sshPort !== undefined;
  createEffect(() => {
    const scanned = entries().map((entry) => entry.services);
    if (!rdpSet) setRdpPort(defaultPort(scanned, RDP_ALTERNATIVES));
    if (!sshSet) setSshPort(defaultPort(scanned, SSH_ALTERNATIVES));
  });

  const query = (target: ConnectTarget, port: number, fallback: number) => ({
    ...(target.address ? { address: target.address } : {}),
    ...(port !== fallback ? { port } : {}),
    ...(user().trim() ? { user: user().trim() } : {}),
  });

  const run = async (key: string, work: () => Promise<void>) => {
    store();
    setBusy(key);
    try {
      await work();
    } catch (err) {
      toast({ kind: "bad", title: t("hosts.connect.failed"), body: errorMessage(err) });
    } finally {
      setBusy(null);
    }
  };

  const rdp = (target: ConnectTarget) => {
    const host = props.host;
    const args = query(target, rdpPort(), RDP_PORT);
    void run(`rdp:${target.label}`, async () => {
      const text = await remoteRdp(host.id, args);
      saveTextFile(rdpFileName(host.name), text, RDP_MIME);
    });
  };

  const ssh = (target: ConnectTarget) => {
    const host = props.host;
    const args = query(target, sshPort(), SSH_PORT);
    void run(`ssh:${target.label}`, async () => {
      const answer = await remoteSsh(host.id, args);
      openUri(answer.uri);
    });
  };

  /** Why a button is disabled when its port was not seen open at the last scan of the address. */
  const closedTip = (services: Services, port: number) =>
    services.open.includes(port) ? undefined : t("hosts.connect.closed_tip", { port, time: formatDateTime(services.at) });

  return (
    <div class="connect" data-testid="host-connect">
      <Show when={reading()}>
        <p class="muted" data-testid="connect-loading">
          {t("hosts.connect.loading")}
        </p>
      </Show>
      <Show when={!reading() && live.value.error}>
        <p class="muted" data-testid="connect-unknown">
          {t("hosts.connect.unknown")}
        </p>
      </Show>
      <Show when={!reading() && !live.value.error && !anyScanned()}>
        <p class="muted" data-testid="connect-no-scan">
          {t("hosts.connect.no_scan")}{" "}
          <A href={paths.nodes()} data-testid="connect-scan-link">
            {t("hosts.connect.no_scan_link")}
          </A>
        </p>
      </Show>
      <Show when={!reading() && anyScanned()}>
        <ul class="plain-list connect-targets" aria-label={t("hosts.connect.target")}>
          <For each={entries()}>
            {(entry) => (
              <li class="connect-row" data-testid="remote-target" data-key={entry.target.address ?? props.host.name}>
                <span class="connect-name">
                  <span class="mono">{entry.target.label}</span>
                  {entry.target.ip && entry.target.ip !== entry.target.label ? (
                    <span class="muted">
                      {" "}
                      <Addr value={entry.target.ip} />
                    </span>
                  ) : null}
                </span>
                <Show
                  when={entry.services}
                  fallback={
                    <span class="muted connect-unscanned" data-testid="connect-unscanned">
                      {t("hosts.connect.unscanned")}
                    </span>
                  }
                >
                  {(services) => (
                    <>
                      <span title={closedTip(services(), rdpPort())}>
                        <button
                          type="button"
                          class="btn sm"
                          data-testid="host-rdp"
                          data-key={entry.target.address ?? props.host.name}
                          title={closedTip(services(), rdpPort())}
                          disabled={!isValidPort(rdpPort()) || !services().open.includes(rdpPort()) || busy() !== null}
                          onClick={() => rdp(entry.target)}
                        >
                          <Icon name="rdp" />
                          {t("hosts.connect.rdp")}
                        </button>
                      </span>
                      <span title={closedTip(services(), sshPort())}>
                        <button
                          type="button"
                          class="btn sm"
                          data-testid="host-ssh"
                          data-key={entry.target.address ?? props.host.name}
                          title={closedTip(services(), sshPort())}
                          disabled={!isValidPort(sshPort()) || !services().open.includes(sshPort()) || busy() !== null}
                          onClick={() => ssh(entry.target)}
                        >
                          <Icon name="terminal" />
                          {t("hosts.connect.ssh")}
                        </button>
                      </span>
                      <PortsLine services={services()} />
                    </>
                  )}
                </Show>
              </li>
            )}
          </For>
        </ul>
        <Show when={web().primary}>
          {(primary) => (
            <div class="connect-web" data-testid="connect-web">
              <WebAnchor link={primary()} class="btn sm" testid="web-primary">
                {t("hosts.connect.web")}
              </WebAnchor>
              <Show when={web().http}>
                {(http) => (
                  <WebAnchor link={http()} testid="web-http">
                    {t("hosts.connect.web_http")}
                  </WebAnchor>
                )}
              </Show>
              <Show when={primary().addressUrl}>
                {(addressUrl) => (
                  <WebAnchor link={{ ...primary(), url: addressUrl() }} testid="web-address">
                    {t("hosts.connect.web_ip")}
                  </WebAnchor>
                )}
              </Show>
            </div>
          )}
        </Show>
        <Show when={web().more.length > 0}>
          <div class="connect-web connect-more" data-testid="connect-web-more">
            <span class="muted">{t("hosts.connect.web_more")}</span>
            <For each={web().more}>
              {(more) => (
                <WebAnchor link={more} testid="web-more">
                  {String(more.port)}
                </WebAnchor>
              )}
            </For>
          </div>
        </Show>
      </Show>
      <div class="form-row">
        <div class="field">
          <label for="connect-user">{t("hosts.connect.user")}</label>
          <input
            id="connect-user"
            data-testid="field-user"
            class="input mono"
            value={user()}
            spellcheck={false}
            placeholder={t("hosts.connect.user_placeholder")}
            onInput={(e) => setUser(e.currentTarget.value)}
          />
        </div>
        <div class="field">
          <label for="connect-rdp-port">{t("hosts.connect.rdp_port")}</label>
          <input
            id="connect-rdp-port"
            data-testid="field-rdp_port"
            class="input num port"
            type="number"
            min="1"
            max="65535"
            value={rdpPort()}
            aria-invalid={isValidPort(rdpPort()) ? undefined : "true"}
            onInput={(e) => {
              rdpSet = true;
              setRdpPort(Number(e.currentTarget.value));
            }}
          />
        </div>
        <div class="field">
          <label for="connect-ssh-port">{t("hosts.connect.ssh_port")}</label>
          <input
            id="connect-ssh-port"
            data-testid="field-ssh_port"
            class="input num port"
            type="number"
            min="1"
            max="65535"
            value={sshPort()}
            aria-invalid={isValidPort(sshPort()) ? undefined : "true"}
            onInput={(e) => {
              sshSet = true;
              setSshPort(Number(e.currentTarget.value));
            }}
          />
        </div>
      </div>
      <p class="muted">{t("hosts.connect.hint")}</p>
    </div>
  );
}
