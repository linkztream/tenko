// Remote access hand-off (API-11): an RDP and an SSH button next to each address of the host.
// The server builds the `.rdp` file and the `ssh://` URI (`GET /hosts/{id}/remote`) with the
// target, the port and the user name of the bound credential; neither carries a secret. The
// password reaches the clipboard only through the audited reveal of the credentials section
// (credentials.tsx). A user name and ports typed here override the server's choice and are
// remembered per host in this browser.
import { createSignal, For, untrack } from "solid-js";
import { errorMessage } from "../api/problem";
import type { Address, Host } from "../api/types";
import { Addr } from "../components/Addr";
import { Icon } from "../components/Icon";
import { toast } from "../components/toast";
import { t } from "../i18n";
import { parseIp } from "../ipam/ip";
import { remoteRdp, remoteSsh } from "../secrets/api";
import { isValidPort, RDP_MIME, rdpFileName, saveTextFile } from "./handoff";

interface Remembered {
  rdpPort: number;
  sshPort: number;
  user: string;
}

const KEY = "tenko-connect:";
const RDP_PORT = 3389;
const SSH_PORT = 22;

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

export function Connect(props: { host: Host; addresses: readonly Address[] }) {
  const saved = untrack(() => read(props.host.id));
  const [rdpPort, setRdpPort] = createSignal(saved.rdpPort ?? RDP_PORT);
  const [sshPort, setSshPort] = createSignal(saved.sshPort ?? SSH_PORT);
  const [user, setUser] = createSignal(saved.user ?? "");
  const [busy, setBusy] = createSignal<string | null>(null);
  const store = () => remember(props.host.id, { rdpPort: rdpPort(), sshPort: sshPort(), user: user() });

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

  return (
    <div class="connect" data-testid="host-connect">
      <ul class="plain-list connect-targets" aria-label={t("hosts.connect.target")}>
        <For each={connectTargets(props.host, props.addresses)}>
          {(target) => (
            <li class="connect-row" data-testid="remote-target" data-key={target.address ?? props.host.name}>
              <span class="connect-name">
                <span class="mono">{target.label}</span>
                {target.ip && target.ip !== target.label ? (
                  <span class="muted">
                    {" "}
                    <Addr value={target.ip} />
                  </span>
                ) : null}
              </span>
              <button
                type="button"
                class="btn sm"
                data-testid="host-rdp"
                data-key={target.address ?? props.host.name}
                disabled={!isValidPort(rdpPort()) || busy() !== null}
                onClick={() => rdp(target)}
              >
                <Icon name="rdp" />
                {t("hosts.connect.rdp")}
              </button>
              <button
                type="button"
                class="btn sm"
                data-testid="host-ssh"
                data-key={target.address ?? props.host.name}
                disabled={!isValidPort(sshPort()) || busy() !== null}
                onClick={() => ssh(target)}
              >
                <Icon name="terminal" />
                {t("hosts.connect.ssh")}
              </button>
            </li>
          )}
        </For>
      </ul>
      <div class="form-row">
        <div class="field">
          <label for="connect-user">{t("hosts.connect.user")}</label>
          <input
            id="connect-user"
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
            class="input num port"
            type="number"
            min="1"
            max="65535"
            value={rdpPort()}
            aria-invalid={isValidPort(rdpPort()) ? undefined : "true"}
            onInput={(e) => setRdpPort(Number(e.currentTarget.value))}
          />
        </div>
        <div class="field">
          <label for="connect-ssh-port">{t("hosts.connect.ssh_port")}</label>
          <input
            id="connect-ssh-port"
            class="input num port"
            type="number"
            min="1"
            max="65535"
            value={sshPort()}
            aria-invalid={isValidPort(sshPort()) ? undefined : "true"}
            onInput={(e) => setSshPort(Number(e.currentTarget.value))}
          />
        </div>
      </div>
      <p class="muted">{t("hosts.connect.hint")}</p>
    </div>
  );
}
