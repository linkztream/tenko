// Remote access hand-off (API-11): an `.rdp` file for Windows hosts and an `ssh://` link,
// both handed to the operating system. The port and the user are remembered per host in
// this browser. Passwords are not handled here in Slice 1 (see credentials.tsx).
import { createSignal, For, Show, untrack } from "solid-js";
import type { Address, Host } from "../api/types";
import { Icon } from "../components/Icon";
import { t } from "../i18n";
import { parseIp } from "../ipam/ip";
import { isValidPort, RDP_MIME, rdpFile, rdpFileName, saveTextFile, sshUri } from "./handoff";

interface Remembered {
  rdpPort: number;
  sshPort: number;
  user: string;
  target: string;
}

const KEY = "tenko-connect:";

function read(hostId: string): Partial<Remembered> {
  try {
    return JSON.parse(localStorage.getItem(KEY + hostId) ?? "{}") as Partial<Remembered>;
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

/** Where to connect to: the DNS names and addresses of the host, IPv4 first. */
export function connectTargets(host: Host, addresses: readonly Address[]): string[] {
  const live = addresses.filter((a) => !a.meta.deleted);
  const v4 = live.filter((a) => parseIp(a.ip)?.version === 4);
  const v6 = live.filter((a) => parseIp(a.ip)?.version === 6);
  const names = live.map((a) => a.dns_name).filter((n): n is string => !!n);
  return [...new Set([...names, ...v4.map((a) => a.ip), ...v6.map((a) => a.ip), host.name])];
}

export function Connect(props: { host: Host; addresses: readonly Address[] }) {
  const saved = untrack(() => read(props.host.id));
  const targets = () => connectTargets(props.host, props.addresses);
  const [target, setTarget] = createSignal(saved.target ?? "");
  const [rdpPort, setRdpPort] = createSignal(saved.rdpPort ?? 3389);
  const [sshPort, setSshPort] = createSignal(saved.sshPort ?? 22);
  const [user, setUser] = createSignal(saved.user ?? "");
  const current = () => (target() && targets().includes(target()) ? target() : (targets()[0] ?? props.host.name));
  const store = () => remember(props.host.id, { rdpPort: rdpPort(), sshPort: sshPort(), user: user(), target: current() });

  const downloadRdp = () => {
    store();
    saveTextFile(rdpFileName(props.host.name), rdpFile({ address: current(), port: rdpPort(), username: user() || null }), RDP_MIME);
  };
  const ssh = () => (isValidPort(sshPort()) ? sshUri({ host: current(), port: sshPort(), user: user() || null }) : undefined);

  return (
    <div class="connect" data-testid="host-connect">
      <div class="form-row">
        <div class="field">
          <label for="connect-target">{t("hosts.connect.target")}</label>
          <select id="connect-target" class="select mono" value={current()} onChange={(e) => setTarget(e.currentTarget.value)}>
            <For each={targets()}>{(x) => <option value={x}>{x}</option>}</For>
          </select>
        </div>
        <div class="field">
          <label for="connect-user">{t("hosts.connect.user")}</label>
          <input id="connect-user" class="input mono" value={user()} spellcheck={false} onInput={(e) => setUser(e.currentTarget.value)} />
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
      <div class="form-row">
        <button type="button" class="btn" data-testid="host-rdp" disabled={!isValidPort(rdpPort())} onClick={downloadRdp}>
          <Icon name="rdp" />
          {t("hosts.connect.rdp")}
        </button>
        <Show
          when={ssh()}
          fallback={
            <button type="button" class="btn" disabled>
              <Icon name="terminal" />
              {t("hosts.connect.ssh")}
            </button>
          }
        >
          {(uri) => (
            <a class="btn" href={uri()} data-testid="host-ssh" onClick={store}>
              <Icon name="terminal" />
              {t("hosts.connect.ssh")}
            </a>
          )}
        </Show>
        <span class="muted">{t("hosts.connect.hint")}</span>
      </div>
    </div>
  );
}
