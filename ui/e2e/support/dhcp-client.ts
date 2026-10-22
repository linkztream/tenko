// A minimal DHCPv4 client for the end-to-end tests of the DHCP role (WP7.5), acting as a relay
// agent: it sends its BOOTREQUESTs from UDP 127.0.0.1:<relayPort> to the relay-mode listener of the
// server on 127.0.0.1:<port> with `hops` 1 and `giaddr` 127.0.0.1, and reads the replies, which the
// server sends to `giaddr` on the relay port. The loopback address is no network of a scope, so the
// scope is chosen with the subnet selection option (RFC 3011, option 118) naming the network.
//
// One DORA: DISCOVER (option 53 = 1) until an OFFER (2) arrives, then REQUEST (3) with the offered
// address (option 50) and the server identifier (option 54) until the ACK (5) arrives; the address
// is the `yiaddr` of the ACK. The configuration of a scope reaches the role through the store feed
// after it was written, so the first DISCOVER may find no scope yet: it is sent again every second.
//
// Documentation values only: networks of RFC 5737, MACs 00:00:5e:00:53:xx.

import { createSocket, type Socket } from "node:dgram";
import { randomBytes } from "node:crypto";

/** The ports of the role: the UDP port it listens on, and the port a relay receives replies on. */
export interface DhcpPorts {
  port: number;
  relayPort: number;
}

/** A free UDP port on the loopback: bind port 0, read the port, release it. */
export async function freeUdpPort(): Promise<number> {
  const socket = createSocket("udp4");
  await new Promise<void>((done, fail) => {
    socket.once("error", fail);
    socket.bind(0, "127.0.0.1", () => done());
  });
  const { port } = socket.address();
  await new Promise<void>((done) => socket.close(() => done()));
  return port;
}

/** Two free UDP ports for the server's listener and the relay. */
export async function freeDhcpPorts(): Promise<DhcpPorts> {
  const port = await freeUdpPort();
  let relayPort = await freeUdpPort();
  while (relayPort === port) relayPort = await freeUdpPort();
  return { port, relayPort };
}

const MAGIC = Buffer.from([99, 130, 83, 99]);
const FIXED = 236;
const MIN_LENGTH = 300;

const DISCOVER = 1;
const OFFER = 2;
const REQUEST = 3;
const ACK = 5;
const NAK = 6;

const OPT_HOST_NAME = 12;
const OPT_REQUESTED_ADDRESS = 50;
const OPT_MESSAGE_TYPE = 53;
const OPT_SERVER_ID = 54;
const OPT_CLIENT_ID = 61;
const OPT_SUBNET_SELECTION = 118;
const OPT_END = 255;

/** How often an unanswered message is sent again. */
const RESEND_MS = 1000;
/** How long one step of the exchange may take. */
const STEP_TIMEOUT_MS = 10_000;

function ipv4Bytes(address: string): Buffer {
  const parts = address.split(".").map(Number);
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) throw new Error(`${address} is no IPv4 address`);
  return Buffer.from(parts);
}

function macBytes(mac: string): Buffer {
  const parts = mac.split(/[:-]/);
  if (parts.length !== 6 || parts.some((p) => !/^[0-9a-f]{2}$/i.test(p))) throw new Error(`${mac} is no MAC address`);
  return Buffer.from(parts.map((p) => parseInt(p, 16)));
}

function option(code: number, value: Buffer): Buffer {
  return Buffer.concat([Buffer.from([code, value.length]), value]);
}

interface Request {
  type: number;
  xid: Buffer;
  mac: string;
  hostname: string;
  /** The network address the relay names with option 118. */
  network: string;
  /** For a REQUEST: the offered address and the server identifier of the OFFER. */
  requested?: { address: Buffer; server: Buffer };
}

/** A BOOTREQUEST of a relay agent forwarding a client's message. */
export function buildRequest(request: Request): Buffer {
  const mac = macBytes(request.mac);
  const head = Buffer.alloc(FIXED);
  head[0] = 1; // op: BOOTREQUEST
  head[1] = 1; // htype: Ethernet
  head[2] = 6; // hlen
  head[3] = 1; // hops: one relay
  request.xid.copy(head, 4);
  ipv4Bytes("127.0.0.1").copy(head, 24); // giaddr
  mac.copy(head, 28); // chaddr
  const options = [
    option(OPT_MESSAGE_TYPE, Buffer.from([request.type])),
    option(OPT_CLIENT_ID, Buffer.concat([Buffer.from([1]), mac])),
    option(OPT_SUBNET_SELECTION, ipv4Bytes(request.network)),
    option(OPT_HOST_NAME, Buffer.from(request.hostname, "ascii")),
    ...(request.requested
      ? [option(OPT_REQUESTED_ADDRESS, request.requested.address), option(OPT_SERVER_ID, request.requested.server)]
      : []),
    Buffer.from([OPT_END]),
  ];
  const packet = Buffer.concat([head, MAGIC, ...options]);
  return packet.length >= MIN_LENGTH ? packet : Buffer.concat([packet, Buffer.alloc(MIN_LENGTH - packet.length)]);
}

export interface Reply {
  type: number;
  xid: Buffer;
  yiaddr: string;
  options: Map<number, Buffer>;
}

/** A BOOTREPLY, or null when the bytes are no DHCP message. */
export function parseReply(message: Buffer): Reply | null {
  if (message.length < FIXED + MAGIC.length || message[0] !== 2) return null;
  if (!message.subarray(FIXED, FIXED + MAGIC.length).equals(MAGIC)) return null;
  const options = new Map<number, Buffer>();
  for (let at = FIXED + MAGIC.length; at < message.length; ) {
    const code = message[at];
    if (code === OPT_END || code === undefined) break;
    if (code === 0) {
      at += 1;
      continue;
    }
    const length = message[at + 1] ?? 0;
    options.set(code, message.subarray(at + 2, at + 2 + length));
    at += 2 + length;
  }
  const type = options.get(OPT_MESSAGE_TYPE)?.[0];
  if (type === undefined) return null;
  return { type, xid: message.subarray(4, 8), yiaddr: [...message.subarray(16, 20)].join("."), options };
}

export interface DoraOptions {
  mac: string;
  hostname: string;
  /** The network address of the scope (option 118), for example 192.0.2.0. */
  network: string;
  /** Per step; default 10 s. */
  timeoutMs?: number;
}

/** The relay agent: owns the UDP socket the server answers to. */
export class RelayClient {
  private readonly inbox: Reply[] = [];
  private readonly waiting = new Set<() => void>();

  private constructor(
    private readonly socket: Socket,
    private readonly ports: DhcpPorts,
  ) {
    socket.on("message", (message) => {
      const reply = parseReply(message);
      if (!reply) return;
      this.inbox.push(reply);
      for (const wake of [...this.waiting]) wake();
    });
  }

  /** Binds 127.0.0.1:<relayPort>, where the server sends its replies. */
  static async open(ports: DhcpPorts): Promise<RelayClient> {
    const socket = createSocket({ type: "udp4", reuseAddr: true });
    await new Promise<void>((done, fail) => {
      socket.once("error", fail);
      socket.bind(ports.relayPort, "127.0.0.1", () => {
        socket.off("error", fail);
        done();
      });
    });
    return new RelayClient(socket, ports);
  }

  async close(): Promise<void> {
    await new Promise<void>((done) => this.socket.close(() => done()));
  }

  private send(packet: Buffer): Promise<void> {
    return new Promise((done, fail) => this.socket.send(packet, this.ports.port, "127.0.0.1", (error) => (error ? fail(error) : done())));
  }

  /** The first reply to `xid` of one of the `types`; resends `packet` every second until `timeoutMs`. */
  private async exchange(packet: Buffer, xid: Buffer, types: readonly number[], timeoutMs: number): Promise<Reply> {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      await this.send(packet);
      const until = Math.min(deadline, Date.now() + RESEND_MS);
      for (;;) {
        const at = this.inbox.findIndex((reply) => reply.xid.equals(xid));
        if (at >= 0) {
          const [reply] = this.inbox.splice(at, 1);
          if (reply && types.includes(reply.type)) return reply;
          if (reply?.type === NAK) throw new Error("the server answered with a NAK");
          continue;
        }
        const left = until - Date.now();
        if (left <= 0) break;
        await new Promise<void>((done) => {
          const wake = (): void => {
            clearTimeout(timer);
            this.waiting.delete(wake);
            done();
          };
          const timer = setTimeout(wake, left);
          this.waiting.add(wake);
        });
      }
      if (Date.now() >= deadline) throw new Error(`no answer of the DHCP server within ${timeoutMs} ms (message types ${types.join("/")})`);
    }
  }

  /** DISCOVER, OFFER, REQUEST, ACK for one client; the address the server leased. */
  async dora(options: DoraOptions): Promise<string> {
    const timeout = options.timeoutMs ?? STEP_TIMEOUT_MS;
    const xid = randomBytes(4);
    const base = { xid, mac: options.mac, hostname: options.hostname, network: options.network };
    const offer = await this.exchange(buildRequest({ ...base, type: DISCOVER }), xid, [OFFER], timeout);
    const server = offer.options.get(OPT_SERVER_ID);
    if (!server) throw new Error("the OFFER carries no server identifier");
    const address = ipv4Bytes(offer.yiaddr);
    const ack = await this.exchange(buildRequest({ ...base, type: REQUEST, requested: { address, server } }), xid, [ACK], timeout);
    return ack.yiaddr;
  }
}
