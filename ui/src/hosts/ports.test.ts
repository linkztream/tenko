import { describe, expect, it } from "vitest";
import type { ObservedFact } from "../discovery/api";
import type { ConnectTarget } from "./Connect";
import { defaultPort, RDP_ALTERNATIVES, type Scanned, type Services, servicesOf, SSH_ALTERNATIVES, webLinks } from "./ports";

const NOW = Date.parse("2026-10-25T12:00:00Z");

function services(open: number[], extra: { tls?: number[]; last_seen?: string; expires_at?: string | null } = {}): ObservedFact {
  return {
    source: { type: "probe", node: 1, method: "tcp_connect" },
    source_key: "probe:1:tcp_connect",
    subject: { type: "services", data: { ip: "192.0.2.5" } },
    subject_key: "services:192.0.2.5",
    observed: { type: "services", data: { ip: "192.0.2.5", open_tcp: open, ...(extra.tls ? { tls_tcp: extra.tls } : {}) } },
    observation: "0190d1c2-0000-7000-8000-00000f000001",
    first_seen: "2026-10-25T10:00:00Z",
    last_seen: extra.last_seen ?? "2026-10-25T11:00:00Z",
    received_at: "2026-10-25T11:00:00Z",
    expires_at: extra.expires_at === undefined ? "2026-10-25T20:00:00Z" : extra.expires_at,
  } as ObservedFact;
}

describe("servicesOf", () => {
  it("is null without a services fact, which is not a fact with no open port", () => {
    expect(servicesOf([], NOW)).toBeNull();
    expect(servicesOf([services([22], { expires_at: "2026-10-25T11:59:00Z" })], NOW)).toBeNull();
    expect(servicesOf([services([])], NOW)).toEqual({ open: [], tls: [], at: "2026-10-25T11:00:00Z" });
  });

  it("joins the facts of several methods and takes the newest sighting", () => {
    const syn = services([22, 443], { last_seen: "2026-10-25T09:00:00Z" });
    const connect = services([443, 80], { tls: [443], last_seen: "2026-10-25T11:30:00Z" });
    expect(servicesOf([syn, connect], NOW)).toEqual({ open: [22, 80, 443], tls: [443], at: "2026-10-25T11:30:00Z" });
  });

  it("leaves out a TLS mark on a port that is not open and a fact that is not a services fact", () => {
    const other = { ...services([22]), observed: { type: "os", data: { ip: "192.0.2.5", guess: "Linux", confidence: 90 } } } as ObservedFact;
    expect(servicesOf([services([22], { tls: [443] }), other], NOW)?.tls).toEqual([]);
  });
});

describe("defaultPort", () => {
  const seen = (...open: number[]): Services => ({ open, tls: [], at: "2026-10-25T11:00:00Z" });

  it("is the usual port when nothing was scanned or it is open", () => {
    expect(defaultPort([], SSH_ALTERNATIVES)).toBe(22);
    expect(defaultPort([null], SSH_ALTERNATIVES)).toBe(22);
    expect(defaultPort([seen(22, 2222)], SSH_ALTERNATIVES)).toBe(22);
    expect(defaultPort([seen(80)], RDP_ALTERNATIVES)).toBe(3389);
  });

  it("is the alternative that is open when the usual port is not, on any address", () => {
    expect(defaultPort([seen(2222)], SSH_ALTERNATIVES)).toBe(2222);
    expect(defaultPort([seen(80), seen(3390)], RDP_ALTERNATIVES)).toBe(3390);
  });
});

describe("webLinks", () => {
  const entry = (label: string, ip: string, open: number[], tls: number[] = [], address = label): Scanned => ({
    target: { label, ip, address } satisfies ConnectTarget,
    services: { open, tls, at: "2026-10-25T11:00:00Z" },
  });

  it("is empty without a web port", () => {
    expect(webLinks([entry("192.0.2.5", "192.0.2.5", [22])])).toEqual({ primary: null, http: null, more: [] });
    expect(webLinks([{ target: { label: "kiosk" }, services: null }])).toEqual({ primary: null, http: null, more: [] });
  });

  it("omits the default port and the scheme follows the port", () => {
    const links = webLinks([entry("192.0.2.5", "192.0.2.5", [80, 443, 8080, 8443, 9443, 8006, 8123])]);
    expect(links.primary?.url).toBe("https://192.0.2.5/");
    expect(links.http?.url).toBe("http://192.0.2.5/");
    expect(links.more.map((l) => l.url)).toEqual([
      "http://192.0.2.5:8080/",
      "https://192.0.2.5:8443/",
      "https://192.0.2.5:8006/",
      "http://192.0.2.5:8123/",
      "https://192.0.2.5:9443/",
    ]);
  });

  it("switches an alternative port to https when the fact marks it as TLS", () => {
    expect(webLinks([entry("192.0.2.5", "192.0.2.5", [8123], [8123])]).more[0]?.url).toBe("https://192.0.2.5:8123/");
  });

  it("uses the name and keeps the address as the fallback only when they differ", () => {
    const named = webLinks([entry("nas.example.test", "192.0.2.5", [443])]).primary;
    expect(named).toMatchObject({ url: "https://nas.example.test/", addressUrl: "https://192.0.2.5/" });
    expect(webLinks([entry("192.0.2.5", "192.0.2.5", [443])]).primary?.addressUrl).toBeNull();
  });

  it("does not guess a port that the facts do not hold", () => {
    expect(webLinks([entry("192.0.2.5", "192.0.2.5", [22, 8000, 8888, 3000])]).more).toEqual([]);
  });
});
