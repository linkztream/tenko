import { describe, expect, it } from "vitest";
import { BROWSER_BLOCKED_PORTS, browserSafePort } from "./ports";

/** A port source that answers `ports` in order and counts the asks. */
function source(...ports: number[]) {
  let asks = 0;
  const next = async () => {
    const port = ports[asks];
    asks += 1;
    if (port === undefined) throw new Error("the source ran dry");
    return port;
  };
  return { next, asks: () => asks };
}

describe("browserSafePort", () => {
  it("asks again when the system hands out a port the browser blocks", async () => {
    const ports = source(10080, 6667, 2049, 41234);
    expect(await browserSafePort(ports.next)).toBe(41234);
    expect(ports.asks()).toBe(4);
  });

  it("takes the first port the browser may open", async () => {
    const ports = source(41234, 10080);
    expect(await browserSafePort(ports.next)).toBe(41234);
    expect(ports.asks()).toBe(1);
  });

  it("gives up on a source that only hands out blocked ports", async () => {
    await expect(browserSafePort(async () => 10080)).rejects.toThrow("no port a browser may open after 20 asks");
  });

  it("holds the ports above 1024 that Chromium refuses", () => {
    for (const port of [1719, 1720, 1723, 2049, 3659, 4045, 4190, 5060, 5061, 6000, 6566, 6665, 6669, 6679, 6697, 10080]) {
      expect(BROWSER_BLOCKED_PORTS.has(port), String(port)).toBe(true);
    }
    expect(BROWSER_BLOCKED_PORTS.has(8080)).toBe(false);
  });
});
