// Ports a browser refuses to open. A server of the end-to-end harness that the operating system
// happened to put on one of them fails every page load with net::ERR_UNSAFE_PORT.

/**
 * The "bad ports" of the Fetch standard (https://fetch.spec.whatwg.org/#port-blocking), which
 * Chromium's restricted ports (`kRestrictedPorts`, net/base/port_util.cc) follow. Checked
 * against the same list in undici 8.11.2 (`badPorts`, node_modules/undici/lib/web/fetch/
 * constants.js). The system hands out ports above 1024, so 1719 and up matter in practice.
 */
export const BROWSER_BLOCKED_PORTS: ReadonlySet<number> = new Set([
  1, 7, 9, 11, 13, 15, 17, 19, 20, 21, 22, 23, 25, 37, 42, 43, 53, 69, 77, 79, 87, 95, 101, 102, 103, 104, 109, 110, 111, 113, 115,
  117, 119, 123, 135, 137, 139, 143, 161, 179, 389, 427, 465, 512, 513, 514, 515, 526, 530, 531, 532, 540, 548, 554, 556, 563, 587,
  601, 636, 989, 990, 993, 995, 1719, 1720, 1723, 2049, 3659, 4045, 4190, 5060, 5061, 6000, 6566, 6665, 6666, 6667, 6668, 6669,
  6679, 6697, 10080,
]);

/** How often a blocked port is asked again before the harness gives up (a source that only gives blocked ports is broken). */
const ASKS = 20;

/** A port from `next` that a browser may open: a blocked one is asked again. */
export async function browserSafePort(next: () => Promise<number>): Promise<number> {
  for (let ask = 1; ask <= ASKS; ask += 1) {
    const port = await next();
    if (!BROWSER_BLOCKED_PORTS.has(port)) return port;
  }
  throw new Error(`no port a browser may open after ${ASKS} asks`);
}
