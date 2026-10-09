import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { isValidPort, rdpFile, rdpFileName, RDP_MIME, saveTextFile, sshUri } from "./handoff";

/** NUL, NEL, line separator and paragraph separator. */
const CONTROLS = String.fromCharCode(0x00, 0x85, 0x2028, 0x2029);

const TRAILER = ["prompt for credentials:i:1", "administrative session:i:0", "screen mode id:i:2", "authentication level:i:2"];

/** The lines of an .rdp text, without the terminator of the last one. */
function rdpLines(text: string): string[] {
  expect(text.endsWith("\r\n")).toBe(true);
  return text.slice(0, -2).split("\r\n");
}

describe("isValidPort", () => {
  it("accepts the integers 1 to 65535", () => {
    for (const port of [1, 22, 3389, 8080, 65535]) expect(isValidPort(port), String(port)).toBe(true);
  });

  it("refuses everything else", () => {
    for (const port of [0, -1, 65536, 100000, 22.5, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(isValidPort(port), String(port)).toBe(false);
    }
  });
});

describe("rdpFile", () => {
  it("writes an IPv4 address with the default port and the fixed settings", () => {
    const text = rdpFile({ address: "192.0.2.10" });
    expect(text).toBe(["full address:s:192.0.2.10:3389", ...TRAILER].join("\r\n") + "\r\n");
  });

  it("joins the lines with CRLF and ends with CRLF, never a bare LF", () => {
    const text = rdpFile({ address: "192.0.2.10", username: "admin" });
    expect(text.endsWith("\r\n")).toBe(true);
    expect(text.replace(/\r\n/g, "")).not.toMatch(/[\r\n]/);
    expect(text.split("\r\n")).toHaveLength(7);
  });

  it("brackets an IPv6 literal", () => {
    expect(rdpLines(rdpFile({ address: "2001:db8::10" }))[0]).toBe("full address:s:[2001:db8::10]:3389");
  });

  it("does not bracket an IPv6 literal twice", () => {
    expect(rdpLines(rdpFile({ address: "[2001:db8::10]", port: 3390 }))[0]).toBe("full address:s:[2001:db8::10]:3390");
  });

  it("writes the port of a host name", () => {
    expect(rdpLines(rdpFile({ address: "nas.example.test", port: 33890 }))[0]).toBe("full address:s:nas.example.test:33890");
  });

  it("writes the user name right after the address", () => {
    const lines = rdpLines(rdpFile({ address: "192.0.2.10", username: "EXAMPLE\\ops" }));
    expect(lines).toEqual(["full address:s:192.0.2.10:3389", "username:s:EXAMPLE\\ops", ...TRAILER]);
  });

  it("leaves the user name out when there is none", () => {
    for (const username of [undefined, null, "", "   "]) {
      const lines = rdpLines(rdpFile({ address: "192.0.2.10", username }));
      expect(lines.some((line) => line.startsWith("username:")), JSON.stringify(username)).toBe(false);
      expect(lines).toHaveLength(5);
    }
  });

  it("cannot be made to inject a setting through the user name", () => {
    const text = rdpFile({ address: "192.0.2.10", username: "ops\r\nfull address:s:203.0.113.9" });
    const lines = rdpLines(text);
    expect(lines.filter((line) => line.startsWith("full address:"))).toEqual(["full address:s:192.0.2.10:3389"]);
    expect(lines.filter((line) => line.startsWith("username:"))).toEqual(["username:s:opsfull address:s:203.0.113.9"]);
    expect(lines).toHaveLength(6);
  });

  it("cannot be made to inject a setting through a lone CR or LF", () => {
    const lines = rdpLines(rdpFile({ address: "192.0.2.10", username: "a\rb\nc" }));
    expect(lines).toHaveLength(6);
    expect(lines[1]).toBe("username:s:abc");
  });

  it("cannot be made to inject a setting through the address", () => {
    const lines = rdpLines(rdpFile({ address: "192.0.2.10\r\nusername:s:root\nscreen mode id:i:1" }));
    expect(lines).toHaveLength(5);
    expect(lines.filter((line) => line.startsWith("username:"))).toEqual([]);
    expect(lines.filter((line) => line.startsWith("screen mode id:"))).toEqual(["screen mode id:i:2"]);
  });

  it("removes other control characters too", () => {
    const text = rdpFile({ address: "192.0.2.10", username: `o${CONTROLS}p${CONTROLS}s` });
    expect(rdpLines(text)[1]).toBe("username:s:ops");
  });

  it("refuses an invalid port", () => {
    for (const port of [0, -1, 65536, 3389.5, Number.NaN]) {
      expect(() => rdpFile({ address: "192.0.2.10", port }), String(port)).toThrow(RangeError);
    }
  });

  it("accepts the ends of the port range", () => {
    expect(rdpLines(rdpFile({ address: "192.0.2.10", port: 1 }))[0]).toBe("full address:s:192.0.2.10:1");
    expect(rdpLines(rdpFile({ address: "192.0.2.10", port: 65535 }))[0]).toBe("full address:s:192.0.2.10:65535");
  });

  it("refuses an empty address", () => {
    expect(() => rdpFile({ address: "" })).toThrow(RangeError);
    expect(() => rdpFile({ address: " \r\n " })).toThrow(RangeError);
  });
});

describe("rdpFileName", () => {
  it("keeps a plain host name", () => {
    expect(rdpFileName("nas.example.test")).toBe("nas.example.test.rdp");
  });

  it("replaces every character outside A-Z a-z 0-9 . _ -", () => {
    expect(rdpFileName("a b/c")).toBe("a_b_c.rdp");
    expect(rdpFileName("srv-01_lab.example.org")).toBe("srv-01_lab.example.org.rdp");
    expect(rdpFileName("..\\..\\evil:name*?")).toBe(".._.._evil_name__.rdp");
  });

  it("replaces characters outside ASCII", () => {
    expect(rdpFileName("n" + String.fromCharCode(0xe4) + "t")).toBe("n_t.rdp");
  });

  it("allows at most 64 characters before the extension", () => {
    const name = rdpFileName("h".repeat(100));
    expect(name).toBe(`${"h".repeat(64)}.rdp`);
    expect(name).toHaveLength(68);
  });

  it("falls back to host.rdp when nothing is left", () => {
    expect(rdpFileName("")).toBe("host.rdp");
  });
});

describe("sshUri", () => {
  it("writes a host name alone", () => {
    expect(sshUri({ host: "nas.example.test" })).toBe("ssh://nas.example.test");
  });

  it("writes an IPv4 address with a user", () => {
    expect(sshUri({ host: "192.0.2.10", user: "admin" })).toBe("ssh://admin@192.0.2.10");
  });

  it("writes the port only when it is not 22", () => {
    expect(sshUri({ host: "192.0.2.10", port: 22 })).toBe("ssh://192.0.2.10");
    expect(sshUri({ host: "192.0.2.10", port: 2222 })).toBe("ssh://192.0.2.10:2222");
    expect(sshUri({ host: "192.0.2.10", user: "admin", port: 2222 })).toBe("ssh://admin@192.0.2.10:2222");
  });

  it("brackets an IPv6 literal", () => {
    expect(sshUri({ host: "2001:db8::10" })).toBe("ssh://[2001:db8::10]");
    expect(sshUri({ host: "[2001:db8::10]", user: "admin", port: 2222 })).toBe("ssh://admin@[2001:db8::10]:2222");
  });

  it("encodes the zone of a link-local address as RFC 6874 asks", () => {
    expect(sshUri({ host: "fe80::1%eth0" })).toBe("ssh://[fe80::1%25eth0]");
  });

  it("percent-encodes the user name", () => {
    expect(sshUri({ host: "nas.example.test", user: "ops admin@example.test" })).toBe(
      "ssh://ops%20admin%40example.test@nas.example.test",
    );
    expect(sshUri({ host: "nas.example.test", user: "a:b/c%d" })).toBe("ssh://a%3Ab%2Fc%25d@nas.example.test");
  });

  it("keeps the user, host and port apart when the URI is parsed", () => {
    const uri = sshUri({ host: "2001:db8::10", user: "ops admin@example.test", port: 2222 });
    const url = new URL(uri);
    expect(decodeURIComponent(url.username)).toBe("ops admin@example.test");
    expect(url.password).toBe("");
    expect(url.hostname).toBe("[2001:db8::10]");
    expect(url.port).toBe("2222");
  });

  it("cannot be made to change the host through the user or the host", () => {
    const url = new URL(sshUri({ host: "nas.example.test/x@evil.example.net", user: "a@evil.example.net" }));
    expect(url.pathname).toBe("");
    expect(url.username).toBe("a%40evil.example.net");
    expect(url.hostname.toLowerCase()).toBe("nas.example.test%2fx%40evil.example.net");
  });

  it("leaves the user out when there is none", () => {
    for (const user of [undefined, null, ""]) {
      expect(sshUri({ host: "nas.example.test", user }), JSON.stringify(user)).toBe("ssh://nas.example.test");
    }
  });

  it("removes control characters from the user name", () => {
    expect(sshUri({ host: "nas.example.test", user: "ops\r\nadmin" })).toBe("ssh://opsadmin@nas.example.test");
  });

  it("copes with a user name that is not well-formed UTF-16", () => {
    const user = "a" + String.fromCharCode(0xd800) + "b";
    expect(sshUri({ host: "nas.example.test", user })).toBe("ssh://a%EF%BF%BDb@nas.example.test");
  });

  it("refuses an invalid port", () => {
    for (const port of [0, -1, 65536, 22.5, Number.NaN]) {
      expect(() => sshUri({ host: "192.0.2.10", port }), String(port)).toThrow(RangeError);
    }
  });

  it("refuses an empty host", () => {
    expect(() => sshUri({ host: "" })).toThrow(RangeError);
  });
});

describe("saveTextFile", () => {
  const createObjectURL = vi.fn((_blob: Blob) => "blob:https://tenko.example.test/0001");
  const revokeObjectURL = vi.fn((_url: string) => undefined);
  const saved: { createObjectURL?: PropertyDescriptor | undefined; revokeObjectURL?: PropertyDescriptor | undefined } = {};

  function define(name: "createObjectURL" | "revokeObjectURL", value: unknown): void {
    saved[name] = Object.getOwnPropertyDescriptor(URL, name);
    Object.defineProperty(URL, name, { value, configurable: true, writable: true });
  }

  function restore(name: "createObjectURL" | "revokeObjectURL"): void {
    const original = saved[name];
    if (original) Object.defineProperty(URL, name, original);
    else Reflect.deleteProperty(URL, name);
  }

  beforeEach(() => {
    vi.useFakeTimers();
    createObjectURL.mockClear();
    revokeObjectURL.mockClear();
    define("createObjectURL", createObjectURL);
    define("revokeObjectURL", revokeObjectURL);
  });

  afterEach(() => {
    vi.useRealTimers();
    restore("createObjectURL");
    restore("revokeObjectURL");
  });

  it("clicks a temporary anchor with the file name and the object URL", () => {
    const seen: { download: string; href: string; attached: boolean }[] = [];
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (this: HTMLAnchorElement) {
      seen.push({ download: this.download, href: this.getAttribute("href") ?? "", attached: this.isConnected });
    });

    saveTextFile("nas.example.test.rdp", "full address:s:192.0.2.10:3389\r\n", RDP_MIME);

    expect(seen).toEqual([{ download: "nas.example.test.rdp", href: "blob:https://tenko.example.test/0001", attached: true }]);
    expect(document.querySelector("a[download]")).toBeNull();
  });

  it("hands the text to a Blob of the given type", () => {
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);

    saveTextFile("nas.example.test.rdp", "full address:s:192.0.2.10:3389\r\n", RDP_MIME);

    expect(createObjectURL).toHaveBeenCalledTimes(1);
    const blob = createObjectURL.mock.calls[0]?.[0];
    expect(blob).toBeInstanceOf(Blob);
    expect(blob?.type).toBe(RDP_MIME);
    expect(blob?.size).toBe("full address:s:192.0.2.10:3389\r\n".length);
  });

  it("defaults to UTF-8 plain text", () => {
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);

    saveTextFile("notes.txt", "x");

    expect(createObjectURL.mock.calls[0]?.[0].type).toBe("text/plain;charset=utf-8");
  });

  it("revokes the object URL afterwards, not before the click", () => {
    const order: string[] = [];
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {
      order.push("click");
    });
    revokeObjectURL.mockImplementation(() => {
      order.push("revoke");
    });

    saveTextFile("notes.txt", "x");
    expect(revokeObjectURL).not.toHaveBeenCalled();

    vi.runAllTimers();
    expect(revokeObjectURL).toHaveBeenCalledWith("blob:https://tenko.example.test/0001");
    expect(order).toEqual(["click", "revoke"]);
  });

  it("removes the anchor and revokes the URL even when the click throws", () => {
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {
      throw new Error("blocked");
    });

    expect(() => saveTextFile("notes.txt", "x")).toThrow("blocked");
    expect(document.querySelector("a[download]")).toBeNull();
    vi.runAllTimers();
    expect(revokeObjectURL).toHaveBeenCalledTimes(1);
  });
});
