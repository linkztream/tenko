// The rules of the Kerberos wizard (DNS-28): realms, account names, SPNs and KDCs as the server
// and the PowerShell block take them, the keytab in base64url, the keys of the findings.
import { describe, expect, it } from "vitest";
import {
  accountName,
  base64url,
  blockName,
  canonicalRealm,
  findingKey,
  parseLines,
  validAccountName,
  validKdc,
  validRealm,
  validSpns,
} from "./model";

describe("the Kerberos rules", () => {
  it("dns_28 folds and checks realms", () => {
    expect(canonicalRealm(" corp.example.test ")).toBe("CORP.EXAMPLE.TEST");
    for (const good of ["CORP.EXAMPLE.TEST", "corp", "a-b.example.test"]) expect(validRealm(good), good).toBe(true);
    for (const bad of ["", "corp example", "a@b", "a/b", "-a.test", "a..b"]) expect(validRealm(bad), bad).toBe(false);
  });

  it("dns_28 names the computer account with and without its $", () => {
    expect(accountName("tenko-dns")).toBe("TENKO-DNS$");
    expect(accountName("TENKO-DNS$")).toBe("TENKO-DNS$");
    expect(blockName("tenko-dns$")).toBe("TENKO-DNS");
    expect(validAccountName("TENKO-DNS")).toBe(true);
    expect(validAccountName("a".repeat(15))).toBe(true);
    for (const bad of ["", "-x", "a".repeat(16), "a b", "a$b", "x;Remove-ADComputer"]) expect(validAccountName(bad), bad).toBe(false);
  });

  it("dns_28 takes SPNs one per line in the form the PowerShell block accepts", () => {
    expect(parseLines(" DNS/a.example.test \n\ndns/A.example.test\nHTTP/a.example.test\r\n")).toEqual([
      "DNS/a.example.test",
      "HTTP/a.example.test",
    ]);
    expect(validSpns(["DNS/tenko1.corp.example.test", "HTTP/tenko1.corp.example.test"])).toBe(true);
    expect(validSpns([])).toBe(false);
    for (const bad of [
      "DNS/tenko1",
      "ldap/x.example.test",
      "DNS/x.example.test;whoami",
      "DNS/x.example.test@CORP",
      "DNS/-x.example.test",
    ]) {
      expect(validSpns([bad]), bad).toBe(false);
    }
  });

  it("takes KDCs as hosts, addresses and ports", () => {
    for (const good of ["dc1.corp.example.test", "dc1:88", "192.0.2.5", "192.0.2.5:88", "[2001:db8::5]:88", "2001:db8::5"])
      expect(validKdc(good), good).toBe(true);
    for (const bad of ["", "dc1 dc2", "dc1:88:88x", "http://dc1"]) expect(validKdc(bad), bad).toBe(false);
  });

  it("dns_28 sends the keytab in base64url without padding", () => {
    expect(base64url(new Uint8Array([0x05, 0x02]))).toBe("BQI");
    expect(base64url(new Uint8Array([0xfb, 0xff, 0xfe]))).toBe("-__-");
    const large = new Uint8Array(70_000).fill(0x41);
    expect(base64url(large)).toHaveLength(Math.ceil((70_000 * 4) / 3));
  });

  it("maps finding codes to their keys", () => {
    expect(findingKey("dns.gss.spn_missing")).toBe("spn_missing");
    expect(findingKey("dns.gss.rotation_failed")).toBe("rotation_failed");
    expect(findingKey("dns.gss.context_limit")).toBe("other");
    expect(findingKey("dns.made.up")).toBe("other");
  });
});
