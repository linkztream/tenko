// The split behind the "Emphasize host part" preference (design decision 2): the
// network part of an address, its host part and an optional prefix length, and the
// vendor part of a MAC. Rendering stays plain unless the preference is on; the markup
// always carries the split (see components/Addr.tsx).

export interface AddressParts {
  net: string;
  host: string;
  /** "/24" when the input had a prefix length, else "". */
  len: string;
}

/**
 * Splits an IPv4 or IPv6 address (optionally with "/len"). IPv4: the host part is the
 * octets not wholly covered by the prefix length (default 24). IPv6: the interface
 * identifier after the last 64 bits of prefix, or what follows "::" when the text
 * compresses zeros inside the host part. Anything else is returned as host only.
 */
export function splitAddress(text: string, prefixLength?: number): AddressParts {
  const slash = text.indexOf("/");
  const addr = slash >= 0 ? text.slice(0, slash) : text;
  const len = slash >= 0 ? text.slice(slash) : "";
  const fromText = slash >= 0 ? Number(text.slice(slash + 1)) : Number.NaN;
  const bits = prefixLength ?? (Number.isFinite(fromText) ? fromText : undefined);

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(addr)) {
    const octets = addr.split(".");
    const netOctets = Math.min(3, Math.max(0, Math.floor((bits ?? 24) / 8)));
    return {
      net: octets.slice(0, netOctets).map((o) => `${o}.`).join(""),
      host: octets.slice(netOctets).join("."),
      len,
    };
  }

  if (addr.includes(":")) {
    const groups = (bits ?? 64) / 16;
    const dbl = addr.indexOf("::");
    if (dbl >= 0) {
      const before = addr.slice(0, dbl).split(":").filter(Boolean).length;
      if (before <= groups) return { net: addr.slice(0, dbl + 2), host: addr.slice(dbl + 2), len };
    }
    const parts = addr.split(":");
    const n = Math.min(parts.length - 1, Math.max(0, Math.floor(groups)));
    return { net: parts.slice(0, n).map((p) => `${p}:`).join(""), host: parts.slice(n).join(":"), len };
  }

  return { net: "", host: addr, len };
}

/** Splits a MAC (any of -, : or . separators) into its vendor part (OUI) and the rest. */
export function splitMac(text: string): { oui: string; rest: string } {
  const m = /^([0-9A-Fa-f]{2}[-:])([0-9A-Fa-f]{2}[-:])([0-9A-Fa-f]{2}[-:])(.*)$/.exec(text);
  if (!m) return { oui: "", rest: text };
  return { oui: `${m[1]}${m[2]}${m[3]}`, rest: m[4] ?? "" };
}
