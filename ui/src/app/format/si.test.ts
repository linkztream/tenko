import { describe, it, expect, vi } from "vitest";
import { exact, si, siTitle } from "./si";

/** The mockup's `si()` as written (design/mockups/shell.js), the reference for the port. */
function mockupSi(input: number): string {
  let n = input;
  const neg = n < 0;
  n = Math.abs(n);
  const units = ["", "K", "M", "G", "T", "P"];
  let i = 0;
  while (n >= 1000 && i < units.length - 1) {
    n /= 1000;
    i++;
  }
  let s: string;
  if (i === 0) s = String(Math.round(n));
  else {
    let r = n < 10 ? Math.round(n * 10) / 10 : Math.round(n);
    if (r >= 1000 && i < units.length - 1) {
      r = 1;
      i++;
    }
    s = (r < 10 ? r.toFixed(1) : String(r)) + units[i];
  }
  return (neg ? "-" : "") + s;
}

/** Largest value that still fits in three digits and the P suffix (999.5P rounds to 1000P). */
const LIMIT = 9.995e17;

/** U+2212, the minus sign the Swedish locale uses for negative numbers. */
const MINUS_SIGN = String.fromCodePoint(0x2212);

/** Same text with the decimal comma and the typographic minus of other locales made ASCII. */
function ascii(text: string): string {
  return text.replace(",", ".").replace(MINUS_SIGN, "-");
}

/** Digits, then an optional fraction and suffix; an integer mantissa has no fraction. */
const COMPACT = /^-?(?:\d{1,3}|\d\.\d[KMGTP]|\d{2,3}[KMGTP])$/;

describe("si", () => {
  it("shows the rounded integer below 1000", () => {
    expect(si(0)).toBe("0");
    expect(si(7)).toBe("7");
    expect(si(982)).toBe("982");
    expect(si(999)).toBe("999");
    expect(si(999.4)).toBe("999");
    expect(si(0.4)).toBe("0");
    expect(si(0.5)).toBe("1");
  });

  it("carries a value below 1000 that rounds to 1000 into the next unit", () => {
    // The mockup prints "1000" here.
    expect(mockupSi(999.5)).toBe("1000");
    expect(si(999.5)).toBe("1.0K");
    expect(si(999.99)).toBe("1.0K");
    expect(si(-999.5)).toBe("-1.0K");
  });

  it("uses one decimal for a mantissa below 10", () => {
    expect(si(1000)).toBe("1.0K");
    expect(si(1049)).toBe("1.0K");
    expect(si(1050)).toBe("1.1K");
    // 1.25 * 10 is exactly 12.5 and Math.round goes up, as in the mockup.
    expect(si(1250)).toBe("1.3K");
    expect(si(1299)).toBe("1.3K");
    expect(si(9900)).toBe("9.9K");
    expect(si(9949)).toBe("9.9K");
  });

  it("uses an integer for a mantissa of 10 and above", () => {
    expect(si(9950)).toBe("10K");
    expect(si(9999)).toBe("10K");
    expect(si(10_000)).toBe("10K");
    expect(si(48_213)).toBe("48K");
    expect(si(123_456)).toBe("123K");
    expect(si(999_499)).toBe("999K");
  });

  it("carries a rounded mantissa of 1000 into the next unit", () => {
    expect(si(999_500)).toBe("1.0M");
    expect(si(999_950)).toBe("1.0M");
    expect(si(999_999_999)).toBe("1.0G");
  });

  it("covers every unit", () => {
    expect(si(1_300_000)).toBe("1.3M");
    expect(si(48_000_000)).toBe("48M");
    expect(si(1.3e9)).toBe("1.3G");
    expect(si(2e12)).toBe("2.0T");
    expect(si(123e12)).toBe("123T");
    expect(si(Number.MAX_SAFE_INTEGER)).toBe("9.0P");
    expect(si(7.5e17)).toBe("750P");
  });

  it("keeps counting in P beyond the last unit", () => {
    expect(si(1e18)).toBe("1000P");
    expect(si(1e21)).toBe("1000000P");
  });

  it("keeps the sign of a negative value", () => {
    expect(si(-1500)).toBe("-1.5K");
    expect(si(-982)).toBe("-982");
    expect(si(-48_213)).toBe("-48K");
    expect(si(-1.3e9)).toBe("-1.3G");
  });

  it("never prints a negative zero", () => {
    expect(si(-0)).toBe("0");
    expect(si(-0.3)).toBe("0");
  });

  it("gives an empty string for null, undefined, NaN and infinities", () => {
    expect(si(null)).toBe("");
    expect(si(undefined)).toBe("");
    expect(si(Number.NaN)).toBe("");
    expect(si(Number.POSITIVE_INFINITY)).toBe("");
    expect(si(Number.NEGATIVE_INFINITY)).toBe("");
  });

  it("follows the locale for the decimal separator, with no space before the suffix", () => {
    expect(si(1_300_000, "en")).toBe("1.3M");
    expect(si(1_300_000, "sv")).toBe("1,3M");
    expect(si(1000, "sv")).toBe("1,0K");
    expect(si(999.5, "sv")).toBe("1,0K");
    expect(si(48_213, "sv")).toBe("48K");
    expect(si(982, "sv")).toBe("982");
    // The sign is the locale's too: Swedish writes a typographic minus.
    expect(ascii(si(-1500, "sv"))).toBe("-1.5K");
    expect(si(-1500, "sv")).toMatch(/^\D1,5K$/);
  });

  it("defaults to English", () => {
    expect(si(1_300_000)).toBe(si(1_300_000, "en"));
  });

  it("keeps grouping out of the text", () => {
    expect(si(999)).toBe("999");
    expect(si(1e21, "sv")).toBe("1000000P");
  });

  it("matches the mockup everywhere except the repaired edge", () => {
    // Deterministic pseudo-random magnitudes, spread evenly over the exponent.
    let seed = 0x2545f491;
    const next = () => {
      seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
      return seed / 2 ** 32;
    };
    let compared = 0;
    for (let k = 0; k < 5000; k++) {
      const value = (next() < 0.5 ? -1 : 1) * 10 ** (next() * 17.9 - 0.3);
      const magnitude = Math.abs(value);
      if (magnitude < 0.5 || (magnitude >= 999.5 && magnitude < 1000) || magnitude >= LIMIT) continue;
      expect(si(value), String(value)).toBe(mockupSi(value));
      compared++;
    }
    expect(compared).toBeGreaterThan(4000);
  });

  it("never needs more than three digits, one separator and a suffix", () => {
    const mantissas = [
      1, 1.05, 1.5, 4.999, 9.949, 9.95, 9.999, 10, 12.34, 99.4, 99.5, 99.95, 100, 123.456, 500, 999, 999.4, 999.5,
      999.9,
    ];
    let checked = 0;
    for (let exponent = 0; exponent <= 17; exponent++) {
      for (const mantissa of mantissas) {
        const magnitude = mantissa * 10 ** exponent;
        if (magnitude >= LIMIT) continue;
        for (const value of [magnitude, -magnitude]) {
          for (const locale of ["en", "sv"]) {
            const text = ascii(si(value, locale));
            expect(text, `${value} in ${locale}`).toMatch(COMPACT);
            expect(text.replace(/\D/g, "").length, `${value} in ${locale}`).toBeLessThanOrEqual(3);
            checked++;
          }
        }
      }
    }
    expect(checked).toBeGreaterThan(500);
  });

  it("stays within four characters up to 999P", () => {
    let widest = 0;
    for (let exponent = 0; exponent < 17.99; exponent += 0.01) {
      widest = Math.max(widest, si(10 ** exponent).length);
    }
    // "123K", "1.0K" and "999" are the widest shapes.
    expect(widest).toBe(4);
  });

  it("creates one formatter per locale and kind", () => {
    const NumberFormat = Intl.NumberFormat;
    const spy = vi.spyOn(Intl, "NumberFormat").mockImplementation(function (
      this: unknown,
      ...args: ConstructorParameters<typeof Intl.NumberFormat>
    ) {
      return new NumberFormat(...args);
    } as unknown as typeof Intl.NumberFormat);
    // A locale no other test uses, so nothing is cached yet.
    const locale = "de-CH";
    si(1500, locale);
    si(2500, locale);
    si(150, locale);
    si(48_000, locale);
    exact(1234, locale);
    exact(5678, locale);
    siTitle(1234, locale, "queries");
    // Decimal ("1.5K"), integer ("150") and exact: three kinds, each created once.
    expect(spy).toHaveBeenCalledTimes(3);
  });
});

describe("exact", () => {
  it("groups the digits like the locale", () => {
    expect(exact(0)).toBe("0");
    expect(exact(982)).toBe("982");
    expect(exact(48_213)).toBe("48,213");
    expect(exact(1_300_000)).toBe("1,300,000");
    expect(exact(-1500)).toBe("-1,500");
  });

  it("follows the locale", () => {
    expect(exact(48_213, "sv")).toBe(new Intl.NumberFormat("sv").format(48_213));
    // Swedish groups with a (no-break) space.
    expect(exact(48_213, "sv")).toMatch(/^48\s213$/);
    expect(exact(1234.5, "sv")).toMatch(/^1\s234,5$/);
  });

  it("is not abbreviated", () => {
    expect(exact(999_999_999)).toBe("999,999,999");
    expect(exact(Number.MAX_SAFE_INTEGER)).toBe("9,007,199,254,740,991");
  });
});

describe("siTitle", () => {
  it("is the exact value", () => {
    expect(siTitle(48_213)).toBe("48,213");
    expect(siTitle(48_213, "en")).toBe("48,213");
    expect(siTitle(48_213, "sv")).toBe(exact(48_213, "sv"));
  });

  it("appends the unit word after a space", () => {
    expect(siTitle(48_213, "en", "queries")).toBe("48,213 queries");
    expect(siTitle(1, "en", "lease")).toBe("1 lease");
    expect(siTitle(48_213, "sv", "queries")).toBe(`${exact(48_213, "sv")} queries`);
  });

  it("ignores an empty unit", () => {
    expect(siTitle(48_213, "en", "")).toBe("48,213");
    expect(siTitle(48_213, "en", undefined)).toBe("48,213");
  });

  it("is empty where si shows nothing", () => {
    expect(siTitle(null, "en", "queries")).toBe("");
    expect(siTitle(undefined)).toBe("");
    expect(siTitle(Number.NaN, "en", "queries")).toBe("");
    expect(siTitle(Number.POSITIVE_INFINITY)).toBe("");
  });
});
