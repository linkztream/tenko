import { describe, expect, it } from "vitest";
import {
  generatePassword,
  generatorFor,
  isTrivialDigits,
  PASSPHRASE_WORDS,
  PASSWORD_LENGTH,
  PIN_DIGITS,
  secureRandomInt,
  UNAMBIGUOUS_ALPHABET,
  type RandomInt,
} from "./generate";
import { WORDS } from "./words";

/** A deterministic source: the sequence of draws is `values`, repeated. */
function sequence(values: number[]): RandomInt {
  let i = 0;
  return (max) => {
    const v = values[i % values.length] ?? 0;
    i += 1;
    return v % max;
  };
}

describe("generatorFor", () => {
  it("maps the presets: PIN, password, passphrase", () => {
    expect(generatorFor({ preset: "pin" })).toBe("pin");
    expect(generatorFor({ preset: "standard" })).toBe("password");
    expect(generatorFor({ preset: "hardened" })).toBe("passphrase");
    expect(generatorFor({ preset: "custom", min_length: 20 })).toBe("password");
    expect(generatorFor(undefined)).toBe("password");
  });
});

describe("secureRandomInt", () => {
  it("stays inside the range and reaches every value", () => {
    const seen = new Set<number>();
    for (let i = 0; i < 2000; i += 1) {
      const v = secureRandomInt(6);
      expect(Number.isInteger(v)).toBe(true);
      expect(v).toBeGreaterThanOrEqual(0);
      expect(v).toBeLessThan(6);
      seen.add(v);
    }
    expect(seen.size).toBe(6);
  });

  it("refuses a range it cannot sample", () => {
    expect(() => secureRandomInt(0)).toThrow(RangeError);
    expect(() => secureRandomInt(1.5)).toThrow(RangeError);
  });
});

describe("generatePassword", () => {
  it("makes an 8-digit PIN", () => {
    for (let i = 0; i < 50; i += 1) {
      const pin = generatePassword("pin");
      expect(pin).toMatch(new RegExp(`^[0-9]{${PIN_DIGITS}}$`));
      expect(isTrivialDigits(pin)).toBe(false);
    }
  });

  it("never makes a repeated or sequential PIN", () => {
    // 0 0 0 0 ... would be the first candidate; the second is 1 2 3 4 5 6 7 8; the third is fine.
    const random = sequence([0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 4, 8, 2, 7, 1, 9, 3, 5]);
    expect(generatePassword("pin", { random })).toBe("48271935");
  });

  it("makes a 16-character password from the unambiguous alphabet", () => {
    for (let i = 0; i < 50; i += 1) {
      const password = generatePassword("password");
      expect(password).toHaveLength(PASSWORD_LENGTH);
      for (const c of password) expect(UNAMBIGUOUS_ALPHABET).toContain(c);
    }
  });

  it("leaves out the look-alike characters", () => {
    for (const c of "0O1lI") expect(UNAMBIGUOUS_ALPHABET).not.toContain(c);
  });

  it("makes a longer password when asked", () => {
    expect(generatePassword("password", { length: 24 })).toHaveLength(24);
    expect(generatePassword("password", { length: 4 })).toHaveLength(12);
  });

  it("makes a four-word passphrase of at least 16 characters", () => {
    for (let i = 0; i < 50; i += 1) {
      const phrase = generatePassword("passphrase");
      const words = phrase.split("-");
      expect(words).toHaveLength(PASSPHRASE_WORDS);
      for (const word of words) expect(WORDS).toContain(word);
      expect(phrase.length).toBeGreaterThanOrEqual(16);
    }
  });

  it("never contains a word to avoid, without regard to case", () => {
    // Draw 0 first: the first word of the list, then others. Avoiding that word forces a redraw.
    const first = WORDS[0] ?? "";
    const random = sequence([0, 1, 2, 3, 10, 11, 12, 13]);
    const phrase = generatePassword("passphrase", { random, avoid: [first.toUpperCase()] });
    expect(phrase.toLowerCase()).not.toContain(first);
    const user = "alex";
    for (let i = 0; i < 200; i += 1) {
      expect(generatePassword("password", { avoid: [user, "tenko1"] }).toLowerCase()).not.toContain(user);
    }
  });
});

describe("isTrivialDigits", () => {
  it("flags repeats and runs", () => {
    expect(isTrivialDigits("00000000")).toBe(true);
    expect(isTrivialDigits("12345678")).toBe(true);
    expect(isTrivialDigits("87654321")).toBe(true);
    expect(isTrivialDigits("48271935")).toBe(false);
    expect(isTrivialDigits("13572468")).toBe(false);
  });
});
