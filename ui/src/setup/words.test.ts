import { describe, expect, it } from "vitest";
import { WORDS } from "./words";

describe("the passphrase word list", () => {
  it("has about 40 bits for four words", () => {
    expect(WORDS.length).toBeGreaterThanOrEqual(1024);
  });

  it("has no duplicates", () => {
    expect(new Set(WORDS).size).toBe(WORDS.length);
  });

  it("holds lowercase words of 4 to 8 letters only", () => {
    for (const word of WORDS) expect(word).toMatch(/^[a-z]{4,8}$/);
  });

  it("holds no product or brand word", () => {
    expect(WORDS).not.toContain("tenko");
    expect(WORDS.some((w) => w.includes("tenko"))).toBe(false);
  });
});
