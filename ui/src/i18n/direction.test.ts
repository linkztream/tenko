import { describe, expect, it } from "vitest";
import { textDirection } from "./direction";

describe("writing direction", () => {
  it("is right to left for languages written in a right-to-left script", () => {
    for (const tag of ["ar", "ar-EG", "he", "he-IL", "fa", "fa-IR", "ur", "ur-PK", "ps", "yi", "ckb", "dv", "ug", "ar-XB"]) {
      expect(textDirection(tag), tag).toBe("rtl");
    }
  });

  it("is left to right for everything else", () => {
    for (const tag of ["en", "sv", "sv-SE", "fr", "de-CH", "zh-Hant", "ja", "hi", "en-XA", "tr", "ku", "pa", "uz"]) {
      expect(textDirection(tag), tag).toBe("ltr");
    }
    expect(textDirection(null)).toBe("ltr");
    expect(textDirection("")).toBe("ltr");
  });

  it("follows an explicit script subtag", () => {
    expect(textDirection("ku-Arab")).toBe("rtl");
    expect(textDirection("pa-Arab-PK")).toBe("rtl");
    expect(textDirection("uz-Arab")).toBe("rtl");
    expect(textDirection("az-Latn")).toBe("ltr");
    expect(textDirection("ug-Latn")).toBe("ltr");
    expect(textDirection("AR_eg")).toBe("rtl");
  });

  it("ignores private-use and extension parts", () => {
    expect(textDirection("en-x-arab")).toBe("ltr");
    expect(textDirection("he-u-nu-latn")).toBe("rtl");
  });
});
