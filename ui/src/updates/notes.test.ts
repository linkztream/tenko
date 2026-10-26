import { describe, expect, it } from "vitest";
import { repositoryOf } from "./notes";

describe("the repository behind a release source", () => {
  it("reads the repository from the address of the latest manifest", () => {
    expect(repositoryOf("https://github.example.org/example/tenko/releases/latest/download/releases.json")).toBe(
      "https://github.example.org/example/tenko",
    );
  });

  it("reads it from the address of the manifest of one tag", () => {
    expect(repositoryOf("https://github.example.org/example/tenko/releases/download/v0.2.0/releases.json")).toBe(
      "https://github.example.org/example/tenko",
    );
  });

  it("gives nothing for a source of another shape, a plain http source or a bad address", () => {
    expect(repositoryOf("https://releases.example.org/tenko/releases.json")).toBeNull();
    expect(repositoryOf("http://127.0.0.1:9/releases.json")).toBeNull();
    expect(repositoryOf("http://github.example.org/example/tenko/releases/latest/download/releases.json")).toBeNull();
    expect(repositoryOf("https://user:secret@github.example.org/example/tenko/releases/latest/download/releases.json")).toBeNull();
    expect(repositoryOf("/releases/latest/download/releases.json")).toBeNull();
    expect(repositoryOf("")).toBeNull();
  });
});
