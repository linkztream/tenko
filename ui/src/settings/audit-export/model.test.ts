import { describe, expect, it } from "vitest";
import { formProblems, newForm, withChoice } from "./model";

describe("the file name of a file sink", () => {
  const problemsFor = (file: string) => formProblems({ ...withChoice({ ...newForm(), name: "file" }, "file"), file });

  it("refuses Windows device names, also with an extension, and a trailing dot", () => {
    for (const name of ["NUL", "con", "COM1", "lpt9.log", "nul.jsonl", "audit."]) {
      expect(problemsFor(name).file, name).toBeTruthy();
    }
  });

  it("accepts names that only look like device names", () => {
    for (const name of ["audit.jsonl", "comd", "lptx.log", "console.log", "com10", "null"]) {
      expect(problemsFor(name).file, name).toBeUndefined();
    }
  });
});
