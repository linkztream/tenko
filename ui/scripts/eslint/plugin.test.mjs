// @vitest-environment node
// @ts-check
import { RuleTester } from "eslint";
import { describe, it } from "vitest";
import plugin from "./plugin.mjs";

RuleTester.describe = describe;
RuleTester.it = it;

const tester = new RuleTester({
  languageOptions: { ecmaVersion: 2022, sourceType: "module", parserOptions: { ecmaFeatures: { jsx: true } } },
});

tester.run("no-literal-ui-string", plugin.rules["no-literal-ui-string"], {
  valid: [
    { code: 'const a = <p>{t("common.loading")}</p>;' },
    { code: 'const a = <button title={t("shell.keys.title")} aria-label={t("common.action.close")} />;' },
    { code: "const a = <span>, · / : 192.0.2.41 {count}</span>;" },
    { code: 'const a = <Kbd keys={["Ctrl", "K"]} />;' },
    { code: 'const a = <input type="password" autocomplete="current-password" class="input mono" />;' },
    { code: 'const a = <span class="mono">{"/"}</span>;' },
  ],
  invalid: [
    { code: "const a = <p>Sign in</p>;", errors: [{ messageId: "text" }] },
    { code: 'const a = <p>{"Sign in"}</p>;', errors: [{ messageId: "text" }] },
    { code: "const a = <p>{ok ? `Saved` : t(\"x.y\")}</p>;", errors: [{ messageId: "text" }] },
    { code: 'const a = <button title="Close" />;', errors: [{ messageId: "attribute" }] },
    { code: 'const a = <input placeholder="Search" />;', errors: [{ messageId: "attribute" }] },
    { code: 'const a = <img alt={"Fox"} />;', errors: [{ messageId: "attribute" }] },
    { code: 'const a = <nav aria-label="Main" />;', errors: [{ messageId: "attribute" }] },
    { code: "const a = <p>Välkommen</p>;", errors: [{ messageId: "text" }] },
  ],
});

tester.run("no-static-style", plugin.rules["no-static-style"], {
  valid: [
    { code: "const a = <div class=\"meter\" />;" },
    { code: 'const a = <div style={{ "--v": `${pct()}%` }} />;' },
    { code: "const a = <div style={styles()} />;" },
  ],
  invalid: [
    { code: 'const a = <div style="color: red" />;', errors: [{ messageId: "style" }] },
    { code: 'const a = <div style={{ "--v": "52%" }} />;', errors: [{ messageId: "style" }] },
    { code: 'const a = <div style={{ width: 4, "margin-top": "2px" }} />;', errors: [{ messageId: "style" }] },
    { code: "const a = <div style={`top: 2px`} />;", errors: [{ messageId: "style" }] },
  ],
});
