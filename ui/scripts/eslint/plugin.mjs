// @ts-check
// Project rules of the Tenko DDI UI.
//
// - no-literal-ui-string: every UI string goes through the i18n layer under a stable key
//   (API-21). Flags JSX text and user-visible attributes that contain letters.
// - no-static-style: the server's Content Security Policy has no 'unsafe-inline', and
//   Solid compiles a constant `style` into the HTML template, where the browser would
//   block it. Use a class, or a dynamic value (set through the CSSOM).

/** Attributes whose value a person reads or hears. */
const VISIBLE_ATTRIBUTES = new Set([
  "title",
  "alt",
  "placeholder",
  "label",
  "aria-label",
  "aria-description",
  "aria-placeholder",
  "aria-roledescription",
  "aria-valuetext",
]);

const LETTER = /\p{L}/u;

/** @param {string} text */
function hasLetters(text) {
  return LETTER.test(text);
}

/**
 * @param {any} node
 * @returns {boolean}
 */
function isLiteralText(node) {
  if (!node) return false;
  if (node.type === "Literal") return typeof node.value === "string" && hasLetters(node.value);
  if (node.type === "TemplateLiteral") return node.quasis.some((/** @type {any} */ q) => hasLetters(q.value.cooked ?? ""));
  if (node.type === "ConditionalExpression") return isLiteralText(node.consequent) || isLiteralText(node.alternate);
  if (node.type === "LogicalExpression") return isLiteralText(node.right) || (node.operator !== "&&" && isLiteralText(node.left));
  return false;
}

/** @type {import("eslint").Rule.RuleModule} */
const noLiteralUiString = {
  meta: {
    type: "problem",
    docs: { description: "UI text must come from the language packs through t() or tx()" },
    messages: {
      text: "Literal UI text {{text}}: add a key to ui/i18n/en.xlf and sv.xlf and use t().",
      attribute: "Literal text in the {{name}} attribute: add a key to ui/i18n/en.xlf and sv.xlf and use t().",
    },
    schema: [],
  },
  create(context) {
    return {
      /** @param {any} node */
      JSXText(node) {
        const text = String(node.value);
        if (hasLetters(text)) {
          context.report({ node, messageId: "text", data: { text: JSON.stringify(text.trim().slice(0, 40)) } });
        }
      },
      /** @param {any} node */
      JSXExpressionContainer(node) {
        if (node.parent?.type === "JSXAttribute") return;
        if (isLiteralText(node.expression)) {
          context.report({ node, messageId: "text", data: { text: "in an expression" } });
        }
      },
      /** @param {any} node */
      JSXAttribute(node) {
        const name = node.name?.type === "JSXNamespacedName" ? `${node.name.namespace.name}:${node.name.name.name}` : node.name?.name;
        if (typeof name !== "string" || !VISIBLE_ATTRIBUTES.has(name)) return;
        const value = node.value;
        if (!value) return;
        const literal =
          (value.type === "Literal" && typeof value.value === "string" && hasLetters(value.value)) ||
          (value.type === "JSXExpressionContainer" && isLiteralText(value.expression));
        if (literal) context.report({ node, messageId: "attribute", data: { name } });
      },
    };
  },
};

/**
 * @param {any} node
 * @returns {boolean}
 */
function isConstant(node) {
  if (!node) return true;
  if (node.type === "Literal") return true;
  if (node.type === "TemplateLiteral") return node.expressions.length === 0;
  if (node.type === "UnaryExpression") return isConstant(node.argument);
  return false;
}

/** @type {import("eslint").Rule.RuleModule} */
const noStaticStyle = {
  meta: {
    type: "problem",
    docs: { description: "Constant style attributes are blocked by the Content Security Policy" },
    messages: {
      style:
        "A constant style ends up as an inline style attribute, which the Content Security Policy blocks. Use a class (or a dynamic custom property).",
    },
    schema: [],
  },
  create(context) {
    return {
      /** @param {any} node */
      JSXAttribute(node) {
        if (node.name?.name !== "style" || !node.value) return;
        const v = node.value;
        if (v.type === "Literal") {
          context.report({ node, messageId: "style" });
          return;
        }
        if (v.type !== "JSXExpressionContainer") return;
        const e = v.expression;
        if (isConstant(e) && e.type !== "JSXEmptyExpression") {
          context.report({ node, messageId: "style" });
          return;
        }
        if (e.type === "ObjectExpression" && e.properties.every((/** @type {any} */ p) => p.type === "Property" && isConstant(p.value))) {
          context.report({ node, messageId: "style" });
        }
      },
    };
  },
};

export default {
  meta: { name: "tenko" },
  rules: {
    "no-literal-ui-string": noLiteralUiString,
    "no-static-style": noStaticStyle,
  },
};
