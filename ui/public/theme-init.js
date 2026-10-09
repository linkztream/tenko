// Applies the remembered theme, density and address emphasis before the first paint, so
// a dark choice never flashes light. A file rather than an inline script: the server's
// Content Security Policy allows scripts from the same origin only.
(function () {
  try {
    var root = document.documentElement;
    var theme = localStorage.getItem("tenko-theme");
    if (theme === "light" || theme === "dark") root.dataset.theme = theme;
    var density = localStorage.getItem("tenko-density");
    if (density === "dense" || density === "comfortable") root.dataset.density = density;
    if (localStorage.getItem("tenko-emphasize") === "host") root.dataset.emphasize = "host";
  } catch (e) {
    // Storage can be unavailable (private windows, blocked site data); defaults apply.
  }
})();
