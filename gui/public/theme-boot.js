// Apply an explicit light/dark choice before first paint. "system" leaves the
// attribute unset so color-scheme: light-dark follows the OS. Mirrors App.tsx.
(function () {
  try {
    var theme = localStorage.getItem("ocx-theme");
    if (theme === "light" || theme === "dark") {
      document.documentElement.setAttribute("data-theme", theme);
    }
  } catch (_) {
    // Storage can be unavailable in a restricted webview; React handles the fallback.
  }
})();
