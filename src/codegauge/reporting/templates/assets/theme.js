(function () {
  var root = document.documentElement;
  var key = "codegauge-theme";
  var states = ["dark", "light", "auto"];
  var stored = "dark";
  try {
    stored = window.localStorage.getItem(key) || "dark";
  } catch (e) {
    stored = "dark";
  }
  if (states.indexOf(stored) < 0) {
    stored = "dark";
  }
  root.setAttribute("data-theme", stored);

  function applyLabel(button) {
    var current = root.getAttribute("data-theme") || "dark";
    button.textContent = "Theme: " + current.charAt(0).toUpperCase() + current.slice(1);
  }

  window.addEventListener("DOMContentLoaded", function () {
    var button = document.querySelector("[data-theme-toggle]");
    if (!button) return;
    applyLabel(button);
    button.addEventListener("click", function () {
      var current = root.getAttribute("data-theme") || "dark";
      var index = states.indexOf(current);
      if (index < 0) index = 0;
      var next = states[(index + 1) % states.length];
      root.setAttribute("data-theme", next);
      try {
        window.localStorage.setItem(key, next);
      } catch (e) {
        // ignore localStorage failures
      }
      applyLabel(button);
    });
  });
})();
