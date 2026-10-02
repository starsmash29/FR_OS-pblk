// Confirmation prompts for destructive form submits.
//
// A form that should ask first carries `data-confirm="<question>"`; with
// `data-confirm-when-checked="<checkbox name>"` it asks only while that
// checkbox is ticked. This replaces inline `onsubmit="return confirm(...)"`
// handlers, so the CSP can forbid inline script entirely
// (script-src 'self', review v0.2.0 R15). The question is plain text in an
// attribute, never JavaScript, so a value in it can't become code.
(function () {
  "use strict";
  document.addEventListener("submit", function (event) {
    var form = event.target;
    if (!(form instanceof HTMLFormElement)) {
      return;
    }
    var question = form.getAttribute("data-confirm");
    if (question === null) {
      return;
    }
    var gate = form.getAttribute("data-confirm-when-checked");
    if (gate !== null) {
      var box = form.elements.namedItem(gate);
      if (!box || !box.checked) {
        return;
      }
    }
    if (!window.confirm(question)) {
      event.preventDefault();
    }
  });
})();
