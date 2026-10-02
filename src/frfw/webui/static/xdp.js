// XDP screen: the live log terminal fed by GET /xdp/logs/stream (SSE).
// A static file rather than an inline <script>, so the CSP can say
// script-src 'self' without 'unsafe-inline' (review v0.2.0 R15).
(function () {
  "use strict";

  var term = document.getElementById("xdp-terminal");
  var dot = document.getElementById("xdp-live-dot");
  var statusText = document.getElementById("xdp-live-status");
  var MAX_LINES = 300;
  var lineCount = 0;
  var placeholderCleared = false;

  function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  function formatEvent(ev) {
    if (ev.error) {
      return '<span class="t-drop">[error] ' + escapeHtml(ev.error) + "</span>";
    }
    var ts = ev.ts ? new Date(ev.ts * 1000).toLocaleTimeString() : "";
    return (
      '<span class="t-meta">[' + escapeHtml(ts) + "]</span> " +
      '<span class="t-drop">DROP</span> ' +
      escapeHtml(ev.saddr) + ":" + escapeHtml(ev.sport) + " &rarr; " +
      escapeHtml(ev.daddr) + ":" + escapeHtml(ev.dport) +
      " sni=<strong>" + escapeHtml(ev.sni) + "</strong>"
    );
  }

  function appendLine(html) {
    if (!placeholderCleared) {
      term.innerHTML = "";
      placeholderCleared = true;
    }
    var atBottom = term.scrollHeight - term.clientHeight <= term.scrollTop + 4;
    var row = document.createElement("div");
    row.innerHTML = html;
    term.appendChild(row);
    lineCount++;
    while (lineCount > MAX_LINES && term.firstChild) {
      term.removeChild(term.firstChild);
      lineCount--;
    }
    if (atBottom) {
      term.scrollTop = term.scrollHeight;
    }
  }

  function connect() {
    var source = new EventSource("/xdp/logs/stream");

    source.onopen = function () {
      dot.classList.add("live");
      statusText.textContent = "Live";
    };

    source.onmessage = function (event) {
      try {
        var parsed = JSON.parse(event.data);
        appendLine(formatEvent(parsed));
      } catch (err) {
        // Malformed line from the stream -- drop it rather than break the page.
      }
    };

    source.onerror = function () {
      dot.classList.remove("live");
      statusText.textContent = "Reconnecting…";
      // EventSource retries automatically; nothing else to do here.
    };
  }

  connect();
})();
