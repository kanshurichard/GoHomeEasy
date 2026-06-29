package gohomeeasy

import "fmt"

func renderDashboardHTML(mode string, showLogin bool) string {
	view := "dashboard"
	if showLogin {
		view = "login"
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>GoHomeEasy Dashboard</title>
    <style>
      body {
        margin: 0;
        font-family: "Avenir Next", "Segoe UI", sans-serif;
        background: linear-gradient(160deg, #020617 0%%, #0f172a 50%%, #1e293b 100%%);
        color: #e2e8f0;
      }
      .wrap {
        width: min(1120px, calc(100vw - 32px));
        margin: 28px auto 48px;
      }
      .card {
        background: rgba(15, 23, 42, 0.82);
        border: 1px solid rgba(148, 163, 184, 0.18);
        border-radius: 24px;
        box-shadow: 0 20px 60px rgba(2, 6, 23, 0.4);
        padding: 24px;
      }
      .hero {
        margin-bottom: 18px;
      }
      .pill {
        display: inline-block;
        padding: 8px 14px;
        border-radius: 999px;
        background: rgba(15, 23, 42, 0.8);
        border: 1px solid rgba(148, 163, 184, 0.18);
      }
      .grid {
        display: grid;
        gap: 18px;
      }
      .two {
        grid-template-columns: repeat(2, minmax(0, 1fr));
      }
      .notice {
        margin-top: 14px;
        padding: 14px 16px;
        border-radius: 16px;
        background: rgba(15, 23, 42, 0.58);
        border: 1px solid rgba(148, 163, 184, 0.18);
        color: #94a3b8;
      }
      .warn {
        border-color: rgba(249, 115, 22, 0.28);
      }
      code {
        color: #22d3ee;
        word-break: break-all;
      }
      button {
        appearance: none;
        border: 0;
        border-radius: 999px;
        padding: 10px 16px;
        font: inherit;
        font-weight: 600;
        cursor: pointer;
        color: white;
        background: linear-gradient(135deg, #f97316, #fb923c);
      }
      button.secondary {
        background: rgba(148, 163, 184, 0.14);
      }
      button.danger {
        background: linear-gradient(135deg, #ef4444, #fb7185);
      }
      button:disabled {
        cursor: not-allowed;
        opacity: 0.45;
      }
      table {
        width: 100%%;
        border-collapse: collapse;
        min-width: 760px;
      }
      th, td {
        text-align: left;
        padding: 12px 10px;
        border-bottom: 1px solid rgba(148, 163, 184, 0.12);
        vertical-align: top;
      }
      th {
        color: #94a3b8;
        font-size: 0.76rem;
        text-transform: uppercase;
        letter-spacing: 0.08em;
      }
      .table-wrap {
        overflow-x: auto;
      }
      .tag {
        display: inline-block;
        padding: 6px 10px;
        border-radius: 999px;
        font-size: 0.78rem;
        text-transform: uppercase;
        font-weight: 700;
      }
      .tag.ss {
        color: #34d399;
        background: rgba(52, 211, 153, 0.14);
      }
      .tag.site {
        color: #22d3ee;
        background: rgba(34, 211, 238, 0.14);
      }
      .login-wrap {
        width: min(460px, calc(100vw - 32px));
        margin: 72px auto;
      }
      .token-input {
        width: 100%%;
        box-sizing: border-box;
        border-radius: 16px;
        padding: 14px 16px;
        background: rgba(15, 23, 42, 0.62);
        color: #e2e8f0;
        border: 1px solid rgba(148, 163, 184, 0.2);
        margin-top: 14px;
      }
      .error {
        color: #fecaca;
        margin-top: 12px;
      }
      @media (max-width: 900px) {
        .two {
          grid-template-columns: 1fr;
        }
      }
    </style>
  </head>
  <body>
    <div id="app" data-view="%s" data-mode="%s"></div>
    <script>
      var app = document.getElementById("app");
      var initialView = app.getAttribute("data-view");
      var initialMode = app.getAttribute("data-mode") || "";

      function escapeHtml(value) {
        return String(value)
          .replace(/&/g, "&amp;")
          .replace(/</g, "&lt;")
          .replace(/>/g, "&gt;")
          .replace(/"/g, "&quot;")
          .replace(/'/g, "&#39;");
      }

      function renderLogin(errorMessage) {
        errorMessage = errorMessage || "";
        app.innerHTML = ''
          + '<div class="login-wrap">'
          + '  <div class="card">'
          + '    <div class="pill">Access token required</div>'
          + '    <h1>GoHomeEasy Dashboard</h1>'
          + '    <p>Use READ_TOKEN for read-only access or WRITE_TOKEN for full control. The token will be exchanged for a short-lived session cookie.</p>'
          + '    <form id="login-form">'
          + '      <input class="token-input" id="token-input" type="password" autocomplete="off" placeholder="Paste READ_TOKEN or WRITE_TOKEN">'
          + '      <div style="margin-top: 14px;"><button type="submit">Enter Dashboard</button></div>'
          + '    </form>'
          + (errorMessage ? '<div class="error">' + escapeHtml(errorMessage) + '</div>' : '')
          + '  </div>'
          + '</div>';

        document.getElementById("login-form").addEventListener("submit", function (event) {
          event.preventDefault();
          var token = document.getElementById("token-input").value.trim();
          if (!token) {
            renderLogin("Token is required.");
            return;
          }
          window.location.href = "/dashboard?api_key=" + encodeURIComponent(token);
        });
      }

      function renderShell(mode) {
        var readOnly = mode !== "write";
        app.innerHTML = ''
          + '<main class="wrap">'
          + '  <section class="card hero">'
          + '    <div class="pill">' + (readOnly ? 'Read-Only Mode' : 'Admin Mode') + '</div>'
          + '    <h1>GoHomeEasy Control Panel</h1>'
          + '    <p>Review Shadowsocks nodes, inspect site records, and manage subscription exports without leaving the browser.</p>'
          + '    <div id="status-text">Loading records…</div>'
          + '  </section>'
          + '  <section class="grid two">'
          + '    <div class="card">'
          + '      <h2>Subscription URLs</h2>'
          + '      <div id="links"></div>'
          + '      <div id="legacy-note" class="notice warn" hidden></div>'
          + '    </div>'
          + '    <div class="card">'
          + '      <h2>Session</h2>'
          + '      <div class="notice">Open /dashboard?api_key=&lt;TOKEN&gt; again to switch between read-only and write access.</div>'
          + '      <div class="notice">Only type=ss records enter subscriptions. type=site records are shown for reference.</div>'
          + '      <div style="margin-top: 16px;"><button class="secondary" id="refresh-btn" type="button">Refresh</button></div>'
          + '    </div>'
          + '  </section>'
          + '  <section class="card" style="margin-top: 18px;">'
          + '    <div style="display:flex;justify-content:space-between;align-items:center;"><h2>Records</h2><div id="record-count"></div></div>'
          + '    <div class="table-wrap">'
          + '      <table>'
          + '        <thead>'
          + '          <tr><th>Rule</th><th>Type</th><th>Address</th><th>Cipher</th><th>Password</th><th>Updated</th><th>Source Time</th><th>Action</th></tr>'
          + '        </thead>'
          + '        <tbody id="records-body"><tr><td colspan="8">Loading…</td></tr></tbody>'
          + '      </table>'
          + '    </div>'
          + '  </section>'
          + '</main>';

        document.getElementById("refresh-btn").addEventListener("click", function () {
          loadRecords(mode);
        });
      }

      function renderLinks(payload) {
        var linksNode = document.getElementById("links");
        var entries = [
          ["Shadowsocks", payload.subscriptionUrls.ss || ""],
          ["Clash", payload.subscriptionUrls.clash || ""]
        ];
        linksNode.innerHTML = entries.map(function (entry) {
          return ''
            + '<div class="sub-link">'
            + '  <div><strong>' + escapeHtml(entry[0]) + '</strong><div><code>' + escapeHtml(entry[1] || 'Unavailable') + '</code></div></div>'
            + '  <button class="secondary" type="button" data-copy="' + escapeHtml(entry[1] || '') + '"' + (entry[1] ? '' : ' disabled') + '>Copy</button>'
            + '</div>';
        }).join('');

        Array.prototype.forEach.call(linksNode.querySelectorAll("[data-copy]"), function (button) {
          button.addEventListener("click", async function () {
            var value = button.getAttribute("data-copy");
            if (!value) return;
            await navigator.clipboard.writeText(value);
            button.textContent = "Copied";
            window.setTimeout(function () { button.textContent = "Copy"; }, 1200);
          });
        });
      }

      function renderRecords(records, canDelete) {
        var body = document.getElementById("records-body");
        if (!records.length) {
          body.innerHTML = '<tr><td colspan="8">No v2 records yet. Lucky can create them on the next valid webhook.</td></tr>';
          return;
        }

        body.innerHTML = records.map(function (record) {
          return ''
            + '<tr>'
            + '  <td><strong>' + escapeHtml(record.ruleName) + '</strong></td>'
            + '  <td><span class="tag ' + escapeHtml(record.type) + '">' + escapeHtml(record.type) + '</span></td>'
            + '  <td><code>' + escapeHtml(record.host) + ':' + escapeHtml(record.port) + '</code></td>'
            + '  <td>' + (record.method ? '<code>' + escapeHtml(record.method) + '</code>' : '<span style="color:#94a3b8;">Not used</span>') + '</td>'
            + '  <td>' + (record.password ? '<span class="password-value">Hidden</span> <button class="secondary" type="button" data-password="' + escapeHtml(record.password) + '">Reveal</button>' : 'None') + '</td>'
            + '  <td>' + escapeHtml(record.updatedAt) + '</td>'
            + '  <td>' + escapeHtml(record.sourceTime || '—') + '</td>'
            + '  <td><button class="danger" type="button" data-delete="' + escapeHtml(record.ruleName) + '"' + (canDelete ? '' : ' disabled') + '>Delete</button></td>'
            + '</tr>';
        }).join('');

        Array.prototype.forEach.call(body.querySelectorAll("[data-password]"), function (button) {
          button.addEventListener("click", function () {
            var valueNode = button.parentElement.querySelector(".password-value");
            var visible = button.getAttribute("data-state") === "visible";
            valueNode.textContent = visible ? "Hidden" : button.getAttribute("data-password");
            button.setAttribute("data-state", visible ? "hidden" : "visible");
            button.textContent = visible ? "Reveal" : "Hide";
          });
        });

        Array.prototype.forEach.call(body.querySelectorAll("[data-delete]"), function (button) {
          button.addEventListener("click", async function () {
            var ruleName = button.getAttribute("data-delete");
            if (!ruleName || !window.confirm('Delete record "' + ruleName + '"?')) {
              return;
            }

            var response = await fetch("/api/delete", {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
                "Accept": "application/json"
              },
              body: JSON.stringify({ ruleName: ruleName })
            });

            if (response.status === 204) {
              await loadRecords(initialMode || "read");
              return;
            }

            alert(await response.text());
          });
        });
      }

      async function loadRecords(modeHint) {
        var response = await fetch("/api/records", {
          headers: { "Accept": "application/json" }
        });

        if (response.status === 401) {
          renderLogin("Session expired. Re-enter your token.");
          return;
        }

        var contentType = response.headers.get("content-type") || "";
        var payload = contentType.indexOf("application/json") >= 0
          ? await response.json()
          : { error: await response.text() };

        if (!response.ok) {
          renderLogin(payload.error || "Dashboard is unavailable.");
          return;
        }

        var mode = payload.mode || modeHint || "read";
        renderShell(mode);
        renderLinks(payload);
        renderRecords(payload.records || [], mode === "write");
        document.getElementById("record-count").textContent = String(payload.records.length) + " record" + (payload.records.length === 1 ? "" : "s");
        document.getElementById("status-text").textContent = mode === "write" ? "Admin session active" : "Read-only session active";

        var legacyNode = document.getElementById("legacy-note");
        if (payload.legacyFallbackActive) {
          legacyNode.hidden = false;
          legacyNode.textContent = "No v2 Shadowsocks records exist yet. Subscription downloads are still using legacy fallback content until Lucky sends the next valid SS webhook.";
        } else {
          legacyNode.hidden = true;
        }
      }

      if (initialView === "login") {
        renderLogin("");
      } else {
        renderShell(initialMode || "read");
        loadRecords(initialMode || "read").catch(function (error) {
          console.error(error);
          renderLogin("Failed to load dashboard.");
        });
      }
    </script>
  </body>
</html>`, view, mode)
}
