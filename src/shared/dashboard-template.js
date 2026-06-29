function escapeScriptString(value) {
  return String(value)
    .replace(/\\/g, "\\\\")
    .replace(/"/g, '\\"')
    .replace(/\n/g, "\\n");
}

export function renderDashboardHtml({ mode = null, showLogin = false } = {}) {
  const initialMode = mode ? `"${escapeScriptString(mode)}"` : "null";
  const view = showLogin ? "login" : "dashboard";

  return `<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>GoHomeEasy Control Panel</title>
    <style>
      :root {
        --bg: #0f172a;
        --bg-soft: #15223b;
        --card: rgba(15, 23, 42, 0.78);
        --card-border: rgba(148, 163, 184, 0.2);
        --text: #e2e8f0;
        --muted: #94a3b8;
        --accent: #f97316;
        --accent-2: #22d3ee;
        --danger: #fb7185;
        --success: #34d399;
        --shadow: 0 25px 80px rgba(2, 6, 23, 0.4);
        --radius: 24px;
        --font: "Avenir Next", "Segoe UI", "Helvetica Neue", sans-serif;
      }

      * {
        box-sizing: border-box;
      }

      body {
        margin: 0;
        min-height: 100vh;
        font-family: var(--font);
        color: var(--text);
        background:
          radial-gradient(circle at top left, rgba(34, 211, 238, 0.18), transparent 30%),
          radial-gradient(circle at bottom right, rgba(249, 115, 22, 0.22), transparent 34%),
          linear-gradient(160deg, #020617 0%, #0f172a 45%, #1e293b 100%);
      }

      body::before {
        content: "";
        position: fixed;
        inset: 0;
        background-image:
          linear-gradient(rgba(148, 163, 184, 0.05) 1px, transparent 1px),
          linear-gradient(90deg, rgba(148, 163, 184, 0.05) 1px, transparent 1px);
        background-size: 44px 44px;
        pointer-events: none;
        mask-image: linear-gradient(to bottom, rgba(0, 0, 0, 0.45), transparent 90%);
      }

      .shell {
        position: relative;
        width: min(1180px, calc(100vw - 32px));
        margin: 32px auto 56px;
      }

      .hero {
        display: flex;
        gap: 18px;
        align-items: flex-start;
        justify-content: space-between;
        padding: 28px 30px;
        border: 1px solid var(--card-border);
        border-radius: calc(var(--radius) + 6px);
        background: linear-gradient(160deg, rgba(15, 23, 42, 0.84), rgba(30, 41, 59, 0.68));
        box-shadow: var(--shadow);
        backdrop-filter: blur(24px);
      }

      .hero h1 {
        margin: 0;
        font-size: clamp(2rem, 3vw, 3rem);
        letter-spacing: -0.04em;
      }

      .hero p {
        margin: 10px 0 0;
        max-width: 720px;
        color: var(--muted);
        line-height: 1.55;
      }

      .pill {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        padding: 8px 14px;
        border-radius: 999px;
        border: 1px solid rgba(255, 255, 255, 0.12);
        background: rgba(15, 23, 42, 0.72);
        color: #f8fafc;
        font-size: 0.92rem;
      }

      .grid {
        display: grid;
        gap: 18px;
        margin-top: 18px;
      }

      .grid.cols-2 {
        grid-template-columns: repeat(2, minmax(0, 1fr));
      }

      .card {
        border: 1px solid var(--card-border);
        border-radius: var(--radius);
        background: var(--card);
        box-shadow: var(--shadow);
        backdrop-filter: blur(18px);
        overflow: hidden;
      }

      .card-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 12px;
        padding: 22px 24px 0;
      }

      .card-header h2 {
        margin: 0;
        font-size: 1.15rem;
        letter-spacing: -0.03em;
      }

      .card-body {
        padding: 20px 24px 24px;
      }

      .link-grid {
        display: grid;
        gap: 14px;
      }

      .sub-link {
        display: flex;
        gap: 12px;
        align-items: center;
        justify-content: space-between;
        border: 1px solid rgba(148, 163, 184, 0.18);
        border-radius: 18px;
        padding: 16px 18px;
        background: rgba(15, 23, 42, 0.58);
      }

      .sub-link strong {
        display: block;
        font-size: 0.98rem;
      }

      .sub-link code {
        display: block;
        margin-top: 8px;
        color: var(--accent-2);
        font-size: 0.88rem;
        overflow-wrap: anywhere;
      }

      .btn-row {
        display: flex;
        gap: 10px;
        flex-wrap: wrap;
      }

      button,
      .token-submit {
        appearance: none;
        border: 0;
        cursor: pointer;
        padding: 11px 16px;
        border-radius: 999px;
        font: inherit;
        font-weight: 600;
        background: linear-gradient(135deg, var(--accent), #fb923c);
        color: white;
        transition: transform 140ms ease, opacity 140ms ease, box-shadow 140ms ease;
        box-shadow: 0 12px 30px rgba(249, 115, 22, 0.28);
      }

      button:hover,
      .token-submit:hover {
        transform: translateY(-1px);
      }

      button.secondary {
        background: rgba(148, 163, 184, 0.12);
        color: var(--text);
        box-shadow: none;
      }

      button.danger {
        background: linear-gradient(135deg, #ef4444, var(--danger));
        box-shadow: 0 12px 30px rgba(251, 113, 133, 0.24);
      }

      button:disabled {
        cursor: not-allowed;
        opacity: 0.45;
        transform: none;
        box-shadow: none;
      }

      .notice {
        margin-top: 16px;
        padding: 15px 18px;
        border-radius: 18px;
        border: 1px solid rgba(34, 211, 238, 0.18);
        background: rgba(15, 23, 42, 0.62);
        color: var(--muted);
        line-height: 1.55;
      }

      .notice.warn {
        border-color: rgba(249, 115, 22, 0.24);
      }

      .table-wrap {
        overflow-x: auto;
      }

      table {
        width: 100%;
        border-collapse: collapse;
        min-width: 760px;
      }

      th,
      td {
        padding: 14px 12px;
        border-bottom: 1px solid rgba(148, 163, 184, 0.12);
        text-align: left;
        font-size: 0.94rem;
        vertical-align: top;
      }

      th {
        color: var(--muted);
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        font-size: 0.75rem;
      }

      td code {
        color: var(--accent-2);
      }

      .tag {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        padding: 6px 10px;
        border-radius: 999px;
        font-size: 0.78rem;
        font-weight: 700;
        letter-spacing: 0.04em;
        text-transform: uppercase;
      }

      .tag.ss {
        background: rgba(52, 211, 153, 0.14);
        color: var(--success);
      }

      .tag.site {
        background: rgba(34, 211, 238, 0.14);
        color: var(--accent-2);
      }

      .status {
        display: inline-block;
        margin-left: 10px;
        color: var(--muted);
        font-size: 0.9rem;
      }

      .password {
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      }

      .password button {
        padding: 8px 12px;
        font-size: 0.85rem;
      }

      .password-value {
        display: inline-block;
        max-width: 240px;
        overflow-wrap: anywhere;
        margin-right: 10px;
      }

      .empty {
        padding: 42px 16px;
        color: var(--muted);
        text-align: center;
      }

      .login-wrap {
        display: grid;
        place-items: center;
        min-height: calc(100vh - 48px);
        padding: 24px;
      }

      .login-card {
        width: min(460px, 100%);
        border-radius: calc(var(--radius) + 8px);
        background: linear-gradient(180deg, rgba(15, 23, 42, 0.92), rgba(30, 41, 59, 0.78));
        border: 1px solid var(--card-border);
        box-shadow: var(--shadow);
        padding: 30px;
      }

      .login-card h1 {
        margin: 0;
        font-size: 2rem;
        letter-spacing: -0.04em;
      }

      .login-card p {
        color: var(--muted);
        line-height: 1.55;
      }

      .token-row {
        display: grid;
        gap: 14px;
      }

      .token-input {
        width: 100%;
        border-radius: 18px;
        border: 1px solid rgba(148, 163, 184, 0.25);
        background: rgba(15, 23, 42, 0.62);
        color: var(--text);
        padding: 16px 18px;
        font: inherit;
      }

      .error {
        color: #fecaca;
        margin-top: 14px;
      }

      @media (max-width: 900px) {
        .grid.cols-2 {
          grid-template-columns: 1fr;
        }

        .hero {
          flex-direction: column;
        }
      }
    </style>
  </head>
  <body>
    <div id="app" data-view="${view}" data-mode="${mode ? escapeScriptString(mode) : ""}"></div>
    <script>
      const initialMode = ${initialMode};
      const app = document.getElementById("app");
      const initialView = app.dataset.view;

      function escapeHtml(value) {
        return String(value)
          .replace(/&/g, "&amp;")
          .replace(/</g, "&lt;")
          .replace(/>/g, "&gt;")
          .replace(/"/g, "&quot;")
          .replace(/'/g, "&#39;");
      }

      function renderLogin(errorMessage = "") {
        app.innerHTML = \`
          <div class="login-wrap">
            <div class="login-card">
              <div class="pill">Access token required</div>
              <h1>GoHomeEasy Dashboard</h1>
              <p>Use <code>READ_TOKEN</code> for read-only access or <code>WRITE_TOKEN</code> for full control. The token will be exchanged for a short-lived session cookie.</p>
              <form class="token-row" id="login-form">
                <input class="token-input" id="token-input" type="password" autocomplete="off" placeholder="Paste READ_TOKEN or WRITE_TOKEN">
                <button class="token-submit" type="submit">Enter Dashboard</button>
              </form>
              \${errorMessage ? \`<div class="error">\${escapeHtml(errorMessage)}</div>\` : ""}
            </div>
          </div>
        \`;

        const form = document.getElementById("login-form");
        form.addEventListener("submit", (event) => {
          event.preventDefault();
          const token = document.getElementById("token-input").value.trim();
          if (!token) {
            renderLogin("Token is required.");
            return;
          }
          window.location.href = "/dashboard?api_key=" + encodeURIComponent(token);
        });
      }

      function renderDashboardShell(mode) {
        const readOnly = mode !== "write";
        app.innerHTML = \`
          <main class="shell">
            <section class="hero">
              <div>
                <div class="pill">\${readOnly ? "Read-Only Mode" : "Admin Mode"}</div>
                <h1>GoHomeEasy Control Panel</h1>
                <p>Review Shadowsocks nodes, inspect site records, and copy subscription URLs without leaving the browser.</p>
              </div>
              <div class="status" id="status-text">Loading records…</div>
            </section>

            <section class="grid cols-2">
              <div class="card">
                <div class="card-header">
                  <h2>Subscription URLs</h2>
                </div>
                <div class="card-body">
                  <div id="links" class="link-grid"></div>
                  <div id="legacy-note" class="notice warn" hidden></div>
                </div>
              </div>

              <div class="card">
                <div class="card-header">
                  <h2>Session</h2>
                </div>
                <div class="card-body">
                  <div class="notice">Dashboard mode is determined by your current session. Open <code>/dashboard?api_key=&lt;TOKEN&gt;</code> again to switch between read-only and write access.</div>
                  <div class="notice">Only <code>type=ss</code> records enter subscriptions. <code>type=site</code> records are displayed for reference and are never exported to clients.</div>
                  <div class="btn-row" style="margin-top: 16px;">
                    <button class="secondary" id="refresh-btn" type="button">Refresh</button>
                  </div>
                </div>
              </div>
            </section>

            <section class="card" style="margin-top: 18px;">
              <div class="card-header">
                <h2>Records</h2>
                <div class="status" id="record-count"></div>
              </div>
              <div class="card-body">
                <div class="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Rule</th>
                        <th>Type</th>
                        <th>Address</th>
                        <th>Cipher</th>
                        <th>Password</th>
                        <th>Updated</th>
                        <th>Source Time</th>
                        <th>Action</th>
                      </tr>
                    </thead>
                    <tbody id="records-body">
                      <tr><td class="empty" colspan="8">Loading…</td></tr>
                    </tbody>
                  </table>
                </div>
              </div>
            </section>
          </main>
        \`;

        document.getElementById("refresh-btn").addEventListener("click", () => loadRecords(mode));
      }

      async function loadRecords(modeHint) {
        const statusNode = document.getElementById("status-text");
        if (statusNode) {
          statusNode.textContent = "Refreshing…";
        }

        const response = await fetch("/api/records", {
          headers: {
            Accept: "application/json"
          }
        });

        if (response.status === 401) {
          renderLogin("Session expired. Re-enter your token.");
          return;
        }

        const contentType = response.headers.get("content-type") || "";
        const payload = contentType.includes("application/json")
          ? await response.json()
          : { error: await response.text() };

        if (!response.ok) {
          renderLogin(payload.error || "Dashboard is unavailable.");
          return;
        }

        const mode = payload.mode || modeHint || "read";
        renderDashboardShell(mode);
        hydrateLinks(payload);
        hydrateRecords(payload.records || [], mode === "write");

        const countNode = document.getElementById("record-count");
        countNode.textContent = \`\${payload.records.length} record\${payload.records.length === 1 ? "" : "s"}\`;

        const legacyNode = document.getElementById("legacy-note");
        if (payload.legacyFallbackActive) {
          legacyNode.hidden = false;
          legacyNode.textContent = "No v2 Shadowsocks records exist yet. Subscription downloads are still using legacy fallback content until Lucky sends the next valid SS webhook.";
        } else {
          legacyNode.hidden = true;
        }

        const statusNodeUpdated = document.getElementById("status-text");
        statusNodeUpdated.textContent = mode === "write" ? "Admin session active" : "Read-only session active";
      }

      function hydrateLinks(payload) {
        const linksNode = document.getElementById("links");
        const urls = payload.subscriptionUrls || {};
        const entries = [
          ["Shadowsocks", urls.ss || ""],
          ["Clash", urls.clash || ""]
        ];

        linksNode.innerHTML = entries.map(([label, url]) => \`
          <div class="sub-link">
            <div>
              <strong>\${escapeHtml(label)}</strong>
              <code>\${escapeHtml(url || "Unavailable")}</code>
            </div>
            <div class="btn-row">
              <button class="secondary" type="button" \${url ? "" : "disabled"} data-copy="\${escapeHtml(url || "")}">Copy</button>
            </div>
          </div>
        \`).join("");

        linksNode.querySelectorAll("[data-copy]").forEach((button) => {
          button.addEventListener("click", async () => {
            const value = button.getAttribute("data-copy");
            if (!value) {
              return;
            }
            await navigator.clipboard.writeText(value);
            button.textContent = "Copied";
            window.setTimeout(() => {
              button.textContent = "Copy";
            }, 1200);
          });
        });
      }

      function hydrateRecords(records, canDelete) {
        const body = document.getElementById("records-body");

        if (!records.length) {
          body.innerHTML = '<tr><td class="empty" colspan="8">No v2 records yet. Lucky can create them on the next valid webhook.</td></tr>';
          return;
        }

        body.innerHTML = records.map((record) => {
          const passwordText = record.password ? "Hidden" : "None";
          return \`
            <tr>
              <td><strong>\${escapeHtml(record.ruleName)}</strong></td>
              <td><span class="tag \${escapeHtml(record.type)}">\${escapeHtml(record.type)}</span></td>
              <td><code>\${escapeHtml(record.host)}:\${escapeHtml(record.port)}</code></td>
              <td>\${record.method ? \`<code>\${escapeHtml(record.method)}</code>\` : '<span class="status">Not used</span>'}</td>
              <td class="password">
                <span class="password-value" data-password-value>\${escapeHtml(passwordText)}</span>
                \${record.password ? \`<button class="secondary" type="button" data-password="\${escapeHtml(record.password)}">Reveal</button>\` : ""}
              </td>
              <td>\${escapeHtml(record.updatedAt)}</td>
              <td>\${escapeHtml(record.sourceTime || "—")}</td>
              <td>
                <button class="danger" type="button" data-delete="\${escapeHtml(record.ruleName)}" \${canDelete ? "" : "disabled"}>Delete</button>
              </td>
            </tr>
          \`;
        }).join("");

        body.querySelectorAll("[data-password]").forEach((button) => {
          button.addEventListener("click", () => {
            const valueNode = button.parentElement.querySelector("[data-password-value]");
            const isHidden = button.dataset.state !== "visible";
            valueNode.textContent = isHidden ? button.getAttribute("data-password") : "Hidden";
            button.dataset.state = isHidden ? "visible" : "hidden";
            button.textContent = isHidden ? "Hide" : "Reveal";
          });
        });

        body.querySelectorAll("[data-delete]").forEach((button) => {
          button.addEventListener("click", async () => {
            const ruleName = button.getAttribute("data-delete");
            if (!ruleName || !window.confirm(\`Delete record "\${ruleName}"?\`)) {
              return;
            }

            const response = await fetch("/api/delete", {
              body: JSON.stringify({ ruleName }),
              headers: {
                "Content-Type": "application/json",
                Accept: "application/json"
              },
              method: "POST"
            });

            if (response.status === 204) {
              await loadRecords(initialMode || "read");
              return;
            }

            const error = await response.text();
            alert(error || "Delete failed.");
          });
        });
      }

      if (initialView === "login") {
        renderLogin();
      } else {
        renderDashboardShell(initialMode || "read");
        loadRecords(initialMode || "read").catch((error) => {
          console.error(error);
          renderLogin("Failed to load dashboard.");
        });
      }
    </script>
  </body>
</html>`;
}
