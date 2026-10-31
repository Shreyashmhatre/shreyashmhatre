"use strict";
const $ = (id) => document.getElementById(id);
let token = null;
let events = [];
let streamAbort = null;
let polling = null;
let refreshing = false;

function notice(message, error = false) {
  $("notice").textContent = message;
  $("notice").classList.toggle("error", error);
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}`, ...options.headers },
  });
  if (response.status === 401 && path !== "/api/admin/login") logout("Session expired. Sign in again.");
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(typeof body.detail === "string" ? body.detail : `Request failed (${response.status})`);
  }
  return response.json();
}

function renderSummary(data) {
  const actions = data.actions || {};
  $("total").textContent = data.requests.toLocaleString();
  $("allowed").textContent = (actions.allow || 0).toLocaleString();
  $("prevented").textContent = ((actions.block || 0) + (actions.deny || 0) + (actions.throttle || 0)).toLocaleString();
  $("latency").textContent = `${data.avg_inspection_ms.toFixed(1)} ms`;
  if (data.model) {
    $("model").textContent = data.model.loaded ? "Isolation Forest + rules" : "Rules only · model not trained";
    $("state").textContent = data.state_backend === "redis" ? "Redis · shared" : "In-memory · single worker";
  }
  $("outcomes").replaceChildren();
  for (const action of ["allow", "deny", "throttle", "block", "error"]) {
    const row = document.createElement("div"); row.className = "outcome";
    const label = document.createElement("span"); label.textContent = action[0].toUpperCase() + action.slice(1);
    const track = document.createElement("div"); track.className = "track";
    const bar = document.createElement("div"); bar.className = `bar ${action}`;
    // Width is numeric, derived only from counters returned by our API.
    bar.style.width = `${Math.min(100, (actions[action] || 0) / Math.max(1, data.requests) * 100)}%`;
    track.append(bar);
    const count = document.createElement("b"); count.textContent = (actions[action] || 0).toLocaleString();
    row.append(label, track, count); $("outcomes").append(row);
  }
}

function cell(text, className = "") {
  const td = document.createElement("td"); td.textContent = text; td.className = className; return td;
}

function renderEvents() {
  const filtered = events.filter((e) => $("filter").value === "all" || e.action === $("filter").value);
  $("event-count").textContent = filtered.length;
  $("event-rows").replaceChildren();
  if (!filtered.length) {
    const row = document.createElement("tr"); const td = cell("No matching requests yet. Run the local traffic simulator.", "empty");
    td.colSpan = 7; row.append(td); $("event-rows").append(row);
  }
  for (const event of filtered) {
    const row = document.createElement("tr");
    const request = cell("");
    const method = document.createElement("span"); method.className = "method"; method.textContent = event.method;
    request.append(method, document.createTextNode(event.path));
    const action = cell(""); const badge = document.createElement("span");
    const known = ["allow", "block", "throttle", "deny", "error", "admin_release"];
    badge.className = `badge ${known.includes(event.action) ? event.action : "error"}`;
    badge.textContent = event.action; action.append(badge);
    row.append(cell(new Date(event.timestamp * 1000).toLocaleTimeString()), request, cell(event.identity),
      cell(`${event.risk_score}/100`, `risk ${event.risk_score >= 71 ? "high" : event.risk_score >= 31 ? "medium" : ""}`),
      action, cell(event.status_code), cell(event.reasons.join(", ")));
    row.title = `Request ${event.id} · total ${event.total_ms} ms · inspection ${event.inspection_ms} ms`;
    $("event-rows").append(row);
  }
}

function renderQuarantines(items) {
  $("quarantine-list").replaceChildren();
  if (!items.length) { const p = document.createElement("p"); p.className = "empty"; p.textContent = "All clear. No active quarantines."; $("quarantine-list").append(p); }
  for (const item of items) {
    const row = document.createElement("div"); row.className = "quarantine";
    const label = document.createElement("div"); label.textContent = item.identity;
    const expiry = document.createElement("small"); expiry.textContent = `Expires ${new Date(item.expires_at * 1000).toLocaleTimeString()}`; label.append(expiry);
    const button = document.createElement("button"); button.textContent = "Release identity";
    button.addEventListener("click", async () => {
      button.disabled = true;
      try { await api("/api/quarantines/release", { method: "POST", body: JSON.stringify({ identity: item.identity }) }); await refresh(); }
      catch (error) { notice(error.message, true); button.disabled = false; }
    });
    row.append(label, button); $("quarantine-list").append(row);
  }
}

async function refresh() {
  if (!token || refreshing) return;
  refreshing = true;
  try {
    const [summary, rows, quarantines] = await Promise.all([api("/api/summary"), api("/api/events"), api("/api/quarantines")]);
    if (!token) return;
    renderSummary(summary); events = rows; renderEvents(); renderQuarantines(quarantines);
    $("connection").textContent = "● Connected";
    notice(`Live telemetry · ${summary.model.loaded ? "Model: " + summary.model.version + " · " + summary.model.training_source : "Rules-only mode; train a model to enable ML"}. Last updated ${new Date().toLocaleTimeString()}.`);
  } catch (error) { if (token) { notice(error.message, true); $("connection").textContent = "Connection interrupted"; } }
  finally { refreshing = false; }
}

async function startStream() {
  streamAbort = new AbortController();
  try {
    const response = await fetch("/api/stream", { headers: { Authorization: `Bearer ${token}` }, signal: streamAbort.signal });
    if (!response.ok || !response.body) throw new Error("Live stream unavailable; polling remains active.");
    const reader = response.body.getReader(); const decoder = new TextDecoder(); let buffer = "";
    while (token) {
      const { done, value } = await reader.read(); if (done) break;
      buffer += decoder.decode(value, { stream: true });
      let boundary;
      while ((boundary = buffer.indexOf("\n\n")) !== -1) {
        const message = buffer.slice(0, boundary); buffer = buffer.slice(boundary + 2);
        const data = message.split("\n").find((line) => line.startsWith("data: "));
        if (data && token) renderSummary(JSON.parse(data.slice(6)));
      }
    }
  } catch (error) { if (error.name !== "AbortError" && token) console.warn(error.message); }
}

function logout(message = "Signed out. Authenticate to view telemetry.") {
  token = null; streamAbort?.abort(); clearInterval(polling);
  events = []; renderEvents(); $("login-panel").hidden = false; $("logout").hidden = true;
  $("connection").textContent = "Not connected";
  for (const id of ["total", "allowed", "prevented", "latency", "model", "state"]) $(id).textContent = "—";
  $("outcomes").replaceChildren(); $("quarantine-list").replaceChildren(); notice(message);
}

$("login-form").addEventListener("submit", async (event) => {
  event.preventDefault(); $("login-error").textContent = "";
  const button = event.target.querySelector("button"); button.disabled = true;
  try {
    const result = await api("/api/admin/login", { method: "POST", body: JSON.stringify({ username: $("username").value, password: $("password").value }) });
    token = result.access_token; $("password").value = "";
    $("login-panel").hidden = true; $("logout").hidden = false;
    await refresh(); polling = setInterval(refresh, 5000); startStream();
  } catch (error) { $("login-error").textContent = error.message; }
  finally { button.disabled = false; }
});
$("logout").addEventListener("click", () => logout());
$("filter").addEventListener("change", renderEvents);
