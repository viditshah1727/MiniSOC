/* MiniSOC shared front-end helpers: API fetch (with CSRF), formatting,
   badges, toasts, the simulate button, and the auto-refresh toggle. */

const CSRF_TOKEN = document.querySelector('meta[name="csrf-token"]')?.content || "";

/* ---------- API helpers ---------- */

async function apiGet(url) {
  const res = await fetch(url, { headers: { "Accept": "application/json" } });
  if (res.status === 401) { window.location = "/login"; throw new Error("unauthenticated"); }
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || `HTTP ${res.status}`);
  return res.json();
}

async function apiSend(url, method, body) {
  const res = await fetch(url, {
    method,
    headers: {
      "Content-Type": "application/json",
      "Accept": "application/json",
      "X-CSRF-Token": CSRF_TOKEN,
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (res.status === 401) { window.location = "/login"; throw new Error("unauthenticated"); }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

/* ---------- formatting ---------- */

/* Escape untrusted strings before inserting into innerHTML (XSS defence). */
function esc(value) {
  if (value === null || value === undefined) return "";
  return String(value)
    .replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;").replaceAll("'", "&#39;");
}

/* Backend timestamps are naive UTC; append Z so the browser localises them. */
function parseTs(iso) {
  if (!iso) return null;
  return new Date(iso.endsWith("Z") || iso.includes("+") ? iso : iso + "Z");
}

function fmtTime(iso) {
  const d = parseTs(iso);
  if (!d) return "—";
  return d.toLocaleString(undefined, {
    month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
  });
}

function timeAgo(iso) {
  const d = parseTs(iso);
  if (!d) return "—";
  const secs = Math.max(0, (Date.now() - d.getTime()) / 1000);
  if (secs < 60) return `${Math.floor(secs)}s ago`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`;
  return `${Math.floor(secs / 86400)}d ago`;
}

function sevBadge(sev) {
  return `<span class="badge sev-${esc(sev)}">${esc(sev)}</span>`;
}

function statusBadge(status) {
  const label = String(status || "").replace("_", " ");
  return `<span class="badge st-${esc(status)}">${esc(label)}</span>`;
}

/* ---------- toasts ---------- */

function toast(message, kind = "") {
  const zone = document.getElementById("toast-zone");
  if (!zone) return;
  const el = document.createElement("div");
  el.className = `toast ${kind}`;
  el.innerHTML = message;               // callers pass trusted/escaped HTML
  zone.appendChild(el);
  setTimeout(() => el.remove(), 6000);
}

/* ---------- simulate button + refresh bus ---------- */

/* Pages register a loader; the simulate button and auto-refresh reuse it. */
function onRefresh(fn) {
  window._refreshFns = window._refreshFns || [];
  window._refreshFns.push(fn);
}

function triggerRefresh() {
  (window._refreshFns || []).forEach((fn) => fn());
}

document.getElementById("btn-simulate")?.addEventListener("click", async (ev) => {
  const btn = ev.currentTarget;
  btn.disabled = true;
  try {
    const result = await apiSend("/api/simulate", "POST", {});
    const scenario = esc(result.scenario.replaceAll("_", " "));
    if (result.alerts_created > 0) {
      const alerts = result.alerts
        .map((a) => `${sevBadge(a.severity)} ${esc(a.title)}`).join("<br>");
      toast(`Simulated <b>${scenario}</b>: ${result.events_created} event(s) → ` +
            `<b>${result.alerts_created} alert(s)</b><br>${alerts}`, "alert");
    } else {
      toast(`Simulated <b>${scenario}</b>: ${result.events_created} event(s), ` +
            `no detection rule matched.`, "ok");
    }
    triggerRefresh();
  } catch (err) {
    toast(`Simulation failed: ${esc(err.message)}`, "alert");
  } finally {
    btn.disabled = false;
  }
});

/* Auto-refresh toggle (persists across pages via localStorage). */
(function initAutoRefresh() {
  const box = document.getElementById("auto-refresh");
  if (!box) return;
  let timer = null;
  const apply = () => {
    if (timer) { clearInterval(timer); timer = null; }
    if (box.checked) timer = setInterval(triggerRefresh, 10000);
    localStorage.setItem("minisoc.autorefresh", box.checked ? "1" : "0");
  };
  box.checked = localStorage.getItem("minisoc.autorefresh") === "1";
  box.addEventListener("change", apply);
  apply();
})();
