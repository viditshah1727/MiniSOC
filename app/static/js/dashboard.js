/* Dashboard: KPI cards, four charts, and two recent-activity tables.
   Every number here comes from the JSON API (i.e. the SQLite database). */

let timelineRange = "24h";

const timelineChart = makeTimelineChart(document.getElementById("chart-timeline"));
const severityChart = makeDonutChart(
  document.getElementById("chart-severity"),
  ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
  ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map((s) => PALETTE.severity[s]),
);
const topIpsChart = makeBarChart(document.getElementById("chart-topips"),
                                 { horizontal: true });
const categoriesChart = makeBarChart(document.getElementById("chart-categories"),
                                     { color: PALETTE.categorical });

async function loadKpis() {
  const s = await apiGet("/api/metrics/summary");
  document.getElementById("kpi-events").textContent = s.total_events;
  document.getElementById("kpi-critical").textContent = s.critical_alerts;
  document.getElementById("kpi-high").textContent = s.high_alerts;
  document.getElementById("kpi-incidents").textContent = s.active_incidents;
  document.getElementById("kpi-failed").textContent = s.failed_logins_24h;
  document.getElementById("kpi-ips").textContent = s.unique_source_ips_24h;
}

async function loadTimeline() {
  const t = await apiGet(`/api/metrics/timeline?range=${timelineRange}`);
  const short = timelineRange === "7d"
    ? { month: "short", day: "numeric" }
    : { hour: "2-digit", minute: "2-digit" };
  timelineChart.data.labels = t.labels.map((l) =>
    parseTs(l).toLocaleString(undefined, short));
  timelineChart.data.datasets[0].data = t.events;
  timelineChart.data.datasets[1].data = t.alerts;
  timelineChart.update();
}

async function loadSeverity() {
  const s = await apiGet("/api/metrics/severity");
  severityChart.data.datasets[0].data =
    ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map((k) => s[k] || 0);
  severityChart.update();
}

async function loadTopIps() {
  const rows = await apiGet("/api/metrics/top-ips?range=7d");
  topIpsChart.data.labels = rows.map((r) => r.ip);
  topIpsChart.data.datasets[0].data = rows.map((r) => r.count);
  topIpsChart.update();
}

async function loadCategories() {
  const counts = await apiGet("/api/metrics/categories?range=7d");
  const labels = Object.keys(counts);
  categoriesChart.data.labels = labels;
  categoriesChart.data.datasets[0].data = labels.map((l) => counts[l]);
  categoriesChart.data.datasets[0].backgroundColor =
    labels.map((_, i) => PALETTE.categorical[i % PALETTE.categorical.length]);
  categoriesChart.update();
}

async function loadRecentAlerts() {
  const alerts = await apiGet("/api/alerts/recent?limit=8");
  const tbody = document.getElementById("recent-alerts");
  if (!alerts.length) {
    tbody.innerHTML = '<tr><td colspan="8" class="empty">No alerts</td></tr>';
    return;
  }
  tbody.innerHTML = alerts.map((a) => `
    <tr class="clickable" onclick="window.location='/alerts/${a.id}'">
      <td class="mono">#${a.id}</td>
      <td class="nowrap dim" title="${esc(a.timestamp)}">${timeAgo(a.timestamp)}</td>
      <td>${sevBadge(a.severity)}</td>
      <td>${esc(a.detection_rule || a.title)}</td>
      <td class="mono">${esc(a.source_ip || "—")}</td>
      <td>${esc(a.username || "—")}</td>
      <td class="mono">${esc(a.mitre_technique || "—")}</td>
      <td>${statusBadge(a.status)}</td>
    </tr>`).join("");
}

async function loadRecentIncidents() {
  const incidents = await apiGet("/api/incidents/recent?limit=6");
  const tbody = document.getElementById("recent-incidents");
  if (!incidents.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty">No incidents</td></tr>';
    return;
  }
  tbody.innerHTML = incidents.map((i) => `
    <tr class="clickable" onclick="window.location='/incidents/${i.id}'">
      <td class="mono">#${i.id}</td>
      <td>${esc(i.title)}</td>
      <td>${sevBadge(i.severity)}</td>
      <td>${statusBadge(i.status)}</td>
      <td class="nowrap dim">${fmtTime(i.created_at)}</td>
      <td>${esc(i.assigned_analyst || "—")}</td>
    </tr>`).join("");
}

function loadAll() {
  loadKpis(); loadTimeline(); loadSeverity(); loadTopIps();
  loadCategories(); loadRecentAlerts(); loadRecentIncidents();
}

document.getElementById("timeline-ranges").addEventListener("click", (ev) => {
  const btn = ev.target.closest("button[data-range]");
  if (!btn) return;
  timelineRange = btn.dataset.range;
  document.querySelectorAll("#timeline-ranges .btn")
    .forEach((b) => b.classList.toggle("active", b === btn));
  loadTimeline();
});

onRefresh(loadAll);
loadAll();
