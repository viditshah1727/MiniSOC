/* Alerts list: server-side filtering + pagination via /api/alerts. */

let page = 1;

function currentFilters() {
  const params = new URLSearchParams();
  const q = document.getElementById("f-q").value.trim();
  const severity = document.getElementById("f-severity").value;
  const status = document.getElementById("f-status").value;
  const ip = document.getElementById("f-ip").value.trim();
  const from = document.getElementById("f-from").value;
  const to = document.getElementById("f-to").value;
  if (q) params.set("q", q);
  if (severity) params.set("severity", severity);
  if (status) params.set("status", status);
  if (ip) params.set("source_ip", ip);
  if (from) params.set("date_from", from);
  if (to) params.set("date_to", to);
  params.set("page", page);
  params.set("per_page", 25);
  return params;
}

async function loadAlerts() {
  const data = await apiGet(`/api/alerts?${currentFilters()}`);
  const tbody = document.getElementById("alerts-body");
  document.getElementById("alert-count").textContent = `${data.total} total`;
  if (!data.items.length) {
    tbody.innerHTML = '<tr><td colspan="10" class="empty">No alerts match the filters</td></tr>';
  } else {
    tbody.innerHTML = data.items.map((a) => `
      <tr class="clickable" onclick="window.location='/alerts/${a.id}'">
        <td class="mono">#${a.id}</td>
        <td class="nowrap dim">${fmtTime(a.timestamp)}</td>
        <td>${sevBadge(a.severity)}</td>
        <td>${esc(a.title)}</td>
        <td class="dim">${esc(a.detection_rule || "—")}</td>
        <td class="mono">${esc(a.source_ip || "—")}</td>
        <td>${esc(a.username || "—")}</td>
        <td class="dim">${esc(a.hostname || "—")}</td>
        <td class="mono">${esc(a.mitre_technique || "—")}</td>
        <td>${statusBadge(a.status)}</td>
      </tr>`).join("");
  }
  document.getElementById("pg-info").textContent = `Page ${data.page} of ${data.pages}`;
  document.getElementById("pg-prev").disabled = data.page <= 1;
  document.getElementById("pg-next").disabled = data.page >= data.pages;
}

document.getElementById("f-apply").addEventListener("click", () => { page = 1; loadAlerts(); });
document.getElementById("f-q").addEventListener("keydown", (e) => {
  if (e.key === "Enter") { page = 1; loadAlerts(); }
});
document.getElementById("f-clear").addEventListener("click", () => {
  for (const id of ["f-q", "f-ip", "f-from", "f-to"]) document.getElementById(id).value = "";
  for (const id of ["f-severity", "f-status"]) document.getElementById(id).value = "";
  page = 1; loadAlerts();
});
document.getElementById("pg-prev").addEventListener("click", () => { page--; loadAlerts(); });
document.getElementById("pg-next").addEventListener("click", () => { page++; loadAlerts(); });

onRefresh(loadAlerts);
loadAlerts();
