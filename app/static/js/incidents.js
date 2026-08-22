/* Incidents list: server-side filtering + pagination via /api/incidents. */

let page = 1;

function currentFilters() {
  const params = new URLSearchParams();
  const q = document.getElementById("f-q").value.trim();
  const severity = document.getElementById("f-severity").value;
  const status = document.getElementById("f-status").value;
  if (q) params.set("q", q);
  if (severity) params.set("severity", severity);
  if (status) params.set("status", status);
  params.set("page", page);
  params.set("per_page", 25);
  return params;
}

async function loadIncidents() {
  const data = await apiGet(`/api/incidents?${currentFilters()}`);
  const tbody = document.getElementById("incidents-body");
  document.getElementById("incident-count").textContent = `${data.total} total`;
  if (!data.items.length) {
    tbody.innerHTML = '<tr><td colspan="11" class="empty">No incidents match the filters</td></tr>';
  } else {
    tbody.innerHTML = data.items.map((i) => `
      <tr class="clickable" onclick="window.location='/incidents/${i.id}'">
        <td class="mono">#${i.id}</td>
        <td>${esc(i.title)}</td>
        <td>${sevBadge(i.severity)}</td>
        <td>${statusBadge(i.status)}</td>
        <td class="mono">${esc(i.source_ip || "—")}</td>
        <td class="dim">${esc(i.affected_host || "—")}</td>
        <td>${esc(i.affected_user || "—")}</td>
        <td class="mono">${esc(i.mitre_technique || "—")}</td>
        <td>${esc(i.assigned_analyst || "—")}</td>
        <td class="nowrap dim">${fmtTime(i.created_at)}</td>
        <td class="mono">${i.alert_count}</td>
      </tr>`).join("");
  }
  document.getElementById("pg-info").textContent = `Page ${data.page} of ${data.pages}`;
  document.getElementById("pg-prev").disabled = data.page <= 1;
  document.getElementById("pg-next").disabled = data.page >= data.pages;
}

document.getElementById("f-apply").addEventListener("click", () => { page = 1; loadIncidents(); });
document.getElementById("f-q").addEventListener("keydown", (e) => {
  if (e.key === "Enter") { page = 1; loadIncidents(); }
});
document.getElementById("f-clear").addEventListener("click", () => {
  document.getElementById("f-q").value = "";
  document.getElementById("f-severity").value = "";
  document.getElementById("f-status").value = "";
  page = 1; loadIncidents();
});
document.getElementById("pg-prev").addEventListener("click", () => { page--; loadIncidents(); });
document.getElementById("pg-next").addEventListener("click", () => { page++; loadIncidents(); });

onRefresh(loadIncidents);
loadIncidents();
