/* Security events: server-side filters, pagination, and a detail modal. */

let page = 1;

function currentFilters() {
  const params = new URLSearchParams();
  const fields = {
    q: "f-q", event_type: "f-type", severity: "f-severity",
    source_ip: "f-ip", username: "f-user", hostname: "f-host",
    date_from: "f-from", date_to: "f-to",
  };
  for (const [key, id] of Object.entries(fields)) {
    const value = document.getElementById(id).value.trim();
    if (value) params.set(key, value);
  }
  params.set("page", page);
  params.set("per_page", 30);
  return params;
}

async function loadEvents() {
  const data = await apiGet(`/api/events?${currentFilters()}`);
  const tbody = document.getElementById("events-body");
  document.getElementById("event-count").textContent = `${data.total} total`;
  if (!data.items.length) {
    tbody.innerHTML = '<tr><td colspan="11" class="empty">No events match the filters</td></tr>';
  } else {
    tbody.innerHTML = data.items.map((e) => `
      <tr class="clickable" data-event-id="${e.id}">
        <td class="mono">#${e.id}</td>
        <td class="nowrap dim">${fmtTime(e.timestamp)}</td>
        <td class="mono">${esc(e.event_type)}</td>
        <td class="mono">${esc(e.source_ip || "—")}</td>
        <td class="mono">${esc(e.destination_ip || "—")}</td>
        <td class="mono">${esc(e.destination_port ?? "—")}</td>
        <td class="dim">${esc(e.protocol || "—")}</td>
        <td>${esc(e.username || "—")}</td>
        <td class="dim">${esc(e.hostname || "—")}</td>
        <td>${esc(e.result || "—")}</td>
        <td>${sevBadge(e.severity)}</td>
      </tr>`).join("");
  }
  document.getElementById("pg-info").textContent = `Page ${data.page} of ${data.pages}`;
  document.getElementById("pg-prev").disabled = data.page <= 1;
  document.getElementById("pg-next").disabled = data.page >= data.pages;
}

async function openEventModal(eventId) {
  const e = await apiGet(`/api/events/${eventId}`);
  document.getElementById("m-id").textContent = `#${e.id}`;
  const rows = [
    ["Timestamp (UTC)", e.timestamp?.replace("T", " ")],
    ["Event type", e.event_type], ["Severity", e.severity],
    ["Source IP", e.source_ip], ["Source port", e.source_port],
    ["Destination IP", e.destination_ip], ["Destination port", e.destination_port],
    ["Protocol", e.protocol], ["Username", e.username],
    ["Hostname", e.hostname], ["Action", e.action], ["Result", e.result],
  ];
  document.getElementById("m-fields").innerHTML = rows
    .map(([k, v]) => `<dt>${k}</dt><dd class="mono">${esc(v ?? "—")}</dd>`).join("");
  document.getElementById("m-raw").textContent = e.raw_log || "(no raw log)";
  const alertsDiv = document.getElementById("m-alerts");
  alertsDiv.innerHTML = e.alerts.length
    ? "<b>Alerts raised by this event:</b><br>" + e.alerts.map((a) =>
        `${sevBadge(a.severity)} <a href="/alerts/${a.id}">#${a.id} ${esc(a.title)}</a>`)
        .join("<br>")
    : '<span class="faint">No alerts were raised by this event.</span>';
  document.getElementById("event-modal").classList.add("open");
}

document.getElementById("events-body").addEventListener("click", (ev) => {
  const row = ev.target.closest("tr[data-event-id]");
  if (row) openEventModal(row.dataset.eventId);
});
document.getElementById("event-modal").addEventListener("click", (ev) => {
  if (ev.target.id === "event-modal") ev.target.classList.remove("open");
});

document.getElementById("f-apply").addEventListener("click", () => { page = 1; loadEvents(); });
document.getElementById("f-q").addEventListener("keydown", (e) => {
  if (e.key === "Enter") { page = 1; loadEvents(); }
});
document.getElementById("f-clear").addEventListener("click", () => {
  ["f-q", "f-type", "f-severity", "f-ip", "f-user", "f-host", "f-from", "f-to"]
    .forEach((id) => { document.getElementById(id).value = ""; });
  page = 1; loadEvents();
});
document.getElementById("pg-prev").addEventListener("click", () => { page--; loadEvents(); });
document.getElementById("pg-next").addEventListener("click", () => { page++; loadEvents(); });

onRefresh(loadEvents);
loadEvents();
