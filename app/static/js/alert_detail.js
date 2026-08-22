/* Alert investigation actions: status changes, notes, escalate to incident. */

const actions = document.getElementById("alert-actions");
const alertId = actions.dataset.alertId;

actions.querySelectorAll("button[data-status]").forEach((btn) => {
  btn.addEventListener("click", async () => {
    try {
      const updated = await apiSend(`/api/alerts/${alertId}`, "PATCH",
                                    { status: btn.dataset.status });
      const badge = document.getElementById("alert-status-badge");
      badge.textContent = updated.status.replaceAll("_", " ");
      badge.className = `badge st-${updated.status}`;
      toast(`Alert #${alertId} marked ${esc(updated.status.replaceAll("_", " "))}`, "ok");
    } catch (err) {
      toast(`Update failed: ${esc(err.message)}`, "alert");
    }
  });
});

document.getElementById("btn-escalate")?.addEventListener("click", async (ev) => {
  ev.currentTarget.disabled = true;
  try {
    const incident = await apiSend(`/api/alerts/${alertId}/escalate`, "POST", {});
    toast(`Incident #${incident.id} created`, "ok");
    window.location = `/incidents/${incident.id}`;
  } catch (err) {
    toast(`Escalation failed: ${esc(err.message)}`, "alert");
    ev.target.disabled = false;
  }
});

document.getElementById("btn-add-note").addEventListener("click", async () => {
  const input = document.getElementById("note-input");
  const content = input.value.trim();
  if (!content) return;
  try {
    const note = await apiSend(`/api/alerts/${alertId}/notes`, "POST", { content });
    document.getElementById("no-notes")?.remove();
    const el = document.createElement("div");
    el.className = "note";
    el.innerHTML = `<div class="meta">${esc(note.author)} — just now</div>${esc(note.content)}`;
    document.getElementById("notes-list").appendChild(el);
    input.value = "";
    toast("Note added", "ok");
  } catch (err) {
    toast(`Failed to add note: ${esc(err.message)}`, "alert");
  }
});
