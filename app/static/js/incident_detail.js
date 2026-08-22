/* Incident actions: update status/assignee and add notes. */

const incidentId = document.getElementById("incident-actions").dataset.incidentId;

document.getElementById("btn-save").addEventListener("click", async () => {
  const status = document.getElementById("status-select").value;
  const analyst = document.getElementById("analyst-input").value.trim();
  try {
    const updated = await apiSend(`/api/incidents/${incidentId}`, "PATCH",
                                  { status, assigned_analyst: analyst });
    const badge = document.getElementById("incident-status-badge");
    badge.textContent = updated.status;
    badge.className = `badge st-${updated.status}`;
    toast(`Incident #${incidentId} updated`, "ok");
  } catch (err) {
    toast(`Update failed: ${esc(err.message)}`, "alert");
  }
});

document.getElementById("btn-add-note").addEventListener("click", async () => {
  const input = document.getElementById("note-input");
  const content = input.value.trim();
  if (!content) return;
  try {
    const note = await apiSend(`/api/incidents/${incidentId}/notes`, "POST", { content });
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
