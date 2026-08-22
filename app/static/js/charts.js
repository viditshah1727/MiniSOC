/* Chart.js theme + small factory helpers for the MiniSOC dark theme. */

const PALETTE = {
  grid: "rgba(255,255,255,0.06)",
  tick: "#5b6675",
  accent: "#22d3ee",
  accentFill: "rgba(34,211,238,0.12)",
  alert: "#ef4444",
  severity: {
    CRITICAL: "#ef4444",
    HIGH: "#f97316",
    MEDIUM: "#eab308",
    LOW: "#3b82f6",
    INFO: "#64748b",
  },
  categorical: ["#22d3ee", "#f97316", "#a78bfa", "#34d399", "#f472b6",
                "#eab308", "#60a5fa", "#fb7185"],
};

if (window.Chart) {
  Chart.defaults.color = PALETTE.tick;
  Chart.defaults.borderColor = PALETTE.grid;
  Chart.defaults.font.family = '"Inter", "Segoe UI", system-ui, sans-serif';
  Chart.defaults.font.size = 11.5;
  Chart.defaults.plugins.legend.labels.boxWidth = 12;
  Chart.defaults.plugins.legend.labels.boxHeight = 12;
  Chart.defaults.animation.duration = 250;
}

function makeTimelineChart(ctx) {
  return new Chart(ctx, {
    type: "line",
    data: { labels: [], datasets: [
      { label: "Events", data: [], borderColor: PALETTE.accent,
        backgroundColor: PALETTE.accentFill, fill: true, tension: 0.3,
        pointRadius: 0, borderWidth: 2 },
      { label: "Alerts", data: [], borderColor: PALETTE.alert,
        backgroundColor: "rgba(239,68,68,0.10)", fill: true, tension: 0.3,
        pointRadius: 0, borderWidth: 2 },
    ]},
    options: {
      responsive: true, maintainAspectRatio: false,
      interaction: { mode: "index", intersect: false },
      scales: {
        x: { grid: { display: false }, ticks: { maxTicksLimit: 10, maxRotation: 0 } },
        y: { beginAtZero: true, ticks: { precision: 0 } },
      },
    },
  });
}

function makeDonutChart(ctx, labels, colors) {
  return new Chart(ctx, {
    type: "doughnut",
    data: { labels, datasets: [{ data: [], backgroundColor: colors,
                                 borderColor: "#111827", borderWidth: 2 }] },
    options: {
      responsive: true, maintainAspectRatio: false, cutout: "62%",
      plugins: { legend: { position: "right" } },
    },
  });
}

function makeBarChart(ctx, { horizontal = false, color = PALETTE.accent } = {}) {
  return new Chart(ctx, {
    type: "bar",
    data: { labels: [], datasets: [{ data: [], backgroundColor: color,
                                     borderRadius: 3, maxBarThickness: 26 }] },
    options: {
      indexAxis: horizontal ? "y" : "x",
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { beginAtZero: true, ticks: { precision: 0 },
             grid: { display: horizontal } },
        y: { beginAtZero: true, ticks: { precision: 0 },
             grid: { display: !horizontal } },
      },
    },
  });
}
