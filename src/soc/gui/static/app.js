const state = {
  dashboard: null,
  selectedFlowId: null,
  timer: null,
};

const els = {
  serviceStatus: document.querySelector("#service-status"),
  configPath: document.querySelector("#config-path"),
  lastUpdated: document.querySelector("#last-updated"),
  refreshButton: document.querySelector("#refresh-button"),
  metricAlerts: document.querySelector("#metric-alerts"),
  metricSeverity: document.querySelector("#metric-severity"),
  metricTier1: document.querySelector("#metric-tier1"),
  metricWatchlist: document.querySelector("#metric-watchlist"),
  metricTotal: document.querySelector("#metric-total"),
  metricStorage: document.querySelector("#metric-storage"),
  routeBreakdown: document.querySelector("#route-breakdown"),
  flowTableBody: document.querySelector("#flow-table-body"),
  summaryStatus: document.querySelector("#summary-status"),
  summaryPreview: document.querySelector("#summary-preview"),
  artifactList: document.querySelector("#artifact-list"),
  sourceCounts: document.querySelector("#source-counts"),
  sourceList: document.querySelector("#source-list"),
  selectedFlow: document.querySelector("#selected-flow"),
};

async function fetchJson(url) {
  const response = await fetch(url, { headers: { Accept: "application/json" } });
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }
  return response.json();
}

async function loadDashboard() {
  try {
    const dashboard = await fetchJson("/api/dashboard");
    state.dashboard = dashboard;
    renderDashboard(dashboard);
    els.serviceStatus.textContent = "Running";
    els.lastUpdated.textContent = `Updated ${new Date().toLocaleTimeString()}`;
  } catch (error) {
    els.serviceStatus.textContent = "Disconnected";
    els.lastUpdated.textContent = "API unavailable";
    els.selectedFlow.textContent = `Dashboard request failed: ${error.message}`;
  }
}

function renderDashboard(data) {
  const status = data.status || {};
  const counters = data.counters || {};
  const routes = counters.routes || {};
  const verdicts = counters.verdicts || {};
  const severities = counters.severities || {};
  const storage = status.storage || {};

  els.configPath.textContent = status.config_path || "-";
  els.metricAlerts.textContent = number(verdicts.alert);
  els.metricSeverity.textContent = `high/critical: ${number(severities.high) + number(severities.critical)}`;
  els.metricTier1.textContent = number(routes.tier1_llm);
  els.metricWatchlist.textContent = number(counters.watchlist_hits);
  els.metricTotal.textContent = number(counters.total_recent);
  els.metricStorage.textContent = storage.enabled === false ? "storage disabled" : storage.sqlite_path || "storage enabled";
  els.routeBreakdown.textContent = formatRouteBreakdown(routes);

  renderFlows(data.recent_flows || []);
  renderArtifacts(data.tier2_artifacts || {});
  renderSources((data.source_inputs || {}).sources || []);
  renderSummary(data.latest_summary || {});
  renderSelectedFlow();
}

function renderFlows(flows) {
  if (!flows.length) {
    els.flowTableBody.innerHTML = '<tr><td colspan="7" class="empty-state">Waiting for events</td></tr>';
    return;
  }

  els.flowTableBody.innerHTML = flows
    .map((flow) => {
      const selected = flow.flow_id === state.selectedFlowId ? " selected" : "";
      return `
        <tr class="${selected}" data-flow-id="${escapeHtml(flow.flow_id)}">
          <td><strong>${escapeHtml(flow.flow_id || "-")}</strong><br><span class="soft-label">${formatTime(flow)}</span></td>
          <td>${escapeHtml(flow.src_ip || "-")}<br><span class="soft-label">${portLabel(flow.src_port)}</span></td>
          <td>${escapeHtml(flow.dst_ip || "-")}<br><span class="soft-label">${portLabel(flow.dst_port)} / ${escapeHtml(flow.protocol || "-")}</span></td>
          <td>${formatProbability(flow.prob)}</td>
          <td>${badge(flow.route || "unknown", flow.route)}</td>
          <td>${badge(flow.verdict || "unknown", flow.severity || flow.verdict)} ${badge(flow.severity || "n/a", flow.severity)}</td>
          <td>${flow.watchlist_matched ? badge("hit", "tier1_llm") : '<span class="soft-label">none</span>'}</td>
        </tr>
      `;
    })
    .join("");

  els.flowTableBody.querySelectorAll("tr[data-flow-id]").forEach((row) => {
    row.addEventListener("click", () => {
      state.selectedFlowId = row.getAttribute("data-flow-id");
      renderFlows(flows);
      renderSelectedFlow();
    });
  });
}

function renderArtifacts(artifacts) {
  const items = [
    ["Watchlist", artifacts.watchlist],
    ["Brief", artifacts.brief],
    ["Memory", artifacts.memory],
  ];
  els.artifactList.innerHTML = items
    .map(([label, artifact]) => {
      const exists = artifact && artifact.exists;
      const preview = exists ? previewText(artifact.content, 92) : "missing";
      return `
        <div class="artifact-item">
          <div>
            <strong>${label}</strong>
            <div class="source-path">${escapeHtml(preview)}</div>
          </div>
          ${badge(exists ? "ready" : "missing", exists ? "benign" : "alert")}
        </div>
      `;
    })
    .join("");
}

function renderSources(sources) {
  const counts = sources.reduce((acc, source) => {
    const key = source.status || "unknown";
    acc[key] = (acc[key] || 0) + 1;
    return acc;
  }, {});
  els.sourceCounts.textContent = Object.entries(counts).map(([key, value]) => `${key}: ${value}`).join("  ");
  els.sourceList.innerHTML = sources.length
    ? sources
        .map((source) => `
          <div class="source-item">
            <div class="source-name">
              <span class="status-dot status-${escapeAttr(source.status || "unknown")}"></span>
              <div>
                <strong>${escapeHtml(source.name || "-")}</strong>
                <div class="source-path">${escapeHtml(source.path_or_uri || source.source_type || "-")}</div>
              </div>
            </div>
            ${badge(`${source.item_count ?? 0}`, source.status)}
          </div>
        `)
        .join("")
    : '<div class="selected-flow">No source status is available.</div>';
}

function renderSummary(summary) {
  const markdown = summary.markdown || {};
  if (markdown.exists && markdown.content) {
    els.summaryStatus.textContent = markdown.path || "latest.md";
    els.summaryPreview.textContent = markdown.content.slice(0, 2200);
  } else {
    els.summaryStatus.textContent = "No summary";
    els.summaryPreview.textContent = "No daily summary artifact is available yet.";
  }
}

function renderSelectedFlow() {
  const flows = (state.dashboard && state.dashboard.recent_flows) || [];
  const flow = flows.find((item) => item.flow_id === state.selectedFlowId) || flows[0];
  if (!flow) {
    els.selectedFlow.textContent = "Select a flow row to inspect the route and verdict.";
    return;
  }
  state.selectedFlowId = flow.flow_id;
  els.selectedFlow.innerHTML = `
    ${detailRow("Flow", flow.flow_id)}
    ${detailRow("Route", `${flow.route || "-"} - ${flow.route_reason || "no route reason"}`)}
    ${detailRow("ML probability", formatProbability(flow.prob))}
    ${detailRow("Verdict", `${flow.verdict || "-"} / ${flow.severity || "-"}`)}
    ${detailRow("Path", `${flow.src_ip || "-"}:${flow.src_port || "-"} -> ${flow.dst_ip || "-"}:${flow.dst_port || "-"}`)}
    ${detailRow("Watchlist", flow.watchlist_matched || "none")}
    ${detailRow("Fallback", flow.fallback_reason || "none")}
  `;
}

function detailRow(label, value) {
  return `<div class="detail-row"><strong>${escapeHtml(label)}</strong><span>${escapeHtml(String(value))}</span></div>`;
}

function badge(label, tone) {
  return `<span class="badge ${escapeAttr(String(tone || "").toLowerCase())}">${escapeHtml(String(label))}</span>`;
}

function formatRouteBreakdown(routes) {
  const parts = ["auto_dismiss", "tier1_llm", "auto_alert"]
    .map((key) => `${key}: ${number(routes[key])}`);
  return parts.join("  ");
}

function formatProbability(value) {
  if (value === null || value === undefined || value === "") {
    return "-";
  }
  const numeric = Number(value);
  return Number.isFinite(numeric) ? numeric.toFixed(3) : escapeHtml(String(value));
}

function formatTime(flow) {
  if (flow.start_ms) {
    const date = new Date(Number(flow.start_ms));
    if (!Number.isNaN(date.getTime())) {
      return date.toLocaleString();
    }
  }
  return flow.created_at || "-";
}

function portLabel(value) {
  return value === null || value === undefined || value === "" ? "port -" : `port ${value}`;
}

function previewText(value, length) {
  const clean = String(value || "").replace(/\s+/g, " ").trim();
  return clean ? clean.slice(0, length) : "empty";
}

function number(value) {
  return Number(value || 0);
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function escapeAttr(value) {
  return escapeHtml(value).replace(/\s+/g, "-");
}

document.querySelectorAll(".nav-item").forEach((button) => {
  button.addEventListener("click", () => {
    document.querySelectorAll(".nav-item").forEach((item) => item.classList.remove("active"));
    button.classList.add("active");
  });
});

els.refreshButton.addEventListener("click", loadDashboard);
loadDashboard();
state.timer = window.setInterval(loadDashboard, 5000);
