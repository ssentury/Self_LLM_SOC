const VIEW_LABELS = {
  dashboard: ["Operations Dashboard", "Current SOC Situation"],
  realtime: ["Realtime Monitoring", "Live Flow Triage"],
  inputs: ["Tier 2 Inputs", "Organization And Security Inputs"],
  context: ["Tier 2 Context", "Curated Watchlist And Context"],
  reports: ["Reports", "Summary And Report Archive"],
};

const state = {
  activeView: "dashboard",
  dashboard: null,
  sources: [],
  selectedFlowId: null,
  selectedFlowDetail: null,
  selectedSourceName: "organization",
  selectedArtifact: "watchlist",
  detailCache: new Map(),
  timer: null,
  sidebarCollapsed: false,
  topologyViewBox: { x: 0, y: 0, width: 820, height: 520 },
  topologyDrag: null,
  knownFlowIds: new Set(),
  newFlowIds: new Set(),
  isInitialLoad: true,
};

const els = {
  appShell: document.querySelector("#app-shell"),
  sidebarToggle: document.querySelector("#sidebar-toggle"),
  serviceStatus: document.querySelector("#service-status"),
  configPath: document.querySelector("#config-path"),
  lastUpdated: document.querySelector("#last-updated"),
  refreshButton: document.querySelector("#refresh-button"),
  viewEyebrow: document.querySelector("#view-eyebrow"),
  viewTitle: document.querySelector("#view-title"),
  metricAlerts: document.querySelector("#metric-alerts"),
  metricSeverity: document.querySelector("#metric-severity"),
  metricTier1: document.querySelector("#metric-tier1"),
  metricWatchlist: document.querySelector("#metric-watchlist"),
  metricTotal: document.querySelector("#metric-total"),
  metricStorage: document.querySelector("#metric-storage"),
  routeBreakdown: document.querySelector("#route-breakdown"),
  realtimeRouteBreakdown: document.querySelector("#realtime-route-breakdown"),
  flowTableBody: document.querySelector("#flow-table-body"),
  realtimeFlowTableBody: document.querySelector("#realtime-flow-table-body"),
  topologyStatus: document.querySelector("#topology-status"),
  topologyGraph: document.querySelector("#topology-graph"),
  summaryStatus: document.querySelector("#summary-status"),
  summaryPreview: document.querySelector("#summary-preview"),
  artifactList: document.querySelector("#artifact-list"),
  sourceCounts: document.querySelector("#source-counts"),
  sourceList: document.querySelector("#source-list"),
  selectedFlow: document.querySelector("#selected-flow"),
  runtimeState: document.querySelector("#runtime-state"),
  realtimeContextSnapshot: document.querySelector("#realtime-context-snapshot"),
  inputTabList: document.querySelector("#input-tab-list"),
  inputSourceDetail: document.querySelector("#input-source-detail"),
  inputSourceContent: document.querySelector("#input-source-content"),
  inputPreviewStatus: document.querySelector("#input-preview-status"),
  inputsRefreshTier2: document.querySelector("#inputs-refresh-tier2"),
  contextRefreshTier2: document.querySelector("#context-refresh-tier2"),
  contextTabList: document.querySelector("#context-tab-list"),
  contextArtifactContent: document.querySelector("#context-artifact-content"),
  contextArtifactList: document.querySelector("#context-artifact-list"),
  contextSourceList: document.querySelector("#context-source-list"),
  reportsSummaryStatus: document.querySelector("#reports-summary-status"),
  reportsSummaryPreview: document.querySelector("#reports-summary-preview"),
  reportList: document.querySelector("#report-list"),
  flowDetailModal: document.querySelector("#flow-detail-modal"),
  flowDetailClose: document.querySelector("#flow-detail-close"),
  flowDetailTitle: document.querySelector("#flow-detail-title"),
  flowDetailBody: document.querySelector("#flow-detail-body"),
};

async function fetchJson(url, options = {}) {
  const response = await fetch(url, {
    ...options,
    headers: { Accept: "application/json", ...(options.headers || {}) },
  });
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }
  return response.json();
}

async function loadDashboard() {
  try {
    const [dashboard, sourceInputs] = await Promise.all([
      fetchJson("/api/dashboard"),
      fetchJson("/api/source-inputs"),
    ]);
    state.dashboard = dashboard;
    state.sources = sourceInputs.sources || [];
    for (const flow of dashboard.recent_flows || []) {
      if (flow.processing_state !== "complete") {
        state.detailCache.delete(flow.flow_id);
      }
    }

    // Determine new flows for animation
    const currentFlows = dashboard.recent_flows || [];
    const currentIds = new Set(currentFlows.map(f => f.flow_id).filter(Boolean));
    if (state.isInitialLoad) {
      state.knownFlowIds = currentIds;
      state.newFlowIds = new Set();
      state.isInitialLoad = false;
    } else {
      state.newFlowIds = new Set();
      for (const id of currentIds) {
        if (!state.knownFlowIds.has(id)) {
          state.newFlowIds.add(id);
        }
      }
      state.knownFlowIds = currentIds;
    }

    renderAll();
    els.serviceStatus.textContent = "Running";
    els.lastUpdated.textContent = `Updated ${new Date().toLocaleTimeString()}`;
  } catch (error) {
    els.serviceStatus.textContent = "Disconnected";
    els.lastUpdated.textContent = "API unavailable";
    els.selectedFlow.textContent = `Dashboard request failed: ${error.message}`;
  }
}

function renderAll() {
  const data = state.dashboard || {};
  renderTopLevel(data);
  renderDashboard(data);
  renderRealtime(data);
  renderInputs();
  renderContext(data);
  renderReports(data);
}

function renderTopLevel(data) {
  const status = data.status || {};
  els.configPath.textContent = status.config_path || "-";
}

function renderDashboard(data) {
  const counters = data.counters || {};
  const routes = counters.routes || {};
  const verdicts = counters.verdicts || {};
  const severities = counters.severities || {};
  const storage = (data.status || {}).storage || {};
  const pendingTier1 = number(counters.pending_tier1);

  els.metricAlerts.textContent = number(verdicts.alert);
  els.metricSeverity.textContent = `high/critical: ${number(severities.high) + number(severities.critical)}`;
  els.metricTier1.textContent = pendingTier1
    ? `${number(routes.tier1_llm)} / ${pendingTier1} pending`
    : number(routes.tier1_llm);
  els.metricWatchlist.textContent = number(counters.watchlist_hits);
  els.metricTotal.textContent = number(counters.total_recent);
  els.metricStorage.textContent = storage.enabled === false ? "storage disabled" : storage.sqlite_path || "storage enabled";
  els.routeBreakdown.textContent = formatRouteBreakdown(routes);
  renderFlowRows(els.flowTableBody, data.recent_flows || [], "dashboard");
  renderArtifacts(els.artifactList, data.tier2_artifacts || {});
  renderSources(els.sourceList, state.sources, true);
  renderSourceCounts();
  renderSummary(data.latest_summary || {}, els.summaryStatus, els.summaryPreview, 2200);
  renderSelectedFlowCard(els.selectedFlow, false);
}

function renderRealtime(data) {
  const routes = ((data.counters || {}).routes) || {};
  els.realtimeRouteBreakdown.textContent = formatRouteBreakdown(routes);
  renderTopology(data.topology || {}, data.recent_flows || []);
  renderFlowRows(els.realtimeFlowTableBody, data.recent_flows || [], "realtime");
  renderRuntimeState(data.status || {});
  renderArtifacts(els.realtimeContextSnapshot, data.tier2_artifacts || {});
}

function renderTopology(topology, flows) {
  const nodes = topology.nodes || [];
  const edges = topology.edges || [];
  const groups = topology.groups || [];
  const selected = selectedFlowSummary(flows);
  els.topologyStatus.textContent = `${topology.status || "unknown"} / ${nodes.length} nodes / ${edges.length} edges`;

  if (!nodes.length) {
    els.topologyGraph.innerHTML = '<div class="selected-flow">No asset topology is available. Check the Tier 2 asset source input.</div>';
    return;
  }

  const grouped = new Map(groups.map((group) => [group.id, { ...group, nodes: [] }]));
  for (const node of nodes) {
    if (!grouped.has(node.group)) {
      grouped.set(node.group, { id: node.group, label: sourceLabel(node.group), nodes: [] });
    }
    grouped.get(node.group).nodes.push(node);
  }
  const visibleGroups = topologyGroupOrder()
    .map((groupId) => grouped.get(groupId))
    .filter((group) => group && group.nodes.length);
  for (const group of grouped.values()) {
    if (group.nodes.length && !visibleGroups.includes(group)) {
      visibleGroups.push(group);
    }
  }

  const layout = topologyLayout(visibleGroups);
  const nodeGroup = new Map();
  for (const group of visibleGroups) {
    for (const node of group.nodes) {
      nodeGroup.set(node.id, group.id);
    }
  }

  const groupEdges = aggregateGroupEdges(edges, nodeGroup);
  const latestFlowId = flows[0] && flows[0].flow_id;
  const edgeLayers = groupEdges.map((edge) => {
    const src = layout.groups.get(edge.src);
    const dst = layout.groups.get(edge.dst);
    if (!src || !dst || edge.src === edge.dst) {
      return "";
    }
    const selectedEdge = selected && edge.flow_ids.includes(selected.flow_id);
    const classes = [
      "topology-edge",
      edge.alert_count ? "alert" : "",
      edge.watchlist_hit_count ? "watchlist" : "",
      edge.latest_flow_id === latestFlowId ? "recent" : "",
      selectedEdge ? "selected" : "",
    ].filter(Boolean).join(" ");
    const start = groupAnchor(src, dst);
    const end = groupAnchor(dst, src);
    const midX = (start.x + end.x) / 2;
    const width = Math.min(7, 1.8 + Math.log2(edge.count + 1));
    return `
      <path class="${classes}" style="stroke-width:${width.toFixed(1)}" d="M ${start.x} ${start.y} C ${midX} ${start.y}, ${midX} ${end.y}, ${end.x} ${end.y}">
        <title>${escapeHtml(edge.src_label)} -> ${escapeHtml(edge.dst_label)} / ${edge.count} recent flows</title>
      </path>
    `;
  }).join("");

  const groupLayers = visibleGroups.map((group) => {
    const box = layout.groups.get(group.id);
    if (!box) {
      return "";
    }
    const selectedSource = selected && group.nodes.some((node) => node.ip === selected.src_ip);
    const selectedDest = selected && group.nodes.some((node) => node.ip === selected.dst_ip);
    const chips = topologyChips(group.nodes, selected)
      .map((node, index) => {
        const x = box.x + 16 + (index % 2) * 88;
        const y = box.y + 62 + Math.floor(index / 2) * 28;
        const sourceClass = selected && selected.src_ip === node.ip ? " selected-source" : "";
        const destClass = selected && selected.dst_ip === node.ip ? " selected-dest" : "";
        const sourceTypeClass = node.source === "recent_flow" ? " virtual" : "";
        return `
          <g class="topology-node${sourceClass}${destClass}${sourceTypeClass}">
            <rect x="${x}" y="${y}" width="78" height="21" rx="6"></rect>
            <title>${escapeHtml(node.label || node.ip)} - ${escapeHtml(node.ip || "-")}</title>
            <text x="${x + 7}" y="${y + 14}">${escapeHtml(ellipsis(node.label || node.ip, 11))}</text>
          </g>
        `;
      }).join("");
    const hiddenCount = Math.max(0, group.nodes.length - 8);
    const total = number(group.asset_count) + number(group.recent_endpoint_count);
    const groupClasses = [
      "topology-group",
      selectedSource ? "selected-source-group" : "",
      selectedDest ? "selected-dest-group" : "",
    ].filter(Boolean).join(" ");
    return `
      <g class="${groupClasses}">
        <rect x="${box.x}" y="${box.y}" width="${box.width}" height="${box.height}" rx="10"></rect>
        <text class="topology-group-label" x="${box.x + 16}" y="${box.y + 24}">${escapeHtml(ellipsis(group.label || group.id, 24))}</text>
        <text class="topology-group-count" x="${box.x + 16}" y="${box.y + 43}">${total} endpoints / ${number(group.asset_count)} assets</text>
        ${chips}
        ${hiddenCount ? `<text class="topology-group-count" x="${box.x + 16}" y="${box.y + 181}">+${hiddenCount} more</text>` : ""}
      </g>
    `;
  }).join("");

  els.topologyGraph.innerHTML = `
    <svg class="topology-svg" viewBox="${state.topologyViewBox.x} ${state.topologyViewBox.y} ${state.topologyViewBox.width} ${state.topologyViewBox.height}" data-world-width="${layout.width}" data-world-height="${layout.height}" role="img" aria-label="Organization asset relationship view">
      <rect class="topology-world-bg" x="0" y="0" width="${layout.width}" height="${layout.height}" rx="18"></rect>
      ${edgeLayers}
      ${groupLayers}
    </svg>
    <div class="topology-note">${escapeHtml(topology.note || "")}</div>
  `;
  bindTopologyPan();
}

function renderInputs() {
  const sources = orderedSources(state.sources);
  if (!sources.length) {
    els.inputTabList.innerHTML = "";
    els.inputSourceDetail.innerHTML = '<div class="selected-flow">No source inputs are available.</div>';
    els.inputSourceContent.textContent = "No source inputs are available.";
    return;
  }
  if (!sources.some((source) => source.name === state.selectedSourceName)) {
    state.selectedSourceName = sources[0].name;
  }

  els.inputTabList.innerHTML = sources
    .map((source) => `
      <button class="tab-item ${source.name === state.selectedSourceName ? "active" : ""}" type="button" data-source="${escapeHtml(source.name)}">
        ${escapeHtml(sourceLabel(source.name))}
      </button>
    `)
    .join("");
  els.inputTabList.querySelectorAll("button[data-source]").forEach((button) => {
    button.addEventListener("click", () => {
      state.selectedSourceName = button.getAttribute("data-source");
      renderInputs();
    });
  });

  const source = sources.find((item) => item.name === state.selectedSourceName) || sources[0];
  els.inputPreviewStatus.textContent = `${source.status || "unknown"} / ${source.item_count ?? 0} items`;
  els.inputSourceDetail.innerHTML = `
    ${detailRow("Source", sourceLabel(source.name))}
    ${detailRow("Status", source.status || "unknown")}
    ${detailRow("Type", source.source_type || "-")}
    ${detailRow("Path", source.path_or_uri || "-")}
    ${detailRow("Item count", source.item_count ?? 0)}
    ${detailRow("Error", source.error || "none")}
  `;
  els.inputSourceContent.textContent = source.content || "No content is available for this source.";
}

function renderContext(data) {
  const artifacts = data.tier2_artifacts || {};
  renderArtifacts(els.contextArtifactList, artifacts);
  renderSources(els.contextSourceList, state.sources, false);
  const artifact = artifacts[state.selectedArtifact] || {};
  els.contextArtifactContent.textContent = artifact.exists
    ? artifact.content || "Artifact exists but is empty."
    : `Missing artifact: ${state.selectedArtifact}`;
}

function renderReports(data) {
  renderSummary(data.latest_summary || {}, els.reportsSummaryStatus, els.reportsSummaryPreview, 8000);
  const reports = data.reports || {};
  const htmlReports = reports.html_reports || [];
  const dailySummaries = reports.daily_summaries || [];
  const items = [
    ...dailySummaries.map((report) => ({ ...report, kind: "daily" })),
    ...htmlReports.map((report) => ({ ...report, kind: "event" })),
  ];
  els.reportList.innerHTML = items.length
    ? items
        .slice(0, 80)
        .map((report) => `
          <div class="artifact-item">
            <div>
              <strong>${escapeHtml(report.name || "-")}</strong>
              <div class="source-path">${escapeHtml(report.path || "-")}</div>
            </div>
            ${badge(report.kind, report.kind === "daily" ? "tier1_llm" : "benign")}
          </div>
        `)
        .join("")
    : '<div class="selected-flow">No generated reports are available.</div>';
}

function renderFlowRows(target, flows, scope) {
  const colspan = scope === "realtime" ? 9 : 7;
  if (!flows.length) {
    target.innerHTML = `<tr><td colspan="${colspan}" class="empty-state">Waiting for events</td></tr>`;
    return;
  }

  target.innerHTML = flows
    .map((flow) => {
      const selected = flow.flow_id === state.selectedFlowId ? " selected" : "";
      const isNew = state.newFlowIds.has(flow.flow_id);
      const newClass = isNew ? " row-new-animate" : "";
      if (scope === "realtime") {
        return `
          <tr class="${selected}${newClass}" data-flow-id="${escapeHtml(flow.flow_id || "")}">
            <td>${escapeHtml(formatTime(flow))}</td>
            <td><strong>${escapeHtml(flow.flow_id || "-")}</strong></td>
            <td>${escapeHtml(flow.src_ip || "-")}<br><span class="soft-label">${portLabel(flow.src_port)}</span></td>
            <td>${escapeHtml(flow.dst_ip || "-")}<br><span class="soft-label">${portLabel(flow.dst_port)} / ${escapeHtml(flow.protocol || "-")}</span></td>
            <td>${formatProbability(flow.prob)}</td>
            <td>${badge(flow.route || "unknown", flow.route)}</td>
            <td>${badge(flow.verdict || "unknown", flow.verdict)}</td>
            <td>${badge(flow.severity || "n/a", flow.severity)}</td>
            <td>${flow.watchlist_matched ? badge("hit", "tier1_llm") : '<span class="soft-label">none</span>'}</td>
          </tr>
        `;
      }
      return `
        <tr class="${selected}${newClass}" data-flow-id="${escapeHtml(flow.flow_id || "")}">
          <td><strong>${escapeHtml(flow.flow_id || "-")}</strong><br><span class="soft-label">${formatTime(flow)}</span></td>
          <td>${escapeHtml(flow.src_ip || "-")}<br><span class="soft-label">${portLabel(flow.src_port)}</span></td>
          <td>${escapeHtml(flow.dst_ip || "-")}<br><span class="soft-label">${portLabel(flow.dst_port)} / ${escapeHtml(flow.protocol || "-")}</span></td>
          <td>${formatProbability(flow.prob)}</td>
          <td>${badge(flow.route || "unknown", flow.route)}</td>
          <td>${badge(flow.verdict || "unknown", flow.verdict)} ${badge(flow.severity || "n/a", flow.severity)}</td>
          <td>${flow.watchlist_matched ? badge("hit", "tier1_llm") : '<span class="soft-label">none</span>'}</td>
        </tr>
      `;
    })
    .join("");

  target.querySelectorAll("tr[data-flow-id]").forEach((row) => {
    row.addEventListener("click", () => {
      selectFlow(row.getAttribute("data-flow-id"));
    });
  });
}

async function selectFlow(flowId) {
  state.selectedFlowId = flowId;
  renderAll();
  if (state.activeView === "realtime") {
    openFlowDetailModal("Loading flow detail...");
  }
  try {
    if (!state.detailCache.has(flowId)) {
      const detail = await fetchJson(`/api/flows/${encodeURIComponent(flowId)}`);
      state.detailCache.set(flowId, detail.event);
    }
    state.selectedFlowDetail = state.detailCache.get(flowId);
  } catch (error) {
    state.selectedFlowDetail = { flow_id: flowId, detail_error: error.message };
  }
  renderSelectedFlowCard(els.selectedFlow, false);
  if (state.activeView === "realtime") {
    openFlowDetailModal();
    renderAll();
  }
}

function renderSelectedFlowCard(target, expanded) {
  const flows = (state.dashboard && state.dashboard.recent_flows) || [];
  const summary = flows.find((item) => item.flow_id === state.selectedFlowId) || flows[0];
  const detail = state.selectedFlowDetail && state.selectedFlowDetail.flow_id === state.selectedFlowId
    ? state.selectedFlowDetail
    : null;
  const flow = detail || summary;
  if (!flow) {
    target.innerHTML = "Select a flow row to inspect the route and verdict.";
    return;
  }
  if (!state.selectedFlowId) {
    state.selectedFlowId = flow.flow_id;
  }
  const isProcessing = flow.processing_state === "tier1_processing";
  const verdictText = isProcessing
    ? "Tier 1 processing / pending"
    : `${flow.verdict || "-"} / ${flow.severity || "-"}`;

  const rows = [
    detailRow("Flow", flow.flow_id),
    detailRow("Route", `${flow.route || "-"} - ${flow.route_reason || "no route reason"}`),
    detailRow("ML probability", formatProbability(flow.prob)),
    detailRow("Verdict", verdictText),
    detailRow("Path", `${flow.src_ip || "-"}:${flow.src_port || "-"} -> ${flow.dst_ip || "-"}:${flow.dst_port || "-"}`),
    detailRow("Watchlist", flow.watchlist_matched || "none"),
    detailRow("Fallback", flow.fallback_reason || "none"),
  ];

  if (!expanded) {
    target.innerHTML = rows.join("");
    return;
  }

  target.innerHTML = flowDetailHtml(flow, rows, isProcessing, detail);
}

function flowDetailHtml(flow, rows, isProcessing, detail) {
  return `
    <div class="evidence-card">
      <h4>Flow Fields</h4>
      ${rows.join("")}
      ${detailRow("Protocol", flow.protocol || "-")}
      ${detailRow("Raw label", flow.raw_label || "-")}
      ${detailRow("Raw attack", flow.raw_attack || "-")}
    </div>
    <div class="evidence-card">
      <h4>ML Evidence</h4>
      ${detailRow("Category hint", flow.category_hint || "not evaluated")}
      ${detailRow("Category confidence", formatProbability(flow.category_confidence))}
      ${detailRow("SHAP top 5", formatShap(flow.shap_top5))}
    </div>
    <div class="evidence-card">
      <h4>Tier 1 Verdict</h4>
      ${detailRow("State", isProcessing ? "waiting for LLM response" : (flow.processing_state || "complete"))}
      ${detailRow("Rationale", flow.rationale_ko || (isProcessing ? "Tier 1 LLM has not returned a verdict yet." : "not available"))}
      ${detailRow("Recommended action", flow.recommended_action_ko || (isProcessing ? "Keep the event pending until Tier 1 completes." : "not available"))}
      ${detailRow("Confidence", formatProbability(flow.confidence))}
    </div>
    <div class="evidence-card">
      <h4>Routing And Watchlist</h4>
      ${detailRow("Adjusted by watchlist", boolLabel(flow.adjusted_by_watchlist))}
      ${detailRow("Effective threshold", flow.effective_review_threshold ?? "none")}
      ${detailRow("Dynamic threshold", boolLabel(flow.dynamic_threshold_applied))}
      ${detailRow("Dynamic reason", flow.dynamic_threshold_reason || "none")}
      ${detailRow("Watchlist match", flow.watchlist_matched || "none")}
      ${detailRow("Match strength", watchlistDetail(flow, "match_strength"))}
      ${detailRow("Trigger completeness", watchlistDetail(flow, "trigger_completeness"))}
      ${detailRow("Matched conditions", listLabel(watchlistDetail(flow, "matched_conditions", [])))}
      ${detailRow("Trigger hints", listLabel(watchlistDetail(flow, "matched_trigger_hints", [])))}
      ${detailRow("Detail state", flow.detail_error || (detail ? "loaded from storage" : "summary only"))}
    </div>
  `;
}

function openFlowDetailModal(message) {
  const flows = (state.dashboard && state.dashboard.recent_flows) || [];
  const summary = flows.find((item) => item.flow_id === state.selectedFlowId) || flows[0];
  const detail = state.selectedFlowDetail && state.selectedFlowDetail.flow_id === state.selectedFlowId
    ? state.selectedFlowDetail
    : null;
  const flow = detail || summary;
  els.flowDetailModal.hidden = false;
  if (message || !flow) {
    els.flowDetailTitle.textContent = "Flow Detail";
    els.flowDetailBody.innerHTML = `<div class="selected-flow">${escapeHtml(message || "No flow selected.")}</div>`;
    return;
  }
  const isProcessing = flow.processing_state === "tier1_processing";
  const verdictText = isProcessing
    ? "Tier 1 processing / pending"
    : `${flow.verdict || "-"} / ${flow.severity || "-"}`;
  const rows = [
    detailRow("Flow", flow.flow_id),
    detailRow("Route", `${flow.route || "-"} - ${flow.route_reason || "no route reason"}`),
    detailRow("ML probability", formatProbability(flow.prob)),
    detailRow("Verdict", verdictText),
    detailRow("Path", `${flow.src_ip || "-"}:${flow.src_port || "-"} -> ${flow.dst_ip || "-"}:${flow.dst_port || "-"}`),
    detailRow("Watchlist", flow.watchlist_matched || "none"),
    detailRow("Fallback", flow.fallback_reason || "none"),
  ];
  els.flowDetailTitle.textContent = flow.flow_id || "Flow Detail";
  els.flowDetailBody.innerHTML = flowDetailHtml(flow, rows, isProcessing, detail);
}

function closeFlowDetailModal() {
  els.flowDetailModal.hidden = true;
}

function renderRuntimeState(status) {
  const storage = status.storage || {};
  els.runtimeState.innerHTML = [
    ["Detector", status.detector],
    ["Tier 1 provider", status.tier1_provider],
    ["Queue mode", status.tier1_queue_mode],
    ["Tier 2 provider", status.tier2_provider],
    ["SQLite", storage.sqlite_path || "disabled"],
    ["Stored flows", ((storage.tables || {}).flows) ?? 0],
    ["Tier 1 calls", ((storage.tables || {}).tier1_calls) ?? 0],
  ]
    .map(([label, value]) => `<div class="artifact-item"><strong>${escapeHtml(label)}</strong><span>${escapeHtml(value ?? "-")}</span></div>`)
    .join("");
}

function renderArtifacts(target, artifacts) {
  const items = [
    ["Watchlist", artifacts.watchlist],
    ["Brief", artifacts.brief],
    ["Memory", artifacts.memory],
  ];
  target.innerHTML = items
    .map(([label, artifact]) => {
      const exists = artifact && artifact.exists;
      const preview = exists ? previewText(artifact.content, 92) : "missing";
      return `
        <div class="artifact-item">
          <div>
            <strong>${label}</strong>
            <div class="source-path">${escapeHtml(preview)}</div>
            <div class="source-path">${escapeHtml((artifact && artifact.path) || "-")}</div>
          </div>
          ${badge(exists ? "ready" : "missing", exists ? "benign" : "alert")}
        </div>
      `;
    })
    .join("");
}

function renderSources(target, sources, compact) {
  target.innerHTML = sources.length
    ? orderedSources(sources)
        .map((source) => `
          <div class="source-item">
            <div class="source-name">
              <span class="status-dot status-${escapeAttr(source.status || "unknown")}"></span>
              <div>
                <strong>${escapeHtml(sourceLabel(source.name))}</strong>
                <div class="source-path">${escapeHtml(source.path_or_uri || source.source_type || "-")}</div>
                ${compact ? "" : `<div class="source-path">${escapeHtml(source.error || "no error")}</div>`}
              </div>
            </div>
            ${badge(`${source.item_count ?? 0}`, source.status)}
          </div>
        `)
        .join("")
    : '<div class="selected-flow">No source status is available.</div>';
}

function renderSourceCounts() {
  const counts = state.sources.reduce((acc, source) => {
    const key = source.status || "unknown";
    acc[key] = (acc[key] || 0) + 1;
    return acc;
  }, {});
  els.sourceCounts.textContent = Object.entries(counts).map(([key, value]) => `${key}: ${value}`).join("  ");
}

function renderSummary(summary, statusTarget, previewTarget, maxLength) {
  const markdown = summary.markdown || {};
  if (markdown.exists && markdown.content) {
    statusTarget.textContent = markdown.path || "latest.md";
    previewTarget.textContent = markdown.content.slice(0, maxLength);
  } else {
    statusTarget.textContent = "No summary";
    previewTarget.textContent = "No daily summary artifact is available yet.";
  }
}

async function refreshTier2(button) {
  const original = button.textContent;
  button.disabled = true;
  button.textContent = "Refreshing...";
  try {
    await fetchJson("/api/tier2/refresh", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    });
    state.detailCache.clear();
    await loadDashboard();
  } catch (error) {
    els.lastUpdated.textContent = `Tier 2 refresh failed: ${error.message}`;
  } finally {
    button.disabled = false;
    button.textContent = original;
  }
}

function setActiveView(viewName) {
  state.activeView = viewName;
  document.querySelectorAll(".nav-item").forEach((item) => {
    item.classList.toggle("active", item.getAttribute("data-view") === viewName);
  });
  document.querySelectorAll(".view-section").forEach((section) => {
    section.classList.toggle("active", section.id === `view-${viewName}`);
  });
  const [eyebrow, title] = VIEW_LABELS[viewName] || VIEW_LABELS.dashboard;
  els.viewEyebrow.textContent = eyebrow;
  els.viewTitle.textContent = title;
  renderAll();
}

function detailRow(label, value) {
  return `<div class="detail-row"><strong>${escapeHtml(label)}</strong><span>${escapeHtml(String(value))}</span></div>`;
}

function badge(label, tone) {
  return `<span class="badge ${escapeAttr(String(tone || "").toLowerCase())}">${escapeHtml(String(label))}</span>`;
}

function formatRouteBreakdown(routes) {
  const pending = ((state.dashboard || {}).counters || {}).pending_tier1;
  const routeText = ["auto_dismiss", "tier1_llm", "auto_alert"]
    .map((key) => `${key}: ${number(routes[key])}`)
    .join("  ");
  return pending ? `${routeText}  pending_tier1: ${number(pending)}` : routeText;
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

function formatShap(items) {
  if (!Array.isArray(items) || !items.length) {
    return "not available";
  }
  return items
    .slice(0, 5)
    .map((item) => Array.isArray(item) ? `${item[0]}=${item[1]} (${item[2]})` : String(item))
    .join("; ");
}

function portLabel(value) {
  return value === null || value === undefined || value === "" ? "port -" : `port ${value}`;
}

function previewText(value, length) {
  const clean = String(value || "").replace(/\s+/g, " ").trim();
  return clean ? clean.slice(0, length) : "empty";
}

function sourceLabel(name) {
  return String(name || "-").replace(/_/g, " ");
}

function orderedSources(sources) {
  const order = ["organization", "assets", "policy", "cve_feed", "threat_feed", "tier1_db"];
  return [...sources].sort((a, b) => order.indexOf(a.name) - order.indexOf(b.name));
}

function boolLabel(value) {
  if (value === true || value === 1) {
    return "yes";
  }
  if (value === false || value === 0) {
    return "no";
  }
  return "unknown";
}

function watchlistDetail(flow, key, fallback = "none") {
  const detail = flow.watchlist_detail || {};
  return detail[key] ?? fallback;
}

function selectedFlowSummary(flows) {
  if (!flows.length) {
    return null;
  }
  return flows.find((item) => item.flow_id === state.selectedFlowId) || flows[0];
}

function topologyGroupOrder() {
  return [
    "external",
    "dmz",
    "internal-app",
    "database",
    "clinical",
    "backup",
    "admin",
    "infrastructure",
    "workstation",
    "other",
  ];
}

function topologyLayout(groups) {
  const preset = {
    external: [40, 60],
    dmz: [310, 60],
    "internal-app": [580, 60],
    database: [850, 60],
    workstation: [40, 350],
    admin: [310, 350],
    infrastructure: [580, 350],
    backup: [850, 350],
    clinical: [580, 620],
    other: [310, 620],
  };
  const boxes = new Map();
  let overflowIndex = 0;
  for (const group of groups) {
    const fallback = [40 + (overflowIndex % 4) * 270, 620 + Math.floor(overflowIndex / 4) * 270];
    const [x, y] = preset[group.id] || fallback;
    if (!preset[group.id]) {
      overflowIndex += 1;
    }
    boxes.set(group.id, {
      id: group.id,
      label: group.label,
      x,
      y,
      width: 216,
      height: 210,
      cx: x + 108,
      cy: y + 105,
    });
  }
  return { groups: boxes, width: 1120, height: 900 };
}

function aggregateGroupEdges(edges, nodeGroup) {
  const grouped = new Map();
  for (const edge of edges) {
    const srcGroup = nodeGroup.get(edge.src);
    const dstGroup = nodeGroup.get(edge.dst);
    if (!srcGroup || !dstGroup) {
      continue;
    }
    const key = `${srcGroup}->${dstGroup}`;
    const groupEdge = grouped.get(key) || {
      src: srcGroup,
      dst: dstGroup,
      src_label: sourceLabel(srcGroup),
      dst_label: sourceLabel(dstGroup),
      count: 0,
      flow_ids: [],
      latest_flow_id: null,
      alert_count: 0,
      watchlist_hit_count: 0,
    };
    groupEdge.count += number(edge.count);
    groupEdge.flow_ids.push(...(edge.flow_ids || []));
    groupEdge.latest_flow_id = groupEdge.latest_flow_id || edge.latest_flow_id;
    groupEdge.alert_count += number(edge.alert_count);
    groupEdge.watchlist_hit_count += number(edge.watchlist_hit_count);
    grouped.set(key, groupEdge);
  }
  return Array.from(grouped.values()).sort((a, b) => {
    return (b.alert_count - a.alert_count) || (b.watchlist_hit_count - a.watchlist_hit_count) || (b.count - a.count);
  });
}

function groupAnchor(from, to) {
  const dx = to.cx - from.cx;
  const dy = to.cy - from.cy;
  if (Math.abs(dx) > Math.abs(dy)) {
    return {
      x: from.cx + Math.sign(dx || 1) * from.width / 2,
      y: from.cy + Math.max(-from.height / 3, Math.min(from.height / 3, dy * 0.2)),
    };
  }
  return {
    x: from.cx + Math.max(-from.width / 3, Math.min(from.width / 3, dx * 0.2)),
    y: from.cy + Math.sign(dy || 1) * from.height / 2,
  };
}

function topologyChips(nodes, selected) {
  const scored = nodes.map((node) => {
    const isSelected = selected && (selected.src_ip === node.ip || selected.dst_ip === node.ip);
    const sourceScore = node.source === "asset_input" ? 10 : 0;
    const criticalScore = ["critical", "high"].includes(String(node.criticality).toLowerCase()) ? 5 : 0;
    return { node, score: (isSelected ? 100 : 0) + sourceScore + criticalScore };
  });
  return scored
    .sort((a, b) => b.score - a.score || String(a.node.label).localeCompare(String(b.node.label)))
    .slice(0, 8)
    .map((item) => item.node);
}

function bindTopologyPan() {
  const svg = els.topologyGraph.querySelector(".topology-svg");
  if (!svg) {
    return;
  }
  svg.addEventListener("pointerdown", (event) => {
    svg.setPointerCapture(event.pointerId);
    state.topologyDrag = {
      pointerId: event.pointerId,
      startX: event.clientX,
      startY: event.clientY,
      viewBox: { ...state.topologyViewBox },
    };
    svg.classList.add("dragging");
  });
  svg.addEventListener("pointermove", (event) => {
    if (!state.topologyDrag || state.topologyDrag.pointerId !== event.pointerId) {
      return;
    }
    const bounds = svg.getBoundingClientRect();
    const dx = ((event.clientX - state.topologyDrag.startX) / bounds.width) * state.topologyDrag.viewBox.width;
    const dy = ((event.clientY - state.topologyDrag.startY) / bounds.height) * state.topologyDrag.viewBox.height;
    const worldWidth = Number(svg.getAttribute("data-world-width") || state.topologyDrag.viewBox.width);
    const worldHeight = Number(svg.getAttribute("data-world-height") || state.topologyDrag.viewBox.height);
    state.topologyViewBox.x = clamp(state.topologyDrag.viewBox.x - dx, -40, Math.max(40, worldWidth - state.topologyDrag.viewBox.width + 40));
    state.topologyViewBox.y = clamp(state.topologyDrag.viewBox.y - dy, -40, Math.max(40, worldHeight - state.topologyDrag.viewBox.height + 40));
    svg.setAttribute("viewBox", `${state.topologyViewBox.x} ${state.topologyViewBox.y} ${state.topologyViewBox.width} ${state.topologyViewBox.height}`);
  });
  const endDrag = (event) => {
    if (state.topologyDrag && state.topologyDrag.pointerId === event.pointerId) {
      state.topologyDrag = null;
      svg.classList.remove("dragging");
    }
  };
  svg.addEventListener("pointerup", endDrag);
  svg.addEventListener("pointercancel", endDrag);
}

function ellipsis(value, length) {
  const text = String(value || "");
  return text.length > length ? `${text.slice(0, Math.max(0, length - 3))}...` : text;
}

function listLabel(value) {
  if (!Array.isArray(value) || !value.length) {
    return "none";
  }
  return value.join("; ");
}

function number(value) {
  return Number(value || 0);
}

function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
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
  button.addEventListener("click", () => setActiveView(button.getAttribute("data-view")));
});

els.sidebarToggle.addEventListener("click", () => {
  state.sidebarCollapsed = !state.sidebarCollapsed;
  els.appShell.classList.toggle("sidebar-collapsed", state.sidebarCollapsed);
});

els.flowDetailClose.addEventListener("click", closeFlowDetailModal);
els.flowDetailModal.addEventListener("click", (event) => {
  if (event.target === els.flowDetailModal) {
    closeFlowDetailModal();
  }
});
window.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && !els.flowDetailModal.hidden) {
    closeFlowDetailModal();
  }
});

els.contextTabList.querySelectorAll("button[data-artifact]").forEach((button) => {
  button.addEventListener("click", () => {
    state.selectedArtifact = button.getAttribute("data-artifact");
    els.contextTabList.querySelectorAll(".tab-item").forEach((item) => {
      item.classList.toggle("active", item.getAttribute("data-artifact") === state.selectedArtifact);
    });
    renderContext(state.dashboard || {});
  });
});

els.refreshButton.addEventListener("click", loadDashboard);
els.inputsRefreshTier2.addEventListener("click", () => refreshTier2(els.inputsRefreshTier2));
els.contextRefreshTier2.addEventListener("click", () => refreshTier2(els.contextRefreshTier2));

setActiveView("dashboard");
loadDashboard();
state.timer = window.setInterval(loadDashboard, 2000);
