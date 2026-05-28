const VIEW_LABELS = {
  dashboard: ["Operations Dashboard", "Current SOC Situation"],
  realtime: ["Realtime Monitoring", "Live Flow Triage"],
  inputs: ["Tier 2 Inputs", "Organization And Security Inputs"],
  context: ["Tier 2 Context", "Curated Watchlist And Context"],
  reports: ["Reports", "Summary And Report Archive"],
  settings: ["Settings", "Runtime Configuration"],
};

const SAVED_GEMINI_KEY_MASK = "saved-gemini-api-key";

const state = {
  activeView: "dashboard",
  dashboard: null,
  sources: [],
  startupOptions: null,
  startupStatus: null,
  startupLog: [],
  selectedFlowId: null,
  selectedFlowDetail: null,
  selectedSourceName: "organization",
  selectedArtifact: "watchlist",
  inputRawDirty: false,
  detailCache: new Map(),
  timer: null,
  sidebarCollapsed: false,
  topologyViewBox: { x: 0, y: 0, width: 820, height: 520 },
  topologyDrag: null,
  topologyFullscreenOpen: false,
  liveFreezeUntil: {},
  deferredRenderTimer: null,
  knownFlowIds: new Set(),
  newFlowIds: new Set(),
  isInitialLoad: true,
  reviewKnownUncertainIds: new Set(),
  newReviewIds: new Set(),
  reviewTrackingStarted: false,
  flowListModal: {
    type: null,
    page: 1,
    pageSize: 30,
    events: null,
  },
  inputEditMode: null,
  realtimeHideBenign: true,
  reportFilters: {
    date: "",
    severity: "",
    verdict: "",
    asset: "",
  },
  settingsOptions: null,
  settingsDirty: false,
  settingsHydrated: false,
  llmOptionsRefreshInFlight: false,
  llmOptionsAutoTimer: null,
};

const els = {
  startupScreen: document.querySelector("#startup-screen"),
  startupTier1Provider: document.querySelector("#startup-tier1-provider"),
  startupTier1Model: document.querySelector("#startup-tier1-model"),
  startupTier1OllamaUrl: document.querySelector("#startup-tier1-ollama-url"),
  startupTier2Provider: document.querySelector("#startup-tier2-provider"),
  startupTier2Model: document.querySelector("#startup-tier2-model"),
  startupTier2OllamaUrl: document.querySelector("#startup-tier2-ollama-url"),
  startupGeminiApiKey: document.querySelector("#startup-gemini-api-key"),
  startupOllamaWarning: document.querySelector("#startup-ollama-warning"),
  startupStart: document.querySelector("#startup-start"),
  startupStatus: document.querySelector("#startup-status"),
  startupProgress: document.querySelector("#startup-progress"),
  startupLog: document.querySelector("#startup-log"),
  appShell: document.querySelector("#app-shell"),
  sidebarToggle: document.querySelector("#sidebar-toggle"),
  serviceStatus: document.querySelector("#service-status"),
  viewSubtitle: document.querySelector("#view-subtitle"),
  lastUpdated: document.querySelector("#last-updated"),
  refreshButton: document.querySelector("#refresh-button"),
  viewEyebrow: document.querySelector("#view-eyebrow"),
  viewTitle: document.querySelector("#view-title"),
  metricAlerts: document.querySelector("#metric-alerts"),
  metricAlertsCard: document.querySelector("#metric-alerts-card"),
  metricSeverity: document.querySelector("#metric-severity"),
  metricTier1: document.querySelector("#metric-tier1"),
  metricTier1WorkerState: document.querySelector("#metric-tier1-worker-state"),
  metricTier1Model: document.querySelector("#metric-tier1-model"),
  metricNeedsReview: document.querySelector("#metric-needs-review"),
  metricNeedsReviewCard: document.querySelector("#metric-needs-review-card"),
  metricNeedsReviewLabel: document.querySelector("#metric-needs-review-label"),
  routeBreakdown: document.querySelector("#route-breakdown"),
  flowTrendChart: document.querySelector("#flow-trend-chart"),
  flowTrendSummary: document.querySelector("#flow-trend-summary"),
  realtimeRouteBreakdown: document.querySelector("#realtime-route-breakdown"),
  realtimeHideBenign: document.querySelector("#realtime-hide-benign"),
  realtimeOpenAll: document.querySelector("#realtime-open-all"),
  dashboardTableWrap: document.querySelector(".dashboard-table-wrap"),
  realtimeTableWrap: document.querySelector(".realtime-table-wrap"),
  flowTableBody: document.querySelector("#flow-table-body"),
  realtimeFlowTableBody: document.querySelector("#realtime-flow-table-body"),
  topologyStatus: document.querySelector("#topology-status"),
  topologyGraph: document.querySelector("#topology-graph"),
  topologyFullscreen: document.querySelector("#topology-fullscreen"),
  topologyModal: document.querySelector("#topology-modal"),
  topologyModalClose: document.querySelector("#topology-modal-close"),
  topologyModalStatus: document.querySelector("#topology-modal-status"),
  topologyModalGraph: document.querySelector("#topology-modal-graph"),
  summaryStatus: document.querySelector("#summary-status"),
  summaryPreview: document.querySelector("#summary-preview"),
  artifactList: document.querySelector("#artifact-list"),
  sourceCounts: document.querySelector("#source-counts"),
  sourceList: document.querySelector("#source-list"),
  selectedFlow: document.querySelector("#selected-flow"),
  runtimeState: document.querySelector("#runtime-state"),
  inputTabList: document.querySelector("#input-tab-list"),
  inputSourceDetail: document.querySelector("#input-source-detail"),
  inputStructuredContent: document.querySelector("#input-structured-content"),
  inputOpenAdd: document.querySelector("#input-open-add"),
  inputOpenRaw: document.querySelector("#input-open-raw"),
  inputEditModal: document.querySelector("#input-edit-modal"),
  inputEditClose: document.querySelector("#input-edit-close"),
  inputEditEyebrow: document.querySelector("#input-edit-eyebrow"),
  inputEditTitle: document.querySelector("#input-edit-title"),
  inputAddPanel: document.querySelector("#input-add-panel"),
  inputRawPanel: document.querySelector("#input-raw-panel"),
  inputAddTitle: document.querySelector("#input-add-title"),
  inputRawTitle: document.querySelector("#input-raw-title"),
  inputQuickAdd: document.querySelector("#input-quick-add"),
  inputAddItem: document.querySelector("#input-add-item"),
  inputAddCancel: document.querySelector("#input-add-cancel"),
  inputAddStatus: document.querySelector("#input-add-status"),
  inputRawStatus: document.querySelector("#input-raw-status"),
  inputRawEditor: document.querySelector("#input-raw-editor"),
  inputSaveRaw: document.querySelector("#input-save-raw"),
  inputRawCancel: document.querySelector("#input-raw-cancel"),
  inputPreviewStatus: document.querySelector("#input-preview-status"),
  contextRefreshTier2: document.querySelector("#context-refresh-tier2"),
  contextRefreshStatus: document.querySelector("#context-refresh-status"),
  contextTabList: document.querySelector("#context-tab-list"),
  contextArtifactContent: document.querySelector("#context-artifact-content"),
  contextArtifactList: document.querySelector("#context-artifact-list"),
  contextSourceList: document.querySelector("#context-source-list"),
  reportsSummaryStatus: document.querySelector("#reports-summary-status"),
  reportsGenerateSummary: document.querySelector("#reports-generate-summary"),
  reportsGenerateStatus: document.querySelector("#reports-generate-status"),
  reportsSummaryPreview: document.querySelector("#reports-summary-preview"),
  reportsRiskLabel: document.querySelector("#reports-risk-label"),
  reportsFlowCount: document.querySelector("#reports-flow-count"),
  reportsWatchlistCount: document.querySelector("#reports-watchlist-count"),
  reportsTier1Count: document.querySelector("#reports-tier1-count"),
  reportsEasySummary: document.querySelector("#reports-easy-summary"),
  reportsFirstChecks: document.querySelector("#reports-first-checks"),
  reportsImportantAlerts: document.querySelector("#reports-important-alerts"),
  reportsDateFilter: document.querySelector("#reports-date-filter"),
  reportsSeverityFilter: document.querySelector("#reports-severity-filter"),
  reportsVerdictFilter: document.querySelector("#reports-verdict-filter"),
  reportsAssetFilter: document.querySelector("#reports-asset-filter"),
  reportsAssetOptions: document.querySelector("#reports-asset-options"),
  flowListHideBenignRow: document.querySelector("#flow-list-hide-benign-row"),
  flowListHideBenign: document.querySelector("#flow-list-hide-benign"),
  reportsFilterSummary: document.querySelector("#reports-filter-summary"),
  reportList: document.querySelector("#report-list"),
  settingsRefreshModels: document.querySelector("#settings-refresh-models"),
  settingsApply: document.querySelector("#settings-apply"),
  settingsResetDb: document.querySelector("#settings-reset-db"),
  settingsStatus: document.querySelector("#settings-status"),
  settingsTier1Provider: document.querySelector("#settings-tier1-provider"),
  settingsTier1Model: document.querySelector("#settings-tier1-model"),
  settingsTier1OllamaUrl: document.querySelector("#settings-tier1-ollama-url"),
  settingsTier1MaxTokens: document.querySelector("#settings-tier1-max-tokens"),
  settingsTier1Workers: document.querySelector("#settings-tier1-workers"),
  settingsTier2Provider: document.querySelector("#settings-tier2-provider"),
  settingsTier2Model: document.querySelector("#settings-tier2-model"),
  settingsTier2OllamaUrl: document.querySelector("#settings-tier2-ollama-url"),
  settingsTier2MaxTokens: document.querySelector("#settings-tier2-max-tokens"),
  settingsGeminiApiKey: document.querySelector("#settings-gemini-api-key"),
  settingsOllamaWarning: document.querySelector("#settings-ollama-warning"),
  settingsThresholdLow: document.querySelector("#settings-threshold-low"),
  settingsThresholdHigh: document.querySelector("#settings-threshold-high"),
  flowDetailModal: document.querySelector("#flow-detail-modal"),
  flowDetailClose: document.querySelector("#flow-detail-close"),
  flowDetailTitle: document.querySelector("#flow-detail-title"),
  flowDetailBody: document.querySelector("#flow-detail-body"),
  flowListModal: document.querySelector("#flow-list-modal"),
  flowListClose: document.querySelector("#flow-list-close"),
  flowListEyebrow: document.querySelector("#flow-list-eyebrow"),
  flowListTitle: document.querySelector("#flow-list-title"),
  flowListBody: document.querySelector("#flow-list-body"),
  flowListPagination: document.querySelector("#flow-list-pagination"),
};

async function fetchJson(url, options = {}) {
  const response = await fetch(url, {
    ...options,
    headers: { Accept: "application/json", ...(options.headers || {}) },
  });
  const text = await response.text();
  if (!response.ok) {
    let detail = text;
    try {
      const parsed = JSON.parse(text);
      detail = parsed.error || parsed.detail || text;
    } catch (_) {
      detail = text;
    }
    throw new Error(`${response.status} ${response.statusText}${detail ? `: ${detail}` : ""}`);
  }
  return text ? JSON.parse(text) : {};
}

async function loadDashboard() {
  try {
    const [dashboard, sourceInputs] = await Promise.all([
      fetchJson("/api/dashboard"),
      fetchJson("/api/source-inputs"),
    ]);
    state.dashboard = dashboard;
    state.sources = sourceInputs.sources || [];
    if (!els.flowListModal.hidden && state.flowListModal.type === "all") {
      try {
        const flowList = await fetchJson("/api/flows/recent?limit=500");
        state.flowListModal.events = flowList.events || [];
      } catch (_) {
        state.flowListModal.events = dashboard.recent_flows || [];
      }
    }
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
    updateReviewTracking(dashboard);

    renderAll();
    els.serviceStatus.textContent = "Running";
    els.lastUpdated.textContent = `Updated ${new Date().toLocaleTimeString()}`;
  } catch (error) {
    els.serviceStatus.textContent = "Disconnected";
    els.lastUpdated.textContent = "API unavailable";
    if (els.selectedFlow) {
      els.selectedFlow.textContent = `Dashboard request failed: ${error.message}`;
    }
  }
}

function renderAll({ force = false } = {}) {
  const data = state.dashboard || {};
  renderTopLevel(data);
  if (!viewRenderDeferred("dashboard", force)) {
    renderDashboard(data);
  }
  if (!viewRenderDeferred("realtime", force)) {
    renderRealtime(data);
  }
  if ((state.activeView !== "inputs" || !isEditingInputView()) && !viewRenderDeferred("inputs", force)) {
    renderInputs();
  }
  if (!viewRenderDeferred("context", force)) {
    renderContext(data);
  }
  if (!viewRenderDeferred("reports", force)) {
    renderReports(data);
  }
  if (!viewRenderDeferred("settings", force)) {
    renderSettings((data && data.status) || {});
  }
  if (!els.flowListModal.hidden && state.flowListModal.type && !shouldDeferLiveRender("flowListModal", force)) {
    renderFlowListModal();
  }
}

function renderTopLevel(data) {
  const status = data.status || {};
  if (els.viewSubtitle) {
    const showConfig = state.activeView === "settings";
    els.viewSubtitle.hidden = !showConfig;
    els.viewSubtitle.textContent = showConfig ? `Config: ${status.config_path || "-"}` : "";
  }
}

function viewRenderDeferred(viewName, force = false) {
  return state.activeView === viewName && shouldDeferLiveRender(viewName, force);
}

function shouldDeferLiveRender(region, force = false) {
  if (force) {
    return false;
  }
  const until = state.liveFreezeUntil[region] || 0;
  if (Date.now() < until) {
    scheduleDeferredRender();
    return true;
  }
  return false;
}

function markLiveInteraction(region, holdMs = 1300) {
  if (!region) {
    return;
  }
  state.liveFreezeUntil[region] = Math.max(state.liveFreezeUntil[region] || 0, Date.now() + holdMs);
}

function scheduleDeferredRender() {
  window.clearTimeout(state.deferredRenderTimer);
  const until = Math.max(0, ...Object.values(state.liveFreezeUntil || {}));
  const delay = Math.max(90, until - Date.now() + 60);
  state.deferredRenderTimer = window.setTimeout(() => {
    state.deferredRenderTimer = null;
    renderAll({ force: true });
  }, delay);
}

function renderDashboard(data) {
  const scrollSnapshot = captureScrollableRowsScroll(els.dashboardTableWrap);
  const counters = data.counters || {};
  const routes = counters.routes || {};
  const status = data.status || {};
  const alertEvents = dashboardEvents(data).filter(isAlertEvent);
  const reviewEvents = dashboardEvents(data).filter(isReviewEvent);
  const highCriticalAlerts = alertEvents.filter((event) => ["high", "critical"].includes(String(event.severity || "").toLowerCase())).length;

  els.metricAlerts.textContent = alertEvents.length;
  els.metricSeverity.textContent = `high/critical: ${highCriticalAlerts}`;
  els.metricNeedsReview.textContent = state.newReviewIds.size;
  els.metricNeedsReviewLabel.textContent = `${reviewEvents.length} uncertain total`;
  els.metricNeedsReviewCard.classList.toggle("needs-attention", state.newReviewIds.size > 0);
  const tier1Queue = status.tier1_queue || {};
  const activeWorkers = number(tier1Queue.current_active_workers);
  const pendingJobs = number(tier1Queue.current_queue_depth);
  const liveQueueTotal = activeWorkers + pendingJobs;
  els.metricTier1.textContent = liveQueueTotal;
  els.metricTier1WorkerState.textContent = `${activeWorkers} ${activeWorkers === 1 ? "worker" : "workers"} working, ${pendingJobs} pending`;
  const queueWorkers = status.tier1_queue_workers || ((status.tier1_queue || {}).tier1_workers);
  els.metricTier1Model.textContent = status.tier1_model || status.tier1_provider || "model unavailable";
  els.metricTier1Model.title = status.tier1_provider
    ? `${status.tier1_provider}: ${status.tier1_model || "-"} / workers=${queueWorkers || "-"}`
    : "";
  els.metricTier1Model.parentElement.classList.toggle("queue-active", liveQueueTotal > 0);
  els.routeBreakdown.textContent = formatRouteBreakdown(routes);
  renderFlowRows(els.flowTableBody, (data.recent_flows || []).slice(0, 10), "dashboard");
  restoreScrollableRowsScroll(els.dashboardTableWrap, scrollSnapshot);
  renderFlowTrend(data.recent_flows || []);
  renderArtifacts(els.artifactList, data.tier2_artifacts || {});
  renderSources(els.sourceList, state.sources, true);
  renderSourceCounts();
  renderSummary(data.latest_summary || {}, els.summaryStatus, els.summaryPreview, 2200);
}

function renderRealtime(data) {
  const routes = ((data.counters || {}).routes) || {};
  const allFlows = data.recent_flows || [];
  const visibleFlows = realtimeVisibleFlows(allFlows).slice(0, 100);
  const scrollSnapshot = captureScrollableRowsScroll(els.realtimeTableWrap);
  els.realtimeRouteBreakdown.textContent = `${formatRouteBreakdown(routes)}  showing ${visibleFlows.length}/${allFlows.length}`;
  renderTopology(data.topology || {}, data.recent_flows || []);
  renderFlowRows(els.realtimeFlowTableBody, visibleFlows, "realtime");
  restoreScrollableRowsScroll(els.realtimeTableWrap, scrollSnapshot);
  renderRuntimeState(data.status || {});
}

function renderTopology(topology, flows) {
  renderLegacyTopology(topology, flows, {
    graph: els.topologyGraph,
    status: els.topologyStatus,
  });
  if (state.topologyFullscreenOpen && els.topologyModalGraph) {
    renderLegacyTopology(topology, flows, {
      graph: els.topologyModalGraph,
      status: els.topologyModalStatus,
    });
  }
}

function renderLegacyTopology(topology, flows, target = {}) {
  const graph = target.graph || els.topologyGraph;
  const status = target.status || els.topologyStatus;
  const nodes = topology.nodes || [];
  const edges = topology.edges || [];
  const groups = topology.groups || [];
  const selected = selectedFlowSummary(flows);
  status.textContent = `${topology.status || "unknown"} / SVG / ${nodes.length} nodes / ${edges.length} edges`;

  if (!nodes.length) {
    graph.innerHTML = '<div class="selected-flow">No asset topology is available. Check the Tier 2 asset source input.</div>';
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

  const nodeEdgeScores = topologyNodeEdgeScores(edges);
  const chipPositions = new Map();
  const latestFlowId = flows[0] && flows[0].flow_id;

  const groupLayers = [];
  const gatewayLayers = [];
  const nodeLayers = [];
  const groupGateways = new Map();
  for (const group of visibleGroups) {
    const box = layout.groups.get(group.id);
    if (!box) {
      continue;
    }
    groupGateways.set(group.id, {
      id: group.id,
      x: box.cx,
      y: box.y + 50,
      label: group.label || group.id,
    });
    const selectedSource = selected && group.nodes.some((node) => node.ip === selected.src_ip);
    const selectedDest = selected && group.nodes.some((node) => node.ip === selected.dst_ip);
    const chips = topologyChips(group.nodes, selected, nodeEdgeScores)
      .map((node, index) => {
        const colWidth = 92;
        const colGap = 12;
        const x = box.x + 10 + (index % 2) * (colWidth + colGap);
        const y = box.y + 62 + Math.floor(index / 2) * 28;
        chipPositions.set(node.id, {
          id: node.id,
          x: x + 46,
          y: y + 10.5,
          label: node.label || node.ip,
          group: group.id,
        });
        const sourceClass = selected && selected.src_ip === node.ip ? " selected-source" : "";
        const destClass = selected && selected.dst_ip === node.ip ? " selected-dest" : "";
        const sourceTypeClass = node.source === "recent_flow" ? " virtual" : "";
        return `
          <g class="topology-node${sourceClass}${destClass}${sourceTypeClass}">
            <rect x="${x}" y="${y}" width="92" height="21" rx="6"></rect>
            <title>${escapeHtml(node.label || node.ip)} - ${escapeHtml(node.ip || "-")}</title>
            <text x="${x + 6}" y="${y + 14}">${escapeHtml(ellipsis(node.label || node.ip, 15))}</text>
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
    groupLayers.push(`
      <g class="${groupClasses}">
        <rect x="${box.x}" y="${box.y}" width="${box.width}" height="${box.height}" rx="10"></rect>
        <text class="topology-group-label" x="${box.x + 16}" y="${box.y + 24}">${escapeHtml(ellipsis(group.label || group.id, 24))}</text>
        <text class="topology-group-count" x="${box.x + 16}" y="${box.y + 43}">${total} endpoints / ${number(group.asset_count)} assets</text>
        ${hiddenCount ? `<text class="topology-group-count" x="${box.x + 16}" y="${box.y + 181}">+${hiddenCount} more</text>` : ""}
      </g>
    `);
    gatewayLayers.push(`
      <g class="topology-gateway">
        <circle cx="${box.cx}" cy="${box.y + 50}" r="5"></circle>
        <title>${escapeHtml(group.label || group.id)} gateway</title>
      </g>
    `);
    nodeLayers.push(chips);
  }

  const edgeLayers = topologyGatewayEdgeLayers(
    edges,
    chipPositions,
    groupGateways,
    selected,
    latestFlowId,
    nodeGroup,
  );

  graph.innerHTML = `
    <svg class="topology-svg" viewBox="${state.topologyViewBox.x} ${state.topologyViewBox.y} ${state.topologyViewBox.width} ${state.topologyViewBox.height}" data-world-width="${layout.width}" data-world-height="${layout.height}" role="img" aria-label="Organization asset relationship view">
      <rect class="topology-world-bg" x="0" y="0" width="${layout.width}" height="${layout.height}" rx="18"></rect>
      ${groupLayers.join("")}
      <g class="topology-edge-layer">${edgeLayers}</g>
      <g class="topology-gateway-layer">${gatewayLayers.join("")}</g>
      <g class="topology-node-layer">${nodeLayers.join("")}</g>
    </svg>
    <div class="topology-note">${escapeHtml(topology.note || "")}</div>
  `;
  bindTopologyPan(graph);
}

function renderInputs() {
  const sources = orderedSources(state.sources);
  if (!sources.length) {
    els.inputTabList.innerHTML = "";
    els.inputSourceDetail.innerHTML = '<div class="selected-flow">No source inputs are available.</div>';
    els.inputStructuredContent.innerHTML = '<div class="selected-flow">No source inputs are available.</div>';
    els.inputQuickAdd.innerHTML = "";
    els.inputRawEditor.value = "";
    return;
  }
  if (!sources.some((source) => source.name === state.selectedSourceName)) {
    state.selectedSourceName = sources[0].name;
    state.inputRawDirty = false;
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
      state.inputRawDirty = false;
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
  els.inputStructuredContent.innerHTML = structuredSourceHtml(source);
  els.inputStructuredContent.querySelectorAll("[data-delete-list][data-delete-index]").forEach((button) => {
    button.addEventListener("click", (event) => {
      event.stopPropagation();
      deleteStructuredInputItem(
        button.getAttribute("data-delete-list"),
        Number(button.getAttribute("data-delete-index")),
      );
    });
  });
  els.inputQuickAdd.innerHTML = quickAddFieldsHtml(source.name);
  updateInputModalTitles(source);
  if (!state.inputRawDirty) {
    els.inputRawEditor.value = source.content || "";
  }
}

function isEditingInputView() {
  const active = document.activeElement;
  return (
    state.inputRawDirty ||
    !els.inputEditModal.hidden ||
    Boolean(active && active.closest && (active.closest("#view-inputs") || active.closest("#input-edit-modal")))
  );
}

function structuredSourceHtml(source) {
  const data = source.data || {};
  if (source.name === "organization") {
    const organization = data.organization && typeof data.organization === "object" ? data.organization : data;
    return keyValueCardHtml(organization, "Organization");
  }
  if (source.name === "assets") {
    return listCardsHtml(
      source.name,
      sourceListDescriptors(data, ["assets"]),
      ["id", "ip", "role", "zone", "criticality"],
      "No assets are listed yet.",
    );
  }
  if (source.name === "policy") {
    return listCardsHtml(
      source.name,
      sourceListDescriptors(data, ["policies", "elevated_risk_rules", "asset_specific_policies"]),
      ["name", "description", "condition", "action"],
      "No policies are listed yet.",
    );
  }
  if (source.name === "cve_feed") {
    return listCardsHtml(
      source.name,
      sourceListDescriptors(data, ["cves", "advisories"]),
      ["cve_id", "id", "severity", "summary"],
      "No CVE items are listed yet.",
    );
  }
  if (source.name === "threat_feed") {
    return listCardsHtml(
      source.name,
      sourceListDescriptors(data, ["known_malicious_ips", "suspicious_patterns", "custom_threat_context"]),
      ["ip", "pattern", "name", "description"],
      "No threat indicators are listed yet.",
    );
  }
  return '<div class="selected-flow compact">This source can be edited with raw YAML.</div>';
}

function sourceListDescriptors(data, keys) {
  return keys.flatMap((listKey) => {
    const values = Array.isArray(data[listKey]) ? data[listKey] : [];
    return values.map((item, index) => ({ item, index, listKey }));
  });
}

function keyValueCardHtml(value, title) {
  if (!value || typeof value !== "object" || Array.isArray(value) || !Object.keys(value).length) {
    return `<div class="selected-flow compact">${escapeHtml(title)} is empty.</div>`;
  }
  return `
    <div class="structured-card">
      <strong>${escapeHtml(title)}</strong>
      ${Object.entries(value)
        .map(([key, val]) => detailRow(key, sourceValueLabel(val)))
        .join("")}
    </div>
  `;
}

function listCardsHtml(sourceName, descriptors, preferredKeys, emptyText) {
  if (!Array.isArray(descriptors) || !descriptors.length) {
    return `<div class="selected-flow compact">${escapeHtml(emptyText)}</div>`;
  }
  return descriptors
    .slice(0, 80)
    .map((descriptor, visibleIndex) => {
      const item = descriptor.item;
      const value = item && typeof item === "object" ? item : { value: item };
      const keys = preferredKeys.filter((key) => value[key] !== undefined && value[key] !== "");
      const rest = Object.keys(value).filter((key) => !keys.includes(key)).slice(0, 4);
      const visibleKeys = [...keys, ...rest].slice(0, 6);
      const title = value.id || value.name || value.cve_id || value.ip || value.pattern || `Item ${visibleIndex + 1}`;
      return `
        <div class="structured-card">
          <div class="structured-card-heading">
            <strong>${escapeHtml(title)}</strong>
            <button class="remove-item-button" type="button" title="Remove item" aria-label="Remove item" data-delete-list="${escapeAttr(descriptor.listKey)}" data-delete-index="${escapeAttr(String(descriptor.index))}">-</button>
          </div>
          ${visibleKeys.map((key) => detailRow(key, sourceValueLabel(value[key]))).join("")}
        </div>
      `;
    })
    .join("");
}

function quickAddFieldsHtml(sourceName) {
  const fields = {
    organization: [
      ["name", "Organization name"],
      ["industry", "Industry"],
      ["timezone", "Timezone"],
    ],
    assets: [
      ["id", "Asset ID"],
      ["ip", "IP address"],
      ["role", "Role"],
      ["zone", "Zone"],
      ["services", "Services, comma-separated"],
      ["criticality", "Criticality"],
    ],
    policy: [
      ["name", "Policy name"],
      ["description", "Description"],
      ["condition", "Condition"],
      ["action", "Action"],
    ],
    cve_feed: [
      ["cve_id", "CVE ID"],
      ["severity", "Severity"],
      ["affected_assets", "Affected assets, comma-separated"],
      ["summary", "Summary"],
    ],
    threat_feed: [
      ["ip", "Malicious IP"],
      ["pattern", "Suspicious pattern"],
      ["description", "Description"],
      ["tags", "Tags, comma-separated"],
    ],
  }[sourceName] || [];
  if (!fields.length) {
    return '<div class="selected-flow compact">Use raw YAML for this source.</div>';
  }
  return fields
    .map(([name, label]) => `
      <label>
        ${escapeHtml(label)}
        <input data-input-field="${escapeAttr(name)}" type="text" spellcheck="false">
      </label>
    `)
    .join("");
}

function sourceValueLabel(value) {
  if (Array.isArray(value)) {
    return value.join(", ");
  }
  if (value && typeof value === "object") {
    return JSON.stringify(value);
  }
  return value ?? "";
}

function selectedSource() {
  return orderedSources(state.sources).find((source) => source.name === state.selectedSourceName) || null;
}

function updateInputModalTitles(source) {
  const label = source ? sourceLabel(source.name) : "Input";
  if (els.inputEditEyebrow) {
    els.inputEditEyebrow.textContent = label;
  }
  if (els.inputAddTitle) {
    els.inputAddTitle.textContent = `Add ${label} Item`;
  }
  if (els.inputRawTitle) {
    els.inputRawTitle.textContent = `Edit ${label} Raw YAML`;
  }
}

function openInputEditor(mode) {
  const source = selectedSource();
  if (!source) {
    setInputStatus("No source input is selected.");
    return;
  }
  state.inputEditMode = mode;
  updateInputModalTitles(source);
  els.inputEditTitle.textContent = mode === "raw" ? "Edit Raw YAML" : "Add Item";
  els.inputAddPanel.hidden = mode !== "add";
  els.inputRawPanel.hidden = mode !== "raw";
  if (mode === "add") {
    els.inputQuickAdd.innerHTML = quickAddFieldsHtml(source.name);
    setInputStatus("Ready");
  } else {
    state.inputRawDirty = false;
    els.inputRawEditor.value = source.content || "";
    setInputStatus("Ready");
  }
  els.inputEditModal.hidden = false;
}

function closeInputEditor() {
  state.inputEditMode = null;
  state.inputRawDirty = false;
  els.inputEditModal.hidden = true;
}

function renderContext(data) {
  const artifacts = data.tier2_artifacts || {};
  if (els.contextArtifactList) {
    renderArtifacts(els.contextArtifactList, artifacts);
  }
  renderSources(els.contextSourceList, state.sources, false);
  const artifact = artifacts[state.selectedArtifact] || {};
  els.contextArtifactContent.textContent = artifact.exists
    ? artifact.content || "Artifact exists but is empty."
    : `Missing artifact: ${state.selectedArtifact}`;
}

function renderReports(data) {
  renderReportSummary(data.latest_summary || {});
  const reports = data.reports || {};
  renderReportFilters(reports.filter_options || {});
  const dailySummaries = reports.daily_summaries || [];
  els.reportList.innerHTML = dailySummaries.length
    ? dailySummaries
        .filter((report) => !state.reportFilters.date || report.date === state.reportFilters.date)
        .slice(0, 20)
        .map((report) => `
          <div class="artifact-item">
            <div>
              <strong>${escapeHtml(report.date || report.name || "-")}</strong>
              <div class="source-path">${escapeHtml(report.risk_label || "Unknown")} / ${number(report.flow_count)} flows / ${number(report.watchlist_hit_count)} watchlist hits</div>
              <div class="source-path">${escapeHtml(report.path || "-")}</div>
            </div>
            ${badge("daily", "tier1_llm")}
          </div>
        `)
        .join("")
    : '<div class="selected-flow">No daily summaries are available.</div>';
}

function reportQueryString() {
  const params = new URLSearchParams();
  params.set("limit", "250");
  if (state.reportFilters.date) {
    params.set("date", state.reportFilters.date);
  }
  if (state.reportFilters.severity) {
    params.set("severity", state.reportFilters.severity);
  }
  if (state.reportFilters.verdict) {
    params.set("verdict", state.reportFilters.verdict);
  }
  if (state.reportFilters.asset) {
    params.set("asset", state.reportFilters.asset);
  }
  return params.toString();
}

async function refreshReports() {
  els.reportsFilterSummary.textContent = "Refreshing...";
  try {
    const [summary, reports] = await Promise.all([
      fetchJson("/api/summary/latest"),
      fetchJson("/api/reports?limit=250"),
    ]);
    state.dashboard = {
      ...(state.dashboard || {}),
      latest_summary: summary,
      reports,
    };
    renderReports(state.dashboard);
    els.reportsGenerateStatus.textContent = "Report archive refreshed.";
    els.lastUpdated.textContent = `Updated ${new Date().toLocaleTimeString()}`;
  } catch (error) {
    els.reportsGenerateStatus.textContent = `Report refresh failed: ${error.message}`;
  }
}

async function generateDailySummary() {
  const status = ((state.dashboard || {}).status) || {};
  const tier2Provider = status.tier2_provider || "deterministic";
  const tier2Model = status.tier2_model || tier2Provider;
  const usesLlm = ["gemini", "ollama"].includes(String(tier2Provider).toLowerCase());
  els.reportsGenerateSummary.disabled = true;
  els.reportsGenerateStatus.textContent = usesLlm
    ? `Calling Tier 2 ${tier2Provider} daily-summary model (${tier2Model}). This can take a little while.`
    : "Generating deterministic daily summary from stored events because Tier 2 is not set to an LLM provider.";
  try {
    const result = await fetchJson("/api/summary/generate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    });
    state.dashboard = {
      ...(state.dashboard || {}),
      latest_summary: result.latest_summary || {},
      reports: result.reports || ((state.dashboard || {}).reports || {}),
    };
    renderReports(state.dashboard);
    const mode = result.generation_mode || ((result.summary || {}).generation || {}).mode || "deterministic_sqlite";
    const generation = ((result.summary || {}).generation) || {};
    const llmText = generation.fallback
      ? "Tier 2 LLM fallback used"
      : (result.llm_called ? "LLM call used" : "no Gemini/LLM call");
    els.reportsGenerateStatus.textContent = `Daily summary generation finished (${mode}, ${llmText}). The latest summary is shown here.`;
    els.lastUpdated.textContent = `Updated ${new Date().toLocaleTimeString()}`;
  } catch (error) {
    els.reportsGenerateStatus.textContent = `Daily summary generation failed: ${error.message}`;
  } finally {
    els.reportsGenerateSummary.disabled = false;
  }
}

async function refreshCurrentView() {
  if (state.activeView === "reports") {
    await refreshReports();
    return;
  }
  await loadDashboard();
}

function renderOrRefreshReports() {
  if (!els.flowListModal.hidden && state.flowListModal.type) {
    state.flowListModal.page = 1;
    renderFlowListModal({ preserveScroll: false });
    return;
  }
  if (state.activeView === "reports") {
    refreshReports();
    return;
  }
  renderReports(state.dashboard || {});
}

function renderFlowRows(target, flows, scope) {
  const colspan = scope === "realtime" ? 8 : 6;
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
            <td>${escapeHtml(flow.src_ip || "-")}<br><span class="soft-label">${portLabel(flow.src_port)}</span></td>
            <td>${escapeHtml(flow.dst_ip || "-")}<br><span class="soft-label">${portLabel(flow.dst_port)} / ${escapeHtml(flow.protocol || "-")}</span></td>
            <td>${formatProbability(flow.prob)}</td>
            <td>${badge(flow.route || "unknown", flow.route)}</td>
            <td>${flowVerdictBadge(flow)}</td>
            <td>${flowSeverityBadge(flow)}</td>
            <td>${flow.watchlist_matched ? badge("hit", "tier1_llm") : '<span class="soft-label">none</span>'}</td>
          </tr>
        `;
      }
      return `
        <tr class="${selected}${newClass}" data-flow-id="${escapeHtml(flow.flow_id || "")}">
          <td>${escapeHtml(compactTime(flow))}</td>
          <td>${escapeHtml(flow.src_ip || "-")}<br><span class="soft-label">${portLabel(flow.src_port)}</span></td>
          <td>${escapeHtml(flow.dst_ip || "-")}<br><span class="soft-label">${portLabel(flow.dst_port)} / ${escapeHtml(flow.protocol || "-")}</span></td>
          <td>${formatProbability(flow.prob)}</td>
          <td>${badge(flow.route || "unknown", flow.route)} ${flowVerdictBadge(flow)}</td>
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

function updateReviewTracking(dashboard) {
  const currentReviewIds = new Set(
    dashboardEvents(dashboard)
      .filter(isReviewEvent)
      .map((event) => event.flow_id)
      .filter(Boolean),
  );
  if (!state.reviewTrackingStarted) {
    state.reviewKnownUncertainIds = currentReviewIds;
    state.newReviewIds = new Set();
    state.reviewTrackingStarted = true;
    return;
  }
  for (const id of currentReviewIds) {
    if (!state.reviewKnownUncertainIds.has(id)) {
      state.newReviewIds.add(id);
    }
  }
  state.newReviewIds = new Set([...state.newReviewIds].filter((id) => currentReviewIds.has(id)));
  state.reviewKnownUncertainIds = currentReviewIds;
}

function dashboardEvents(data) {
  const reportEvents = (((data || {}).reports || {}).event_reports) || [];
  if (reportEvents.length) {
    return reportEvents;
  }
  return (data || {}).recent_flows || [];
}

function isAlertEvent(event) {
  return String(event.verdict || "").toLowerCase() === "alert";
}

function isReviewEvent(event) {
  return String(event.verdict || "").toLowerCase() === "uncertain";
}

function isBenignEvent(event) {
  return (
    String(event.verdict || "").toLowerCase() === "benign" ||
    String(event.route || "").toLowerCase() === "auto_dismiss" ||
    String(event.severity || "").toLowerCase() === "low"
  );
}

function realtimeVisibleFlows(flows) {
  return state.realtimeHideBenign ? flows.filter((flow) => !isBenignEvent(flow)) : flows;
}

function openFlowListModal(type, page = 1) {
  state.flowListModal = { ...state.flowListModal, type, page, events: null };
  if (type === "review") {
    state.newReviewIds = new Set();
    state.reviewKnownUncertainIds = new Set(
      dashboardEvents(state.dashboard || {})
        .filter(isReviewEvent)
        .map((event) => event.flow_id)
        .filter(Boolean),
    );
  }
  els.flowListModal.hidden = false;
  renderFlowListModal({ preserveScroll: false });
  renderDashboard(state.dashboard || {});
}

async function openAllFlowsModal(page = 1) {
  state.flowListModal = { ...state.flowListModal, type: "all", page, events: null };
  els.flowListModal.hidden = false;
  els.flowListEyebrow.textContent = "Realtime";
  els.flowListTitle.textContent = "All Recent Flows";
  els.flowListBody.innerHTML = '<div class="selected-flow compact">Loading flow list...</div>';
  els.flowListPagination.innerHTML = "";
  try {
    const response = await fetchJson("/api/flows/recent?limit=500");
    state.flowListModal.events = response.events || [];
    renderFlowListModal({ preserveScroll: false });
  } catch (error) {
    els.flowListBody.innerHTML = `<div class="selected-flow compact">Flow list failed: ${escapeHtml(error.message)}</div>`;
  }
}

function closeFlowListModal() {
  els.flowListModal.hidden = true;
}

function openTopologyModal() {
  state.topologyFullscreenOpen = true;
  els.topologyModal.hidden = false;
  renderTopology((state.dashboard && state.dashboard.topology) || {}, (state.dashboard && state.dashboard.recent_flows) || []);
}

function closeTopologyModal() {
  state.topologyFullscreenOpen = false;
  els.topologyModal.hidden = true;
  state.topologyDrag = null;
}

function captureFlowListScroll() {
  return flowListScrollContainers()
    .map(({ name, element }) => ({ name, snapshot: captureScrollableRowsScroll(element) }))
    .filter((item) => item.snapshot);
}

function captureScrollableRowsScroll(body) {
  if (
    !body ||
    (
      body.scrollHeight <= body.clientHeight &&
      body.scrollWidth <= body.clientWidth &&
      body.scrollTop === 0 &&
      body.scrollLeft === 0
    )
  ) {
    return null;
  }
  const bodyRect = body.getBoundingClientRect();
  const rows = Array.from(body.querySelectorAll("tr[data-flow-id]"));
  const anchor = rows.find((row) => {
    const rowRect = row.getBoundingClientRect();
    return rowRect.bottom > bodyRect.top && rowRect.top < bodyRect.bottom;
  });
  return {
    top: body.scrollTop,
    left: body.scrollLeft,
    anchorId: anchor ? anchor.getAttribute("data-flow-id") : "",
    anchorOffset: anchor ? anchor.getBoundingClientRect().top - bodyRect.top : 0,
  };
}

function restoreFlowListScroll(snapshot) {
  if (!snapshot || !snapshot.length) {
    return;
  }
  const containers = flowListScrollContainers();
  snapshot.forEach((item) => {
    const container = containers.find((candidate) => candidate.name === item.name);
    restoreScrollableRowsScroll(container ? container.element : null, item.snapshot);
  });
}

function restoreScrollableRowsScroll(body, snapshot) {
  if (!snapshot || !body) {
    return;
  }
  body.scrollLeft = snapshot.left;
  const anchor = snapshot.anchorId
    ? Array.from(body.querySelectorAll("tr[data-flow-id]")).find((row) => row.getAttribute("data-flow-id") === snapshot.anchorId)
    : null;
  if (anchor) {
    const bodyRect = body.getBoundingClientRect();
    const anchorRect = anchor.getBoundingClientRect();
    body.scrollTop += anchorRect.top - bodyRect.top - snapshot.anchorOffset;
    return;
  }
  body.scrollTop = Math.min(snapshot.top, Math.max(0, body.scrollHeight - body.clientHeight));
}

function flowListScrollContainers() {
  const containers = [];
  if (els.flowListBody) {
    containers.push({ name: "body", element: els.flowListBody });
    const tableWrap = els.flowListBody.querySelector(".flow-list-table-wrap");
    if (tableWrap) {
      containers.push({ name: "table", element: tableWrap });
    }
  }
  return containers;
}

function renderFlowListModal({ preserveScroll = true } = {}) {
  const scrollSnapshot = preserveScroll ? captureFlowListScroll() : null;
  const type = state.flowListModal.type;
  const rawEvents = type === "all"
    ? realtimeVisibleFlows(state.flowListModal.events || ((state.dashboard || {}).recent_flows || []))
    : dashboardEvents(state.dashboard || {}).filter(type === "review" ? isReviewEvent : isAlertEvent);
  const events = applyReportFilters(rawEvents);
  const pageSize = state.flowListModal.pageSize;
  const totalPages = Math.max(1, Math.ceil(events.length / pageSize));
  const page = clamp(state.flowListModal.page, 1, totalPages);
  state.flowListModal.page = page;
  const start = (page - 1) * pageSize;
  const pageEvents = events.slice(start, start + pageSize);
  const title = type === "all" ? "Recent Flows" : type === "review" ? "Uncertain Flows" : "Alert Flows";

  els.flowListEyebrow.textContent = type === "all" ? "Realtime Full View" : type === "review" ? "Needs Review" : "Active Alerts";
  els.flowListTitle.textContent = `${title} (${events.length})`;
  renderReportFilters((((state.dashboard || {}).reports || {}).filter_options) || {});
  const showHideBenign = type === "all";
  els.flowListHideBenignRow.hidden = !showHideBenign;
  els.flowListHideBenign.checked = state.realtimeHideBenign;
  const hideText = type === "all" && state.realtimeHideBenign ? " / benign hidden" : "";
  els.reportsFilterSummary.textContent = `${events.length} events${hideText}`;
  els.flowListBody.innerHTML = pageEvents.length
    ? flowListTableHtml(pageEvents)
    : `<div class="selected-flow compact">No ${type === "all" ? "recent" : type === "review" ? "uncertain" : "alert"} flows are available.</div>`;
  els.flowListPagination.innerHTML = paginationHtml(page, totalPages);
  restoreFlowListScroll(scrollSnapshot);
  if (scrollSnapshot && scrollSnapshot.length) {
    requestAnimationFrame(() => restoreFlowListScroll(scrollSnapshot));
  }

  els.flowListBody.querySelectorAll("tr[data-flow-id]").forEach((row) => {
    row.addEventListener("click", () => {
      selectFlow(row.getAttribute("data-flow-id"));
    });
  });
  els.flowListPagination.querySelectorAll("[data-page]").forEach((button) => {
    button.addEventListener("click", () => {
      state.flowListModal.page = Number(button.getAttribute("data-page"));
      renderFlowListModal({ preserveScroll: false });
    });
  });
}

function flowListTableHtml(events) {
  return `
    <div class="table-wrap flow-list-table-wrap" data-live-scroll-region="flowListModal">
      <table class="flow-list-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Source</th>
            <th>Destination</th>
            <th>ML</th>
            <th>Route</th>
            <th>Verdict</th>
            <th>Severity</th>
            <th>Watchlist</th>
          </tr>
        </thead>
        <tbody>
          ${events.map(flowListTableRowHtml).join("")}
        </tbody>
      </table>
    </div>
  `;
}

function flowListTableRowHtml(flow) {
  const selected = flow.flow_id === state.selectedFlowId ? " selected" : "";
  const isNew = state.newFlowIds.has(flow.flow_id);
  const newClass = isNew ? " row-new-animate" : "";
  return `
    <tr class="${selected}${newClass}" data-flow-id="${escapeHtml(flow.flow_id || "")}">
      <td>${escapeHtml(formatTime(flow))}</td>
      <td>${escapeHtml(flow.src_ip || "-")}<br><span class="soft-label">${portLabel(flow.src_port)}</span></td>
      <td>${escapeHtml(flow.dst_ip || "-")}<br><span class="soft-label">${portLabel(flow.dst_port)} / ${escapeHtml(flow.protocol || "-")}</span></td>
      <td>${formatProbability(flow.prob)}</td>
      <td>${badge(flow.route || "unknown", flow.route)}</td>
      <td>${flowVerdictBadge(flow)}</td>
      <td>${flowSeverityBadge(flow)}</td>
      <td>${flow.watchlist_matched ? badge("hit", "tier1_llm") : '<span class="soft-label">none</span>'}</td>
    </tr>
  `;
}

function paginationHtml(page, totalPages) {
  if (totalPages <= 1) {
    return "";
  }
  const pages = [];
  for (let index = 1; index <= totalPages; index += 1) {
    pages.push(`<button class="page-button${index === page ? " active" : ""}" type="button" data-page="${index}">${index}</button>`);
  }
  return pages.join("");
}

function renderFlowTrend(flows) {
  if (!els.flowTrendChart || !els.flowTrendSummary) {
    return;
  }

  const events = flows
    .map((flow) => ({
      flow,
      timestamp: flowTimestamp(flow),
      series: flowTrendSeries(flow),
    }))
    .filter((event) => event.timestamp !== null && event.series);

  if (!events.length) {
    els.flowTrendSummary.textContent = "No completed outcomes";
    els.flowTrendChart.innerHTML = '<div class="selected-flow compact">Waiting for completed dismiss, alert, or uncertain outcomes.</div>';
    return;
  }

  const bucketCount = Math.min(12, Math.max(4, events.length));
  const timestamps = events.map((event) => event.timestamp);
  const minTs = Math.min(...timestamps);
  const maxTs = Math.max(...timestamps);
  const span = Math.max(1, maxTs - minTs);
  const bucketSize = Math.max(1, Math.ceil(span / bucketCount));
  const buckets = Array.from({ length: bucketCount }, (_, index) => ({
    labelTs: minTs + index * bucketSize,
    dismiss: 0,
    alert: 0,
    uncertain: 0,
  }));

  for (const event of events) {
    const index = Math.min(bucketCount - 1, Math.floor((event.timestamp - minTs) / bucketSize));
    buckets[index][event.series] += 1;
  }

  const maxCount = Math.max(1, ...buckets.flatMap((bucket) => [bucket.dismiss, bucket.alert, bucket.uncertain]));
  const width = 720;
  const height = 190;
  const pad = { top: 18, right: 26, bottom: 34, left: 34 };
  const chartWidth = width - pad.left - pad.right;
  const chartHeight = height - pad.top - pad.bottom;
  const xFor = (index) => pad.left + (bucketCount === 1 ? chartWidth / 2 : (chartWidth * index) / (bucketCount - 1));
  const yFor = (value) => pad.top + chartHeight - (chartHeight * value) / maxCount;
  const series = [
    ["dismiss", "#45c486"],
    ["alert", "#f35d6a"],
    ["uncertain", "#f1b84b"],
  ];
  const gridLines = [0, 0.5, 1]
    .map((ratio) => {
      const y = pad.top + chartHeight * ratio;
      return `<line x1="${pad.left}" y1="${y}" x2="${width - pad.right}" y2="${y}" class="trend-grid" />`;
    })
    .join("");
  const paths = series
    .map(([name, color]) => {
      const points = buckets.map((bucket, index) => `${xFor(index)},${yFor(bucket[name])}`).join(" ");
      const dots = buckets
        .map((bucket, index) => `<circle cx="${xFor(index)}" cy="${yFor(bucket[name])}" r="3" fill="${color}" />`)
        .join("");
      return `<polyline points="${points}" fill="none" stroke="${color}" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" />${dots}`;
    })
    .join("");
  const labels = [
    [pad.left, buckets[0].labelTs],
    [width - pad.right, buckets[buckets.length - 1].labelTs],
  ]
    .map(([x, ts], index) => `<text x="${x}" y="${height - 12}" text-anchor="${index ? "end" : "start"}" class="trend-axis">${escapeHtml(shortTime(ts))}</text>`)
    .join("");
  const legend = series
    .map(([name, color], index) => {
      const x = pad.left + index * 112;
      return `<g transform="translate(${x} 8)"><circle r="4" fill="${color}" /><text x="10" y="4" class="trend-legend">${name}</text></g>`;
    })
    .join("");

  els.flowTrendSummary.textContent = `${events.length} outcomes / latest ${flows.length} flows`;
  els.flowTrendChart.innerHTML = `
    <svg class="trend-svg" viewBox="0 0 ${width} ${height}" role="img" aria-label="Realtime flow outcome counts over time">
      ${gridLines}
      <line x1="${pad.left}" y1="${pad.top + chartHeight}" x2="${width - pad.right}" y2="${pad.top + chartHeight}" class="trend-axis-line" />
      ${paths}
      ${labels}
      ${legend}
    </svg>
  `;
}

async function selectFlow(flowId) {
  state.selectedFlowId = flowId;
  renderAll();
  openFlowDetailModal("Loading flow detail...");
  try {
    if (!state.detailCache.has(flowId)) {
      const detail = await fetchJson(`/api/flows/${encodeURIComponent(flowId)}`);
      state.detailCache.set(flowId, detail.event);
    }
    state.selectedFlowDetail = state.detailCache.get(flowId);
  } catch (error) {
    state.selectedFlowDetail = { flow_id: flowId, detail_error: error.message };
  }
  if (els.selectedFlow) {
    renderSelectedFlowCard(els.selectedFlow, false);
  }
  openFlowDetailModal();
  renderAll();
}

function renderSelectedFlowCard(target, expanded) {
  if (!target) {
    return;
  }
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
    </div>
    <div class="evidence-card">
      <h4>ML Evidence</h4>
      ${detailRow("Category hint", flow.category_hint || "not evaluated")}
      ${detailRow("Category confidence", formatProbability(flow.category_confidence))}
      ${detailRowHtml("SHAP top 5", formatShapList(flow.shap_top5), "detail-block")}
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
      ${dynamicThresholdHtml(flow, detail)}
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
    ["Queue workers", status.tier1_queue_workers],
    ["Queue max", status.tier1_queue_max_size],
    ["Queue depth", ((status.tier1_queue || {}).current_queue_depth) ?? 0],
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
    ["Topology", artifacts.topology],
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
    if (statusTarget) {
      statusTarget.textContent = markdown.path || "latest.md";
    }
    if (previewTarget) {
      previewTarget.textContent = markdown.content.slice(0, maxLength);
    }
  } else {
    if (statusTarget) {
      statusTarget.textContent = "No summary";
    }
    if (previewTarget) {
      previewTarget.textContent = "No daily summary artifact is available yet.";
    }
  }
}

function renderReportSummary(summary) {
  renderSummary(summary, els.reportsSummaryStatus, els.reportsSummaryPreview, 8000);
  const data = ((summary.json || {}).data) || {};
  const hasSummary = Boolean((summary.json || {}).exists && Object.keys(data).length);
  els.reportsRiskLabel.textContent = hasSummary ? data.risk_label || "-" : "-";
  els.reportsFlowCount.textContent = hasSummary ? number(data.flow_count) : 0;
  els.reportsWatchlistCount.textContent = hasSummary ? number(data.watchlist_hit_count) : 0;
  els.reportsTier1Count.textContent = hasSummary ? number((data.tier1_calls || {}).total) : 0;
  els.reportsEasySummary.textContent = hasSummary
    ? data.easy_summary_ko || "No easy summary text is available."
    : "No daily summary artifact is available yet.";
  els.reportsFirstChecks.innerHTML = renderCompactList(data.first_checks_ko || [], "No recommended first checks are available.");
  els.reportsImportantAlerts.innerHTML = renderImportantAlerts(data.top_alerts || []);
}

function renderReportFilters(options) {
  renderSelectOptions(els.reportsDateFilter, options.dates || [], "All dates", state.reportFilters.date);
  renderSelectOptions(els.reportsSeverityFilter, options.severities || [], "All severities", state.reportFilters.severity);
  renderSelectOptions(els.reportsVerdictFilter, options.verdicts || [], "All verdicts", state.reportFilters.verdict);
  els.reportsAssetOptions.innerHTML = (options.assets || [])
    .map((asset) => `<option value="${escapeHtml(asset)}"></option>`)
    .join("");
  if (els.reportsAssetFilter.value !== state.reportFilters.asset) {
    els.reportsAssetFilter.value = state.reportFilters.asset;
  }
}

function renderSelectOptions(target, values, emptyLabel, selectedValue) {
  const uniqueValues = [...new Set(values.map((value) => String(value)).filter(Boolean))];
  target.innerHTML = [
    `<option value="">${escapeHtml(emptyLabel)}</option>`,
    ...uniqueValues.map((value) => `<option value="${escapeHtml(value)}">${escapeHtml(value)}</option>`),
  ].join("");
  target.value = selectedValue || "";
}

function renderCompactList(items, emptyText) {
  if (!Array.isArray(items) || !items.length) {
    return `<div class="selected-flow compact">${escapeHtml(emptyText)}</div>`;
  }
  return items
    .slice(0, 5)
    .map((item) => `<div class="report-list-row">${escapeHtml(String(item))}</div>`)
    .join("");
}

function renderImportantAlerts(alerts) {
  if (!Array.isArray(alerts) || !alerts.length) {
    return '<div class="selected-flow compact">No alert verdicts were stored for this summary.</div>';
  }
  return alerts
    .slice(0, 5)
    .map((alert) => `
      <div class="report-list-row">
        <strong>${escapeHtml(alert.flow_id || "-")}</strong>
        <span>${escapeHtml(alert.src_ip || "-")} -> ${escapeHtml(alert.dst_ip || "-")}:${escapeHtml(alert.dst_port ?? "-")}</span>
        ${badge(alert.severity || "n/a", alert.severity)}
      </div>
    `)
    .join("");
}

function applyReportFilters(events) {
  return events.filter((event) => {
    if (state.reportFilters.date && eventDate(event) !== state.reportFilters.date) {
      return false;
    }
    if (state.reportFilters.severity && String(event.severity || "") !== state.reportFilters.severity) {
      return false;
    }
    if (state.reportFilters.verdict && String(event.verdict || "") !== state.reportFilters.verdict) {
      return false;
    }
    if (state.reportFilters.asset) {
      const asset = state.reportFilters.asset;
      if (String(event.src_ip || "") !== asset && String(event.dst_ip || "") !== asset) {
        return false;
      }
    }
    return true;
  });
}

function eventDate(event) {
  if (event.start_ms) {
    const date = new Date(Number(event.start_ms));
    if (!Number.isNaN(date.getTime())) {
      return date.toISOString().slice(0, 10);
    }
  }
  return String(event.created_at || "").slice(0, 10);
}

function formatReportEventPath(event) {
  return `${eventDate(event) || "-"} / ${event.src_ip || "-"}:${event.src_port || "-"} -> ${event.dst_ip || "-"}:${event.dst_port || "-"} / prob ${formatProbability(event.prob)}`;
}

async function saveRawInput() {
  const sourceName = state.selectedSourceName;
  if (!sourceName) {
    return;
  }
  setInputBusy(true, "Saving raw YAML...");
  try {
    await fetchJson(`/api/source-inputs/${encodeURIComponent(sourceName)}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content: els.inputRawEditor.value }),
    });
    state.inputRawDirty = false;
    await reloadSources();
    setInputStatus("Saved raw YAML.");
    closeInputEditor();
  } catch (error) {
    setInputStatus(`Save failed: ${error.message}`);
  } finally {
    setInputBusy(false);
  }
}

async function addStructuredInputItem() {
  const sourceName = state.selectedSourceName;
  if (!sourceName) {
    return;
  }
  const append = {};
  els.inputQuickAdd.querySelectorAll("[data-input-field]").forEach((input) => {
    const key = input.getAttribute("data-input-field");
    const value = input.value.trim();
    if (value) {
      append[key] = value;
    }
  });
  if (!Object.keys(append).length) {
    setInputStatus("Fill at least one field before adding.");
    return;
  }
  setInputBusy(true, "Adding item...");
  try {
    await fetchJson(`/api/source-inputs/${encodeURIComponent(sourceName)}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ append }),
    });
    state.inputRawDirty = false;
    els.inputQuickAdd.querySelectorAll("[data-input-field]").forEach((input) => {
      input.value = "";
    });
    await reloadSources();
    setInputStatus("Added item.");
    closeInputEditor();
  } catch (error) {
    setInputStatus(`Add failed: ${error.message}`);
  } finally {
    setInputBusy(false);
  }
}

async function deleteStructuredInputItem(listKey, index) {
  const sourceName = state.selectedSourceName;
  if (!sourceName || !listKey || !Number.isInteger(index)) {
    return;
  }
  setInputBusy(true, "Removing item...");
  try {
    await fetchJson(`/api/source-inputs/${encodeURIComponent(sourceName)}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ delete: { list_key: listKey, index } }),
    });
    state.inputRawDirty = false;
    await reloadSources();
    setInputStatus("Removed item.");
  } catch (error) {
    setInputStatus(`Remove failed: ${error.message}`);
  } finally {
    setInputBusy(false);
  }
}

async function reloadSources() {
  const sourceInputs = await fetchJson("/api/source-inputs");
  state.sources = sourceInputs.sources || [];
  renderInputs();
  renderContext(state.dashboard || {});
}

function setInputBusy(isBusy, message) {
  els.inputOpenAdd.disabled = isBusy;
  els.inputOpenRaw.disabled = isBusy;
  els.inputAddItem.disabled = isBusy;
  els.inputSaveRaw.disabled = isBusy;
  if (message) {
    setInputStatus(message);
  }
}

function setInputStatus(message) {
  if (els.inputAddStatus) {
    els.inputAddStatus.textContent = message;
  }
  if (els.inputRawStatus) {
    els.inputRawStatus.textContent = message;
  }
}

async function refreshTier2(button) {
  const original = button.textContent;
  button.disabled = true;
  button.textContent = "Refreshing...";
  const status = ((state.dashboard || {}).status) || {};
  if (button === els.contextRefreshTier2 && els.contextRefreshStatus) {
    const provider = status.tier2_provider || "Tier 2";
    const model = status.tier2_model || provider;
    els.contextRefreshStatus.textContent = `${model} API was called. This can take a little while.`;
  }
  try {
    await fetchJson("/api/tier2/refresh", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    });
    state.detailCache.clear();
    await loadDashboard();
    if (button === els.contextRefreshTier2 && els.contextRefreshStatus) {
      els.contextRefreshStatus.textContent = "Tier 2 refresh finished. The latest files are shown below.";
    }
  } catch (error) {
    els.lastUpdated.textContent = `Tier 2 refresh failed: ${error.message}`;
    if (button === els.contextRefreshTier2 && els.contextRefreshStatus) {
      els.contextRefreshStatus.textContent = `Tier 2 refresh failed: ${error.message}`;
    }
  } finally {
    button.disabled = false;
    button.textContent = original;
  }
}

async function loadSettingsOptions() {
  setSettingsBusy(true, "Loading model list...");
  try {
    const options = await fetchJson("/api/admin/llm-options");
    state.settingsOptions = normalizeSettingsOptions(options);
    state.settingsHydrated = false;
    renderSettings(((state.dashboard || {}).status) || {});
  } catch (error) {
    settingsLog(`Model discovery failed: ${error.message}`);
  } finally {
    setSettingsBusy(false);
  }
}

async function refreshLlmOptionsQuietly(reason = "auto") {
  if (state.llmOptionsRefreshInFlight || !shouldRefreshLlmOptions()) {
    return;
  }
  state.llmOptionsRefreshInFlight = true;
  try {
    const options = normalizeSettingsOptions(await fetchJson("/api/admin/llm-options"));
    const startupWasMissing = startupOllamaMissing();
    const settingsWasMissing = settingsOllamaMissing();
    if (isStartupVisible()) {
      state.startupOptions = options;
      renderStartupModelSelect("tier1");
      renderStartupModelSelect("tier2");
      updateStartupVisibility();
      if (startupWasMissing && !startupOllamaMissing()) {
        startupLog("Ollama models were detected. Choose a model and continue.");
      }
    }
    if (state.activeView === "settings") {
      state.settingsOptions = options;
      renderSettingsModelSelect("tier1");
      renderSettingsModelSelect("tier2");
      updateSettingsVisibility();
      renderSettingsStatus(((state.dashboard || {}).status) || {}, state.settingsOptions);
      if (settingsWasMissing && !settingsOllamaMissing() && reason !== "initial") {
        settingsLog("Ollama models were detected. Choose a model and apply settings.");
      }
    }
  } catch (error) {
    if (isStartupVisible()) {
      startupLog(`Model discovery retry failed: ${error.message}`);
    } else if (state.activeView === "settings") {
      settingsLog(`Model discovery retry failed: ${error.message}`);
    }
  } finally {
    state.llmOptionsRefreshInFlight = false;
  }
}

function ensureLlmOptionsAutoRefresh() {
  if (state.llmOptionsAutoTimer) {
    return;
  }
  state.llmOptionsAutoTimer = window.setInterval(() => {
    refreshLlmOptionsQuietly();
  }, 3000);
}

function shouldRefreshLlmOptions() {
  if (document.hidden) {
    return false;
  }
  return startupOllamaSelected() || settingsOllamaSelected();
}

function isStartupVisible() {
  return !els.startupScreen.hidden && !els.startupScreen.classList.contains("hidden");
}

function startupOllamaSelected() {
  return isStartupVisible()
    && (els.startupTier1Provider.value === "ollama" || els.startupTier2Provider.value === "ollama");
}

function settingsOllamaSelected() {
  return state.activeView === "settings"
    && (els.settingsTier1Provider.value === "ollama" || els.settingsTier2Provider.value === "ollama");
}

function startupOllamaMissing() {
  return startupOllamaSelected()
    && ((els.startupTier1Provider.value === "ollama" && !els.startupTier1Model.value)
      || (els.startupTier2Provider.value === "ollama" && !els.startupTier2Model.value));
}

function settingsOllamaMissing() {
  return settingsOllamaSelected()
    && ((els.settingsTier1Provider.value === "ollama" && !els.settingsTier1Model.value)
      || (els.settingsTier2Provider.value === "ollama" && !els.settingsTier2Model.value));
}

function normalizeSettingsOptions(options) {
  return {
    tier1: { models: (options.tier1 && options.tier1.models || []).map(normalizeModelChoice) },
    tier2: { models: (options.tier2 && options.tier2.models || []).map(normalizeModelChoice) },
    ollama: normalizeOllamaOptions(options.ollama || {}),
    gemini: options.gemini || {},
  };
}

function normalizeOllamaOptions(ollama) {
  return {
    tier1: normalizeOllamaCatalog(ollama.tier1 || {}),
    tier2: normalizeOllamaCatalog(ollama.tier2 || {}),
  };
}

function normalizeOllamaCatalog(catalog) {
  return {
    reachable: Boolean(catalog.reachable),
    url: catalog.url || "",
    models: Array.isArray(catalog.models) ? catalog.models : [],
    error: catalog.error || "",
  };
}

function normalizeModelChoice(choice) {
  return {
    label: choice.label || `${choice.provider || "-"} - ${choice.model || "-"}`,
    provider: choice.provider || "",
    model: choice.model || "",
    ollama_url: choice.ollama_url || "",
  };
}

function preferredOllamaUrl(statusUrl, catalog) {
  const discoveredUrl = catalog && catalog.reachable && catalog.url ? catalog.url : "";
  const value = discoveredUrl || statusUrl || "http://host.docker.internal:11434";
  if (value === "http://localhost:11434" || value === "http://127.0.0.1:11434") {
    return "http://host.docker.internal:11434";
  }
  return value;
}

function hasSavedGeminiKey(status, options) {
  const gemini = (options && options.gemini) || {};
  return Boolean((status && status.gemini_has_key) || gemini.has_key);
}

function setGeminiKeyDisplay(input, hasKey) {
  input.value = hasKey ? SAVED_GEMINI_KEY_MASK : "";
  input.dataset.savedKey = hasKey ? "true" : "false";
  input.placeholder = hasKey
    ? "Saved key is set. Type to replace it."
    : "Required when Gemini API is selected";
}

function geminiKeyPayloadValue(input) {
  const value = input.value.trim();
  return value === SAVED_GEMINI_KEY_MASK ? "" : value;
}

function renderSettings(status) {
  if (!els.settingsStatus) {
    return;
  }
  const options = state.settingsOptions || { tier1: { models: [] }, tier2: { models: [] }, ollama: {} };
  if (!state.settingsDirty || !state.settingsHydrated) {
    const tier1Provider = status.tier1_provider || "fake";
    const tier2Provider = status.tier2_provider || "deterministic";
    els.settingsTier1Provider.value = providerAllowed(els.settingsTier1Provider, tier1Provider) ? tier1Provider : "fake";
    els.settingsTier2Provider.value = providerAllowed(els.settingsTier2Provider, tier2Provider) ? tier2Provider : "deterministic";
    populateSettingsModelSelect(
      els.settingsTier1Model,
      options.tier1.models,
      els.settingsTier1Provider.value,
      status.tier1_model || "",
      options.ollama && options.ollama.tier1,
    );
    populateSettingsModelSelect(
      els.settingsTier2Model,
      options.tier2.models,
      els.settingsTier2Provider.value,
      status.tier2_model || "",
      options.ollama && options.ollama.tier2,
    );
    els.settingsTier1OllamaUrl.value = preferredOllamaUrl(status.tier1_ollama_url, options.ollama && options.ollama.tier1);
    els.settingsTier1MaxTokens.value = status.tier1_max_tokens || 4096;
    els.settingsTier1Workers.value = status.tier1_queue_workers || 1;
    els.settingsTier2OllamaUrl.value = preferredOllamaUrl(status.tier2_ollama_url, options.ollama && options.ollama.tier2);
    els.settingsTier2MaxTokens.value = status.tier2_max_tokens || 16384;
    setGeminiKeyDisplay(els.settingsGeminiApiKey, hasSavedGeminiKey(status, options));
    const routing = status.routing || {};
    els.settingsThresholdLow.value = routing.threshold_low ?? "";
    els.settingsThresholdHigh.value = routing.threshold_high ?? "";
    state.settingsHydrated = true;
  }
  updateSettingsVisibility();
  renderSettingsStatus(status, options);
}

function providerAllowed(select, provider) {
  return [...select.options].some((option) => option.value === provider);
}

function populateSettingsModelSelect(select, choices, provider, currentModel, ollamaCatalog = null) {
  const matching = (choices || []).filter((choice) => choice.provider === provider && choice.model);
  if (!providerNeedsModel(provider)) {
    select.innerHTML = "";
    select.value = "";
    select.disabled = true;
    return;
  }
  if (provider === "ollama" && (!ollamaCatalog || !ollamaCatalog.reachable || !ollamaCatalog.models.length)) {
    select.innerHTML = '<option value="">No discovered Ollama models</option>';
    select.value = "";
    select.disabled = true;
    return;
  }
  if (!matching.length) {
    const label = provider === "ollama" ? "No discovered Ollama models" : "No available Gemini API models";
    select.innerHTML = `<option value="">${escapeHtml(label)}</option>`;
    select.value = "";
    select.disabled = true;
    return;
  }
  select.disabled = false;
  select.innerHTML = matching
    .map((choice) => `<option value="${escapeAttr(choice.model)}">${escapeHtml(choice.label)}</option>`)
    .join("");
  if (matching.some((choice) => choice.model === currentModel)) {
    select.value = currentModel;
  }
}

function providerNeedsModel(provider) {
  return provider !== "fake" && provider !== "deterministic";
}

function updateSettingsVisibility() {
  document.querySelectorAll("[data-settings-model='tier1']").forEach((node) => {
    node.classList.toggle("hidden", !providerNeedsModel(els.settingsTier1Provider.value));
  });
  document.querySelectorAll("[data-settings-model='tier2']").forEach((node) => {
    node.classList.toggle("hidden", !providerNeedsModel(els.settingsTier2Provider.value));
  });
  document.querySelectorAll("[data-settings-ollama='tier1']").forEach((node) => {
    node.classList.toggle("hidden", els.settingsTier1Provider.value !== "ollama");
  });
  document.querySelectorAll("[data-settings-ollama='tier2']").forEach((node) => {
    node.classList.toggle("hidden", els.settingsTier2Provider.value !== "ollama");
  });
  document.querySelectorAll("[data-settings-tier2-output]").forEach((node) => {
    node.classList.toggle("hidden", !providerNeedsModel(els.settingsTier2Provider.value));
  });
  document.querySelectorAll("[data-settings-tier1-output]").forEach((node) => {
    node.classList.toggle("hidden", els.settingsTier1Provider.value === "fake");
  });
  const geminiSelected = els.settingsTier1Provider.value === "gemini" || els.settingsTier2Provider.value === "gemini";
  document.querySelectorAll("[data-settings-gemini]").forEach((node) => {
    node.classList.toggle("hidden", !geminiSelected);
  });
  renderOllamaWarning({
    target: els.settingsOllamaWarning,
    tier1Provider: els.settingsTier1Provider.value,
    tier2Provider: els.settingsTier2Provider.value,
    tier1Url: els.settingsTier1OllamaUrl.value,
    tier2Url: els.settingsTier2OllamaUrl.value,
    options: state.settingsOptions,
  });
}

function renderOllamaWarning({ target, tier1Provider, tier2Provider, tier1Url, tier2Url, options }) {
  if (!target) {
    return;
  }
  const ollama = (options && options.ollama) || {};
  const warnings = [];
  if (tier1Provider === "ollama") {
    const message = ollamaStatusMessage("Tier 1", ollama.tier1 || {}, tier1Url);
    if (message) {
      warnings.push(message);
    }
  }
  if (tier2Provider === "ollama") {
    const message = ollamaStatusMessage("Tier 2", ollama.tier2 || {}, tier2Url);
    if (message) {
      warnings.push(message);
    }
  }
  target.hidden = warnings.length === 0;
  target.textContent = warnings.join("\n");
}

function ollamaStatusMessage(scope, catalog, configuredUrl) {
  const url = catalog.url || configuredUrl || "http://host.docker.internal:11434";
  if (!catalog.reachable) {
    const detail = catalog.error ? ` Last error: ${catalog.error}` : "";
    return `${scope}: Ollama was not detected at ${url}. Start Ollama from a Windows command prompt with 'ollama serve', then click Refresh Models.${detail}`;
  }
  if (!Array.isArray(catalog.models) || catalog.models.length === 0) {
    return `${scope}: Ollama is reachable at ${url}, but no local models were discovered. Pull gemma4:e4b, then click Refresh Models.`;
  }
  return "";
}

function renderSettingsStatus(status, options) {
  const t1 = (options.ollama && options.ollama.tier1) || {};
  const t2 = (options.ollama && options.ollama.tier2) || {};
  const gemini = options.gemini || {};
  const lines = [
    `config: ${status.config_path || "-"}`,
    `Tier 1: ${status.tier1_provider || "-"} / ${status.tier1_model || "-"}`,
    `Tier 1 output tokens: ${status.tier1_max_tokens || "-"}`,
    `Tier 1 queue: mode=${status.tier1_queue_mode || "-"} workers=${status.tier1_queue_workers || "-"} max=${status.tier1_queue_max_size || "-"} timeout=${status.tier1_queue_timeout || "-"}s`,
    `Tier 2: ${status.tier2_provider || "-"} / ${status.tier2_model || "-"}`,
    `Tier 2 output tokens: ${status.tier2_max_tokens || "-"}`,
    `Ollama discovery: tier1=${t1.reachable ? `ok ${t1.url}` : "not reachable"} / tier2=${t2.reachable ? `ok ${t2.url}` : "not reachable"}`,
    `Gemini key: ${(status.gemini_has_key || gemini.has_key) ? `set (${status.gemini_api_key_env || gemini.api_key_env || "env"})` : "not set"}`,
  ];
  const routing = status.routing || {};
  if (routing.threshold_low !== undefined || routing.threshold_high !== undefined) {
    lines.push(`routing: low=${routing.threshold_low ?? "-"} high=${routing.threshold_high ?? "-"}`);
  }
  if (state.settingsDirty) {
    lines.push("pending: unsaved changes");
  }
  const ollamaWarning = settingsOllamaWarningText(status, options);
  if (ollamaWarning) {
    lines.push(ollamaWarning);
  }
  els.settingsStatus.textContent = lines.join("\n");
}

function settingsOllamaWarningText(status, options) {
  const messages = [];
  const ollama = (options && options.ollama) || {};
  if ((status.tier1_provider || els.settingsTier1Provider.value) === "ollama") {
    const message = ollamaStatusMessage("Tier 1", ollama.tier1 || {}, status.tier1_ollama_url || els.settingsTier1OllamaUrl.value);
    if (message) {
      messages.push(message);
    }
  }
  if ((status.tier2_provider || els.settingsTier2Provider.value) === "ollama") {
    const message = ollamaStatusMessage("Tier 2", ollama.tier2 || {}, status.tier2_ollama_url || els.settingsTier2OllamaUrl.value);
    if (message) {
      messages.push(message);
    }
  }
  return messages.join("\n");
}

function settingsPayload() {
  const payload = {
    tier1_provider: els.settingsTier1Provider.value,
    tier2_provider: els.settingsTier2Provider.value,
    tier1_max_tokens: els.settingsTier1MaxTokens.value,
    tier1_workers: els.settingsTier1Workers.value,
    tier2_max_tokens: els.settingsTier2MaxTokens.value,
    threshold_low: els.settingsThresholdLow.value,
    threshold_high: els.settingsThresholdHigh.value,
  };
  if (payload.tier1_provider !== "fake") {
    payload.tier1_model = els.settingsTier1Model.value;
  }
  if (payload.tier1_provider === "ollama") {
    payload.tier1_ollama_url = els.settingsTier1OllamaUrl.value;
  }
  if (payload.tier2_provider !== "fake" && payload.tier2_provider !== "deterministic") {
    payload.tier2_model = els.settingsTier2Model.value;
  }
  if (payload.tier2_provider === "ollama") {
    payload.tier2_ollama_url = els.settingsTier2OllamaUrl.value;
  }
  if (payload.tier1_provider === "gemini" || payload.tier2_provider === "gemini") {
    const geminiKey = geminiKeyPayloadValue(els.settingsGeminiApiKey);
    if (geminiKey) {
      payload.gemini_api_key = geminiKey;
    }
  }
  return payload;
}

async function applySettings() {
  const payload = settingsPayload();
  const missingOllamaModel = (
    (payload.tier1_provider === "ollama" && !payload.tier1_model) ||
    (payload.tier2_provider === "ollama" && !payload.tier2_model)
  );
  if (missingOllamaModel) {
    settingsLog("No discovered Ollama model is selected. Refresh models after starting Ollama.");
    return;
  }
  const geminiSelected = payload.tier1_provider === "gemini" || payload.tier2_provider === "gemini";
  const geminiAlreadySet = hasSavedGeminiKey(((state.dashboard || {}).status) || {}, state.settingsOptions || {});
  if (geminiSelected && !payload.gemini_api_key && !geminiAlreadySet) {
    settingsLog("Gemini API key is required when a Gemini API model is selected.");
    return;
  }
  if (payload.tier1_provider === "ollama" || payload.tier2_provider === "ollama") {
    settingsLog("Ollama will be started when possible, or checked from Docker. First model load can take tens of seconds.");
  }
  if (payload.tier1_provider === "gemini" || payload.tier2_provider === "gemini") {
    settingsLog("Gemini API model check is running.");
  }
  setSettingsBusy(true, "Applying settings...");
  try {
    const result = await fetchJson("/api/admin/config", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    state.settingsDirty = false;
    state.settingsHydrated = false;
    settingsLog(`Applied: ${Object.keys(result.applied || {}).join(", ") || "no changes"}`);
    await loadDashboard();
    await loadSettingsOptions();
  } catch (error) {
    settingsLog(`Apply failed: ${error.message}`);
  } finally {
    setSettingsBusy(false);
  }
}

async function resetProductDb() {
  if (!confirm("Delete all stored flow, ML, route, verdict, and Tier 1 call rows?")) {
    return;
  }
  setSettingsBusy(true, "Resetting DB...");
  try {
    const result = await fetchJson("/api/admin/reset", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    });
    const deleted = result.deleted || {};
    const total = Object.values(deleted).reduce((sum, value) => sum + Number(value || 0), 0);
    state.detailCache.clear();
    settingsLog(`DB reset complete: ${total} rows deleted`);
    await loadDashboard();
  } catch (error) {
    settingsLog(`DB reset failed: ${error.message}`);
  } finally {
    setSettingsBusy(false);
  }
}

function setSettingsBusy(isBusy, message) {
  if (!els.settingsApply) {
    return;
  }
  els.settingsApply.disabled = isBusy;
  els.settingsRefreshModels.disabled = isBusy;
  els.settingsResetDb.disabled = isBusy;
  if (message && els.settingsStatus) {
    els.settingsStatus.textContent = message;
  }
}

function settingsLog(message) {
  if (els.settingsStatus) {
    els.settingsStatus.textContent = message;
  }
}

function markSettingsDirty() {
  state.settingsDirty = true;
  updateSettingsVisibility();
  renderSettingsStatus(((state.dashboard || {}).status) || {}, state.settingsOptions || { ollama: {} });
}

function renderSettingsModelSelect(scope) {
  const options = state.settingsOptions || { tier1: { models: [] }, tier2: { models: [] } };
  if (scope === "tier1") {
    populateSettingsModelSelect(
      els.settingsTier1Model,
      options.tier1.models,
      els.settingsTier1Provider.value,
      "",
      options.ollama && options.ollama.tier1,
    );
  } else {
    populateSettingsModelSelect(
      els.settingsTier2Model,
      options.tier2.models,
      els.settingsTier2Provider.value,
      "",
      options.ollama && options.ollama.tier2,
    );
  }
}

function refreshSettingsModelSelect(scope) {
  renderSettingsModelSelect(scope);
  markSettingsDirty();
  refreshLlmOptionsQuietly("provider-change");
}

async function bootStartup() {
  els.appShell.classList.add("hidden");
  els.startupScreen.classList.remove("hidden");
  els.startupScreen.hidden = false;
  window.scrollTo(0, 0);
  setStartupBusy(true, "Loading available models...");
  startupLog("Loading current runtime settings.");
  try {
    const [status, options] = await Promise.all([
      fetchJson("/api/status"),
      fetchJson("/api/admin/llm-options"),
    ]);
    state.startupStatus = status;
    state.startupOptions = normalizeSettingsOptions(options);
    hydrateStartupControls(status, state.startupOptions);
    startupLog("Ready. Choose the LLM settings and press Start.");
    setStartupBusy(false, "Ready");
  } catch (error) {
    startupLog(`Setup load failed: ${error.message}`);
    setStartupBusy(false, "Setup failed");
  } finally {
    ensureLlmOptionsAutoRefresh();
  }
}

function hydrateStartupControls(status, options) {
  els.startupTier1Provider.value = providerAllowed(els.startupTier1Provider, status.tier1_provider || "fake")
    ? status.tier1_provider || "fake"
    : "fake";
  els.startupTier2Provider.value = providerAllowed(els.startupTier2Provider, status.tier2_provider || "deterministic")
    ? status.tier2_provider || "deterministic"
    : "deterministic";
  populateSettingsModelSelect(
    els.startupTier1Model,
    options.tier1.models,
    els.startupTier1Provider.value,
    status.tier1_model || "",
    options.ollama && options.ollama.tier1,
  );
  populateSettingsModelSelect(
    els.startupTier2Model,
    options.tier2.models,
    els.startupTier2Provider.value,
    status.tier2_model || "",
    options.ollama && options.ollama.tier2,
  );
  els.startupTier1OllamaUrl.value = preferredOllamaUrl(status.tier1_ollama_url, options.ollama && options.ollama.tier1);
  els.startupTier2OllamaUrl.value = preferredOllamaUrl(status.tier2_ollama_url, options.ollama && options.ollama.tier2);
  setGeminiKeyDisplay(els.startupGeminiApiKey, hasSavedGeminiKey(status, options));
  updateStartupVisibility();
}

function updateStartupVisibility() {
  document.querySelectorAll("[data-startup-model='tier1']").forEach((node) => {
    node.classList.toggle("hidden", !providerNeedsModel(els.startupTier1Provider.value));
  });
  document.querySelectorAll("[data-startup-model='tier2']").forEach((node) => {
    node.classList.toggle("hidden", !providerNeedsModel(els.startupTier2Provider.value));
  });
  document.querySelectorAll("[data-startup-ollama='tier1']").forEach((node) => {
    node.classList.toggle("hidden", els.startupTier1Provider.value !== "ollama");
  });
  document.querySelectorAll("[data-startup-ollama='tier2']").forEach((node) => {
    node.classList.toggle("hidden", els.startupTier2Provider.value !== "ollama");
  });
  const geminiSelected = els.startupTier1Provider.value === "gemini" || els.startupTier2Provider.value === "gemini";
  document.querySelectorAll("[data-startup-gemini]").forEach((node) => {
    node.classList.toggle("hidden", !geminiSelected);
  });
  renderOllamaWarning({
    target: els.startupOllamaWarning,
    tier1Provider: els.startupTier1Provider.value,
    tier2Provider: els.startupTier2Provider.value,
    tier1Url: els.startupTier1OllamaUrl.value,
    tier2Url: els.startupTier2OllamaUrl.value,
    options: state.startupOptions,
  });
}

function renderStartupModelSelect(scope) {
  const options = state.startupOptions || { tier1: { models: [] }, tier2: { models: [] } };
  if (scope === "tier1") {
    populateSettingsModelSelect(
      els.startupTier1Model,
      options.tier1.models,
      els.startupTier1Provider.value,
      "",
      options.ollama && options.ollama.tier1,
    );
  } else {
    populateSettingsModelSelect(
      els.startupTier2Model,
      options.tier2.models,
      els.startupTier2Provider.value,
      "",
      options.ollama && options.ollama.tier2,
    );
  }
}

function refreshStartupModelSelect(scope) {
  renderStartupModelSelect(scope);
  updateStartupVisibility();
  refreshLlmOptionsQuietly("provider-change");
}

function startupPayload() {
  const payload = {
    tier1_provider: els.startupTier1Provider.value,
    tier2_provider: els.startupTier2Provider.value,
  };
  if (payload.tier1_provider !== "fake") {
    payload.tier1_model = els.startupTier1Model.value;
  }
  if (payload.tier1_provider === "ollama") {
    payload.tier1_ollama_url = els.startupTier1OllamaUrl.value;
  }
  if (payload.tier2_provider !== "fake" && payload.tier2_provider !== "deterministic") {
    payload.tier2_model = els.startupTier2Model.value;
  }
  if (payload.tier2_provider === "ollama") {
    payload.tier2_ollama_url = els.startupTier2OllamaUrl.value;
  }
  if (payload.tier1_provider === "gemini" || payload.tier2_provider === "gemini") {
    const geminiKey = geminiKeyPayloadValue(els.startupGeminiApiKey);
    if (geminiKey) {
      payload.gemini_api_key = geminiKey;
    }
  }
  return payload;
}

async function startAppFromSetup() {
  const payload = startupPayload();
  const missingOllamaModel = (
    (payload.tier1_provider === "ollama" && !payload.tier1_model) ||
    (payload.tier2_provider === "ollama" && !payload.tier2_model)
  );
  if (missingOllamaModel) {
    startupLog("No Ollama model is selected. Start Ollama if needed, refresh the page, and choose a model.");
    return;
  }
  const geminiSelected = payload.tier1_provider === "gemini" || payload.tier2_provider === "gemini";
  const geminiAlreadySet = hasSavedGeminiKey(state.startupStatus || {}, state.startupOptions || {});
  if (geminiSelected && !payload.gemini_api_key && !geminiAlreadySet) {
    startupLog("Gemini API key is required when a Gemini API model is selected.");
    return;
  }

  setStartupBusy(true, "Starting...");
  startupLog("Applying LLM settings.");
  if (payload.tier1_provider === "ollama" || payload.tier2_provider === "ollama") {
    startupLog("Ollama was selected. The API will start it when possible, or check the host Ollama endpoint from Docker.");
  }
  if (geminiSelected) {
    startupLog("Gemini API was selected. The API will check the key and connection without a generation request.");
  }
  try {
    await fetchJson("/api/admin/config", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    startupLog("Settings applied.");
    startupLog("Loading the main dashboard.");
    els.startupScreen.hidden = true;
    els.startupScreen.classList.add("hidden");
    els.appShell.classList.remove("hidden");
    window.scrollTo(0, 0);
    setActiveView("dashboard");
    await loadDashboard();
    state.timer = window.setInterval(loadDashboard, 2000);
  } catch (error) {
    startupLog(`Start failed: ${error.message}`);
    setStartupBusy(false, "Start failed");
  }
}

function setStartupBusy(isBusy, message) {
  els.startupStart.disabled = isBusy;
  els.startupProgress.hidden = !isBusy;
  if (message) {
    els.startupStatus.textContent = message;
  }
}

function startupLog(message) {
  const line = `[${new Date().toLocaleTimeString()}] ${message}`;
  state.startupLog.push(line);
  els.startupLog.textContent = state.startupLog.slice(-12).join("\n");
}

function setActiveView(viewName) {
  if (!viewName || viewName === state.activeView) {
    return;
  }
  if (state.activeView === "settings" && state.settingsDirty) {
    const leave = confirm("There are unapplied settings changes. Leave Settings without applying them?");
    if (!leave) {
      return;
    }
  }
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
  if (viewName === "settings") {
    loadSettingsOptions();
    ensureLlmOptionsAutoRefresh();
  }
  renderAll();
}

function detailRow(label, value) {
  return detailRowHtml(label, escapeHtml(String(value)));
}

function detailRowHtml(label, html, className = "") {
  const rowClass = ["detail-row", className].filter(Boolean).join(" ");
  return `<div class="${rowClass}"><strong>${escapeHtml(label)}</strong><span class="detail-value">${html}</span></div>`;
}

function badge(label, tone) {
  return `<span class="badge ${escapeAttr(String(tone || "").toLowerCase())}">${escapeHtml(String(label))}</span>`;
}

function flowVerdictBadge(flow) {
  const verdict = String(flow.verdict || "unknown");
  return badge(verdict, verdict);
}

function flowSeverityBadge(flow) {
  const severity = String(flow.severity || "n/a");
  const label = severity.toLowerCase() === "pending" ? "-" : severity;
  return badge(label, severity);
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

function compactTime(flow) {
  const timestamp = flowTimestamp(flow);
  if (timestamp === null) {
    return "-";
  }
  return new Date(timestamp).toLocaleTimeString();
}

function shortTime(timestamp) {
  const date = new Date(Number(timestamp));
  if (Number.isNaN(date.getTime())) {
    return "-";
  }
  return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function flowTimestamp(flow) {
  if (flow.start_ms !== null && flow.start_ms !== undefined && flow.start_ms !== "") {
    const timestamp = Number(flow.start_ms);
    if (Number.isFinite(timestamp)) {
      return timestamp;
    }
  }
  const parsed = Date.parse(flow.created_at || "");
  return Number.isNaN(parsed) ? null : parsed;
}

function flowTrendSeries(flow) {
  const route = String(flow.route || "").toLowerCase();
  const verdict = String(flow.verdict || "").toLowerCase();
  if (verdict === "alert" || route === "auto_alert") {
    return "alert";
  }
  if (verdict === "uncertain") {
    return "uncertain";
  }
  if (verdict === "benign" || route === "auto_dismiss") {
    return "dismiss";
  }
  return null;
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

function formatShapList(items) {
  const topItems = shapItems(items).slice(0, 5);
  if (!topItems.length) {
    return '<span class="soft-label">not available</span>';
  }
  return `
    <ol class="shap-list">
      ${topItems.map((item) => `
        <li>
          <span class="shap-feature">${escapeHtml(item.feature)}</span>
          <span class="shap-meta">${escapeHtml(item.detail)}</span>
        </li>
      `).join("")}
    </ol>
  `;
}

function shapItems(items) {
  if (Array.isArray(items)) {
    return items
      .filter((item) => item !== null && item !== undefined)
      .map((item) => {
        if (Array.isArray(item)) {
          const [feature, value, contribution] = item;
          return {
            feature: String(feature ?? "-"),
            detail: `value ${formatShapNumber(value)} / contribution ${formatShapNumber(contribution)}`,
          };
        }
        return { feature: String(item), detail: "" };
      });
  }
  return String(items || "")
    .split(";")
    .map((item) => item.trim())
    .filter(Boolean)
    .map((item) => {
      const [feature, ...rest] = item.split("=");
      return {
        feature: feature.trim() || item,
        detail: rest.join("=").trim(),
      };
    });
}

function formatShapNumber(value) {
  const numeric = Number(value);
  return Number.isFinite(numeric) ? numeric.toFixed(3) : String(value ?? "-");
}

function dynamicThresholdHtml(flow, detail) {
  const watchlistMatched = Boolean(flow.adjusted_by_watchlist);
  const behaviorMatched = Boolean(flow.dynamic_threshold_applied);
  const dynamicApplied = watchlistMatched || behaviorMatched;
  const rows = [
    detailRowHtml("Dynamic threshold applied", yesNoHtml(dynamicApplied)),
    detailRow("Applied threshold", formatThreshold(flow.effective_review_threshold)),
    detailRowHtml("Watchlist match", yesNoHtml(watchlistMatched)),
  ];

  if (dynamicApplied && watchlistMatched) {
    rows.push(
      detailRow("Watchlist name", watchlistName(flow)),
      detailRow("Match strength", matchStrengthLabel(watchlistDetail(flow, "match_strength"))),
      detailRowHtml("Details", watchlistDetailsHtml(flow, detail), "detail-block"),
    );
  }

  rows.push(detailRowHtml("Behavior match", yesNoHtml(behaviorMatched)));
  if (dynamicApplied && behaviorMatched) {
    rows.push(detailRow("Behavior reason", flow.dynamic_threshold_reason || "none"));
  }
  return rows.join("");
}

function yesNoHtml(value) {
  const label = boolLabel(value);
  const className = label === "yes" ? "status-text yes" : "status-text";
  return `<span class="${className}">${escapeHtml(label)}</span>`;
}

function formatThreshold(value) {
  if (value === null || value === undefined || value === "") {
    return "none";
  }
  const numeric = Number(value);
  return Number.isFinite(numeric) ? numeric.toFixed(2) : String(value);
}

function watchlistName(flow) {
  const detail = flow.watchlist_detail || {};
  return flow.watchlist_matched || detail.item_id || "none";
}

function matchStrengthLabel(value) {
  const reason = String(value || "none");
  const strong = new Set(["critical_forbidden", "policy_violation", "threat_source", "behavior"]);
  const middle = new Set(["behavioral_review", "review_candidate", "asset_service"]);
  const bucket = strong.has(reason) ? "strong" : middle.has(reason) ? "middle" : "weak";
  return `${bucket} (${reason})`;
}

function watchlistDetailsHtml(flow, detail) {
  const groups = [
    ["Matched conditions", watchlistDetail(flow, "matched_conditions", [])],
    ["Trigger hints", watchlistDetail(flow, "matched_trigger_hints", [])],
    ["Scope conditions", watchlistDetail(flow, "scope_conditions", [])],
    ["Unmatched trigger hints", watchlistDetail(flow, "unmatched_trigger_hints", [])],
    ["Benign hints", watchlistDetail(flow, "matched_benign_hints", [])],
    ["Linter warnings", watchlistDetail(flow, "linter_warnings", [])],
  ].filter(([, values]) => Array.isArray(values) && values.length);
  const stateText = flow.detail_error || (detail ? "loaded from storage" : "summary only");

  if (!groups.length) {
    return `<span class="soft-label">${escapeHtml(stateText)}</span>`;
  }
  return `
    <div class="detail-groups">
      ${groups.map(([label, values]) => `
        <div class="detail-group">
          <span>${escapeHtml(label)}</span>
          <ul>
            ${values.map((value) => `<li>${escapeHtml(String(value))}</li>`).join("")}
          </ul>
        </div>
      `).join("")}
      <div class="detail-group detail-state">
        <span>Detail state</span>
        <p>${escapeHtml(stateText)}</p>
      </div>
    </div>
  `;
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

function topologyNodeEdgeScores(edges) {
  const scores = new Map();
  for (const edge of edges) {
    const score = number(edge.count) + number(edge.alert_count) * 20 + number(edge.watchlist_hit_count) * 12;
    scores.set(edge.src, number(scores.get(edge.src)) + score);
    scores.set(edge.dst, number(scores.get(edge.dst)) + score);
  }
  return scores;
}

function nodeEdgePath(src, dst) {
  const midX = (src.x + dst.x) / 2;
  const midY = (src.y + dst.y) / 2;
  const dx = dst.x - src.x;
  const dy = dst.y - src.y;
  const length = Math.max(1, Math.hypot(dx, dy));
  const curve = clamp(length * 0.18, 10, 30);
  const offsetX = (-dy / length) * curve;
  const offsetY = (dx / length) * curve;
  return `M ${src.x} ${src.y} Q ${midX + offsetX} ${midY + offsetY}, ${dst.x} ${dst.y}`;
}

function topologyGatewayEdgeLayers(edges, chipPositions, groupGateways, selected, latestFlowId, nodeGroup) {
  const gatewayEdges = new Map();
  const selectedDirectEdges = [];
  for (const edge of edges) {
    const srcGroup = nodeGroup.get(edge.src);
    const dstGroup = nodeGroup.get(edge.dst);
    const selectedEdge = selected && (edge.flow_ids || []).includes(selected.flow_id);
    if (selectedEdge) {
      const src = chipPositions.get(edge.src);
      const dst = chipPositions.get(edge.dst);
      if (src && dst) {
        const width = Math.min(5.8, 1.8 + Math.log2(number(edge.count) + 1));
        selectedDirectEdges.push(`
          <path class="topology-edge selected" style="stroke-width:${width.toFixed(1)}" d="${nodeEdgePath(src, dst)}">
            <title>${escapeHtml(src.label)} -> ${escapeHtml(dst.label)} / selected flow</title>
          </path>
        `);
      }
    }
    if (!srcGroup || !dstGroup || srcGroup === dstGroup) {
      continue;
    }
    const src = groupGateways.get(srcGroup);
    const dst = groupGateways.get(dstGroup);
    if (!src || !dst) {
      continue;
    }
    const key = `${srcGroup}->${dstGroup}`;
    const aggregate = gatewayEdges.get(key) || {
      src,
      dst,
      count: 0,
      alert_count: 0,
      watchlist_hit_count: 0,
      recent: false,
      selected: false,
    };
    aggregate.count += number(edge.count);
    aggregate.alert_count += number(edge.alert_count);
    aggregate.watchlist_hit_count += number(edge.watchlist_hit_count);
    aggregate.recent = aggregate.recent || edge.latest_flow_id === latestFlowId;
    aggregate.selected = aggregate.selected || selectedEdge;
    gatewayEdges.set(key, aggregate);
  }

  const gatewayLayers = [...gatewayEdges.values()]
    .map((edge) => {
      const classes = [
        "topology-edge",
        "gateway",
        edge.alert_count ? "alert" : "",
        edge.watchlist_hit_count ? "watchlist" : "",
        edge.recent ? "recent" : "",
        edge.selected ? "selected" : "",
      ].filter(Boolean).join(" ");
      const width = Math.min(6.2, 1.8 + Math.log2(edge.count + 1));
      return `
        <path class="${classes}" style="stroke-width:${width.toFixed(1)}" d="${nodeEdgePath(edge.src, edge.dst)}">
          <title>${escapeHtml(edge.src.label)} -> ${escapeHtml(edge.dst.label)} / ${edge.count} recent flows</title>
        </path>
      `;
    })
    .join("");
  return `${gatewayLayers}${selectedDirectEdges.join("")}`;
}

function topologyChips(nodes, selected, nodeEdgeScores) {
  const scored = nodes.map((node) => {
    const isSelected = selected && (selected.src_ip === node.ip || selected.dst_ip === node.ip);
    const sourceScore = node.source === "asset_input" ? 10 : 0;
    const criticalScore = ["critical", "high"].includes(String(node.criticality).toLowerCase()) ? 5 : 0;
    const edgeScore = number(nodeEdgeScores.get(node.id));
    return { node, score: (isSelected ? 100 : 0) + edgeScore + sourceScore + criticalScore };
  });
  return scored
    .sort((a, b) => b.score - a.score || String(a.node.label).localeCompare(String(b.node.label)))
    .slice(0, 8)
    .map((item) => item.node);
}

function bindTopologyPan(graph = els.topologyGraph) {
  const svg = graph.querySelector(".topology-svg");
  if (!svg) {
    return;
  }
  svg.addEventListener("wheel", (event) => {
    event.preventDefault();
    markLiveInteraction("realtime", 1400);
    zoomTopologyAt(svg, event);
  }, { passive: false });
  svg.addEventListener("pointerdown", (event) => {
    markLiveInteraction("realtime", 1800);
    svg.setPointerCapture(event.pointerId);
    state.topologyDrag = {
      graph,
      pointerId: event.pointerId,
      startX: event.clientX,
      startY: event.clientY,
      viewBox: { ...state.topologyViewBox },
    };
    svg.classList.add("dragging");
  });
  svg.addEventListener("pointermove", (event) => {
    if (!state.topologyDrag || state.topologyDrag.graph !== graph || state.topologyDrag.pointerId !== event.pointerId) {
      return;
    }
    markLiveInteraction("realtime", 1800);
    const bounds = svg.getBoundingClientRect();
    const dx = ((event.clientX - state.topologyDrag.startX) / bounds.width) * state.topologyDrag.viewBox.width;
    const dy = ((event.clientY - state.topologyDrag.startY) / bounds.height) * state.topologyDrag.viewBox.height;
    const worldWidth = Number(svg.getAttribute("data-world-width") || state.topologyDrag.viewBox.width);
    const worldHeight = Number(svg.getAttribute("data-world-height") || state.topologyDrag.viewBox.height);
    state.topologyViewBox.x = state.topologyDrag.viewBox.x - dx;
    state.topologyViewBox.y = state.topologyDrag.viewBox.y - dy;
    clampTopologyViewBox(worldWidth, worldHeight);
    setTopologyViewBox(svg);
  });
  const endDrag = (event) => {
    if (state.topologyDrag && state.topologyDrag.graph === graph && state.topologyDrag.pointerId === event.pointerId) {
      markLiveInteraction("realtime", 1000);
      state.topologyDrag = null;
      svg.classList.remove("dragging");
    }
  };
  svg.addEventListener("pointerup", endDrag);
  svg.addEventListener("pointercancel", endDrag);
}

function zoomTopologyAt(svg, event) {
  const bounds = svg.getBoundingClientRect();
  const worldWidth = Number(svg.getAttribute("data-world-width") || state.topologyViewBox.width);
  const worldHeight = Number(svg.getAttribute("data-world-height") || state.topologyViewBox.height);
  const cursorX = (event.clientX - bounds.left) / bounds.width;
  const cursorY = (event.clientY - bounds.top) / bounds.height;
  const anchorX = state.topologyViewBox.x + cursorX * state.topologyViewBox.width;
  const anchorY = state.topologyViewBox.y + cursorY * state.topologyViewBox.height;
  const scale = event.deltaY < 0 ? 0.88 : 1.14;
  const nextWidth = clamp(state.topologyViewBox.width * scale, 360, worldWidth + 80);
  const nextHeight = clamp(state.topologyViewBox.height * scale, 240, worldHeight + 80);
  state.topologyViewBox.x = anchorX - cursorX * nextWidth;
  state.topologyViewBox.y = anchorY - cursorY * nextHeight;
  state.topologyViewBox.width = nextWidth;
  state.topologyViewBox.height = nextHeight;
  clampTopologyViewBox(worldWidth, worldHeight);
  setTopologyViewBox(svg);
}

function clampTopologyViewBox(worldWidth, worldHeight) {
  state.topologyViewBox.x = clamp(
    state.topologyViewBox.x,
    -40,
    Math.max(40, worldWidth - state.topologyViewBox.width + 40),
  );
  state.topologyViewBox.y = clamp(
    state.topologyViewBox.y,
    -40,
    Math.max(40, worldHeight - state.topologyViewBox.height + 40),
  );
}

function setTopologyViewBox(svg) {
  svg.setAttribute("viewBox", `${state.topologyViewBox.x} ${state.topologyViewBox.y} ${state.topologyViewBox.width} ${state.topologyViewBox.height}`);
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

const LIVE_INTERACTION_SELECTOR = [
  "[data-live-scroll-region]",
  ".table-wrap",
  ".flow-list-body",
  ".flow-list-table-wrap",
  ".modal-evidence",
  ".summary-preview",
  ".artifact-list",
  ".source-list",
  ".structured-list",
  ".raw-editor",
  "textarea",
  "select",
].join(",");

function bindLiveInteractionFreeze() {
  document.addEventListener("wheel", (event) => markLiveInteractionFromEvent(event, 1500), { capture: true, passive: true });
  document.addEventListener("scroll", (event) => markLiveInteractionFromEvent(event, 1500), true);
  document.addEventListener("pointerdown", (event) => markLiveInteractionFromEvent(event, 1800), true);
  document.addEventListener("pointermove", (event) => {
    if (event.buttons) {
      markLiveInteractionFromEvent(event, 1800);
    }
  }, true);
  document.addEventListener("pointerup", (event) => markLiveInteractionFromEvent(event, 900), true);
  document.addEventListener("keydown", (event) => {
    if (["ArrowDown", "ArrowUp", "PageDown", "PageUp", "Home", "End", " "].includes(event.key)) {
      markLiveInteractionFromEvent(event, 1300);
    }
  }, true);
}

function markLiveInteractionFromEvent(event, holdMs) {
  const target = event.target;
  if (!target || !target.closest || !target.closest(LIVE_INTERACTION_SELECTOR)) {
    return;
  }
  const region = liveInteractionRegion(target);
  if (region) {
    markLiveInteraction(region, holdMs);
  }
}

function liveInteractionRegion(target) {
  const explicit = target.closest("[data-live-scroll-region]");
  if (explicit) {
    return explicit.getAttribute("data-live-scroll-region");
  }
  if (target.closest("#flow-list-modal")) {
    return "flowListModal";
  }
  const view = target.closest(".view-section.active");
  if (view && view.id) {
    return view.id.replace(/^view-/, "");
  }
  return null;
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
els.flowListClose.addEventListener("click", closeFlowListModal);
els.flowListModal.addEventListener("click", (event) => {
  if (event.target === els.flowListModal) {
    closeFlowListModal();
  }
});
els.topologyFullscreen.addEventListener("click", openTopologyModal);
els.topologyModalClose.addEventListener("click", closeTopologyModal);
els.topologyModal.addEventListener("click", (event) => {
  if (event.target === els.topologyModal) {
    closeTopologyModal();
  }
});
els.inputEditClose.addEventListener("click", closeInputEditor);
els.inputAddCancel.addEventListener("click", closeInputEditor);
els.inputRawCancel.addEventListener("click", closeInputEditor);
els.inputEditModal.addEventListener("click", (event) => {
  if (event.target === els.inputEditModal) {
    closeInputEditor();
  }
});
window.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && !els.topologyModal.hidden) {
    closeTopologyModal();
  } else if (event.key === "Escape" && !els.flowDetailModal.hidden) {
    closeFlowDetailModal();
  } else if (event.key === "Escape" && !els.inputEditModal.hidden) {
    closeInputEditor();
  } else if (event.key === "Escape" && !els.flowListModal.hidden) {
    closeFlowListModal();
  }
});

bindMetricAction(els.metricAlertsCard, () => openFlowListModal("alert", 1));
bindMetricAction(els.metricNeedsReviewCard, () => openFlowListModal("review", 1));

els.contextTabList.querySelectorAll("button[data-artifact]").forEach((button) => {
  button.addEventListener("click", () => {
    state.selectedArtifact = button.getAttribute("data-artifact");
    els.contextTabList.querySelectorAll(".tab-item").forEach((item) => {
      item.classList.toggle("active", item.getAttribute("data-artifact") === state.selectedArtifact);
    });
    renderContext(state.dashboard || {});
  });
});

els.reportsDateFilter.addEventListener("change", () => {
  state.reportFilters.date = els.reportsDateFilter.value;
  renderOrRefreshReports();
});
els.reportsSeverityFilter.addEventListener("change", () => {
  state.reportFilters.severity = els.reportsSeverityFilter.value;
  renderOrRefreshReports();
});
els.reportsVerdictFilter.addEventListener("change", () => {
  state.reportFilters.verdict = els.reportsVerdictFilter.value;
  renderOrRefreshReports();
});
els.reportsAssetFilter.addEventListener("change", () => {
  state.reportFilters.asset = els.reportsAssetFilter.value.trim();
  renderOrRefreshReports();
});

els.startupTier1Provider.addEventListener("change", () => refreshStartupModelSelect("tier1"));
els.startupTier2Provider.addEventListener("change", () => refreshStartupModelSelect("tier2"));
els.startupStart.addEventListener("click", startAppFromSetup);
els.realtimeHideBenign.addEventListener("change", () => {
  state.realtimeHideBenign = els.realtimeHideBenign.checked;
  els.flowListHideBenign.checked = state.realtimeHideBenign;
  renderRealtime(state.dashboard || {});
  if (!els.flowListModal.hidden && state.flowListModal.type === "all") {
    renderFlowListModal({ preserveScroll: false });
  }
});
els.flowListHideBenign.addEventListener("change", () => {
  state.realtimeHideBenign = els.flowListHideBenign.checked;
  els.realtimeHideBenign.checked = state.realtimeHideBenign;
  state.flowListModal.page = 1;
  renderRealtime(state.dashboard || {});
  renderFlowListModal({ preserveScroll: false });
});
els.realtimeOpenAll.addEventListener("click", () => openAllFlowsModal(1));
els.inputRawEditor.addEventListener("input", () => {
  state.inputRawDirty = true;
  setInputStatus("Raw YAML has unsaved changes.");
});
els.inputOpenAdd.addEventListener("click", () => openInputEditor("add"));
els.inputOpenRaw.addEventListener("click", () => openInputEditor("raw"));
els.inputSaveRaw.addEventListener("click", saveRawInput);
els.inputAddItem.addEventListener("click", addStructuredInputItem);
els.refreshButton.addEventListener("click", refreshCurrentView);
els.reportsGenerateSummary.addEventListener("click", generateDailySummary);
els.contextRefreshTier2.addEventListener("click", () => refreshTier2(els.contextRefreshTier2));
els.settingsRefreshModels.addEventListener("click", loadSettingsOptions);
els.settingsApply.addEventListener("click", applySettings);
els.settingsResetDb.addEventListener("click", resetProductDb);
els.settingsTier1Provider.addEventListener("change", () => refreshSettingsModelSelect("tier1"));
els.settingsTier2Provider.addEventListener("change", () => refreshSettingsModelSelect("tier2"));
[
  els.settingsTier1Model,
  els.settingsTier1OllamaUrl,
  els.settingsTier1MaxTokens,
  els.settingsTier1Workers,
  els.settingsTier2Model,
  els.settingsTier2OllamaUrl,
  els.settingsTier2MaxTokens,
  els.settingsGeminiApiKey,
  els.settingsThresholdLow,
  els.settingsThresholdHigh,
].forEach((element) => element.addEventListener("input", markSettingsDirty));

[els.startupGeminiApiKey, els.settingsGeminiApiKey].forEach((element) => {
  element.addEventListener("focus", () => {
    if (element.value === SAVED_GEMINI_KEY_MASK) {
      element.select();
    }
  });
});

window.addEventListener("focus", () => refreshLlmOptionsQuietly("focus"));
document.addEventListener("visibilitychange", () => {
  if (!document.hidden) {
    refreshLlmOptionsQuietly("visible");
  }
});

window.addEventListener("beforeunload", (event) => {
  if (!state.settingsDirty) {
    return;
  }
  event.preventDefault();
  event.returnValue = "";
});

els.realtimeHideBenign.checked = state.realtimeHideBenign;
els.flowListHideBenign.checked = state.realtimeHideBenign;
bindLiveInteractionFreeze();
bootStartup();

function bindMetricAction(element, callback) {
  element.addEventListener("click", callback);
  element.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      callback();
    }
  });
}
