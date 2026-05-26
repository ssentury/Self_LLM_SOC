/* Demo Controller app.js */
(function () {
  "use strict";

  const els = {
    productUrl: document.getElementById("product-url"),
    btnRefresh: document.getElementById("btn-refresh-status"),
    productStatus: document.getElementById("product-status-box"),
    productBadge: document.getElementById("product-badge"),
    injectorBadge: document.getElementById("injector-badge"),
    scenario: document.getElementById("scenario"),
    dayFilter: document.getElementById("day-filter"),
    limit: document.getElementById("limit"),
    interval: document.getElementById("interval"),
    timeout: document.getElementById("timeout"),
    continueErr: document.getElementById("continue-on-error"),
    dryRun: document.getElementById("dry-run"),
    btnApplyInputs: document.getElementById("btn-apply-inputs"),
    btnStart: document.getElementById("btn-start"),
    btnStop: document.getElementById("btn-stop"),
    progressSection: document.getElementById("progress-section"),
    progressBar: document.getElementById("progress-bar"),
    progressText: document.getElementById("progress-text"),
    logBox: document.getElementById("log-box"),
    btnClearLog: document.getElementById("btn-clear-log"),
  };

  let pollTimer = null;

  function log(message, cls) {
    const div = document.createElement("div");
    div.className = `log-entry ${cls || "log-info"}`;
    const ts = new Date().toLocaleTimeString("ko-KR", { hour12: false });
    div.textContent = `[${ts}] ${message}`;
    els.logBox.appendChild(div);
    els.logBox.scrollTop = els.logBox.scrollHeight;
  }

  async function demoApi(path, method, body) {
    const opts = { method: method || "GET", headers: {} };
    if (body !== undefined) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }
    try {
      const resp = await fetch(path, opts);
      return await resp.json();
    } catch (err) {
      log(`API error: ${err.message}`, "log-fail");
      return { error: err.message };
    }
  }

  async function refreshProductStatus() {
    const status = await demoApi("/api/demo/product-status");
    if (status.error) {
      els.productBadge.textContent = "Product: offline";
      els.productBadge.className = "badge badge-offline";
      showStatus(`Connection failed: ${status.error}`);
      return;
    }

    els.productBadge.textContent = "Product: online";
    els.productBadge.className = "badge badge-online";
    showStatus(statusLines(status).join("\n"));
  }

  function statusLines(status) {
    const lines = [
      `service: ${status.service || "-"}`,
      `detector: ${status.detector || "-"}`,
      `Tier 1: ${status.tier1_provider || "-"} / ${status.tier1_model || "-"}`,
      `Tier 1 Ollama URL: ${status.tier1_ollama_url || "-"}`,
      `Tier 1 queue: ${status.tier1_queue_mode || "-"}`,
      `Tier 2: ${status.tier2_provider || "-"} / ${status.tier2_model || "-"}`,
      `Tier 2 Ollama URL: ${status.tier2_ollama_url || "-"}`,
      `Source input dir: ${status.source_input_dir || "-"}`,
    ];
    if (status.storage) {
      lines.push(`storage: ${status.storage.enabled ? "enabled" : "disabled"} (${status.storage.sqlite_path || "-"})`);
      if (status.storage.tables) {
        const t = status.storage.tables;
        lines.push(`  flows=${t.flows || 0}  ml=${t.ml_results || 0}  route=${t.route_decisions || 0}  verdict=${t.verdicts || 0}  t1_calls=${t.tier1_calls || 0}`);
      }
    }
    return lines;
  }

  function showStatus(text) {
    els.productStatus.textContent = text;
    els.productStatus.classList.remove("hidden");
  }

  async function startInjection() {
    const payload = {
      target_url: els.productUrl.value,
      scenario: els.scenario.value,
      day: els.dayFilter.value || null,
      limit: parseInt(els.limit.value, 10) || 0,
      interval: parseFloat(els.interval.value) || 0.25,
      timeout: parseFloat(els.timeout.value) || 30,
      continue_on_error: els.continueErr.checked,
      dry_run: els.dryRun.checked,
    };
    log(`Starting injection: scenario=${payload.scenario}, day=${payload.day || "all"}, limit=${payload.limit}, interval=${payload.interval}s`);
    els.btnStart.disabled = true;
    try {
      const data = await demoApi("/api/demo/start", "POST", payload);
      if (data.error) {
        log(`Injection start failed: ${data.error}`, "log-fail");
        els.btnStart.disabled = false;
        return;
      }
      setInjectorState("running");
      startPolling();
    } catch (err) {
      els.btnStart.disabled = false;
      throw err;
    }
  }

  async function applyScenarioInputs() {
    const payload = {
      scenario: els.scenario.value,
      day: els.dayFilter.value || null,
    };
    log(`Applying scenario inputs: scenario=${payload.scenario}, day=${payload.day || "base"}`);
    els.btnApplyInputs.disabled = true;
    try {
      const data = await demoApi("/api/demo/apply-scenario-inputs", "POST", payload);
      if (data.error) {
        log(`Scenario input apply failed: ${data.error}`, "log-fail");
        return;
      }
      const copied = Object.keys(data.copied || {});
      log(`Scenario inputs copied: ${copied.join(", ") || "none"}`, "log-ok");
      if (data.config_path) {
        log(`Product active config: ${data.config_path}`, "log-info");
      }
      refreshProductStatus();
    } finally {
      els.btnApplyInputs.disabled = false;
    }
  }

  async function stopInjection() {
    log("Requesting injector stop...");
    await demoApi("/api/demo/stop", "POST", {});
    log("Stop signal sent.", "log-warn");
  }

  function startPolling() {
    stopPolling();
    pollTimer = setInterval(pollStatus, 500);
  }

  function stopPolling() {
    if (pollTimer) {
      clearInterval(pollTimer);
      pollTimer = null;
    }
  }

  async function pollStatus() {
    const data = await demoApi("/api/demo/status");
    if (data.error) return;

    const summary = data.summary || {};
    const attempted = data.attempted !== undefined ? data.attempted : (summary.attempted || 0);
    const total = data.total !== undefined ? data.total : attempted;
    const succeeded = data.succeeded !== undefined ? data.succeeded : (summary.succeeded || 0);
    const failed = data.failed !== undefined ? data.failed : (summary.failed || 0);

    if (total > 0) {
      els.progressSection.classList.remove("hidden");
      const pct = Math.round((attempted / total) * 100);
      els.progressBar.style.width = `${pct}%`;
      els.progressText.textContent = `${attempted} / ${total}  (ok: ${succeeded}, failed: ${failed})`;
    }

    if (!data.running) {
      stopPolling();
      if (data.error) {
        log(`Injection error: ${data.error}`, "log-fail");
        setInjectorState("error");
      } else if (data.attempted !== undefined || summary.attempted !== undefined) {
        log(`Injection complete: attempted=${attempted}, ok=${succeeded}, failed=${failed}`, failed > 0 ? "log-warn" : "log-ok");
        setInjectorState("done");
      } else {
        setInjectorState("idle");
      }
      refreshProductStatus();
    }
  }

  function setInjectorState(state) {
    els.btnStart.disabled = state === "running";
    els.btnStop.disabled = state !== "running";

    switch (state) {
      case "running":
        els.injectorBadge.textContent = "Injector: running";
        els.injectorBadge.className = "badge badge-running";
        break;
      case "done":
        els.injectorBadge.textContent = "Injector: done";
        els.injectorBadge.className = "badge badge-done";
        break;
      case "error":
        els.injectorBadge.textContent = "Injector: error";
        els.injectorBadge.className = "badge badge-error";
        break;
      default:
        els.injectorBadge.textContent = "Injector: idle";
        els.injectorBadge.className = "badge badge-idle";
    }
  }

  function escapeHtml(value) {
    return String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  els.btnRefresh.addEventListener("click", refreshProductStatus);
  els.btnApplyInputs.addEventListener("click", applyScenarioInputs);
  els.btnStart.addEventListener("click", startInjection);
  els.btnStop.addEventListener("click", stopInjection);
  els.btnClearLog.addEventListener("click", () => { els.logBox.innerHTML = ""; });

  log("Demo Controller initialized.", "log-info");
  demoApi("/api/demo/status").then((data) => {
    if (data && data.product_url) {
      els.productUrl.value = data.product_url;
      log(`Product API URL initialized: ${data.product_url}`);
    }
    refreshProductStatus();
  });
})();
