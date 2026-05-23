/* Demo Controller app.js */
(function () {
  "use strict";

  const DEFAULT_TIER1_CHOICES = [
    { label: "Ollama Local - gemma4:e4b", provider: "ollama", model: "gemma4:e4b", ollama_url: "http://host.docker.internal:11434" },
  ];
  const DEFAULT_TIER2_CHOICES = [
    { label: "Gemini API - gemini-3.5-flash", provider: "gemini", model: "gemini-3.5-flash", ollama_url: "" },
    { label: "Gemini API - gemini-3-flash-preview", provider: "gemini", model: "gemini-3-flash-preview", ollama_url: "" },
    { label: "Ollama Local - gemma4:26b", provider: "ollama", model: "gemma4:26b", ollama_url: "http://host.docker.internal:11434" },
  ];

  const els = {
    productUrl: document.getElementById("product-url"),
    tier1Mode: document.getElementById("tier1-mode"),
    tier1Choice: document.getElementById("tier1-llm-choice"),
    tier1OllamaUrl: document.getElementById("tier1-ollama-url"),
    tier2Mode: document.getElementById("tier2-mode"),
    tier2Choice: document.getElementById("tier2-llm-choice"),
    tier2OllamaUrl: document.getElementById("tier2-ollama-url"),
    btnApplyConfig: document.getElementById("btn-apply-config"),
    btnResetDb: document.getElementById("btn-reset-db"),
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
    btnStart: document.getElementById("btn-start"),
    btnStop: document.getElementById("btn-stop"),
    progressSection: document.getElementById("progress-section"),
    progressBar: document.getElementById("progress-bar"),
    progressText: document.getElementById("progress-text"),
    logBox: document.getElementById("log-box"),
    btnClearLog: document.getElementById("btn-clear-log"),
  };

  let pollTimer = null;
  let lastOptions = {
    tier1: { models: DEFAULT_TIER1_CHOICES },
    tier2: { models: DEFAULT_TIER2_CHOICES },
  };

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
    const [status, options] = await Promise.all([
      demoApi("/api/demo/product-status"),
      demoApi("/api/demo/llm-options"),
    ]);
    if (status.error) {
      els.productBadge.textContent = "Product: offline";
      els.productBadge.className = "badge badge-offline";
      showStatus(`Connection failed: ${status.error}`);
      return;
    }

    if (!options.error) {
      lastOptions = normalizeOptions(options);
      populateChoiceSelect(els.tier1Choice, lastOptions.tier1.models);
      populateChoiceSelect(els.tier2Choice, lastOptions.tier2.models);
    }

    els.productBadge.textContent = "Product: online";
    els.productBadge.className = "badge badge-online";
    syncControls(status);
    showStatus(statusLines(status, options).join("\n"));
  }

  function normalizeOptions(options) {
    return {
      tier1: { models: mergeChoices(options.tier1 && options.tier1.models, DEFAULT_TIER1_CHOICES) },
      tier2: { models: mergeChoices(options.tier2 && options.tier2.models, DEFAULT_TIER2_CHOICES) },
      ollama: options.ollama || {},
    };
  }

  function mergeChoices(discovered, fallback) {
    const seen = new Set();
    const merged = [];
    for (const choice of [...(discovered || []), ...fallback]) {
      const normalized = normalizeChoice(choice);
      const key = choiceValue(normalized);
      if (!seen.has(key)) {
        seen.add(key);
        merged.push(normalized);
      }
    }
    return merged;
  }

  function normalizeChoice(choice) {
    return {
      label: choice.label || `${choice.provider} - ${choice.model}`,
      provider: choice.provider || "ollama",
      model: choice.model || "",
      ollama_url: choice.ollama_url || "",
    };
  }

  function populateChoiceSelect(select, choices) {
    const current = select.value;
    select.innerHTML = choices
      .map((choice) => `<option value="${escapeAttr(choiceValue(choice))}">${escapeHtml(choice.label)}</option>`)
      .join("");
    if ([...select.options].some((option) => option.value === current)) {
      select.value = current;
    }
  }

  function syncControls(status) {
    els.tier1Mode.value = status.tier1_provider === "fake" ? "fake" : "llm";
    setChoiceFromStatus(els.tier1Choice, lastOptions.tier1.models, {
      provider: status.tier1_provider,
      model: status.tier1_model,
      ollama_url: status.tier1_ollama_url,
    });
    els.tier1OllamaUrl.value = status.tier1_ollama_url || selectedChoice(els.tier1Choice).ollama_url || "http://host.docker.internal:11434";

    els.tier2Mode.value = status.tier2_provider === "deterministic" || status.tier2_provider === "fake"
      ? status.tier2_provider
      : "llm";
    setChoiceFromStatus(els.tier2Choice, lastOptions.tier2.models, {
      provider: status.tier2_provider,
      model: status.tier2_model,
      ollama_url: status.tier2_ollama_url,
    });
    els.tier2OllamaUrl.value = status.tier2_ollama_url || selectedChoice(els.tier2Choice).ollama_url || "http://host.docker.internal:11434";
    updateLlmVisibility();
  }

  function setChoiceFromStatus(select, choices, status) {
    const matching = choices.find((choice) => (
      choice.provider === status.provider && choice.model === status.model
    ));
    if (matching) {
      select.value = choiceValue(matching);
    }
  }

  function statusLines(status, options) {
    const lines = [
      `service: ${status.service || "-"}`,
      `detector: ${status.detector || "-"}`,
      `Tier 1: ${status.tier1_provider || "-"} / ${status.tier1_model || "-"}`,
      `Tier 1 Ollama URL: ${status.tier1_ollama_url || "-"}`,
      `Tier 1 queue: ${status.tier1_queue_mode || "-"}`,
      `Tier 2: ${status.tier2_provider || "-"} / ${status.tier2_model || "-"}`,
      `Tier 2 Ollama URL: ${status.tier2_ollama_url || "-"}`,
    ];
    if (options && !options.error && options.ollama) {
      const t1 = options.ollama.tier1 || {};
      const t2 = options.ollama.tier2 || {};
      lines.push(`Ollama discovery: tier1=${t1.reachable ? `ok ${t1.url}` : "not reachable"} / tier2=${t2.reachable ? `ok ${t2.url}` : "not reachable"}`);
    }
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

  async function applyConfig() {
    const tier1 = selectedChoice(els.tier1Choice);
    const tier2 = selectedChoice(els.tier2Choice);
    const payload = {
      tier1_provider: els.tier1Mode.value === "llm" ? tier1.provider : "fake",
      tier1_model: els.tier1Mode.value === "llm" ? tier1.model : undefined,
      tier1_ollama_url: els.tier1Mode.value === "llm" && tier1.provider === "ollama"
        ? (els.tier1OllamaUrl.value || tier1.ollama_url)
        : undefined,
      tier2_provider: els.tier2Mode.value === "llm" ? tier2.provider : els.tier2Mode.value,
      tier2_model: els.tier2Mode.value === "llm" ? tier2.model : undefined,
      tier2_ollama_url: els.tier2Mode.value === "llm" && tier2.provider === "ollama"
        ? (els.tier2OllamaUrl.value || tier2.ollama_url)
        : undefined,
    };
    log(`Applying settings: ${JSON.stringify(payload)}`);
    const data = await demoApi("/api/demo/product-config", "POST", payload);
    if (data.error) {
      log(`Apply failed: ${data.error}`, "log-fail");
      return;
    }
    const keys = Object.keys(data.applied || {});
    log(`Applied: ${keys.length ? keys.join(", ") : "no changes"}`, "log-ok");
    refreshProductStatus();
  }

  async function resetDb() {
    if (!confirm("Delete all stored flow, ML, route, verdict, and Tier 1 call rows?")) return;
    log("Resetting Product API DB...");
    const data = await demoApi("/api/demo/product-reset", "POST", {});
    if (data.error) {
      log(`DB reset failed: ${data.error}`, "log-fail");
      return;
    }
    const deleted = data.deleted || {};
    const total = Object.values(deleted).reduce((sum, value) => sum + Number(value || 0), 0);
    log(`DB reset complete: ${total} rows deleted (${JSON.stringify(deleted)})`, "log-ok");
    refreshProductStatus();
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
    const data = await demoApi("/api/demo/start", "POST", payload);
    if (data.error) {
      log(`Injection start failed: ${data.error}`, "log-fail");
      return;
    }
    setInjectorState("running");
    startPolling();
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

  function updateLlmVisibility() {
    document.querySelectorAll("[data-llm-scope='tier1']").forEach((node) => {
      node.classList.toggle("hidden", els.tier1Mode.value !== "llm");
    });
    document.querySelectorAll("[data-llm-scope='tier2']").forEach((node) => {
      node.classList.toggle("hidden", els.tier2Mode.value !== "llm");
    });
    const tier1 = selectedChoice(els.tier1Choice);
    const tier2 = selectedChoice(els.tier2Choice);
    els.tier1OllamaUrl.closest(".field-row").classList.toggle("hidden", els.tier1Mode.value !== "llm" || tier1.provider !== "ollama");
    els.tier2OllamaUrl.closest(".field-row").classList.toggle("hidden", els.tier2Mode.value !== "llm" || tier2.provider !== "ollama");
    if (tier1.provider === "ollama" && tier1.ollama_url) els.tier1OllamaUrl.value = tier1.ollama_url;
    if (tier2.provider === "ollama" && tier2.ollama_url) els.tier2OllamaUrl.value = tier2.ollama_url;
  }

  function selectedChoice(select) {
    const [provider, model, ollamaUrl] = String(select.value || "").split("|");
    return { provider, model, ollama_url: ollamaUrl || "" };
  }

  function choiceValue(choice) {
    return `${choice.provider}|${choice.model}|${choice.ollama_url || ""}`;
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
    return escapeHtml(value);
  }

  els.btnApplyConfig.addEventListener("click", applyConfig);
  els.btnResetDb.addEventListener("click", resetDb);
  els.btnRefresh.addEventListener("click", refreshProductStatus);
  els.btnStart.addEventListener("click", startInjection);
  els.btnStop.addEventListener("click", stopInjection);
  els.btnClearLog.addEventListener("click", () => { els.logBox.innerHTML = ""; });
  els.tier1Mode.addEventListener("change", updateLlmVisibility);
  els.tier2Mode.addEventListener("change", updateLlmVisibility);
  els.tier1Choice.addEventListener("change", updateLlmVisibility);
  els.tier2Choice.addEventListener("change", updateLlmVisibility);

  log("Demo Controller initialized.", "log-info");
  updateLlmVisibility();
  demoApi("/api/demo/status").then((data) => {
    if (data && data.product_url) {
      els.productUrl.value = data.product_url;
      log(`Product API URL initialized: ${data.product_url}`);
    }
    refreshProductStatus();
  });
})();
