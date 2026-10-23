(function () {
  "use strict";

  const DB = window.OSINT_DB || { categories: [], tools: [], workflows: [], dorks: [], graveyard: [] };
  const toolsById = new Map(DB.tools.map((t) => [t.id, t]));
  const catsById = new Map(DB.categories.map((c) => [c.id, c]));

  const state = {
    view: "investigate",
    dirSubview: "tools",
    query: "",
    category: "",
    inputSelector: "",
    passiveOnly: false,
    freeOnly: false,
    noAuthOnly: false,
    dorkTarget: "",
    dorkEngine: "",
    dorkQuery: "",
  };

  let lastHuntReport = null;

  function esc(str) {
    return String(str ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function prettyKey(k) {
    return String(k)
      .replace(/_/g, " ")
      .replace(/\b\w/g, (c) => c.toUpperCase());
  }

  function copyText(text, btnEl) {
    navigator.clipboard?.writeText(text);
    if (btnEl) {
      const prev = btnEl.textContent;
      btnEl.textContent = "Copied";
      setTimeout(() => {
        btnEl.textContent = prev;
      }, 1200);
    }
  }

  function downloadBlob(filename, content, mime) {
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  function fileToBase64(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(String(reader.result || ""));
      reader.onerror = () => reject(new Error("Could not read file"));
      reader.readAsDataURL(file);
    });
  }

  // ── Navigation ─────────────────────────────────────────────────────────────
  function switchView(viewName) {
    state.view = viewName;
    document.querySelectorAll(".nav-tab[data-view]").forEach((b) => {
      b.classList.toggle("active", b.dataset.view === viewName);
    });
    document.querySelectorAll(".view-panel").forEach((p) => {
      p.classList.toggle("active", p.id === `view-${viewName}`);
    });
    if (viewName === "cases") renderCasesVault();
    if (viewName === "directory") renderDirectory();
    if (viewName === "settings") renderSettingsAndDoctor();
  }

  document.getElementById("homeBrandBtn")?.addEventListener("click", () => switchView("investigate"));
  document.querySelectorAll(".nav-tab[data-view]").forEach((btn) => {
    btn.addEventListener("click", () => switchView(btn.dataset.view));
  });

  // Close open dropdowns on outside click
  document.addEventListener("click", (e) => {
    document.querySelectorAll(".dropdown.open").forEach((dd) => {
      if (!dd.contains(e.target)) dd.classList.remove("open");
    });
  });

  // ── Clean Entity Graph Renderer ────────────────────────────────────────────
  function renderEntityGraphSvg(graph, opts = {}) {
    const allNodes = graph.nodes || [];
    const allEdges = graph.edges || [];
    if (!allNodes.length) return "";

    const stageFilter = opts.stage || "";
    const typeFilter = opts.type || "";
    const highlightPathSet = opts.highlightPathSet || new Set();
    const highlightNodeSet = opts.highlightNodeSet || new Set();

    const nodes = allNodes.filter((n) => {
      if (stageFilter && String(n.wave || 1) !== stageFilter) return false;
      if (typeFilter && n.type !== typeFilter) return false;
      return true;
    });
    const allowedIds = new Set(nodes.map((n) => n.id));
    const edges = allEdges.filter((e) => allowedIds.has(e.source) && allowedIds.has(e.target));

    if (!nodes.length) {
      return `<div style="padding:28px; text-align:center; color:var(--text-muted);">No entities match this filter.</div>`;
    }

    const byWave = new Map();
    nodes.forEach((n) => {
      const w = n.wave || 1;
      if (!byWave.has(w)) byWave.set(w, []);
      byWave.get(w).push(n);
    });

    const waves = [...byWave.keys()].sort((a, b) => a - b);
    const width = 960;
    const maxPerCol = Math.max(...waves.map((w) => byWave.get(w).length), 1);
    const height = Math.max(220, maxPerCol * 56 + 48);
    const pos = new Map();

    waves.forEach((w, colIdx) => {
      const colNodes = byWave.get(w);
      const x = waves.length === 1 ? width / 2 : 150 + (colIdx * (width - 300)) / (waves.length - 1);
      colNodes.forEach((n, rowIdx) => {
        const y = ((rowIdx + 1) * height) / (colNodes.length + 1);
        pos.set(n.id, { x, y, node: n });
      });
    });

    const colorFor = (tp) => {
      if (tp === "email") return "#f59e0b";
      if (tp === "domain" || tp === "ip") return "#38bdf8";
      if (tp === "username") return "#a78bfa";
      if (tp === "person_name" || tp === "company") return "#f472b6";
      if (tp === "phone" || tp === "crypto_address") return "#34d399";
      return "#94a3b8";
    };

    const edgeLines = edges
      .map((e) => {
        const s = pos.get(e.source);
        const t = pos.get(e.target);
        if (!s || !t) return "";
        const mx = (s.x + t.x) / 2;
        const my = (s.y + t.y) / 2 - 6;
        const isHi = highlightPathSet.has(`${e.source}|${e.target}`) || highlightPathSet.has(`${e.target}|${e.source}`);
        return `
          <line x1="${s.x}" y1="${s.y}" x2="${t.x}" y2="${t.y}" stroke="${isHi ? "#fbbf24" : "rgba(255,255,255,0.16)"}" stroke-width="${isHi ? "2.6" : "1.3"}" />
          <text x="${mx}" y="${my}" fill="${isHi ? "#fde68a" : "#6b7280"}" font-size="9.5" text-anchor="middle">${esc(e.via)}</text>`;
      })
      .join("");

    const nodeCards = [...pos.values()]
      .map(({ x, y, node }) => {
        const isHi = highlightNodeSet.has(node.id);
        const col = isHi ? "#fbbf24" : colorFor(node.type);
        const label = node.value.length > 26 ? node.value.slice(0, 24) + "…" : node.value;
        return `
          <g class="svg-node" data-rehunt="${esc(node.value)}" style="cursor:pointer;">
            <rect x="${x - 108}" y="${y - 18}" width="216" height="36" rx="9" fill="#12151f" stroke="${col}" stroke-opacity="${isHi ? "1" : "0.55"}" stroke-width="${isHi ? "2.2" : "1.2"}" />
            <text x="${x}" y="${y - 3}" fill="${col}" font-size="9" font-weight="600" text-anchor="middle">${esc(node.type)}</text>
            <text x="${x}" y="${y + 11}" fill="#f3f4f6" font-size="11" font-family="monospace" text-anchor="middle">${esc(label)}</text>
          </g>`;
      })
      .join("");

    return `<svg id="interactiveGraphSvg" viewBox="0 0 ${width} ${height}" style="width:100%; height:auto; max-height:460px; display:block; cursor:grab; user-select:none;"><g id="graphViewportGroup">${edgeLines}${nodeCards}</g></svg>`;
  }

  // ── Active Scan Permission Modal (Mandatory Gate) ──────────────────────────
  async function openActiveAuthorizationModal(targetOverride, fromCaseId) {
    const inputEl = document.getElementById("huntTargetInput");
    const target = (targetOverride || inputEl.value || "").trim();
    if (!target && !fromCaseId) {
      inputEl.focus();
      return;
    }

    const backdrop = document.getElementById("activeAuthBackdrop");
    const modal = document.getElementById("activeAuthModalContent");
    backdrop.classList.add("open");
    modal.innerHTML = `<div style="padding:20px; text-align:center; color:var(--text-muted);">Preparing active scan scope (no packets sent yet)...</div>`;

    try {
      const resp = await fetch("./api/hunt/active/prepare", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(fromCaseId ? { target, from_case: fromCaseId } : { target }),
      });
      const plan = await resp.json();
      if (!resp.ok || plan.error) throw new Error(plan.error || `HTTP ${resp.status}`);

      const plannedSet = new Set((plan.planned_active_modules || []).map((m) => m.module));
      const allMods = plan.all_available_modules || plan.planned_active_modules || [];

      modal.innerHTML = `
        <div style="display:flex; justify-content:space-between; align-items:flex-start; gap:12px; margin-bottom:14px;">
          <div>
            <span class="status-pill red">Permission Required</span>
            <h3 style="margin:8px 0 2px; font-size:18px;">Run active network probes?</h3>
            <div style="font-size:12.5px; color:var(--text-muted);">Target: <code>${esc(plan.target)}</code> · Token: <code>${esc(plan.request_id)}</code></div>
          </div>
          <button class="btn-ghost" id="cancelActiveModalBtn">✕</button>
        </div>

        <div style="background:var(--red-soft); border:1px solid rgba(239,68,68,0.3); border-radius:9px; padding:11px 13px; font-size:13px; color:#fecaca; margin-bottom:14px;">
          Active scans connect directly to the target's servers (TLS, HTTP headers, DNS, open ports) and may appear in their server logs.
        </div>

        <details style="margin-bottom:16px;">
          <summary style="cursor:pointer; font-size:13px; color:var(--text-muted);">Customize active probes (${plannedSet.size} selected)</summary>
          <div style="display:grid; gap:6px; max-height:200px; overflow-y:auto; margin-top:10px; padding-right:4px;">
            ${allMods
              .map(
                (m) => `
              <label style="display:flex; gap:8px; align-items:center; font-size:12.5px; cursor:pointer;">
                <input type="checkbox" class="act-mod-chk" value="${esc(m.module)}" ${plannedSet.has(m.module) ? "checked" : ""} />
                <span><strong>${esc(m.title)}</strong> <span style="color:var(--text-dim);">(${esc(m.module)})</span></span>
              </label>`
              )
              .join("")}
          </div>
        </details>

        <div style="display:flex; justify-content:flex-end; gap:8px;">
          <button class="btn" id="abortActiveBtn">Cancel</button>
          <button class="btn btn-danger" id="confirmActiveBtn" style="background:rgba(239,68,68,0.16); font-weight:600;">Approve &amp; Run Active Scan</button>
        </div>
      `;

      const closeModal = () => backdrop.classList.remove("open");
      document.getElementById("cancelActiveModalBtn").onclick = closeModal;
      document.getElementById("abortActiveBtn").onclick = closeModal;
      document.getElementById("confirmActiveBtn").onclick = async () => {
        const chosen = [...modal.querySelectorAll(".act-mod-chk:checked")].map((c) => c.value);
        closeModal();
        await executeApprovedActiveHunt(plan.target, plan.request_id, chosen);
      };
    } catch (err) {
      modal.innerHTML = `<div style="padding:12px;"><h4>Could not prepare active scan</h4><p style="color:var(--text-muted);">${esc(err.message)}</p><button class="btn" id="errCloseAct">Close</button></div>`;
      document.getElementById("errCloseAct").onclick = () => backdrop.classList.remove("open");
    }
  }

  async function executeApprovedActiveHunt(target, requestId, modules) {
    const btn = document.getElementById("launchHuntBtn");
    const depth = Math.min(3, parseInt(document.getElementById("huntDepthSelect").value || "2", 10));
    const outArea = document.getElementById("huntResultsArea");

    btn.disabled = true;
    btn.textContent = "Running...";
    outArea.innerHTML = `<div class="card" style="text-align:center; padding:32px; color:var(--text-muted);">Running authorized active + passive checks on <code>${esc(target)}</code>...</div>`;

    try {
      const resp = await fetch("./api/hunt/active", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Human-Modal-Confirmed": "1" },
        body: JSON.stringify({
          target,
          request_id: requestId,
          user_confirmation: "Approved via Local Web Workspace",
          depth,
          modules,
          save_case: true,
        }),
      });
      const report = await resp.json();
      if (!resp.ok || report.error) throw new Error(report.error || `HTTP ${resp.status}`);
      lastHuntReport = report;
      renderHuntReport(report);
    } catch (err) {
      outArea.innerHTML = `<div class="card"><div class="card-title" style="color:#fca5a5;">Active scan stopped</div><p style="color:var(--text-muted); margin:6px 0 0;">${esc(err.message)}</p></div>`;
    } finally {
      btn.disabled = false;
      btn.textContent = "Investigate";
    }
  }

  // ── Investigate Execution & Clean Results View ─────────────────────────────
  async function executeLiveHunt() {
    const inputEl = document.getElementById("huntTargetInput");
    const modeSel = document.getElementById("huntModeSelect");
    const btn = document.getElementById("launchHuntBtn");
    const depth = parseInt(document.getElementById("huntDepthSelect").value || "4", 10);
    const diffLast = Boolean(document.getElementById("huntDiffLastCheck")?.checked);
    const outArea = document.getElementById("huntResultsArea");
    const target = inputEl.value.trim();
    if (!target) {
      inputEl.focus();
      return;
    }

    if (modeSel && modeSel.value === "active") {
      await openActiveAuthorizationModal(target);
      return;
    }

    btn.disabled = true;
    btn.textContent = "Investigating...";
    outArea.innerHTML = `<div class="card" style="text-align:center; padding:32px; color:var(--text-muted);">Searching public sources and correlating leads for <code>${esc(target)}</code>...</div>`;

    try {
      const resp = await fetch("./api/hunt", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target, depth, save_case: true, diff_last: diffLast }),
      });
      const report = await resp.json();
      if (!resp.ok || report.error) throw new Error(report.error || `HTTP ${resp.status}`);
      lastHuntReport = report;
      renderHuntReport(report);
    } catch (err) {
      outArea.innerHTML = `<div class="card"><div class="card-title" style="color:#fca5a5;">Local server not running</div><p style="color:var(--text-muted); margin:6px 0 0;">Double-click <code>Start-Web-UI.bat</code> (Windows), <code>Start-Web-UI.command</code> (macOS), or run <code>./start-web-ui.sh</code>.</p></div>`;
    } finally {
      btn.disabled = false;
      btn.textContent = "Investigate";
    }
  }

  function renderHuntReport(report) {
    const outArea = document.getElementById("huntResultsArea");
    const m = report.meta || {};
    const syn = report.intelligence_synthesis || {};
    const idC = syn.identity_cluster || {};
    const infC = syn.infrastructure_cluster || {};
    const tprof = report.temporal_profile || {};
    const pconf = report.persona_and_confidence || {};

    const isAct = m.opsec_mode === "Active+Passive";
    const score = syn.exposure_score ?? 0;
    const scoreClass = score >= 65 ? "red" : score >= 35 ? "amber" : "green";
    const tzKeys = Object.keys(tprof.inferred_timezone_offsets || {});
    const sleepWin = tprof.estimated_sleep_window_utc?.sleep_window_utc;

    const svg = renderEntityGraphSvg(report.graph);
    const uniqueStages = [...new Set((report.graph.nodes || []).map((n) => n.wave || 1))].sort((a, b) => a - b);
    const uniqueTypes = [...new Set((report.graph.nodes || []).map((n) => n.type))].sort();
    const nodeOptions = (report.graph.nodes || [])
      .map((n) => `<option value="${esc(n.id)}">${esc(n.type)}: ${esc(n.value.slice(0, 34))}</option>`)
      .join("");

    // Group findings cleanly: show positive matches prominently, collapse empty checks
    const findingsHtml = (report.wave_results || [])
      .map((w) => {
        const hits = (w.collector_outputs || []).filter((c) => c.status === "ok");
        const emptyCnt = (w.collector_outputs || []).length - hits.length;
        return `
          <div class="card">
            <div class="card-header" style="margin-bottom:${hits.length ? "8px" : "0"};">
              <div>
                <span class="status-pill">Stage ${w.wave}</span>
                <strong style="margin-left:8px; font-size:14.5px;">${esc(w.value)}</strong>
                <span style="color:var(--text-dim); font-size:12.5px; margin-left:6px;">${esc(w.type)}</span>
              </div>
              <span style="font-size:12px; color:var(--text-muted);">${hits.length} match${hits.length === 1 ? "" : "es"}${emptyCnt ? ` · ${emptyCnt} empty` : ""}</span>
            </div>
            ${
              hits.length
                ? hits
                    .map(
                      (c) => `
                  <div class="finding-row">
                    <div style="display:flex; justify-content:space-between; gap:8px; align-items:baseline;">
                      <div>
                        <strong style="font-size:13px;">${esc(prettyKey(c.module))}</strong>
                        ${c.opsec === "Active" ? `<span class="status-pill red" style="margin-left:6px;">Active</span>` : ""}
                        <div style="color:var(--text-muted); font-size:13px; margin-top:2px;">${esc(c.summary)}</div>
                      </div>
                    </div>
                    ${
                      c.data && Object.keys(c.data).length
                        ? `<details style="margin-top:6px;"><summary style="cursor:pointer; font-size:12px; color:var(--text-dim);">Details</summary><div class="pre-box">${esc(
                            JSON.stringify(c.data, null, 2)
                          )}</div></details>`
                        : ""
                    }
                  </div>`
                    )
                    .join("")
                : `<div style="font-size:13px; color:var(--text-dim); margin-top:6px;">No public records matched for this selector.</div>`
            }
          </div>`;
      })
      .join("");

    outArea.innerHTML = `
      <!-- Clean Header Bar -->
      <div class="card" style="display:flex; flex-wrap:wrap; justify-content:space-between; align-items:center; gap:12px;">
        <div>
          <div style="display:flex; align-items:center; gap:8px; flex-wrap:wrap;">
            <strong style="font-size:16px;">${esc(m.raw_input)}</strong>
            <span class="status-pill ${isAct ? "red" : "green"}">${isAct ? "Active + Passive" : "Passive"}</span>
            <span class="status-pill ${scoreClass}">Exposure ${esc(score)}/100</span>
          </div>
          <div style="font-size:12.5px; color:var(--text-muted); margin-top:4px;">
            ${report.graph.nodes.length} entities · ${report.graph.edges.length} connections · ${esc(m.stages_executed || m.depth)} stage(s) in ${esc(m.duration_seconds)}s
          </div>
        </div>

        <div style="display:flex; gap:8px; align-items:center; flex-wrap:wrap;">
          ${!isAct ? `<button class="btn" id="escalateActiveBtn">Run Active Scan...</button>` : ""}
          <div class="dropdown" id="exportDropdown">
            <button class="btn" id="exportMenuBtn">Export ▾</button>
            <div class="dropdown-menu">
              ${m.case_id ? `<a class="dropdown-item" href="./api/cases/${encodeURIComponent(m.case_id)}/html" target="_blank" rel="noopener">Printable Report <span>HTML</span></a>` : ""}
              <button class="dropdown-item" id="dlDossierMd">Summary Dossier <span>.md</span></button>
              <button class="dropdown-item" id="dlEntitiesCsv">Spreadsheet <span>.csv</span></button>
              <button class="dropdown-item" id="dlGexfBtn">Gephi Graph <span>.gexf</span></button>
              <button class="dropdown-item" id="dlGraphmlBtn">GraphML <span>.graphml</span></button>
              <button class="dropdown-item" id="dlCypherBtn">Neo4j Import <span>.cypher</span></button>
              ${m.case_id ? `<a class="dropdown-item" href="./api/cases/${encodeURIComponent(m.case_id)}/obsidian.zip" download="${esc(m.case_id)}-obsidian.zip">Obsidian Vault <span>.zip</span></a>` : ""}
              <button class="dropdown-item" id="dlStixJson">STIX 2.1 Bundle <span>.json</span></button>
              <button class="dropdown-item" id="dlFullJson">Raw Telemetry <span>.json</span></button>
            </div>
          </div>
        </div>
      </div>

      ${
        report.surface_delta
          ? `<div class="card" style="border-color:rgba(245,158,11,0.35);">
              <strong style="font-size:13.5px;">Changes since previous run (${esc(report.surface_delta.baseline_case_id)}):</strong>
              <span style="color:var(--text-muted); margin-left:6px;">
                +${esc(report.surface_delta.added_entity_count)} new, -${esc(report.surface_delta.removed_entity_count)} removed · Score ${esc(report.surface_delta.exposure_score_before)} → ${esc(report.surface_delta.exposure_score_after)}
              </span>
            </div>`
          : ""
      }

      <!-- Clean 3-Column Overview -->
      <div class="grid-3">
        <div class="card" style="margin-bottom:0;">
          <div class="card-title" style="margin-bottom:10px;">Identity &amp; Accounts</div>
          <div class="kv-list">
            <div class="kv-row"><span class="kv-key">Names / Orgs</span><span class="kv-val">${esc([...(idC.person_names || []), ...(idC.organizations || [])].slice(0, 4).join(", ") || "—")}</span></div>
            <div class="kv-row"><span class="kv-key">Handles</span><span class="kv-val">${esc((idC.usernames_and_variants || []).slice(0, 6).join(", ") || "—")}</span></div>
            <div class="kv-row"><span class="kv-key">Emails</span><span class="kv-val">${esc((idC.emails || []).slice(0, 4).join(", ") || "—")}</span></div>
            <div class="kv-row"><span class="kv-key">Phones</span><span class="kv-val">${esc((idC.phones || []).map((p) => p.e164 || p).slice(0, 3).join(", ") || "—")}</span></div>
          </div>
        </div>

        <div class="card" style="margin-bottom:0;">
          <div class="card-title" style="margin-bottom:10px;">Domains &amp; Network</div>
          <div class="kv-list">
            <div class="kv-row"><span class="kv-key">Domains</span><span class="kv-val">${esc((infC.domains_and_subdomains || []).slice(0, 5).join(", ") || "—")}</span></div>
            <div class="kv-row"><span class="kv-key">IPs / ASNs</span><span class="kv-val">${esc([...(infC.ip_addresses || []), ...(infC.asns || [])].slice(0, 4).join(", ") || "—")}</span></div>
            <div class="kv-row"><span class="kv-key">Locations</span><span class="kv-val">${esc((idC.locations || []).slice(0, 4).join(", ") || "—")}</span></div>
          </div>
        </div>

        <div class="card" style="margin-bottom:0;">
          <div class="card-title" style="margin-bottom:10px;">Signals &amp; Activity</div>
          <div class="kv-list">
            <div class="kv-row"><span class="kv-key">Timezone</span><span class="kv-val">${esc(tzKeys.join(", ") || (sleepWin ? `Quiet ${sleepWin}` : "—"))}</span></div>
            <div class="kv-row"><span class="kv-key">Key Links</span><span class="kv-val">${esc(String((pconf.attribution_chains || []).length || (syn.cross_entity_attribution_bridges || []).length || 0))}</span></div>
            <div class="kv-row"><span class="kv-key">Security Notes</span><span class="kv-val">${esc((syn.security_and_opsec_exposures || [])[0] || "None flagged")}</span></div>
          </div>
        </div>
      </div>

      <!-- Clean Graph Card -->
      <div class="card">
        <div class="card-header">
          <div>
            <span class="card-title">Relationship Graph</span>
            <span style="color:var(--text-dim); font-size:12px; margin-left:8px;">Drag to pan · Scroll to zoom · Click any node to investigate</span>
          </div>
          <div style="display:flex; gap:6px; flex-wrap:wrap; align-items:center;">
            <select id="graphStageFilter" class="ctrl-select">
              <option value="">All stages</option>
              ${uniqueStages.map((s) => `<option value="${s}">Stage ${s}</option>`).join("")}
            </select>
            <select id="graphTypeFilter" class="ctrl-select">
              <option value="">All types</option>
              ${uniqueTypes.map((t) => `<option value="${esc(t)}">${esc(t)}</option>`).join("")}
            </select>
            <button class="btn" id="graphResetViewBtn">Reset</button>
          </div>
        </div>

        ${
          report.graph.nodes.length > 1
            ? `<details style="margin-bottom:10px;">
                <summary style="cursor:pointer; font-size:12.5px; color:var(--text-muted);">Trace connection path between two entities</summary>
                <div style="display:flex; gap:8px; flex-wrap:wrap; align-items:center; margin-top:8px;">
                  <select id="pathSrcSelect" class="ctrl-select" style="max-width:220px;">${nodeOptions}</select>
                  <span style="color:var(--text-dim);">→</span>
                  <select id="pathDstSelect" class="ctrl-select" style="max-width:220px;">${nodeOptions}</select>
                  <button class="btn" id="tracePathBtn">Highlight Path</button>
                  <span id="tracePathResult" style="font-size:12.5px; color:#fcd34d;"></span>
                </div>
              </details>`
            : ""
        }

        <div id="graphSvgViewport" class="graph-canvas">${svg}</div>
      </div>

      <!-- Findings -->
      ${findingsHtml}

      <!-- Optional Case Expansion -->
      ${
        m.case_id
          ? `<div class="card">
              <div class="card-title" style="margin-bottom:6px;">Add More Clues</div>
              <div style="color:var(--text-muted); font-size:12.5px; margin-bottom:10px;">Paste a bio, Linktree, webpage text, or notes to extract new leads and continue this investigation.</div>
              <div style="display:flex; gap:8px; flex-wrap:wrap;">
                <input type="text" id="expandCaseTextInput" class="ctrl-input" style="flex:1; min-width:240px; padding:8px 12px;" placeholder="Paste additional text or links..." />
                <button class="btn" id="expandCaseBtn">Expand Case</button>
              </div>
            </div>`
          : ""
      }
    `;

    // Bind Export dropdown
    const expDd = document.getElementById("exportDropdown");
    document.getElementById("exportMenuBtn")?.addEventListener("click", (e) => {
      e.stopPropagation();
      expDd?.classList.toggle("open");
    });

    document.getElementById("escalateActiveBtn")?.addEventListener("click", () =>
      openActiveAuthorizationModal(m.raw_input, m.case_id)
    );
    document.getElementById("dlDossierMd")?.addEventListener("click", () =>
      downloadBlob(`${m.case_id}-dossier.md`, report.dossier_markdown, "text/markdown;charset=utf-8")
    );
    document.getElementById("dlEntitiesCsv")?.addEventListener("click", () =>
      downloadBlob(`${m.case_id}-entities.csv`, report.entities_csv || "", "text/csv;charset=utf-8")
    );
    document.getElementById("dlStixJson")?.addEventListener("click", () =>
      downloadBlob(`${m.case_id}-stix2.json`, JSON.stringify(report.stix2_bundle, null, 2), "application/json")
    );
    document.getElementById("dlFullJson")?.addEventListener("click", () =>
      downloadBlob(`${m.case_id}-report.json`, JSON.stringify(report, null, 2), "application/json")
    );

    const fetchAndDl = (btnId, prop, endpoint, ext, mime) => {
      document.getElementById(btnId)?.addEventListener("click", async () => {
        if (report[prop]) {
          downloadBlob(`${m.case_id}.${ext}`, report[prop], mime);
        } else if (m.case_id) {
          const r = await fetch(`./api/cases/${encodeURIComponent(m.case_id)}/${endpoint}`);
          if (r.ok) downloadBlob(`${m.case_id}.${ext}`, await r.text(), mime);
        }
      });
    };
    fetchAndDl("dlGexfBtn", "gexf_xml", "gexf", "gexf", "application/xml;charset=utf-8");
    fetchAndDl("dlGraphmlBtn", "graphml_xml", "graphml", "graphml", "application/xml;charset=utf-8");
    fetchAndDl("dlCypherBtn", "neo4j_cypher", "cypher", "cypher", "text/plain;charset=utf-8");

    // Expand case handler
    const expBtn = document.getElementById("expandCaseBtn");
    expBtn?.addEventListener("click", async () => {
      const txt = (document.getElementById("expandCaseTextInput")?.value || "").trim();
      if (!txt) return;
      expBtn.disabled = true;
      expBtn.textContent = "Expanding...";
      try {
        const r = await fetch("./api/cases/expand", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ case_id: m.case_id, ingested_text: txt, additional_stages: 3 }),
        });
        const nextRep = await r.json();
        if (!r.ok || nextRep.error) throw new Error(nextRep.error || `HTTP ${r.status}`);
        lastHuntReport = nextRep;
        renderHuntReport(nextRep);
      } catch (e) {
        expBtn.textContent = "Expand failed";
        expBtn.disabled = false;
      }
    });

    // Graph Pan/Zoom/Filter
    let gScale = 1, gPanX = 0, gPanY = 0;
    let hiEdgeSet = new Set(), hiNodeSet = new Set();

    function applyTransform() {
      const grp = document.getElementById("graphViewportGroup");
      if (grp) grp.setAttribute("transform", `translate(${gPanX}, ${gPanY}) scale(${gScale})`);
    }

    function bindSvg() {
      const svgEl = document.getElementById("interactiveGraphSvg");
      if (!svgEl) return;
      svgEl.querySelectorAll("[data-rehunt]").forEach((g) => {
        g.addEventListener("click", () => {
          document.getElementById("huntTargetInput").value = g.dataset.rehunt;
          executeLiveHunt();
        });
      });
      let dragging = false, sx = 0, sy = 0;
      svgEl.addEventListener("mousedown", (ev) => {
        if (ev.target.closest(".svg-node")) return;
        dragging = true;
        sx = ev.clientX - gPanX;
        sy = ev.clientY - gPanY;
      });
      window.addEventListener("mousemove", (ev) => {
        if (!dragging) return;
        gPanX = ev.clientX - sx;
        gPanY = ev.clientY - sy;
        applyTransform();
      });
      window.addEventListener("mouseup", () => { dragging = false; });
      svgEl.addEventListener("wheel", (ev) => {
        ev.preventDefault();
        gScale = Math.min(3, Math.max(0.5, gScale * (ev.deltaY < 0 ? 1.1 : 0.9)));
        applyTransform();
      }, { passive: false });
      applyTransform();
    }

    function refreshSvg() {
      const vp = document.getElementById("graphSvgViewport");
      if (!vp) return;
      vp.innerHTML = renderEntityGraphSvg(report.graph, {
        stage: document.getElementById("graphStageFilter")?.value || "",
        type: document.getElementById("graphTypeFilter")?.value || "",
        highlightPathSet: hiEdgeSet,
        highlightNodeSet: hiNodeSet,
      });
      bindSvg();
    }

    document.getElementById("graphStageFilter")?.addEventListener("change", refreshSvg);
    document.getElementById("graphTypeFilter")?.addEventListener("change", refreshSvg);
    document.getElementById("graphResetViewBtn")?.addEventListener("click", () => {
      gScale = 1; gPanX = 0; gPanY = 0;
      hiEdgeSet = new Set(); hiNodeSet = new Set();
      refreshSvg();
    });

    const dstSel = document.getElementById("pathDstSelect");
    if (dstSel && dstSel.options.length > 1) dstSel.selectedIndex = dstSel.options.length - 1;
    document.getElementById("tracePathBtn")?.addEventListener("click", async () => {
      const sId = document.getElementById("pathSrcSelect")?.value;
      const tId = document.getElementById("pathDstSelect")?.value;
      const resSpan = document.getElementById("tracePathResult");
      if (!sId || !tId) return;
      const r = await fetch("./api/graph/path", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ nodes: report.graph.nodes, edges: report.graph.edges, source: sId, target: tId }),
      });
      const d = await r.json();
      hiEdgeSet = new Set(); hiNodeSet = new Set();
      if (d.path?.steps) {
        hiNodeSet.add(sId);
        d.path.steps.forEach((st) => {
          hiEdgeSet.add(`${st.from}|${st.to}`);
          hiNodeSet.add(st.to);
        });
        if (resSpan) resSpan.textContent = `${d.path.hops} step(s) · ${Math.round(d.path.joint_confidence * 100)}% confidence`;
      } else if (resSpan) {
        resSpan.textContent = "No path between those entities";
      }
      refreshSvg();
    });

    bindSvg();
    refreshCasesBadgeCount();
  }

  // ── Investigate Input & File Drop Wiring ───────────────────────────────────
  function initInvestigateControls() {
    const huntInput = document.getElementById("huntTargetInput");
    const detectedRow = document.getElementById("liveDetectedRow");
    const shell = document.getElementById("hunterDropzone");
    const fileIn = document.getElementById("hunterFileInput");

    let detectTimer = null;
    huntInput.addEventListener("input", () => {
      clearTimeout(detectTimer);
      const val = huntInput.value.trim();
      if (!val) {
        detectedRow.style.display = "none";
        detectedRow.innerHTML = "";
        return;
      }
      detectTimer = setTimeout(async () => {
        try {
          const r = await fetch("./api/detect", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ input: val }),
          });
          if (!r.ok) return;
          const d = await r.json();
          const sels = d.selectors || [];
          if (sels.length) {
            detectedRow.style.display = "block";
            detectedRow.innerHTML = "Detected: " + sels.map((s) => `<code>${esc(s.type)}: ${esc(s.value)}</code>`).join(" ");
          } else {
            detectedRow.style.display = "none";
          }
        } catch (_) {}
      }, 180);
    });

    huntInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        executeLiveHunt();
      }
    });
    document.getElementById("launchHuntBtn").addEventListener("click", executeLiveHunt);

    document.querySelectorAll("[data-hunt-preset]").forEach((btn) => {
      btn.addEventListener("click", () => {
        huntInput.value = btn.dataset.huntPreset;
        executeLiveHunt();
      });
    });

    async function handleFileHunt(file) {
      if (!file) return;
      const outArea = document.getElementById("huntResultsArea");
      const depth = parseInt(document.getElementById("huntDepthSelect")?.value || "4", 10);
      const diffLast = Boolean(document.getElementById("huntDiffLastCheck")?.checked);
      outArea.innerHTML = `<div class="card" style="text-align:center; padding:32px; color:var(--text-muted);">Extracting leads from <code>${esc(file.name)}</code> and investigating...</div>`;
      try {
        const b64 = await fileToBase64(file);
        const r = await fetch("./api/hunt/file", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ filename: file.name, content_base64: b64, depth, diff_last: diffLast }),
        });
        const rep = await r.json();
        if (!r.ok || rep.error) throw new Error(rep.error || `HTTP ${r.status}`);
        lastHuntReport = rep;
        renderHuntReport(rep);
      } catch (err) {
        outArea.innerHTML = `<div class="card"><div class="card-title" style="color:#fca5a5;">Could not analyze file</div><p style="color:var(--text-muted);">${esc(err.message)}</p></div>`;
      }
    }

    document.getElementById("pickHuntFileBtn")?.addEventListener("click", () => fileIn.click());
    fileIn?.addEventListener("change", () => { if (fileIn.files?.[0]) handleFileHunt(fileIn.files[0]); });
    shell?.addEventListener("dragover", (e) => { e.preventDefault(); shell.classList.add("drag-over"); });
    shell?.addEventListener("dragleave", () => shell.classList.remove("drag-over"));
    shell?.addEventListener("drop", (e) => {
      e.preventDefault();
      shell.classList.remove("drag-over");
      if (e.dataTransfer?.files?.[0]) handleFileHunt(e.dataTransfer.files[0]);
    });

    document.getElementById("activeAuthBackdrop")?.addEventListener("click", (e) => {
      if (e.target.id === "activeAuthBackdrop") e.target.classList.remove("open");
    });
  }

  // ── Clean Offline Decoder View ─────────────────────────────────────────────
  function renderCleanDecodeCards(items, outEl, sourceText) {
    if (!items.length) {
      outEl.innerHTML = `<div class="card" style="text-align:center; color:var(--text-muted);">No known timestamp, checksum, or file structure matched that input.</div>`;
      return;
    }

    outEl.innerHTML = items
      .map((a) => {
        const scalarRows = Object.entries(a)
          .filter(([k, v]) => k !== "decoder" && (typeof v === "string" || typeof v === "number" || typeof v === "boolean"))
          .map(
            ([k, v]) =>
              `<div class="kv-row"><span class="kv-key">${esc(prettyKey(k))}</span><span class="kv-val"><code>${esc(v)}</code></span></div>`
          )
          .join("");

        return `
          <div class="card">
            <div class="card-header">
              <div>
                <span class="status-pill green">Offline Decode</span>
                <strong style="margin-left:8px; font-size:15px;">${esc(prettyKey(a.decoder || "Artifact"))}</strong>
              </div>
              ${sourceText ? `<button class="btn" data-investigate-decoded="${esc(sourceText)}">Investigate Target →</button>` : ""}
            </div>
            ${scalarRows ? `<div class="kv-list" style="margin-bottom:10px;">${scalarRows}</div>` : ""}
            <details>
              <summary style="cursor:pointer; font-size:12px; color:var(--text-dim);">Full decoded output</summary>
              <div class="pre-box">${esc(JSON.stringify(a, null, 2))}</div>
            </details>
          </div>`;
      })
      .join("");

    outEl.querySelectorAll("[data-investigate-decoded]").forEach((b) => {
      b.onclick = () => {
        document.getElementById("huntTargetInput").value = b.dataset.investigateDecoded;
        switchView("investigate");
        executeLiveHunt();
      };
    });
  }

  function initDecoderControls() {
    const inp = document.getElementById("forensicDecodeInput");
    const btn = document.getElementById("runDecodeBtn");
    const out = document.getElementById("forensicDecodeResults");
    const shell = document.getElementById("decoderDropzone");
    const fileIn = document.getElementById("decoderFileInput");

    async function runDecode() {
      const payload = inp.value.trim();
      if (!payload) { inp.focus(); return; }
      btn.disabled = true;
      btn.textContent = "Decoding...";
      try {
        const r = await fetch("./api/decode", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ payload }),
        });
        const data = await r.json();
        if (!r.ok || data.error) throw new Error(data.error || `HTTP ${r.status}`);
        renderCleanDecodeCards(data.results || [], out, payload);
      } catch (err) {
        out.innerHTML = `<div class="card" style="color:#fca5a5;">Decode error: ${esc(err.message)}</div>`;
      } finally {
        btn.disabled = false;
        btn.textContent = "Decode";
      }
    }

    async function runFileDecode(file) {
      if (!file) return;
      out.innerHTML = `<div class="card" style="text-align:center; color:var(--text-muted);">Inspecting <code>${esc(file.name)}</code> locally...</div>`;
      try {
        const b64 = await fileToBase64(file);
        const r = await fetch("./api/decode/file", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ filename: file.name, content_base64: b64 }),
        });
        const data = await r.json();
        if (!r.ok || data.error) throw new Error(data.error || `HTTP ${r.status}`);
        renderCleanDecodeCards(data.results || [], out, "");
      } catch (err) {
        out.innerHTML = `<div class="card" style="color:#fca5a5;">File inspection error: ${esc(err.message)}</div>`;
      }
    }

    btn.addEventListener("click", runDecode);
    inp.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); runDecode(); } });
    document.querySelectorAll("[data-decode-preset]").forEach((p) => {
      p.addEventListener("click", () => { inp.value = p.dataset.decodePreset; runDecode(); });
    });

    document.getElementById("pickDecodeFileBtn")?.addEventListener("click", () => fileIn.click());
    fileIn?.addEventListener("change", () => { if (fileIn.files?.[0]) runFileDecode(fileIn.files[0]); });
    shell?.addEventListener("dragover", (e) => { e.preventDefault(); shell.classList.add("drag-over"); });
    shell?.addEventListener("dragleave", () => shell.classList.remove("drag-over"));
    shell?.addEventListener("drop", (e) => {
      e.preventDefault();
      shell.classList.remove("drag-over");
      if (e.dataTransfer?.files?.[0]) runFileDecode(e.dataTransfer.files[0]);
    });
  }

  // ── Saved Cases, Compare & Watchlist ───────────────────────────────────────
  async function refreshCasesBadgeCount() {
    try {
      const r = await fetch("./api/cases");
      if (!r.ok) return;
      const d = await r.json();
      const el = document.getElementById("navCntCases");
      if (el && Array.isArray(d.cases)) el.textContent = String(d.cases.length);
    } catch (_) {}
  }

  async function renderCasesVault() {
    const listEl = document.getElementById("savedCasesList");
    const selA = document.getElementById("caseSelectA");
    const selB = document.getElementById("caseSelectB");
    if (!listEl) return;

    try {
      const r = await fetch("./api/cases");
      const d = await r.json();
      const cases = d.cases || [];
      document.getElementById("navCntCases").textContent = String(cases.length);

      const opts = cases
        .map((c) => `<option value="${esc(c.case_id)}">${esc(c.raw_input.slice(0, 32))} (${esc(c.case_id.slice(0, 16))})</option>`)
        .join("");
      if (selA) selA.innerHTML = `<option value="">Baseline case...</option>${opts}`;
      if (selB) {
        selB.innerHTML = `<option value="">Second case...</option>${opts}`;
        if (cases.length >= 2) { selA.selectedIndex = 2; selB.selectedIndex = 1; }
      }

      if (!cases.length) {
        listEl.innerHTML = `<div class="card" style="text-align:center; padding:32px; color:var(--text-muted);">No saved cases yet. Run any investigation to save it automatically.</div>`;
        return;
      }

      listEl.innerHTML = `<div class="grid-2">${cases
        .map(
          (c) => `
          <div class="card" style="margin-bottom:0;">
            <div style="display:flex; justify-content:space-between; align-items:center; gap:8px; margin-bottom:6px;">
              <strong style="font-size:15px;">${esc(c.raw_input)}</strong>
              <span class="status-pill ${c.opsec_mode === "Active+Passive" ? "red" : "green"}">${esc(c.opsec_mode)}</span>
            </div>
            <div style="font-size:12.5px; color:var(--text-muted); margin-bottom:12px;">
              ${esc(c.timestamp_utc)} · ${c.nodes} entities · Score ${esc(c.exposure_score ?? 0)}/100
            </div>
            <div style="display:flex; gap:8px; flex-wrap:wrap;">
              <button class="btn" data-open-case="${esc(c.case_id)}">Open</button>
              <a class="btn" href="./api/cases/${encodeURIComponent(c.case_id)}/html" target="_blank" rel="noopener">HTML Report ↗</a>
              <a class="btn" href="./api/cases/${encodeURIComponent(c.case_id)}/obsidian.zip" download="${esc(c.case_id)}-obsidian.zip">Obsidian .zip</a>
            </div>
          </div>`
        )
        .join("")}</div>`;

      listEl.querySelectorAll("[data-open-case]").forEach((btn) => {
        btn.onclick = async () => {
          const cr = await fetch(`./api/cases/${encodeURIComponent(btn.dataset.openCase)}`);
          const rep = await cr.json();
          if (cr.ok && !rep.error) {
            lastHuntReport = rep;
            switchView("investigate");
            renderHuntReport(rep);
          }
        };
      });
    } catch (err) {
      listEl.innerHTML = `<div class="card" style="color:#fca5a5;">Could not load cases: ${esc(err.message)}</div>`;
    }
  }

  function initCaseVaultControls() {
    document.getElementById("refreshCasesBtn")?.addEventListener("click", renderCasesVault);
    const outBox = document.getElementById("caseComparisonOutput");

    document.getElementById("runCaseCompareBtn")?.addEventListener("click", async () => {
      const ca = document.getElementById("caseSelectA")?.value;
      const cb = document.getElementById("caseSelectB")?.value;
      if (!ca || !cb || !outBox) return;
      const r = await fetch("./api/cases/compare", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ case_a: ca, case_b: cb }),
      });
      const d = await r.json();
      outBox.innerHTML = `<div class="card"><div class="card-title">${d.cases_linked ? "Shared links found between cases" : "No shared entities found"}</div><div class="pre-box">${esc(JSON.stringify(d, null, 2))}</div></div>`;
    });

    document.getElementById("runCaseDiffBtn")?.addEventListener("click", async () => {
      const ca = document.getElementById("caseSelectA")?.value;
      const cb = document.getElementById("caseSelectB")?.value;
      if (!ca || !cb || !outBox) return;
      const r = await fetch("./api/cases/diff", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ baseline_case: ca, current_case: cb }),
      });
      const d = await r.json();
      outBox.innerHTML = `<div class="card"><div class="card-title">Surface Changes: +${esc(d.added_entity_count ?? 0)} added, -${esc(d.removed_entity_count ?? 0)} removed</div><div class="pre-box">${esc(JSON.stringify(d, null, 2))}</div></div>`;
    });

    document.getElementById("runTyposquatBtn")?.addEventListener("click", async () => {
      const dom = document.getElementById("typosquatDomainInput")?.value.trim();
      if (!dom || !outBox) return;
      const r = await fetch("./api/typosquats", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: dom, limit: 40 }),
      });
      const d = await r.json();
      const list = (d.permutations || []).map((p) => `${p.domain}${p.unicode_lookalike ? ` (${p.unicode_lookalike})` : ""}  —  ${p.fuzzer}`).join("\n");
      outBox.innerHTML = `<div class="card"><div class="card-title">${esc(d.count || 0)} Lookalike Domains for ${esc(d.seed_domain || dom)}</div><div class="pre-box">${esc(list)}</div></div>`;
    });

    async function refreshWatchlist() {
      const el = document.getElementById("watchlistItemsArea");
      if (!el) return;
      try {
        const r = await fetch("./api/watchlist");
        const d = await r.json();
        const items = d.watchlist || [];
        if (!items.length) { el.textContent = "No targets on watchlist."; return; }
        el.innerHTML = items
          .map(
            (i) =>
              `<span class="status-pill" style="margin:2px 4px 2px 0;">${esc(i.target)} <button type="button" data-rm-wl="${esc(i.target)}" style="background:none;border:none;color:var(--text-muted);cursor:pointer;padding:0 2px;">✕</button></span>`
          )
          .join("");
        el.querySelectorAll("[data-rm-wl]").forEach((b) => {
          b.onclick = async () => {
            await fetch("./api/watchlist/remove", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ target: b.dataset.rmWl }),
            });
            refreshWatchlist();
          };
        });
      } catch (_) {}
    }

    document.getElementById("addWatchlistBtn")?.addEventListener("click", async () => {
      const inp = document.getElementById("watchlistTargetInput");
      const tgt = inp?.value.trim();
      if (!tgt) return;
      await fetch("./api/watchlist/add", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: tgt, depth: 3 }),
      });
      inp.value = "";
      refreshWatchlist();
    });

    document.getElementById("runWatchlistSweepBtn")?.addEventListener("click", async (ev) => {
      const btn = ev.currentTarget;
      btn.disabled = true;
      btn.textContent = "Running...";
      try {
        const r = await fetch("./api/watchlist/run", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({}),
        });
        const d = await r.json();
        outBox.innerHTML = `<div class="card"><div class="card-title">Watchlist Sweep Complete (${esc(d.swept_count || 0)} target(s))</div><div class="pre-box">${esc(JSON.stringify(d.results || d, null, 2))}</div></div>`;
        renderCasesVault();
      } finally {
        btn.disabled = false;
        btn.textContent = "Run All";
      }
    });

    refreshWatchlist();
    refreshCasesBadgeCount();
  }

  // ── Unified Directory (Tools, Dorks, Playbooks, Retired) ───────────────────
  function initDirectoryControls() {
    const catSel = document.getElementById("categorySelect");
    DB.categories.forEach((c) => {
      const o = document.createElement("option");
      o.value = c.id;
      o.textContent = c.short_title;
      catSel.appendChild(o);
    });

    const inputs = [...new Set(DB.tools.flatMap((t) => t.inputs))].sort();
    const inSel = document.getElementById("inputSelectorSelect");
    inputs.forEach((inp) => {
      const o = document.createElement("option");
      o.value = inp;
      o.textContent = `Evidence: ${prettyKey(inp)}`;
      inSel.appendChild(o);
    });

    const engines = [...new Set(DB.dorks.map((d) => d.engine))];
    const engSel = document.getElementById("dorkEngineSelect");
    engines.forEach((eng) => {
      const o = document.createElement("option");
      o.value = eng;
      o.textContent = eng;
      engSel.appendChild(o);
    });

    document.querySelectorAll("#dirSubTabs .seg-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        state.dirSubview = btn.dataset.subview;
        document.querySelectorAll("#dirSubTabs .seg-btn").forEach((b) => b.classList.toggle("active", b === btn));
        ["tools", "dorks", "playbooks", "retired"].forEach((k) => {
          document.getElementById(`dir-${k}`).style.display = k === state.dirSubview ? "block" : "none";
        });
        renderDirectory();
      });
    });

    document.getElementById("searchInput").addEventListener("input", (e) => { state.query = e.target.value; renderTools(); });
    catSel.addEventListener("change", (e) => { state.category = e.target.value; renderTools(); });
    inSel.addEventListener("change", (e) => { state.inputSelector = e.target.value; renderTools(); });

    const bindChip = (id, key) => {
      const el = document.getElementById(id);
      el.addEventListener("click", () => {
        state[key] = !state[key];
        el.classList.toggle("active", state[key]);
        renderTools();
      });
    };
    bindChip("togPassive", "passiveOnly");
    bindChip("togFree", "freeOnly");
    bindChip("togNoAuth", "noAuthOnly");

    document.getElementById("dorkTargetInput").addEventListener("input", (e) => { state.dorkTarget = e.target.value; renderDorks(); });
    engSel.addEventListener("change", (e) => { state.dorkEngine = e.target.value; renderDorks(); });
    document.getElementById("dorkSearchInput").addEventListener("input", (e) => { state.dorkQuery = e.target.value; renderDorks(); });

    document.getElementById("toolModalBackdrop").addEventListener("click", (e) => {
      if (e.target.id === "toolModalBackdrop") e.target.classList.remove("open");
    });
  }

  function openToolModal(tid) {
    const t = toolsById.get(tid);
    if (!t) return;
    const cat = catsById.get(t.category);
    const backdrop = document.getElementById("toolModalBackdrop");
    const box = document.getElementById("toolModalContent");
    box.innerHTML = `
      <div style="display:flex; justify-content:space-between; align-items:flex-start; gap:12px; margin-bottom:10px;">
        <div>
          <h3 style="margin:0; font-size:18px;">${esc(t.name)}</h3>
          <div style="color:var(--text-muted); font-size:12.5px; margin-top:3px;">${esc(cat ? cat.short_title : t.category)} · ${esc(t.type)} · ${esc(t.pricing)}</div>
        </div>
        <button class="btn-ghost" id="closeToolModalBtn">✕</button>
      </div>
      <p style="color:var(--text); margin:10px 0 14px;">${esc(t.description)}</p>
      <div class="kv-list" style="margin-bottom:14px;">
        <div class="kv-row"><span class="kv-key">OPSEC Mode</span><span class="kv-val">${esc(t.opsec)}</span></div>
        <div class="kv-row"><span class="kv-key">Takes Input</span><span class="kv-val">${esc(t.inputs.join(", "))}</span></div>
        <div class="kv-row"><span class="kv-key">Produces</span><span class="kv-val">${esc(t.outputs.join(", "))}</span></div>
      </div>
      <div style="font-size:12px; color:var(--text-muted); margin-bottom:4px;">Quick start</div>
      <div class="pre-box" style="margin-top:0; margin-bottom:16px;">${esc(t.quick_start)}</div>
      <div style="display:flex; justify-content:flex-end; gap:8px;">
        <button class="btn" id="copyModalCmd">Copy Command</button>
        <a class="btn" href="${esc(t.url)}" target="_blank" rel="noopener noreferrer" style="background:#f8fafc; color:#090a0f; border:none; font-weight:600;">Open Website ↗</a>
      </div>
    `;
    backdrop.classList.add("open");
    document.getElementById("closeToolModalBtn").onclick = () => backdrop.classList.remove("open");
    document.getElementById("copyModalCmd").onclick = function () { copyText(t.quick_start, this); };
  }

  function renderTools() {
    const terms = state.query.trim().toLowerCase().split(/\s+/).filter(Boolean);
    const tierRank = { S: 0, A: 1, B: 2 };

    const list = DB.tools
      .filter((t) => {
        if (state.category && t.category !== state.category) return false;
        if (state.inputSelector && !t.inputs.includes(state.inputSelector)) return false;
        if (state.passiveOnly && t.opsec !== "Passive") return false;
        if (state.freeOnly && t.pricing !== "Free / Open Source" && t.pricing !== "Free") return false;
        if (state.noAuthOnly && t.auth_required) return false;
        if (terms.length) {
          const hay = `${t.name} ${t.description} ${t.tags.join(" ")} ${t.inputs.join(" ")} ${t.outputs.join(" ")}`.toLowerCase();
          if (!terms.every((w) => hay.includes(w))) return false;
        }
        return true;
      })
      .sort((a, b) => tierRank[a.tier] - tierRank[b.tier] || a.name.localeCompare(b.name));

    document.getElementById("dirSummaryLabel").textContent = `${list.length} of ${DB.tools.length} tools`;
    const grid = document.getElementById("toolsContainer");
    grid.innerHTML = list
      .slice(0, 120)
      .map(
        (t) => `
      <div class="card" style="margin-bottom:0; display:flex; flex-direction:column; justify-content:space-between;">
        <div>
          <div style="display:flex; justify-content:space-between; align-items:center; gap:8px; margin-bottom:6px;">
            <strong style="font-size:14.5px; cursor:pointer;" data-open-tool="${esc(t.id)}">${esc(t.name)}</strong>
            <span class="status-pill ${t.opsec === "Passive" ? "green" : t.opsec === "Hybrid" ? "amber" : "red"}">${esc(t.opsec)}</span>
          </div>
          <p style="margin:0 0 12px; color:var(--text-muted); font-size:13px;">${esc(t.description)}</p>
        </div>
        <div style="display:flex; justify-content:space-between; align-items:center; gap:8px; padding-top:10px; border-top:1px solid var(--border); font-size:12px; color:var(--text-dim);">
          <span>${esc(t.pricing)}${t.auth_required ? " · Login" : " · No login"}</span>
          <div style="display:flex; gap:6px;">
            <button class="btn" data-open-tool="${esc(t.id)}">Details</button>
            <a class="btn" href="${esc(t.url)}" target="_blank" rel="noopener noreferrer">Open ↗</a>
          </div>
        </div>
      </div>`
      )
      .join("");

    grid.querySelectorAll("[data-open-tool]").forEach((el) => {
      el.onclick = () => openToolModal(el.dataset.openTool);
    });
  }

  function renderDorks() {
    const q = state.dorkQuery.trim().toLowerCase();
    const tgt = state.dorkTarget.trim();
    const list = DB.dorks.filter((d) => {
      if (state.dorkEngine && d.engine !== state.dorkEngine) return false;
      if (q && !`${d.title} ${d.purpose} ${d.query}`.toLowerCase().includes(q)) return false;
      return true;
    });

    document.getElementById("dirSummaryLabel").textContent = `${list.length} search dorks`;
    const grid = document.getElementById("dorksGrid");
    grid.innerHTML = list
      .map((d) => {
        const rewritten = tgt
          ? d.query.replace(/example\.com|Target Corp|Target Company|target-company|target_company|target_org|target_keyword|target_handle|Target Name/gi, tgt)
          : d.query;
        const enc = encodeURIComponent(rewritten);
        const url =
          d.engine === "Google" ? `https://www.google.com/search?q=${enc}` :
          d.engine === "Shodan" ? `https://www.shodan.io/search?query=${enc}` :
          d.engine === "GitHub" ? `https://github.com/search?q=${enc}&type=code` : "";
        return `
          <div class="card" style="margin-bottom:0;">
            <div style="display:flex; justify-content:space-between; margin-bottom:4px;">
              <strong style="font-size:14px;">${esc(d.title)}</strong>
              <span class="status-pill">${esc(d.engine)}</span>
            </div>
            <div style="color:var(--text-muted); font-size:12.5px;">${esc(d.purpose)}</div>
            <div class="pre-box">${esc(rewritten)}</div>
            <div style="display:flex; gap:8px; margin-top:10px;">
              <button class="btn" data-copy-dork="${esc(rewritten)}">Copy</button>
              ${url ? `<a class="btn" href="${esc(url)}" target="_blank" rel="noopener noreferrer">Search ${esc(d.engine)} ↗</a>` : ""}
            </div>
          </div>`;
      })
      .join("");

    grid.querySelectorAll("[data-copy-dork]").forEach((b) => {
      b.onclick = function () { copyText(this.dataset.copyDork, this); };
    });
  }

  function renderPlaybooks() {
    document.getElementById("dirSummaryLabel").textContent = `${DB.workflows.length} step-by-step playbooks`;
    document.getElementById("workflowsGrid").innerHTML = DB.workflows
      .map(
        (wf) => `
        <div class="card" style="margin-bottom:0;">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
            <strong style="font-size:15px;">${esc(wf.title)}</strong>
            <span class="status-pill">${esc(wf.starting_selector)}</span>
          </div>
          <p style="color:var(--text-muted); font-size:13px; margin:0 0 12px;">${esc(wf.summary)}</p>
          <div style="display:grid; gap:8px;">
            ${wf.steps
              .map(
                (st) => `
              <div style="padding:8px 10px; background:rgba(255,255,255,0.02); border:1px solid var(--border); border-radius:8px; font-size:12.5px;">
                <strong>${st.step}. ${esc(st.phase)}</strong>
                <div style="color:var(--text-muted); margin-top:2px;">${esc(st.action)}</div>
              </div>`
              )
              .join("")}
          </div>
        </div>`
      )
      .join("");
  }

  function renderRetired() {
    document.getElementById("dirSummaryLabel").textContent = `${DB.graveyard.length} retired or unsafe tools`;
    document.getElementById("graveyardGrid").innerHTML = DB.graveyard
      .map(
        (g) => `
        <div class="card" style="margin-bottom:0;">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
            <strong style="font-size:15px;">${esc(g.dead_tool)}</strong>
            <span class="status-pill red">${esc(g.status)}</span>
          </div>
          <p style="color:var(--text-muted); font-size:13px; margin:0 0 10px;">${esc(g.what_happened)}</p>
          <div style="font-size:12px; color:var(--text-dim);">Use instead: ${g.replacements.map((r) => `<strong style="color:var(--text);">${esc(r.name)}</strong>`).join(", ")}</div>
        </div>`
      )
      .join("");
  }

  function renderDirectory() {
    if (state.dirSubview === "tools") renderTools();
    else if (state.dirSubview === "dorks") renderDorks();
    else if (state.dirSubview === "playbooks") renderPlaybooks();
    else if (state.dirSubview === "retired") renderRetired();
  }

  // ── Clean Settings & Doctor ────────────────────────────────────────────────
  async function renderSettingsAndDoctor() {
    const docEl = document.getElementById("doctorStatusArea");
    const byokEl = document.getElementById("byokSettingsArea");
    if (!docEl || !byokEl) return;

    try {
      const r = await fetch("./api/doctor");
      const d = await r.json();
      const ch = d.catalog_health || {};
      const byok = d.byok_providers || [];

      docEl.innerHTML = `
        <div class="card">
          <div class="card-title" style="margin-bottom:10px;">Local Workspace Status</div>
          <div class="grid-3" style="margin-bottom:0;">
            <div class="kv-list">
              <div class="kv-row"><span class="kv-key">Python</span><span class="kv-val"><code>${esc(d.python_version)}</code></span></div>
              <div class="kv-row"><span class="kv-key">Platform</span><span class="kv-val">${esc(d.platform)}</span></div>
            </div>
            <div class="kv-list">
              <div class="kv-row"><span class="kv-key">Verified Tools</span><span class="kv-val">${esc(ch.tools)}</span></div>
              <div class="kv-row"><span class="kv-key">Local Search DB</span><span class="kv-val">${ch.sqlite_fts5_present ? "Ready" : "Missing"}</span></div>
            </div>
            <div class="kv-list">
              <div class="kv-row"><span class="kv-key">Cases Folder</span><span class="kv-val"><code>${esc(d.cases_dir)}</code></span></div>
              <div class="kv-row"><span class="kv-key">Optional Keys</span><span class="kv-val">${byok.filter((p) => p.configured).length} configured</span></div>
            </div>
          </div>
        </div>`;

      byokEl.innerHTML = `
        <div class="card">
          <div class="card-title" style="margin-bottom:4px;">Optional API Keys</div>
          <div style="color:var(--text-muted); font-size:13px; margin-bottom:14px;">All core features work without keys. Adding keys below unlocks extra data sources and saves them locally to <code>.osint.env</code>.</div>
          <div class="grid-2" style="margin-bottom:0;">
            ${byok
              .map((p) => {
                const vName = p.env_vars[0];
                return `
                <div style="padding:12px; background:rgba(255,255,255,0.02); border:1px solid var(--border); border-radius:9px;">
                  <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;">
                    <strong style="font-size:13.5px;">${esc(p.title)}</strong>
                    <span class="status-pill ${p.configured ? "green" : ""}">${p.configured ? esc(p.masked_preview) : "Not set"}</span>
                  </div>
                  <div style="color:var(--text-muted); font-size:12px; margin-bottom:10px;">${esc(p.benefit)}</div>
                  <div style="display:flex; gap:6px;">
                    <input type="password" class="ctrl-input" data-byok-input="${esc(vName)}" placeholder="${esc(vName)}" style="flex:1;" autocomplete="off" />
                    <button class="btn" data-byok-save="${esc(vName)}">Save</button>
                    ${p.configured ? `<button class="btn" data-byok-clear="${esc(vName)}">Clear</button>` : ""}
                  </div>
                </div>`;
              })
              .join("")}
          </div>
        </div>`;

      byokEl.querySelectorAll("[data-byok-save]").forEach((btn) => {
        btn.onclick = async () => {
          const evName = btn.dataset.byokSave;
          const val = byokEl.querySelector(`[data-byok-input="${evName}"]`)?.value.trim();
          if (!val) return;
          await fetch("./api/settings/byok", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ updates: { [evName]: val } }),
          });
          renderSettingsAndDoctor();
        };
      });
      byokEl.querySelectorAll("[data-byok-clear]").forEach((btn) => {
        btn.onclick = async () => {
          const evName = btn.dataset.byokClear;
          await fetch("./api/settings/byok", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ updates: { [evName]: "" } }),
          });
          renderSettingsAndDoctor();
        };
      });
    } catch (err) {
      docEl.innerHTML = `<div class="card" style="color:#fca5a5;">Could not reach local server: ${esc(err.message)}</div>`;
    }
  }

  document.getElementById("refreshDoctorBtn")?.addEventListener("click", renderSettingsAndDoctor);

  initInvestigateControls();
  initDecoderControls();
  initCaseVaultControls();
  initDirectoryControls();
})();
