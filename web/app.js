(function () {
  "use strict";

  const DB = window.OSINT_DB;
  const toolsById = new Map(DB.tools.map((t) => [t.id, t]));
  const catsById = new Map(DB.categories.map((c) => [c.id, c]));

  const STORAGE_KEY = "osint_monster_loadout_v1";
  let savedIds = new Set();
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw) savedIds = new Set(JSON.parse(raw));
  } catch (_) {}

  function persistLoadout() {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify([...savedIds]));
    } catch (_) {}
    document.getElementById("navCntLoadout").textContent = String(savedIds.size);
  }

  const state = {
    view: "hunter",
    category: "",
    query: "",
    type: "",
    output: "",
    inputSelector: "",
    passiveOnly: false,
    freeOnly: false,
    noAuthOnly: false,
    sTierOnly: false,
    githubOnly: false,
    sort: "tier",
    compactTable: false,
    dorkTarget: "",
    dorkEngine: "",
    dorkQuery: "",
  };

  function esc(str) {
    return String(str ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function copyText(text, btnEl) {
    navigator.clipboard?.writeText(text);
    if (btnEl) {
      const prev = btnEl.textContent;
      btnEl.textContent = "✓ Copied!";
      setTimeout(() => {
        btnEl.textContent = prev;
      }, 1300);
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

  function initHeaderTelemetry() {
    document.getElementById("navCntTools").textContent = String(DB.tools.length);
    document.getElementById("navCntWorkflows").textContent = String(DB.workflows.length);
    document.getElementById("navCntDorks").textContent = String(DB.dorks.length);
    document.getElementById("navCntGraveyard").textContent = String(DB.graveyard.length);
    document.getElementById("navCntLoadout").textContent = String(savedIds.size);

    const passiveCnt = DB.tools.filter((t) => t.opsec === "Passive").length;
    const freeCnt = DB.tools.filter((t) => t.pricing === "Free / Open Source" || t.pricing === "Free").length;
    const noAuthCnt = DB.tools.filter((t) => !t.auth_required).length;
    const sTierCnt = DB.tools.filter((t) => t.tier === "S").length;
    const ghCnt = DB.tools.filter((t) => Boolean(t.github)).length;

    const stats = [
      { v: DB.tools.length, l: "Verified Active OSINT Tools" },
      { v: DB.categories.length, l: "Intelligence Disciplines" },
      { v: `${passiveCnt} (${Math.round((passiveCnt * 100) / DB.tools.length)}%)`, l: "🟢 Passive-Safe Tools" },
      { v: freeCnt, l: "💸 Free & Open-Source" },
      { v: noAuthCnt, l: "✅ Keyless / No-Login Ready" },
      { v: `${sTierCnt} S-Tier · ${ghCnt} GH`, l: "Flagships & GitHub Repos" },
    ];

    document.getElementById("telemetryBar").innerHTML = stats
      .map(
        (s) => `
      <div class="stat-card">
        <div class="stat-value">${esc(s.v)}</div>
        <div class="stat-label">${esc(s.l)}</div>
      </div>`
      )
      .join("");
  }

  function initSelectDropdowns() {
    const types = [...new Set(DB.tools.map((t) => t.type))].sort();
    const typeSel = document.getElementById("typeSelect");
    types.forEach((tp) => {
      const opt = document.createElement("option");
      opt.value = tp;
      opt.textContent = `Type: ${tp}`;
      typeSel.appendChild(opt);
    });

    const outputs = [...new Set(DB.tools.flatMap((t) => t.outputs))].sort();
    const outSel = document.getElementById("outputSelect");
    outputs.forEach((o) => {
      const opt = document.createElement("option");
      opt.value = o;
      opt.textContent = `Output → ${o}`;
      outSel.appendChild(opt);
    });

    const engines = [...new Set(DB.dorks.map((d) => d.engine))];
    const engSel = document.getElementById("dorkEngineSelect");
    engines.forEach((eng) => {
      const opt = document.createElement("option");
      opt.value = eng;
      opt.textContent = eng;
      engSel.appendChild(opt);
    });
  }

  function getFilteredTools(ignoreCategory = false) {
    const q = state.query.trim().toLowerCase();
    const terms = q ? q.split(/\s+/) : [];

    const filtered = DB.tools.filter((t) => {
      if (!ignoreCategory && state.category && t.category !== state.category) return false;
      if (state.type && t.type !== state.type) return false;
      if (state.output && !t.outputs.includes(state.output)) return false;
      if (state.inputSelector && !t.inputs.includes(state.inputSelector)) return false;
      if (state.passiveOnly && t.opsec !== "Passive") return false;
      if (state.freeOnly && t.pricing !== "Free / Open Source" && t.pricing !== "Free") return false;
      if (state.noAuthOnly && t.auth_required) return false;
      if (state.sTierOnly && t.tier !== "S") return false;
      if (state.githubOnly && !t.github) return false;

      if (terms.length) {
        const hay = `${t.id} ${t.name} ${t.subcategory} ${t.description} ${t.tags.join(" ")} ${t.inputs.join(" ")} ${t.outputs.join(" ")} ${t.quick_start}`.toLowerCase();
        for (const term of terms) {
          if (!hay.includes(term)) return false;
        }
      }
      return true;
    });

    const tierRank = { S: 0, A: 1, B: 2 };
    const opsecRank = { Passive: 0, Hybrid: 1, Active: 2 };

    filtered.sort((a, b) => {
      if (state.sort === "name") return a.name.localeCompare(b.name);
      if (state.sort === "passive") {
        const d = opsecRank[a.opsec] - opsecRank[b.opsec];
        if (d !== 0) return d;
      }
      const tr = tierRank[a.tier] - tierRank[b.tier];
      if (tr !== 0) return tr;
      return a.name.localeCompare(b.name);
    });

    return filtered;
  }

  function renderSidebar() {
    const basePool = getFilteredTools(true);
    const counts = new Map();
    for (const t of basePool) {
      counts.set(t.category, (counts.get(t.category) || 0) + 1);
    }

    const listEl = document.getElementById("categoryList");
    const allBtn = `
      <button class="cat-btn ${state.category === "" ? "active" : ""}" data-cat="">
        <span>🌐 All 20 Disciplines</span>
        <span class="cnt">${basePool.length}</span>
      </button>`;

    const items = DB.categories
      .map((c) => {
        const cnt = counts.get(c.id) || 0;
        return `
        <button class="cat-btn ${state.category === c.id ? "active" : ""}" data-cat="${esc(c.id)}">
          <span>${esc(c.icon)} ${esc(c.short_title)}</span>
          <span class="cnt">${cnt}</span>
        </button>`;
      })
      .join("");

    listEl.innerHTML = allBtn + items;
    listEl.querySelectorAll(".cat-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        state.category = btn.dataset.cat;
        renderArsenal();
      });
    });
  }

  function renderSelectorPills(filtered) {
    const counts = new Map();
    for (const t of DB.tools) {
      for (const inp of t.inputs) counts.set(inp, (counts.get(inp) || 0) + 1);
    }
    const selectors = [...counts.entries()].sort((a, b) => b[1] - a[1]);
    document.getElementById("navCntPivots").textContent = String(selectors.length);

    const container = document.getElementById("selectorPills");
    container.innerHTML = selectors
      .map(
        ([sel, cnt]) => `
      <button class="sel-pill ${state.inputSelector === sel ? "active" : ""}" data-sel="${esc(sel)}">
        ${esc(sel)} <span style="opacity:0.6;">(${cnt})</span>
      </button>`
      )
      .join("");

    container.querySelectorAll(".sel-pill").forEach((el) => {
      el.addEventListener("click", () => {
        const s = el.dataset.sel;
        state.inputSelector = state.inputSelector === s ? "" : s;
        renderArsenal();
      });
    });

    const banner = document.getElementById("pivotBanner");
    const hint = document.getElementById("activeSelectorHint");
    if (state.inputSelector) {
      const label = DB.selector_labels[state.inputSelector] || state.inputSelector;
      hint.textContent = `Active Pivot: ${label}`;
      const outMap = new Map();
      filtered.forEach((t) => t.outputs.forEach((o) => outMap.set(o, (outMap.get(o) || 0) + 1)));
      const topOuts = [...outMap.entries()]
        .sort((a, b) => b[1] - a[1])
        .slice(0, 8)
        .map(
          ([o, c]) =>
            `<button class="sel-pill" data-out="${esc(o)}" style="margin:2px;">→ ${esc(o)} (${c})</button>`
        )
        .join(" ");
      banner.className = "pivot-banner visible";
      banner.innerHTML = `<strong>Pivot Chain from <code>${esc(state.inputSelector)}</code> (${esc(label)}):</strong> ${filtered.length} matching tools unlock these downstream outputs (click to filter):<div style="margin-top:6px;">${topOuts}</div>`;
      banner.querySelectorAll("[data-out]").forEach((b) => {
        b.addEventListener("click", () => {
          state.output = b.dataset.out;
          document.getElementById("outputSelect").value = state.output;
          renderArsenal();
        });
      });
    } else {
      hint.textContent = "";
      banner.className = "pivot-banner";
      banner.innerHTML = "";
    }
  }

  function renderToolCard(t) {
    const cat = catsById.get(t.category);
    const isSaved = savedIds.has(t.id);
    const opsecIcon = t.opsec === "Passive" ? "🟢" : t.opsec === "Hybrid" ? "🟡" : "🔴";
    const ghLink = t.github
      ? `<a class="ext-link" href="https://github.com/${esc(t.github)}" target="_blank" rel="noopener noreferrer" onclick="event.stopPropagation()">🐙 GitHub</a>`
      : `<span></span>`;

    return `
      <article class="tool-card" data-tool-id="${esc(t.id)}">
        <div>
          <div class="card-top">
            <div style="display:flex; gap:8px; align-items:flex-start;">
              <span class="tier-badge tier-${esc(t.tier)}">${esc(t.tier)}</span>
              <div>
                <h3 class="tool-title">${esc(t.name)}</h3>
                <div class="tool-subcat">${esc(cat ? cat.icon + " " + cat.short_title : t.category)} · ${esc(t.subcategory)}</div>
              </div>
            </div>
            <button class="star-btn ${isSaved ? "saved" : ""}" data-star="${esc(t.id)}" title="Save to Case Loadout">★</button>
          </div>

          <p class="tool-desc" style="margin-top:9px;">${esc(t.description)}</p>
        </div>

        <div style="display:flex; flex-direction:column; gap:8px;">
          <div class="badge-row">
            <span class="badge opsec-${esc(t.opsec)}">${opsecIcon} ${esc(t.opsec)}</span>
            <span class="badge badge-neutral">${esc(t.type)}</span>
            <span class="badge badge-neutral">${esc(t.pricing)}</span>
            <span class="badge badge-neutral">${t.auth_required ? "🔑 Auth/Key" : "✅ No-Auth"}</span>
          </div>

          <div class="io-line" title="Inputs → Outputs">
            in: ${esc(t.inputs.slice(0, 3).join(", "))} → out: ${esc(t.outputs.slice(0, 3).join(", "))}
          </div>

          <div class="card-actions">
            ${ghLink}
            <a class="ext-link" href="${esc(t.url)}" target="_blank" rel="noopener noreferrer" onclick="event.stopPropagation()">Launch Tool ↗</a>
          </div>
        </div>
      </article>`;
  }

  function bindCardEvents(rootEl) {
    rootEl.querySelectorAll("[data-tool-id]").forEach((card) => {
      card.addEventListener("click", () => openToolModal(card.dataset.toolId));
    });
    rootEl.querySelectorAll("[data-star]").forEach((btn) => {
      btn.addEventListener("click", (e) => {
        e.stopPropagation();
        const id = btn.dataset.star;
        if (savedIds.has(id)) savedIds.delete(id);
        else savedIds.add(id);
        persistLoadout();
        btn.classList.toggle("saved", savedIds.has(id));
        if (state.view === "loadout") renderLoadout();
      });
    });
  }

  function renderArsenal() {
    renderSidebar();
    const filtered = getFilteredTools(false);
    renderSelectorPills(filtered);

    const catLabel = state.category ? ` in ${catsById.get(state.category)?.short_title}` : " across all 20 disciplines";
    document.getElementById("resultsSummary").innerHTML = `Showing <strong>${filtered.length}</strong> of ${DB.tools.length} verified tools${esc(catLabel)}`;

    const container = document.getElementById("toolsContainer");
    if (!filtered.length) {
      container.innerHTML = `<div class="filter-console" style="text-align:center; padding:36px;"><h3>No matching tools</h3><p style="color:var(--text-2);">Try clearing active selector/output filters or broadening your search terms.</p></div>`;
      return;
    }

    if (state.compactTable) {
      container.innerHTML = `
        <div class="tools-table-wrap">
          <table class="tools-table">
            <thead>
              <tr>
                <th>Tier</th>
                <th>Tool</th>
                <th>Discipline</th>
                <th>Type</th>
                <th>OPSEC</th>
                <th>Pricing</th>
                <th>Auth</th>
                <th>Link</th>
              </tr>
            </thead>
            <tbody>
              ${filtered
                .map(
                  (t) => `
                <tr data-tool-id="${esc(t.id)}" style="cursor:pointer;">
                  <td><span class="tier-badge tier-${esc(t.tier)}">${esc(t.tier)}</span></td>
                  <td><strong>${esc(t.name)}</strong><div style="font-size:11.5px;color:var(--text-2);">${esc(t.subcategory)}</div></td>
                  <td>${esc(catsById.get(t.category)?.code || t.category)}</td>
                  <td>${esc(t.type)}</td>
                  <td><span class="badge opsec-${esc(t.opsec)}">${esc(t.opsec)}</span></td>
                  <td>${esc(t.pricing)}</td>
                  <td>${t.auth_required ? "🔑" : "✅"}</td>
                  <td><a href="${esc(t.url)}" target="_blank" rel="noopener noreferrer" onclick="event.stopPropagation()">Open ↗</a></td>
                </tr>`
                )
                .join("")}
            </tbody>
          </table>
        </div>`;
      bindCardEvents(container);
    } else {
      container.innerHTML = `<div class="tools-grid">${filtered.map(renderToolCard).join("")}</div>`;
      bindCardEvents(container);
    }
  }

  function openToolModal(toolId) {
    const t = toolsById.get(toolId);
    if (!t) return;
    const cat = catsById.get(t.category);
    const backdrop = document.getElementById("toolModalBackdrop");
    const modal = document.getElementById("toolModalContent");

    modal.innerHTML = `
      <div class="modal-header">
        <div>
          <div style="display:flex; gap:8px; align-items:center; margin-bottom:4px;">
            <span class="tier-badge tier-${esc(t.tier)}">${esc(t.tier)}-TIER</span>
            <span class="badge opsec-${esc(t.opsec)}">${esc(t.opsec)} OPSEC</span>
            <span class="badge badge-neutral">${esc(t.type)}</span>
            <span class="badge badge-neutral">${esc(t.pricing)}</span>
          </div>
          <h2 style="margin:4px 0 2px;">${esc(t.name)}</h2>
          <div style="color:var(--text-2); font-size:12.5px;">${esc(cat?.icon || "")} ${esc(cat?.title || t.category)} › ${esc(t.subcategory)} · ID: <code>${esc(t.id)}</code></div>
        </div>
        <button class="close-btn" id="closeModalBtn">✕ ESC</button>
      </div>

      <p style="font-size:14.5px; color:var(--text-0); line-height:1.6;">${esc(t.description)}</p>

      <div style="margin:14px 0;">
        <div style="font-size:11.5px; font-weight:700; color:var(--text-2); text-transform:uppercase;">Quick-Start Command / Analyst Tradecraft</div>
        <div class="code-block" id="modalQuickCmd">${esc(t.quick_start)}</div>
        <button class="btn-sm" id="copyQuickBtn">📋 Copy Quick-Start</button>
      </div>

      <div style="display:grid; grid-template-columns:1fr 1fr; gap:12px; margin:14px 0;">
        <div style="background:var(--bg-0); padding:10px 12px; border-radius:8px; border:1px solid var(--border);">
          <div style="font-size:11px; color:var(--text-2); text-transform:uppercase; margin-bottom:6px;">Accepts Input Selectors</div>
          <div class="badge-row">${t.inputs.map((i) => `<button class="sel-pill" data-pivot-in="${esc(i)}">${esc(i)}</button>`).join("")}</div>
        </div>
        <div style="background:var(--bg-0); padding:10px 12px; border-radius:8px; border:1px solid var(--border);">
          <div style="font-size:11px; color:var(--text-2); text-transform:uppercase; margin-bottom:6px;">Produces Intelligence Outputs</div>
          <div class="badge-row">${t.outputs.map((o) => `<span class="badge badge-neutral">${esc(o)}</span>`).join("")}</div>
        </div>
      </div>

      <div style="font-size:12.5px; color:var(--text-2); margin-bottom:16px;">
        <strong>Platforms:</strong> ${esc(t.platforms.join(", "))} &nbsp;·&nbsp;
        <strong>Auth:</strong> ${t.auth_required ? "Account / API Key Required" : "Keyless / No Registration Required"} &nbsp;·&nbsp;
        <strong>Tags:</strong> ${t.tags.map((tg) => `<code>#${esc(tg)}</code>`).join(" ")}
      </div>

      <div style="display:flex; gap:10px; flex-wrap:wrap; border-top:1px solid var(--border); padding-top:14px;">
        <a href="${esc(t.url)}" target="_blank" rel="noopener noreferrer" class="nav-tab active" style="text-decoration:none;">🚀 Open Official Tool ↗</a>
        ${
          t.github
            ? `<a href="https://github.com/${esc(t.github)}" target="_blank" rel="noopener noreferrer" class="nav-tab" style="text-decoration:none;">🐙 GitHub (${esc(t.github)}) ↗</a>`
            : ""
        }
      </div>
    `;

    backdrop.classList.add("open");
    document.getElementById("closeModalBtn").onclick = () => backdrop.classList.remove("open");
    document.getElementById("copyQuickBtn").onclick = function () {
      copyText(t.quick_start, this);
    };
    modal.querySelectorAll("[data-pivot-in]").forEach((btn) => {
      btn.addEventListener("click", () => {
        backdrop.classList.remove("open");
        switchView("arsenal");
        state.inputSelector = btn.dataset.pivotIn;
        state.category = "";
        renderArsenal();
      });
    });
  }

  function renderPivotMatrix() {
    const bySel = new Map();
    for (const t of DB.tools) {
      for (const inp of t.inputs) {
        if (!bySel.has(inp)) bySel.set(inp, []);
        bySel.get(inp).push(t);
      }
    }
    const sorted = [...bySel.entries()].sort((a, b) => b[1].length - a[1].length);

    const grid = document.getElementById("pivotMatrixGrid");
    grid.innerHTML = sorted
      .map(([sel, list]) => {
        const passive = list.filter((t) => t.opsec === "Passive").length;
        const outs = new Map();
        list.forEach((t) => t.outputs.forEach((o) => outs.set(o, (outs.get(o) || 0) + 1)));
        const topOuts = [...outs.entries()]
          .sort((a, b) => b[1] - a[1])
          .slice(0, 5)
          .map(([o]) => `<code>${esc(o)}</code>`)
          .join(", ");
        const topTools = list
          .filter((t) => t.tier === "S")
          .slice(0, 4)
          .map((t) => `<span class="wf-tool-chip" data-open-tool="${esc(t.id)}">★ ${esc(t.name)}</span>`)
          .join(" ");

        return `
        <div class="pivot-card">
          <h3>
            <span><code>${esc(sel)}</code> · ${esc(DB.selector_labels[sel] || sel)}</span>
            <span class="version-pill">${list.length} tools</span>
          </h3>
          <div style="font-size:12px; color:var(--text-2); margin-bottom:8px;">
            🟢 ${passive} Passive-Safe &nbsp;·&nbsp; Pivots into: ${topOuts}
          </div>
          <div class="wf-tools" style="margin-bottom:12px;">${topTools}</div>
          <button class="btn-sm" data-jump-sel="${esc(sel)}">🧭 Pivot with ${list.length} Tools in Arsenal →</button>
        </div>`;
      })
      .join("");

    grid.querySelectorAll("[data-open-tool]").forEach((el) => {
      el.addEventListener("click", () => openToolModal(el.dataset.openTool));
    });
    grid.querySelectorAll("[data-jump-sel]").forEach((btn) => {
      btn.addEventListener("click", () => {
        state.inputSelector = btn.dataset.jumpSel;
        state.category = "";
        switchView("arsenal");
        renderArsenal();
      });
    });
  }

  function renderWorkflows() {
    const grid = document.getElementById("workflowsGrid");
    grid.innerHTML = DB.workflows
      .map(
        (wf) => `
      <div class="wf-card">
        <div style="display:flex; justify-content:space-between; gap:8px; align-items:center;">
          <span class="version-pill">${esc(wf.discipline)}</span>
          <span style="font-size:12px; color:var(--text-2);">Seed: <code>${esc(wf.starting_selector)}</code> · ${esc(wf.difficulty)}</span>
        </div>
        <h3 style="margin:8px 0 6px; font-size:16px;">${esc(wf.title)}</h3>
        <p style="margin:0 0 10px; color:var(--text-1); font-size:13px;">${esc(wf.summary)}</p>
        ${wf.steps
          .map(
            (st) => `
          <div class="wf-step">
            <div class="wf-step-title">Phase ${st.step}: ${esc(st.phase)}</div>
            <div style="font-size:12.5px; color:var(--text-1); margin-top:3px;">${esc(st.action)}</div>
            <div class="wf-tools">
              ${st.recommended_tools
                .map((tid) => {
                  const t = toolsById.get(tid);
                  return t
                    ? `<button class="wf-tool-chip" data-open-tool="${esc(tid)}">[${esc(t.tier)}] ${esc(t.name)}</button>`
                    : "";
                })
                .join("")}
            </div>
          </div>`
          )
          .join("")}
      </div>`
      )
      .join("");

    grid.querySelectorAll("[data-open-tool]").forEach((btn) => {
      btn.addEventListener("click", () => openToolModal(btn.dataset.openTool));
    });
  }

  function rewriteDork(query, target) {
    if (!target) return query;
    return query
      .replace(/example\.com/gi, target)
      .replace(/Target Corp/gi, target)
      .replace(/Target Company/gi, target)
      .replace(/target-company/gi, target)
      .replace(/target_company/gi, target)
      .replace(/target_org/gi, target)
      .replace(/target_keyword/gi, target)
      .replace(/target_handle/gi, target)
      .replace(/Target Name/gi, target);
  }

  function dorkLaunchUrl(engine, q) {
    const enc = encodeURIComponent(q);
    if (engine === "Google") return `https://www.google.com/search?q=${enc}`;
    if (engine === "Shodan") return `https://www.shodan.io/search?query=${enc}`;
    if (engine === "Censys") return `https://search.censys.io/search?resource=hosts&q=${enc}`;
    if (engine === "GitHub") return `https://github.com/search?q=${enc}&type=code`;
    if (engine === "URLScan.io") return `https://urlscan.io/search/#${enc}`;
    if (engine === "X (Twitter)") return `https://x.com/search?q=${enc}&f=live`;
    return "";
  }

  function renderDorks() {
    const q = state.dorkQuery.trim().toLowerCase();
    const list = DB.dorks.filter((d) => {
      if (state.dorkEngine && d.engine !== state.dorkEngine) return false;
      if (q) {
        const hay = `${d.title} ${d.category} ${d.purpose} ${d.query} ${d.engine}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });

    const grid = document.getElementById("dorksGrid");
    grid.innerHTML = list
      .map((d) => {
        const rewritten = rewriteDork(d.query, state.dorkTarget.trim());
        const launch = dorkLaunchUrl(d.engine, rewritten);
        return `
        <div class="dork-card">
          <div style="display:flex; justify-content:space-between; gap:8px; margin-bottom:4px;">
            <span class="version-pill">${esc(d.engine)}</span>
            <span style="font-size:11.5px; color:var(--text-2);">${esc(d.category)}</span>
          </div>
          <h3 style="margin:4px 0; font-size:14.5px;">${esc(d.title)}</h3>
          <p style="margin:0; font-size:12.5px; color:var(--text-1);">${esc(d.purpose)}</p>
          <div class="code-block">${esc(rewritten)}</div>
          <div style="display:flex; gap:8px; justify-content:space-between; align-items:center;">
            <button class="btn-sm" data-copy-dork="${esc(rewritten)}">📋 Copy Query</button>
            ${launch ? `<a class="ext-link" href="${esc(launch)}" target="_blank" rel="noopener noreferrer">Run in ${esc(d.engine)} ↗</a>` : ""}
          </div>
        </div>`;
      })
      .join("");

    grid.querySelectorAll("[data-copy-dork]").forEach((btn) => {
      btn.addEventListener("click", function () {
        copyText(this.dataset.copyDork, this);
      });
    });
  }

  function renderGraveyard() {
    const grid = document.getElementById("graveyardGrid");
    grid.innerHTML = DB.graveyard
      .map(
        (g) => `
      <div class="wf-card" style="border-color:rgba(239,68,68,0.28);">
        <div style="display:flex; justify-content:space-between; gap:8px;">
          <span class="badge opsec-Active">${esc(g.status)}</span>
          <code style="font-size:11.5px; color:var(--text-2);">${esc(g.former_url)}</code>
        </div>
        <h3 style="margin:8px 0 6px;">🪦 ${esc(g.dead_tool)}</h3>
        <p style="font-size:13px; color:var(--text-1); margin:0 0 12px;">${esc(g.what_happened)}</p>
        <div style="font-size:11.5px; font-weight:700; color:#34d399; text-transform:uppercase; margin-bottom:6px;">Verified 2026 Replacements:</div>
        <div style="display:flex; flex-direction:column; gap:6px;">
          ${g.replacements
            .map(
              (r) => `
            <div style="background:var(--bg-0); padding:8px 10px; border-radius:6px; border:1px solid var(--border); display:flex; justify-content:space-between; align-items:center; gap:8px;">
              <div>
                <strong style="color:var(--cyan); cursor:pointer;" data-open-tool="${esc(r.id)}">${esc(r.name)}</strong>
                <div style="font-size:12px; color:var(--text-2);">${esc(r.note)}</div>
              </div>
              <button class="btn-sm" data-open-tool="${esc(r.id)}">Inspect</button>
            </div>`
            )
            .join("")}
        </div>
      </div>`
      )
      .join("");

    grid.querySelectorAll("[data-open-tool]").forEach((el) => {
      el.addEventListener("click", () => openToolModal(el.dataset.openTool));
    });
  }

  function renderEntityGraphSvg(graph) {
    const nodes = graph.nodes || [];
    const edges = graph.edges || [];
    if (!nodes.length) return "";

    const byWave = new Map();
    nodes.forEach((n) => {
      const w = n.wave || 1;
      if (!byWave.has(w)) byWave.set(w, []);
      byWave.get(w).push(n);
    });

    const waves = [...byWave.keys()].sort((a, b) => a - b);
    const width = 960;
    const maxPerCol = Math.max(...waves.map((w) => byWave.get(w).length), 1);
    const height = Math.max(230, maxPerCol * 56 + 44);
    const pos = new Map();

    waves.forEach((w, colIdx) => {
      const colNodes = byWave.get(w);
      const x = waves.length === 1 ? width / 2 : 160 + (colIdx * (width - 320)) / (waves.length - 1);
      colNodes.forEach((n, rowIdx) => {
        const y = ((rowIdx + 1) * height) / (colNodes.length + 1);
        pos.set(n.id, { x, y, node: n });
      });
    });

    const colorFor = (tp) => {
      if (tp === "email") return "#f59e0b";
      if (tp === "domain" || tp === "ip") return "#22d3ee";
      if (tp === "username") return "#8b5cf6";
      if (tp === "crypto_address") return "#10b981";
      return "#60a5fa";
    };

    const edgeLines = edges
      .map((e) => {
        const s = pos.get(e.source);
        const t = pos.get(e.target);
        if (!s || !t) return "";
        const mx = (s.x + t.x) / 2;
        const my = (s.y + t.y) / 2 - 6;
        return `
          <line x1="${s.x}" y1="${s.y}" x2="${t.x}" y2="${t.y}" stroke="#35507f" stroke-width="1.6" stroke-dasharray="4 3" />
          <text x="${mx}" y="${my}" fill="#7b90b6" font-size="9.5" text-anchor="middle">${esc(e.via)}</text>`;
      })
      .join("");

    const nodeCircles = [...pos.values()]
      .map(({ x, y, node }) => {
        const col = colorFor(node.type);
        const label = node.value.length > 28 ? node.value.slice(0, 26) + "…" : node.value;
        return `
          <g class="svg-node" data-rehunt="${esc(node.value)}" style="cursor:pointer;">
            <rect x="${x - 115}" y="${y - 18}" width="230" height="36" rx="8" fill="#131c2e" stroke="${col}" stroke-width="1.6" />
            <text x="${x}" y="${y - 3}" fill="${col}" font-size="9.5" font-weight="700" text-anchor="middle">[W${node.wave}] ${esc(node.type.toUpperCase())}</text>
            <text x="${x}" y="${y + 11}" fill="#eef4ff" font-size="11" font-family="monospace" text-anchor="middle">${esc(label)}</text>
          </g>`;
      })
      .join("");

    return `<svg viewBox="0 0 ${width} ${height}" style="width:100%; height:auto; max-height:460px; display:block;">${edgeLines}${nodeCircles}</svg>`;
  }

  let lastHuntReport = null;

  async function openActiveAuthorizationModal(targetOverride) {
    const inputEl = document.getElementById("huntTargetInput");
    const target = (targetOverride || inputEl.value || "").trim();
    if (!target) {
      inputEl.focus();
      return;
    }

    const backdrop = document.getElementById("activeAuthBackdrop");
    const modal = document.getElementById("activeAuthModalContent");
    backdrop.classList.add("open");
    modal.innerHTML = `<div style="padding:24px; text-align:center;"><h3>🔒 Preparing Active OSINT Scope (Zero Packets Sent)...</h3></div>`;

    try {
      const resp = await fetch("./api/hunt/prepare-active", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target }),
      });
      const plan = await resp.json();
      if (!resp.ok || plan.error) throw new Error(plan.error || `HTTP ${resp.status}`);

      const plannedSet = new Set((plan.planned_active_modules || []).map((m) => m.module));
      const allMods = plan.all_available_modules || plan.planned_active_modules || [];

      modal.innerHTML = `
        <div class="modal-header">
          <div>
            <span class="badge opsec-Active" style="font-size:12px;">🔴 MANDATORY USER AUTHORIZATION GATE</span>
            <h2 style="margin:6px 0 2px;">Authorize Active OSINT Probing?</h2>
            <div style="font-size:12px; color:var(--text-2);">Single-Use Request ID: <code>${esc(plan.request_id)}</code> · Zero packets have been sent yet</div>
          </div>
          <button class="close-btn" id="cancelActiveModalBtn">✕ Cancel</button>
        </div>

        <div style="background:var(--red-dim); border:1px solid rgba(239,68,68,0.45); border-radius:8px; padding:11px 13px; font-size:13px; color:#fecaca; margin-bottom:12px;">
          <strong>⚠️ OPSEC DISCLOSURE:</strong> ${esc(plan.opsec_warning)}
        </div>

        <div style="margin-bottom:12px; font-size:13px;">
          <strong>Target Scope:</strong> <code>${esc(plan.target)}</code><br/>
          <strong>Detected Selectors:</strong> ${(plan.detected_selectors || [])
            .map((s) => `<span class="badge badge-neutral" style="margin:2px;">${esc(s.type)}: ${esc(s.value)}</span>`)
            .join("")}
        </div>

        <div style="font-size:11.5px; font-weight:700; color:var(--text-2); text-transform:uppercase; margin-bottom:6px;">
          Select Active Reconnaissance Modules to Permit:
        </div>
        <div style="display:flex; flex-direction:column; gap:6px; max-height:240px; overflow-y:auto; margin-bottom:14px;">
          ${allMods
            .map(
              (m) => `
            <label style="display:flex; gap:9px; align-items:flex-start; background:var(--bg-0); border:1px solid var(--border); padding:8px 10px; border-radius:7px; cursor:pointer;">
              <input type="checkbox" class="active-mod-chk" value="${esc(m.module)}" ${plannedSet.has(m.module) ? "checked" : ""} style="margin-top:3px;" />
              <div>
                <div style="font-weight:700; font-size:12.5px;">${esc(m.title)} (<code>${esc(m.module)}</code>)</div>
                <div style="font-size:11.5px; color:var(--text-2);">${esc(m.opsec_impact)}</div>
              </div>
            </label>`
            )
            .join("")}
        </div>

        <label style="display:flex; gap:9px; align-items:center; padding:10px 12px; background:var(--bg-2); border:1px solid var(--border-hi); border-radius:8px; cursor:pointer; font-weight:600; margin-bottom:14px;">
          <input type="checkbox" id="confirmActiveConsentChk" />
          <span>I explicitly authorize direct Active OSINT network requests against this target for this single run.</span>
        </label>

        <div style="display:flex; justify-content:flex-end; gap:10px;">
          <button class="btn-sm" id="abortActiveBtn">Keep Passive Only (Cancel)</button>
          <button class="btn-hunt" id="confirmActiveLaunchBtn" disabled style="background:linear-gradient(135deg,#dc2626,#ea580c);">
            🔴 Authorize &amp; Launch Active Hunt (${esc(plan.request_id)})
          </button>
        </div>
      `;

      const close = () => backdrop.classList.remove("open");
      document.getElementById("cancelActiveModalBtn").onclick = close;
      document.getElementById("abortActiveBtn").onclick = close;

      const consentChk = document.getElementById("confirmActiveConsentChk");
      const goBtn = document.getElementById("confirmActiveLaunchBtn");
      consentChk.addEventListener("change", () => {
        goBtn.disabled = !consentChk.checked;
      });

      goBtn.addEventListener("click", async () => {
        const chosenMods = [...modal.querySelectorAll(".active-mod-chk:checked")].map((c) => c.value);
        close();
        await runAuthorizedActiveHunt(plan.target, plan.request_id, chosenMods);
      });
    } catch (err) {
      modal.innerHTML = `<div style="padding:18px;"><h3 style="color:var(--red);">Failed to prepare Active request (${esc(err.message)})</h3><button class="btn-sm" onclick="document.getElementById('activeAuthBackdrop').classList.remove('open')">Close</button></div>`;
    }
  }

  async function runAuthorizedActiveHunt(target, requestId, modules) {
    const btn = document.getElementById("launchHuntBtn");
    const depth = parseInt(document.getElementById("huntDepthSelect").value || "2", 10);
    const outArea = document.getElementById("huntResultsArea");

    btn.disabled = true;
    btn.textContent = "🔴 EXECUTING AUTHORIZED ACTIVE + PASSIVE HUNT...";
    outArea.innerHTML = `<div class="collector-card" style="text-align:center; padding:36px; border-color:var(--red);"><h3>🔴 User-Authorized Active + Passive Collectors Running (${esc(requestId)})...</h3><p style="color:var(--text-2);">Inspecting live TLS SANs, HTTP/CSP headers, robots/security.txt, Shodan mmh3 favicon hashes, TCP banners, and passive intelligence.</p></div>`;

    try {
      const resp = await fetch("./api/hunt/active", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Human-Modal-Confirmed": "1",
        },
        body: JSON.stringify({
          target,
          request_id: requestId,
          user_confirmation: "Approved via Web Command Center Authorization Modal",
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
      outArea.innerHTML = `<div class="collector-card" style="border-color:var(--red);"><h3>🚫 Active Gate Rejected Execution</h3><p style="color:var(--text-1);">${esc(err.message)}</p></div>`;
    } finally {
      btn.disabled = false;
      btn.textContent = "⚡ HUNT NOW";
    }
  }

  async function executeLiveHunt() {
    const inputEl = document.getElementById("huntTargetInput");
    const modeSel = document.getElementById("huntModeSelect");
    const btn = document.getElementById("launchHuntBtn");
    const depth = parseInt(document.getElementById("huntDepthSelect").value || "2", 10);
    const outArea = document.getElementById("huntResultsArea");
    const target = inputEl.value.trim();
    if (!target) {
      inputEl.focus();
      return;
    }

    // MANDATORY ACTIVE MODE RULE: NEVER start Active OSINT without asking user first!
    if (modeSel && modeSel.value === "active") {
      await openActiveAuthorizationModal(target);
      return;
    }

    btn.disabled = true;
    btn.textContent = "⏳ HUNTING WAVE 1 → WAVE " + depth + "...";
    outArea.innerHTML = `<div class="collector-card" style="text-align:center; padding:36px;"><h3>🛰️ Autonomous Passive Collectors Firing in Parallel...</h3><p style="color:var(--text-2);">Extracting selectors, querying registries/GitHub/npm/PyPI/DNS/forensic decoders, and pivoting across discovered entities without prompting.</p></div>`;

    try {
      const resp = await fetch("./api/hunt", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target, depth, save_case: true }),
      });
      const report = await resp.json();
      if (!resp.ok || report.error) {
        throw new Error(report.error || `HTTP ${resp.status}`);
      }
      lastHuntReport = report;
      renderHuntReport(report);
    } catch (err) {
      outArea.innerHTML = `<div class="collector-card" style="border-color:var(--red);"><h3>⚠️ Live Hunt Backend Unreachable (${esc(err.message)})</h3><p style="color:var(--text-1);">Run <code>python3 scripts/server.py --port 8000</code> or execute directly from terminal: <code>python3 scripts/hunt.py "${esc(target)}" --depth ${depth}</code></p></div>`;
    } finally {
      btn.disabled = false;
      btn.textContent = "⚡ HUNT NOW";
    }
  }

  function renderHuntReport(report) {
    const outArea = document.getElementById("huntResultsArea");
    const m = report.meta;
    const svg = renderEntityGraphSvg(report.graph);

    const waveHtml = (report.wave_results || [])
      .map(
        (w) => `
        <div class="collector-card">
          <div style="display:flex; justify-content:space-between; align-items:center; gap:8px; margin-bottom:8px;">
            <div>
              <span class="version-pill">WAVE ${w.wave}</span>
              <strong style="margin-left:8px; font-size:15px;">[${esc(w.type)}] <code>${esc(w.value)}</code></strong>
            </div>
            <button class="btn-sm" data-pivot-arsenal="${esc(w.type)}">🧭 Open ${esc(w.type)} Tools in Arsenal</button>
          </div>
          ${w.collector_outputs
            .map((c) => {
              const icon = c.status === "ok" ? "✅" : c.status === "not_found" ? "⚪" : "🔒";
              const hasData = c.status === "ok" && c.data && Object.keys(c.data).length > 0;
              return `
                <div style="background:var(--bg-0); border:1px solid ${c.opsec === "Active" ? "rgba(239,68,68,0.45)" : "var(--border)"}; border-radius:7px; padding:9px 12px; margin-top:7px;">
                  <div style="font-size:13px;">${icon} ${c.opsec === "Active" ? '<span class="badge opsec-Active" style="margin-right:5px;">🔴 ACTIVE</span>' : ""}<strong><code>${esc(c.module)}</code></strong> — <span style="color:var(--text-1);">${esc(c.summary)}</span></div>
                  ${
                    hasData
                      ? `<details style="margin-top:6px;"><summary style="cursor:pointer; font-size:11.5px; color:var(--cyan);">Inspect Raw Telemetry JSON</summary><div class="code-block">${esc(
                          JSON.stringify(c.data, null, 2)
                        )}</div></details>`
                      : ""
                  }
                </div>`;
            })
            .join("")}
        </div>`
      )
      .join("");

    const dorksHtml = (report.forged_dorks || [])
      .slice(0, 8)
      .map(
        (d) => `
        <div style="background:var(--bg-0); border:1px solid var(--border); border-radius:7px; padding:8px 11px;">
          <div style="font-size:11.5px; color:var(--cyan); font-weight:700;">[${esc(d.engine)}] ${esc(d.title)}</div>
          <div class="code-block" style="margin:5px 0;">${esc(d.query)}</div>
        </div>`
      )
      .join("");

    const isAct = m.opsec_mode === "Active+Passive";
    outArea.innerHTML = `
      <div class="collector-card" style="display:flex; flex-wrap:wrap; justify-content:space-between; align-items:center; gap:10px; border-color:${isAct ? "var(--red)" : "var(--border-hi)"};">
        <div>
          <strong>${isAct ? "🔴 Active+Passive" : "🟢 Passive"} Case <code>${esc(m.case_id)}</code> Complete in ${esc(m.duration_seconds)}s</strong>
          <div style="font-size:12px; color:var(--text-2);">
            ${report.graph.nodes.length} Entity Node(s) · ${report.graph.edges.length} Pivot Edge(s) · ${isAct ? `Authorized via <code>${esc(m.approval_request_id)}</code> · ` : ""}Saved to <code>${esc(m.case_dir || "memory")}/</code>
          </div>
        </div>
        <div style="display:flex; gap:8px; flex-wrap:wrap;">
          ${!isAct ? `<button class="btn-sm" id="escalateActiveBtn" style="border-color:var(--red); color:#fca5a5;">🔴 Escalate to Active OSINT (Ask Approval)...</button>` : ""}
          <button class="btn-sm" id="dlDossierMd">📄 Download Dossier (.md)</button>
          <button class="btn-sm" id="dlStixJson">🛡️ Download STIX 2.1 (.json)</button>
          <button class="btn-sm" id="dlFullJson">📦 Download Report (.json)</button>
        </div>
      </div>

      <div class="graph-box">
        <div style="font-size:11.5px; color:var(--text-2); font-weight:700; text-transform:uppercase; margin-bottom:6px;">
          🕸️ Autonomous Entity &amp; Pivot Graph (Click Any Node to Re-Hunt Focused)
        </div>
        ${svg}
      </div>

      ${waveHtml}

      ${
        dorksHtml
          ? `<div class="collector-card"><h3 style="margin:0 0 8px;">🎯 Auto-Forged Search Dorks for Discovered Entities</h3><div class="tools-grid">${dorksHtml}</div></div>`
          : ""
      }
    `;

    const escBtn = document.getElementById("escalateActiveBtn");
    if (escBtn) {
      escBtn.onclick = () => openActiveAuthorizationModal(m.raw_input);
    }
    document.getElementById("dlDossierMd").onclick = () =>
      downloadBlob(`${m.case_id}-dossier.md`, report.dossier_markdown, "text/markdown;charset=utf-8");
    document.getElementById("dlStixJson").onclick = () =>
      downloadBlob(`${m.case_id}-stix2.json`, JSON.stringify(report.stix2_bundle, null, 2), "application/json");
    document.getElementById("dlFullJson").onclick = () =>
      downloadBlob(`${m.case_id}-report.json`, JSON.stringify(report, null, 2), "application/json");

    outArea.querySelectorAll("[data-rehunt]").forEach((g) => {
      g.addEventListener("click", () => {
        document.getElementById("huntTargetInput").value = g.dataset.rehunt;
        executeLiveHunt();
      });
    });

    outArea.querySelectorAll("[data-pivot-arsenal]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const tp = btn.dataset.pivotArsenal;
        state.inputSelector = tp === "local_file" || tp === "jwt_token" ? "document" : tp;
        state.category = "";
        switchView("arsenal");
        renderArsenal();
      });
    });
  }

  function initHunterControls() {
    const huntInput = document.getElementById("huntTargetInput");
    const detectedRow = document.getElementById("liveDetectedRow");
    if (!huntInput) return;

    let detectTimer = null;
    huntInput.addEventListener("input", () => {
      clearTimeout(detectTimer);
      const val = huntInput.value.trim();
      if (!val) {
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
          detectedRow.innerHTML = sels.length
            ? `Auto-Detected Selectors (${sels.length}): ` +
              sels.map((s) => `<span class="badge opsec-Passive" style="margin-right:4px;">${esc(s.type)}: ${esc(s.value)}</span>`).join("")
            : "";
        } catch (_) {}
      }, 160);
    });

    huntInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        executeLiveHunt();
      }
    });

    document.getElementById("launchHuntBtn").addEventListener("click", executeLiveHunt);

    const modeSel = document.getElementById("huntModeSelect");
    if (modeSel) {
      modeSel.addEventListener("change", () => {
        modeSel.style.borderColor = modeSel.value === "active" ? "var(--red)" : "var(--green)";
      });
    }

    const activeBackdrop = document.getElementById("activeAuthBackdrop");
    if (activeBackdrop) {
      activeBackdrop.addEventListener("click", (e) => {
        if (e.target === activeBackdrop) activeBackdrop.classList.remove("open");
      });
    }

    document.querySelectorAll("[data-hunt-preset]").forEach((btn) => {
      btn.addEventListener("click", () => {
        huntInput.value = btn.dataset.huntPreset;
        executeLiveHunt();
      });
    });
  }
  function renderLoadout() {
    const container = document.getElementById("loadoutContainer");
    const items = [...savedIds].map((id) => toolsById.get(id)).filter(Boolean);
    if (!items.length) {
      container.innerHTML = `<div class="filter-console" style="text-align:center; padding:40px;"><h3>Your Case Loadout is Empty</h3><p style="color:var(--text-2);">Click the <strong>★</strong> button on any tool card in the Tool Arsenal to assemble a custom investigation kit.</p></div>`;
      return;
    }
    container.innerHTML = `<div class="tools-grid">${items.map(renderToolCard).join("")}</div>`;
    bindCardEvents(container);
  }

  function switchView(viewName) {
    state.view = viewName;
    document.querySelectorAll(".nav-tab[data-view]").forEach((b) => {
      b.classList.toggle("active", b.dataset.view === viewName);
    });
    document.querySelectorAll(".view-panel").forEach((p) => {
      p.classList.toggle("active", p.id === `view-${viewName}`);
    });
    if (viewName === "loadout") renderLoadout();
  }

  function bindGlobalControls() {
    document.querySelectorAll(".nav-tab[data-view]").forEach((btn) => {
      btn.addEventListener("click", () => switchView(btn.dataset.view));
    });

    document.getElementById("searchInput").addEventListener("input", (e) => {
      state.query = e.target.value;
      renderArsenal();
    });

    document.getElementById("typeSelect").addEventListener("change", (e) => {
      state.type = e.target.value;
      renderArsenal();
    });

    document.getElementById("outputSelect").addEventListener("change", (e) => {
      state.output = e.target.value;
      renderArsenal();
    });

    document.getElementById("sortSelect").addEventListener("change", (e) => {
      state.sort = e.target.value;
      renderArsenal();
    });

    const bindToggle = (id, key) => {
      const btn = document.getElementById(id);
      btn.addEventListener("click", () => {
        state[key] = !state[key];
        btn.classList.toggle("active", state[key]);
        renderArsenal();
      });
    };
    bindToggle("togPassive", "passiveOnly");
    bindToggle("togFree", "freeOnly");
    bindToggle("togNoAuth", "noAuthOnly");
    bindToggle("togSTier", "sTierOnly");
    bindToggle("togGitHub", "githubOnly");

    document.getElementById("resetCatLink").addEventListener("click", (e) => {
      e.preventDefault();
      state.category = "";
      renderArsenal();
    });

    document.getElementById("resetAllBtn").addEventListener("click", () => {
      state.category = "";
      state.query = "";
      state.type = "";
      state.output = "";
      state.inputSelector = "";
      state.passiveOnly = false;
      state.freeOnly = false;
      state.noAuthOnly = false;
      state.sTierOnly = false;
      state.githubOnly = false;
      document.getElementById("searchInput").value = "";
      document.getElementById("typeSelect").value = "";
      document.getElementById("outputSelect").value = "";
      ["togPassive", "togFree", "togNoAuth", "togSTier", "togGitHub"].forEach((id) =>
        document.getElementById(id).classList.remove("active")
      );
      renderArsenal();
    });

    document.getElementById("viewModeBtn").addEventListener("click", function () {
      state.compactTable = !state.compactTable;
      this.textContent = state.compactTable ? "🗂️ Switch to Card Grid" : "📋 Switch to Compact Table";
      renderArsenal();
    });

    document.getElementById("exportFilteredBtn").addEventListener("click", () => {
      const rows = getFilteredTools(false);
      const header = ["id", "name", "tier", "category", "type", "opsec", "pricing", "url"];
      const csv = [
        header.join(","),
        ...rows.map((r) => header.map((k) => `"${String(r[k] ?? "").replace(/"/g, '""')}"`).join(",")),
      ].join("\n");
      downloadBlob("osint-filtered-tools.csv", csv, "text/csv;charset=utf-8");
    });

    // Dorks controls
    document.getElementById("dorkTargetInput").addEventListener("input", (e) => {
      state.dorkTarget = e.target.value;
      renderDorks();
    });
    document.getElementById("dorkEngineSelect").addEventListener("change", (e) => {
      state.dorkEngine = e.target.value;
      renderDorks();
    });
    document.getElementById("dorkSearchInput").addEventListener("input", (e) => {
      state.dorkQuery = e.target.value;
      renderDorks();
    });

    // Loadout export controls
    document.getElementById("exportLoadoutJson").addEventListener("click", () => {
      const items = [...savedIds].map((id) => toolsById.get(id)).filter(Boolean);
      downloadBlob("osint-case-loadout.json", JSON.stringify(items, null, 2), "application/json");
    });
    document.getElementById("exportLoadoutMd").addEventListener("click", () => {
      const items = [...savedIds].map((id) => toolsById.get(id)).filter(Boolean);
      const md = [
        "# OSINT Case Investigation Loadout",
        "",
        ...items.map(
          (t) => `- **[${t.name}](${t.url})** (\`${t.opsec}\`, \`${t.pricing}\`) — ${t.description}\n  - Quick-start: \`${t.quick_start}\``
        ),
      ].join("\n");
      downloadBlob("osint-case-loadout.md", md, "text/markdown;charset=utf-8");
    });
    document.getElementById("clearLoadoutBtn").addEventListener("click", () => {
      savedIds.clear();
      persistLoadout();
      renderLoadout();
      renderArsenal();
    });

    // Modal backdrop & keyboard shortcuts
    const backdrop = document.getElementById("toolModalBackdrop");
    backdrop.addEventListener("click", (e) => {
      if (e.target === backdrop) backdrop.classList.remove("open");
    });

    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape") backdrop.classList.remove("open");
      if (e.key === "/" && document.activeElement.tagName !== "INPUT" && document.activeElement.tagName !== "SELECT") {
        e.preventDefault();
        switchView("arsenal");
        document.getElementById("searchInput").focus();
      }
    });
  }

  initHeaderTelemetry();
  initSelectDropdowns();
  bindGlobalControls();
  initHunterControls();
  renderArsenal();
  renderPivotMatrix();
  renderWorkflows();
  renderDorks();
  renderGraveyard();
})();
