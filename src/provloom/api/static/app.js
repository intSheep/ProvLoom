const TYPE_COLORS = {
  HOST: "#3b82f6",
  PROCESS: "#ec4899",
  USER: "#a855f7",
  FILE: "#10b981",
  NETWORK_ENDPOINT: "#06b6d4",
  SERVICE: "#eab308",
  CONTAINER: "#f97316",
};

function $(id) {
  return document.getElementById(id);
}

function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "className") node.className = v;
    else if (k === "textContent") node.textContent = v;
    else if (k.startsWith("on") && typeof v === "function") {
      node.addEventListener(k.slice(2).toLowerCase(), v);
    } else if (v !== null && v !== undefined) {
      node.setAttribute(k, String(v));
    }
  }
  for (const child of children) {
    if (typeof child === "string") node.appendChild(document.createTextNode(child));
    else if (child) node.appendChild(child);
  }
  return node;
}

function getScopeHeaders() {
  const headers = {
    "Content-Type": "application/json",
    "X-Tenant-Id": $("ctx-tenant").value.trim() || "default",
  };
  const src = $("ctx-sources").value.trim();
  if (src) headers["X-Allowed-Sources"] = src;
  return headers;
}

function getTimeRange() {
  return {
    start_time: $("ctx-start").value.trim(),
    end_time: $("ctx-end").value.trim(),
  };
}

function showBanner(msg, isError = false) {
  const b = $("status-banner");
  b.hidden = false;
  b.textContent = msg;
  b.style.borderColor = isError ? "#ef4444" : "#3b82f6";
}

async function apiFetch(path, options = {}) {
  const res = await fetch(path, {
    ...options,
    headers: { ...getScopeHeaders(), ...(options.headers || {}) },
  });
  if (!res.ok) {
    const errText = await res.text();
    throw new Error(`HTTP ${res.status}: ${errText}`);
  }
  return res.json();
}

// --- Navigation ---
document.querySelectorAll(".nav-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".nav-btn").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    const target = btn.dataset.tab;
    document.querySelectorAll(".view-panel").forEach((p) => {
      p.hidden = p.id !== `tab-${target}`;
    });
    refreshTab(target);
  });
});

async function refreshTab(tab) {
  try {
    if (tab === "overview") await loadOverview();
    else if (tab === "ingestion") await loadFailures();
    else if (tab === "events") await searchEvents();
    else if (tab === "entities") await searchEntities();
    else if (tab === "graph") await initGraphTab();
    else if (tab === "playground") await loadPlayground();
  } catch (err) {
    showBanner(err.message, true);
  }
}

// --- Global Actions ---
$("btn-fit-bounds").addEventListener("click", async () => {
  try {
    const bounds = await apiFetch("/api/v1/ops/time-bounds");
    if (!bounds) {
      showBanner("当前租户尚无标准化事件，请先导入样本。");
      return;
    }
    $("ctx-start").value = bounds.start_time;
    $("ctx-end").value = bounds.end_time;
    showBanner(`已对齐时间窗口: ${bounds.start_time} ~ ${bounds.end_time}`);
  } catch (err) {
    showBanner(err.message, true);
  }
});

$("btn-seed-examples").addEventListener("click", async () => {
  try {
    const res = await apiFetch("/api/v1/ops/batches/examples", { method: "POST" });
    const bounds = await apiFetch("/api/v1/ops/time-bounds");
    if (bounds) {
      $("ctx-start").value = bounds.start_time;
      $("ctx-end").value = bounds.end_time;
    }
    showBanner(
      `标准样本导入完成：批次 ${res.batches_loaded} 个，新增原始记录 ${res.accepted_total} 条，幂等去重 ${res.duplicate_total} 条。`
    );
    const active = document.querySelector(".nav-btn.active")?.dataset.tab || "overview";
    await refreshTab(active);
  } catch (err) {
    showBanner(err.message, true);
  }
});

// --- 1. Overview ---
async function loadOverview() {
  const [snap, batches] = await Promise.all([
    apiFetch("/api/v1/ops/metrics/summary"),
    apiFetch("/api/v1/ops/batches?limit=20"),
  ]);
  const totalAttempt = snap.ingested_total + snap.duplicate_total;
  const dedupRate = totalAttempt > 0 ? ((snap.duplicate_total / totalAttempt) * 100).toFixed(1) : "0.0";
  const parseTotal = snap.parse_success_total + snap.parse_failed_total;
  const parseRate = parseTotal > 0 ? ((snap.parse_success_total / parseTotal) * 100).toFixed(1) : "100.0";

  const cards = [
    ["原始接入新增", snap.ingested_total],
    ["重复拦截 / 重复率", `${snap.duplicate_total} (${dedupRate}%)`],
    ["解析成功率", `${parseRate}% (${snap.parse_failed_total} 失败)`],
    ["OCSF 映射 / 兜底保留", `${snap.normalized_mapped_total} / ${snap.normalized_fallback_total}`],
    ["实体确定性合并次数", snap.entity_merges_total],
    ["确定性事实边 (DETERMINISTIC)", snap.deterministic_relations_total],
    ["候选推断边 (CANDIDATE)", snap.candidate_relations_total],
    ["接入异常死信", snap.ingest_failed_total + snap.normalize_failed_total],
  ];
  const grid = $("metrics-grid");
  grid.replaceChildren(
    ...cards.map(([label, val]) =>
      el("div", { className: "metric-card" }, [
        el("div", { className: "metric-label", textContent: label }),
        el("div", { className: "metric-val", textContent: String(val) }),
      ])
    )
  );

  const tbody = $("overview-batches-table").querySelector("tbody");
  tbody.replaceChildren(
    ...batches.items.map((b) =>
      el("tr", {}, [
        el("td", { textContent: b.received_at }),
        el("td", { textContent: b.source_id }),
        el("td", {}, [el("span", { className: "pill", textContent: `${b.source_type}/${b.adapter_type}` })]),
        el("td", { textContent: String(b.total_count) }),
        el("td", { textContent: String(b.accepted_count) }),
        el("td", { textContent: String(b.duplicate_count) }),
        el("td", { textContent: String(b.failed_count) }),
        el("td", {}, [
          el("span", {
            className: `pill ${b.status === "COMPLETED" ? "pill-ok" : "pill-amber"}`,
            textContent: b.status,
          }),
        ]),
      ])
    )
  );
}
$("btn-refresh-overview").addEventListener("click", loadOverview);

// --- 2. Ingestion & Replay ---
$("imp-file").addEventListener("change", async (ev) => {
  const file = ev.target.files?.[0];
  if (!file) return;
  $("imp-raw-text").value = await file.text();
  if (file.name.endsWith(".csv")) $("imp-adapter").value = "csv";
  else if (file.name.endsWith(".json")) $("imp-adapter").value = "json";
  else $("imp-adapter").value = "jsonl";
});

$("form-raw-import").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  try {
    const res = await apiFetch("/api/v1/ops/batches/raw", {
      method: "POST",
      body: JSON.stringify({
        source_id: $("imp-source-id").value.trim(),
        source_type: $("imp-source-type").value,
        adapter_type: $("imp-adapter").value,
        raw_text: $("imp-raw-text").value,
      }),
    });
    showBanner(`接入完成: 新增 ${res.accepted_count}, 幂等跳过 ${res.duplicate_count}, 失败 ${res.failed_count}`);
    await loadFailures();
  } catch (err) {
    showBanner(err.message, true);
  }
});

$("btn-retry-failures").addEventListener("click", async () => {
  const res = await apiFetch("/api/v1/ops/retry", { method: "POST" });
  showBanner(`重试执行完成: 尝试 ${res.attempted}, 恢复 ${res.succeeded}, 仍失败 ${res.failed}`);
  await loadFailures();
});

$("btn-trigger-replay").addEventListener("click", async () => {
  const res = await apiFetch("/api/v1/ops/replay", {
    method: "POST",
    body: JSON.stringify({}),
  });
  showBanner(
    `全量确定性重建完成: 重放原始日志 ${res.replayed_raw_events} 条 → 实体 ${res.rebuilt_entities} 个, 关系 ${res.rebuilt_relations} 条`
  );
  await loadFailures();
});

async function loadFailures() {
  const page = await apiFetch("/api/v1/ops/failures?limit=50");
  const tbody = $("failures-table").querySelector("tbody");
  if (!page.items.length) {
    tbody.replaceChildren(
      el("tr", {}, [el("td", { colspan: "6", className: "muted", textContent: "当前无失败记录。" })])
    );
    return;
  }
  tbody.replaceChildren(
    ...page.items.map((f) =>
      el("tr", {}, [
        el("td", { textContent: f.occurred_at }),
        el("td", {}, [el("span", { className: "pill pill-amber", textContent: f.stage })]),
        el("td", { textContent: f.error_code }),
        el("td", { textContent: f.error_message }),
        el("td", { textContent: String(f.retry_count) }),
        el("td", { textContent: f.raw_snippet || "-" }),
      ])
    )
  );
}

// --- 3. OCSF Event Explorer ---
async function searchEvents() {
  const clsVal = $("flt-event-class").value;
  const body = {
    time_range: getTimeRange(),
    class_uids: clsVal !== "" ? [Number(clsVal)] : null,
    include_fallback: $("flt-include-fallback").checked,
    limit: 100,
  };
  const page = await apiFetch("/api/v1/events/search", {
    method: "POST",
    body: JSON.stringify(body),
  });
  const tbody = $("events-table").querySelector("tbody");
  tbody.replaceChildren(
    ...page.items.map((item) =>
      el("tr", {}, [
        el("td", { textContent: item.event_time }),
        el("td", { textContent: item.source_id }),
        el("td", {}, [el("span", { className: "pill", textContent: `${item.class_uid} (v${item.ocsf_version})` })]),
        el("td", {}, [
          el("span", {
            className: `pill ${item.normalization_status === "MAPPED" ? "pill-ok" : "pill-amber"}`,
            textContent: item.normalization_status,
          }),
        ]),
        el("td", { textContent: item.original_event_uid || "-" }),
        el("td", {}, [
          el(
            "button",
            {
              type: "button",
              className: "btn-secondary",
              onClick: () => inspectEventDetail(item.event_id),
            },
            ["三栏对照"]
          ),
        ]),
      ])
    )
  );
}
$("btn-search-events").addEventListener("click", searchEvents);

async function inspectEventDetail(eventId) {
  const detail = await apiFetch(`/api/v1/events/${eventId}?include_raw=true`);
  $("dlg-title").textContent = `事件对照 · Rule: ${detail.mapping_rule_id} · Event ${detail.event_id}`;
  $("dlg-raw").textContent = detail.raw
    ? `[source=${detail.raw.source_id} | sha256=${detail.raw.raw_fingerprint}]\n\n${detail.raw.raw_payload}`
    : "(无原始载荷)";
  $("dlg-ocsf").textContent = JSON.stringify(detail.ocsf_payload, null, 2);
  $("dlg-unmapped").textContent = JSON.stringify(detail.unmapped_fields, null, 2);
  $("event-dialog").showModal();
}
$("btn-close-dlg").addEventListener("click", () => $("event-dialog").close());

// --- 4. Entity Inspector ---
async function searchEntities() {
  const et = $("flt-entity-type").value;
  const st = $("flt-entity-state").value;
  const q = $("flt-entity-q").value.trim();
  const page = await apiFetch("/api/v1/entities/search", {
    method: "POST",
    body: JSON.stringify({
      entity_types: et ? [et] : null,
      resolution_states: st ? [st] : null,
      identifier_query: q || null,
      limit: 100,
    }),
  });
  const tbody = $("entities-table").querySelector("tbody");
  tbody.replaceChildren(
    ...page.items.map((ent) =>
      el("tr", {}, [
        el("td", {}, [el("span", { className: "pill", textContent: ent.entity_type })]),
        el("td", { textContent: ent.display_label }),
        el("td", {}, [
          el("span", {
            className: `pill ${ent.resolution_state === "PROVISIONAL" ? "pill-amber" : "pill-ok"}`,
            textContent: ent.resolution_state,
          }),
        ]),
        el("td", {
          className: "muted",
          textContent:
            ent.valid_from || ent.valid_to
              ? `${ent.valid_from || "∞"} → ${ent.valid_to || "active"}`
              : "持久/未限定",
        }),
        el("td", {}, [
          el(
            "button",
            {
              type: "button",
              className: "btn-secondary",
              onClick: () => inspectEntity(ent.entity_id),
            },
            ["详情"]
          ),
          el(
            "button",
            {
              type: "button",
              className: "btn-primary",
              onClick: () => jumpToGraph(ent.entity_id),
            },
            ["查图谱"]
          ),
        ]),
      ])
    )
  );
}
$("btn-search-entities").addEventListener("click", searchEntities);

async function inspectEntity(entityId) {
  const d = await apiFetch(`/api/v1/entities/${entityId}`);
  const pane = $("entity-detail-pane");
  pane.replaceChildren(
    el("h3", { textContent: `${d.entity.entity_type}: ${d.entity.display_label}` }),
    el("p", { className: "muted", textContent: `Entity ID: ${d.entity.entity_id} · State: ${d.entity.resolution_state}` }),
    el("h4", { textContent: "实体属性 (attributes)" }),
    el("pre", { className: "code-box", textContent: JSON.stringify(d.entity.attributes, null, 2) }),
    el("h4", { textContent: `绑定标识与时效窗口 (${d.identifiers.length})` }),
    el("pre", { className: "code-box", textContent: JSON.stringify(d.identifiers, null, 2) }),
    el("h4", { textContent: `实体合并审计记录 (${d.merges.length})` }),
    el("pre", {
      className: "code-box",
      textContent: d.merges.length ? JSON.stringify(d.merges, null, 2) : "无合并记录（独立或首次强键归一）。",
    })
  );
}

async function jumpToGraph(entityId) {
  document.querySelectorAll(".nav-btn").forEach((b) => {
    b.classList.toggle("active", b.dataset.tab === "graph");
  });
  document.querySelectorAll(".view-panel").forEach((p) => {
    p.hidden = p.id !== "tab-graph";
  });
  await initGraphTab(entityId);
}

// --- 5. Provenance Graph & Evidence Chain ---
async function initGraphTab(preferredSeedId = null) {
  const page = await apiFetch("/api/v1/entities/search", {
    method: "POST",
    body: JSON.stringify({ limit: 200 }),
  });
  const sel = $("graph-seed-select");
  const prev = preferredSeedId || sel.value;
  sel.replaceChildren(
    ...page.items.map((e) =>
      el("option", { value: e.entity_id, textContent: `[${e.entity_type}] ${e.display_label}` })
    )
  );
  if (prev && page.items.some((e) => e.entity_id === prev)) {
    sel.value = prev;
  } else {
    const proc = page.items.find((e) => e.entity_type === "PROCESS");
    if (proc) sel.value = proc.entity_id;
  }
  if (sel.value) await runTraverse();
}

$("btn-run-traverse").addEventListener("click", runTraverse);

async function runTraverse() {
  const seedId = $("graph-seed-select").value;
  if (!seedId) return;
  const sub = await apiFetch("/api/v1/graph/traverse", {
    method: "POST",
    body: JSON.stringify({
      seed_entity_id: seedId,
      time_range: getTimeRange(),
      max_depth: Number($("graph-depth").value),
      direction: $("graph-direction").value,
      include_candidates: $("graph-candidates").checked,
    }),
  });
  renderSvgGraph(sub);
}

function renderSvgGraph(sub) {
  const svg = $("graph-svg");
  const ns = "http://www.w3.org/2000/svg";
  svg.replaceChildren();

  // Arrowhead markers for solid DETERMINISTIC vs amber CANDIDATE edges
  const defs = document.createElementNS(ns, "defs");
  for (const [id, color] of [
    ["arrow-det", "#60a5fa"],
    ["arrow-cand", "#f59e0b"],
  ]) {
    const marker = document.createElementNS(ns, "marker");
    marker.setAttribute("id", id);
    marker.setAttribute("viewBox", "0 0 10 10");
    marker.setAttribute("refX", "24");
    marker.setAttribute("refY", "5");
    marker.setAttribute("markerWidth", "6");
    marker.setAttribute("markerHeight", "6");
    marker.setAttribute("orient", "auto-start-reverse");
    const path = document.createElementNS(ns, "path");
    path.setAttribute("d", "M 0 1 L 10 5 L 0 9 z");
    path.setAttribute("fill", color);
    marker.appendChild(path);
    defs.appendChild(marker);
  }
  svg.appendChild(defs);

  const nodes = sub.nodes;
  if (!nodes.length) return;

  // Layered radial/column layout around seed entity
  const cx = 480;
  const cy = 280;
  const pos = new Map();
  const others = nodes.filter((n) => n.entity_id !== sub.seed_entity_id);
  pos.set(sub.seed_entity_id, { x: cx, y: cy });
  others.forEach((n, idx) => {
    const angle = (2 * Math.PI * idx) / Math.max(others.length, 1) - Math.PI / 2;
    const rx = Math.min(360, 170 + others.length * 14);
    const ry = Math.min(210, 130 + others.length * 9);
    pos.set(n.entity_id, { x: cx + rx * Math.cos(angle), y: cy + ry * Math.sin(angle) });
  });

  // Group parallel edges for curve offset
  const pairCounts = new Map();
  sub.edges.forEach((edge) => {
    const p1 = pos.get(edge.src_entity_id);
    const p2 = pos.get(edge.dst_entity_id);
    if (!p1 || !p2) return;
    const pairKey = [edge.src_entity_id, edge.dst_entity_id].sort().join(":");
    const idx = pairCounts.get(pairKey) || 0;
    pairCounts.set(pairKey, idx + 1);

    const dx = p2.x - p1.x;
    const dy = p2.y - p1.y;
    const norm = Math.hypot(dx, dy) || 1;
    const offset = idx === 0 ? 0 : (idx % 2 === 1 ? 26 : -26) * Math.ceil(idx / 2);
    const mx = (p1.x + p2.x) / 2 - (dy / norm) * offset;
    const my = (p1.y + p2.y) / 2 + (dx / norm) * offset;

    const isCand = edge.certainty === "CANDIDATE";
    const g = document.createElementNS(ns, "g");
    g.style.cursor = "pointer";
    g.addEventListener("click", () => loadEdgeEvidence(edge));

    const path = document.createElementNS(ns, "path");
    path.setAttribute("d", `M ${p1.x} ${p1.y} Q ${mx} ${my} ${p2.x} ${p2.y}`);
    path.setAttribute("fill", "none");
    path.setAttribute("stroke", isCand ? "#f59e0b" : "#60a5fa");
    path.setAttribute("stroke-width", edge.evidence_count > 1 ? "2.6" : "1.8");
    if (isCand) path.setAttribute("stroke-dasharray", "6 4");
    path.setAttribute("marker-end", isCand ? "url(#arrow-cand)" : "url(#arrow-det)");
    g.appendChild(path);

    const label = document.createElementNS(ns, "text");
    label.setAttribute("x", String(mx));
    label.setAttribute("y", String(my - 4));
    label.setAttribute("text-anchor", "middle");
    label.setAttribute("fill", isCand ? "#fcd34d" : "#cbd5e1");
    label.setAttribute("font-size", "10.5");
    label.textContent = `${edge.relation_type}${isCand ? " (?)" : ""} [${edge.evidence_count}]`;
    g.appendChild(label);

    svg.appendChild(g);
  });

  nodes.forEach((n) => {
    const p = pos.get(n.entity_id);
    if (!p) return;
    const g = document.createElementNS(ns, "g");
    g.style.cursor = "pointer";
    g.addEventListener("dblclick", () => {
      $("graph-seed-select").value = n.entity_id;
      runTraverse();
    });

    const circle = document.createElementNS(ns, "circle");
    circle.setAttribute("cx", String(p.x));
    circle.setAttribute("cy", String(p.y));
    circle.setAttribute("r", n.entity_id === sub.seed_entity_id ? "20" : "16");
    circle.setAttribute("fill", "#0f172a");
    circle.setAttribute("stroke", TYPE_COLORS[n.entity_type] || "#94a3b8");
    circle.setAttribute("stroke-width", n.entity_id === sub.seed_entity_id ? "3" : "2");
    if (n.resolution_state === "PROVISIONAL") {
      circle.setAttribute("stroke-dasharray", "4 3");
    }
    g.appendChild(circle);

    const badge = document.createElementNS(ns, "text");
    badge.setAttribute("x", String(p.x));
    badge.setAttribute("y", String(p.y + 4));
    badge.setAttribute("text-anchor", "middle");
    badge.setAttribute("fill", "#f8fafc");
    badge.setAttribute("font-size", "9.5");
    badge.setAttribute("font-weight", "700");
    badge.textContent = n.entity_type.slice(0, 4);
    g.appendChild(badge);

    const title = document.createElementNS(ns, "text");
    title.setAttribute("x", String(p.x));
    title.setAttribute("y", String(p.y + 31));
    title.setAttribute("text-anchor", "middle");
    title.setAttribute("fill", "#e2e8f0");
    title.setAttribute("font-size", "11");
    title.textContent =
      n.display_label.length > 28 ? `${n.display_label.slice(0, 26)}…` : n.display_label;
    g.appendChild(title);

    svg.appendChild(g);
  });
}

async function loadEdgeEvidence(edge) {
  const page = await apiFetch(`/api/v1/relations/${edge.relation_id}/evidence`);
  const pane = $("evidence-pane");
  pane.replaceChildren(
    el("h3", { textContent: `${edge.relation_type} (${edge.certainty})` }),
    el("p", {
      className: "muted",
      textContent: `Rule: ${edge.correlation_rule_id} · 聚合原始证据数: ${edge.evidence_count}`,
    }),
    el("h4", { textContent: "关联依据 (correlation_basis)" }),
    el("pre", { className: "code-box", textContent: JSON.stringify(edge.correlation_basis, null, 2) }),
    el("h4", { textContent: `反向追溯原始日志 (${page.items.length})` }),
    ...page.items.map((ev) =>
      el("div", { className: "card", style: "margin-bottom:8px" }, [
        el("div", {
          textContent: `[${ev.evidence_role}] source=${ev.source_id} · class=${ev.ocsf_class_uid} · ${ev.observed_at}`,
        }),
        el("pre", { className: "code-box", textContent: ev.raw_payload }),
      ])
    )
  );
}

// --- 6. API Playground ---
async function loadPlayground() {
  const rules = await apiFetch("/api/v1/ops/mappings");
  const tbody = $("mappings-table").querySelector("tbody");
  tbody.replaceChildren(
    ...rules.map((r) =>
      el("tr", {}, [
        el("td", { textContent: r.rule_id }),
        el("td", { textContent: r.parser_id }),
        el("td", { textContent: r.event_code ?? "*" }),
        el("td", {}, [el("span", { className: "pill", textContent: String(r.class_uid) })]),
      ])
    )
  );
  syncPlaygroundPreset();
}

function syncPlaygroundPreset() {
  const p = $("pg-preset").value;
  if (p === "events_search") {
    $("pg-body").value = JSON.stringify({ time_range: getTimeRange(), limit: 10 }, null, 2);
  } else if (p === "entities_search") {
    $("pg-body").value = JSON.stringify({ entity_types: ["PROCESS", "HOST"], limit: 20 }, null, 2);
  } else {
    $("pg-body").value = "";
  }
}
$("pg-preset").addEventListener("change", syncPlaygroundPreset);

$("btn-run-pg").addEventListener("click", async () => {
  const p = $("pg-preset").value;
  const t0 = performance.now();
  try {
    let data;
    if (p === "events_search") {
      data = await apiFetch("/api/v1/events/search", { method: "POST", body: $("pg-body").value });
    } else if (p === "entities_search") {
      data = await apiFetch("/api/v1/entities/search", { method: "POST", body: $("pg-body").value });
    } else {
      data = await apiFetch("/api/v1/ops/metrics/summary");
    }
    const ms = (performance.now() - t0).toFixed(1);
    $("pg-output").textContent = `// 200 OK (${ms} ms)\n` + JSON.stringify(data, null, 2);
  } catch (err) {
    $("pg-output").textContent = err.message;
  }
});

// Initial load
loadOverview().catch((e) => showBanner(e.message, true));
