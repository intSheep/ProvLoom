import { useEffect, useMemo, useRef, useState } from "react";
import cytoscape, { type Core, type StylesheetStyle } from "cytoscape";
import dagre from "cytoscape-dagre";
import type { EntityType } from "../../api/types";
import { useConsoleContext } from "../../state/ConsoleContext";
import type { GraphLayoutMode, ProvenanceGraphCanvasProps } from "../contracts";

cytoscape.use(dagre);

const ENTITY_COLORS: Record<EntityType, string> = {
  HOST: "#3b82f6",
  PROCESS: "#ec4899",
  USER: "#a855f7",
  FILE: "#10b981",
  NETWORK_ENDPOINT: "#06b6d4",
  SERVICE: "#eab308",
  CONTAINER: "#f97316",
};

const ENTITY_SHAPES: Record<EntityType, string> = {
  HOST: "round-rectangle",
  PROCESS: "round-hexagon",
  USER: "diamond",
  FILE: "rectangle",
  NETWORK_ENDPOINT: "vee",
  SERVICE: "octagon",
  CONTAINER: "barrel",
};

function buildCytoscapeStyles(isDark: boolean): StylesheetStyle[] {
  const nodeBg = isDark ? "#0f172a" : "#ffffff";
  const nodeText = isDark ? "#e2e8f0" : "#0f172a";
  const edgeText = isDark ? "#cbd5e1" : "#334155";
  const edgeTextBg = isDark ? "#070b14" : "#f8fafc";
  const detColor = isDark ? "#60a5fa" : "#2563eb";
  const candColor = "#f59e0b";

  const typeRules: StylesheetStyle[] = (Object.keys(ENTITY_COLORS) as EntityType[]).map(
    (type) => ({
      selector: `node[entityType = "${type}"]`,
      style: {
        shape: ENTITY_SHAPES[type] as cytoscape.Css.NodeShape,
        "border-color": ENTITY_COLORS[type],
      },
    }),
  );

  return [
    {
      selector: "node",
      style: {
        label: "data(label)",
        "background-color": nodeBg,
        "border-width": 2,
        "border-color": detColor,
        color: nodeText,
        "font-size": 10.5,
        "font-weight": 500,
        "text-valign": "bottom",
        "text-margin-y": 6,
        "text-wrap": "ellipsis",
        "text-max-width": "185px",
        width: 34,
        height: 34,
      },
    },
    ...typeRules,
    {
      selector: "node[?isSeed]",
      style: {
        width: 42,
        height: 42,
        "border-width": 3.5,
        "font-weight": 700,
      },
    },
    {
      selector: 'node[state = "PROVISIONAL"]',
      style: {
        "border-style": "dashed",
        "border-color": candColor,
        "border-width": 2.5,
      },
    },
    {
      selector: "node.selected-item",
      style: {
        "underlay-color": detColor,
        "underlay-padding": 6,
        "underlay-opacity": 0.25,
      },
    },
    {
      selector: "edge",
      style: {
        label: "data(label)",
        "curve-style": "bezier",
        "control-point-step-size": 44,
        "target-arrow-shape": "triangle",
        "arrow-scale": 0.9,
        "line-color": detColor,
        "target-arrow-color": detColor,
        width: "data(edgeWidth)",
        color: edgeText,
        "font-size": 9.5,
        "text-background-color": edgeTextBg,
        "text-background-opacity": 0.85,
        "text-background-padding": "2px",
        "text-rotation": "autorotate",
      },
    },
    {
      selector: 'edge[certainty = "CANDIDATE"]',
      style: {
        "line-style": "dashed",
        "line-dash-pattern": [6, 4],
        "line-color": candColor,
        "target-arrow-color": candColor,
        color: isDark ? "#fcd34d" : "#b45309",
      },
    },
    {
      selector: "edge.selected-item",
      style: {
        width: 3.5,
        "underlay-color": candColor,
        "underlay-padding": 3,
        "underlay-opacity": 0.25,
      },
    },
    {
      selector: ".dimmed",
      style: {
        opacity: 0.22,
      },
    },
  ];
}

function getLayoutOptions(mode: GraphLayoutMode): cytoscape.LayoutOptions {
  if (mode === "dagre") {
    return {
      name: "dagre",
      rankDir: "LR",
      nodeSep: 56,
      rankSep: 120,
      padding: 32,
    } as cytoscape.LayoutOptions;
  }
  if (mode === "dagre-tb") {
    return {
      name: "dagre",
      rankDir: "TB",
      nodeSep: 56,
      rankSep: 92,
      padding: 32,
    } as cytoscape.LayoutOptions;
  }
  return {
    name: "cose",
    animate: false,
    padding: 32,
    nodeRepulsion: () => 9000,
    idealEdgeLength: () => 130,
  } as cytoscape.LayoutOptions;
}

export function ProvenanceGraphCanvas({
  nodes,
  edges,
  seedEntityId = null,
  selectedEntityId = null,
  selectedRelationId = null,
  includeCandidates,
  layout,
  onLayoutChange,
  onSelectEntity,
  onExpandEntity,
  onSelectRelation,
}: ProvenanceGraphCanvasProps) {
  const { resolvedTheme } = useConsoleContext();
  const containerRef = useRef<HTMLDivElement | null>(null);
  const cyRef = useRef<Core | null>(null);
  const prevTopologyRef = useRef<string>("");
  const [nodeSearch, setNodeSearch] = useState("");

  const callbacksRef = useRef({ onSelectEntity, onExpandEntity, onSelectRelation });
  callbacksRef.current = { onSelectEntity, onExpandEntity, onSelectRelation };

  const visibleEdges = useMemo(
    () =>
      includeCandidates ? edges : edges.filter((e) => e.certainty === "DETERMINISTIC"),
    [edges, includeCandidates],
  );

  // Initialize cytoscape instance once.
  useEffect(() => {
    if (!containerRef.current) return;

    const cy = cytoscape({
      container: containerRef.current,
      elements: [],
      style: buildCytoscapeStyles(resolvedTheme === "dark"),
      minZoom: 0.2,
      maxZoom: 3,
      wheelSensitivity: 0.25,
    });

    cy.on("tap", "node", (evt) => {
      callbacksRef.current.onSelectEntity(String(evt.target.id()));
    });
    cy.on("dbltap", "node", (evt) => {
      callbacksRef.current.onExpandEntity?.(String(evt.target.id()));
    });
    cy.on("tap", "edge", (evt) => {
      callbacksRef.current.onSelectRelation(String(evt.target.id()));
    });

    cyRef.current = cy;
    return () => {
      cy.destroy();
      cyRef.current = null;
      prevTopologyRef.current = "";
    };
    // Theme updates are synced in a dedicated effect without recreating the canvas.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Update theme styles without resetting viewport or positions.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.style(buildCytoscapeStyles(resolvedTheme === "dark"));
  }, [resolvedTheme]);

  // Incrementally sync elements and run layout only when topology or layout mode changes.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;

    const desiredNodes = new Map(
      nodes.map((n) => [
        n.entity_id,
        {
          id: n.entity_id,
          label: `[${n.entity_type.slice(0, 4)}] ${n.display_label}`,
          entityType: n.entity_type,
          state: n.resolution_state,
          isSeed: n.entity_id === seedEntityId,
        },
      ]),
    );

    const desiredEdges = new Map(
      visibleEdges
        .filter((e) => desiredNodes.has(e.src_entity_id) && desiredNodes.has(e.dst_entity_id))
        .map((e) => [
          e.relation_id,
          {
            id: e.relation_id,
            source: e.src_entity_id,
            target: e.dst_entity_id,
            label: `${e.relation_type}${e.certainty === "CANDIDATE" ? " (?)" : ""} [${e.evidence_count}]`,
            certainty: e.certainty,
            edgeWidth: e.evidence_count > 1 ? 2.8 : 1.8,
          },
        ]),
    );

    cy.batch(() => {
      cy.edges().forEach((edge) => {
        if (!desiredEdges.has(edge.id())) edge.remove();
      });
      cy.nodes().forEach((node) => {
        if (!desiredNodes.has(node.id())) node.remove();
      });

      for (const [id, data] of desiredNodes) {
        const existing = cy.getElementById(id);
        if (existing.length > 0) {
          existing.data(data);
        } else {
          cy.add({ group: "nodes", data });
        }
      }

      for (const [id, data] of desiredEdges) {
        const existing = cy.getElementById(id);
        if (existing.length > 0) {
          existing.data(data);
        } else {
          cy.add({ group: "edges", data });
        }
      }
    });

    const topologySignature = [
      layout,
      Array.from(desiredNodes.keys()).sort().join(","),
      Array.from(desiredEdges.keys()).sort().join(","),
    ].join("|");

    if (topologySignature !== prevTopologyRef.current && desiredNodes.size > 0) {
      prevTopologyRef.current = topologySignature;
      cy.layout(getLayoutOptions(layout)).run();
    }
  }, [nodes, visibleEdges, seedEntityId, layout]);

  // Apply selection & neighborhood highlight classes without moving nodes.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;

    cy.batch(() => {
      cy.elements().removeClass("selected-item dimmed");
      if (selectedEntityId) {
        const node = cy.getElementById(selectedEntityId);
        if (node.length > 0) {
          const hood = node.closedNeighborhood();
          cy.elements().difference(hood).addClass("dimmed");
          node.addClass("selected-item");
        }
      } else if (selectedRelationId) {
        const edge = cy.getElementById(selectedRelationId);
        if (edge.length > 0) {
          const endpoints = edge.connectedNodes().union(edge);
          cy.elements().difference(endpoints).addClass("dimmed");
          edge.addClass("selected-item");
        }
      }
    });
  }, [selectedEntityId, selectedRelationId, nodes, visibleEdges]);

  function handleLocateNode(query: string) {
    setNodeSearch(query);
    const cy = cyRef.current;
    if (!cy || !query.trim()) return;
    const q = query.trim().toLowerCase();
    const hit = nodes.find(
      (n) =>
        n.display_label.toLowerCase().includes(q) ||
        n.entity_id.toLowerCase().includes(q) ||
        (n.canonical_key?.toLowerCase().includes(q) ?? false),
    );
    if (hit) {
      const ele = cy.getElementById(hit.entity_id);
      if (ele.length > 0) {
        cy.animate({ center: { eles: ele }, zoom: Math.max(cy.zoom(), 1.1) }, { duration: 220 });
        onSelectEntity(hit.entity_id);
      }
    }
  }

  function handleExportPng() {
    const cy = cyRef.current;
    if (!cy) return;
    const uri = cy.png({
      bg: resolvedTheme === "dark" ? "#070b14" : "#ffffff",
      full: true,
      scale: 2,
    });
    const a = document.createElement("a");
    a.href = uri;
    a.download = `provloom-subgraph-${seedEntityId ?? "graph"}.png`;
    a.click();
  }

  return (
    <div className="flex flex-col">
      <div className="flex flex-wrap items-center justify-between gap-2 px-3 py-2 border-b border-[var(--pl-border)] bg-[var(--pl-surface-alt)] text-xs">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-mono-code text-[11px] text-[var(--pl-text-muted)]">
            节点 {nodes.length} · 边 {visibleEdges.length}
          </span>
          {onLayoutChange && (
            <select
              aria-label="图谱布局"
              value={layout}
              onChange={(e) => onLayoutChange(e.target.value as GraphLayoutMode)}
              className="pl-input text-[11px]"
            >
              <option value="dagre">Dagre 水平进程树 (LR)</option>
              <option value="dagre-tb">Dagre 垂直层次树 (TB)</option>
              <option value="fcose">力导向关联网络 (CoSE)</option>
            </select>
          )}
          <input
            type="search"
            value={nodeSearch}
            onChange={(e) => handleLocateNode(e.target.value)}
            placeholder="画布内定位节点…"
            className="pl-input w-40 text-[11px]"
          />
        </div>

        <div className="flex items-center gap-1.5">
          <button
            type="button"
            onClick={() => cyRef.current?.zoom(cyRef.current.zoom() * 1.2)}
            className="px-2 py-1 rounded border border-[var(--pl-border-strong)] bg-[var(--pl-surface)] text-[11px] cursor-pointer"
            title="放大"
          >
            +
          </button>
          <button
            type="button"
            onClick={() => cyRef.current?.zoom(cyRef.current.zoom() / 1.2)}
            className="px-2 py-1 rounded border border-[var(--pl-border-strong)] bg-[var(--pl-surface)] text-[11px] cursor-pointer"
            title="缩小"
          >
            −
          </button>
          <button
            type="button"
            onClick={() => cyRef.current?.fit(undefined, 28)}
            className="px-2 py-1 rounded border border-[var(--pl-border-strong)] bg-[var(--pl-surface)] text-[11px] cursor-pointer"
          >
            适配画布
          </button>
          <button
            type="button"
            onClick={() => {
              const cy = cyRef.current;
              if (cy && nodes.length > 0) cy.layout(getLayoutOptions(layout)).run();
            }}
            className="px-2 py-1 rounded border border-[var(--pl-border-strong)] bg-[var(--pl-surface)] text-[11px] cursor-pointer"
          >
            重排
          </button>
          <button
            type="button"
            onClick={handleExportPng}
            className="px-2 py-1 rounded border border-[var(--pl-border-strong)] bg-[var(--pl-surface)] text-[11px] cursor-pointer"
          >
            导出 PNG
          </button>
        </div>
      </div>

      <div className="relative bg-[var(--pl-code-bg)]">
        <div ref={containerRef} className="w-full h-[560px]" />
        {nodes.length === 0 && (
          <div className="absolute inset-0 flex items-center justify-center pointer-events-none text-xs text-[var(--pl-text-muted)]">
            请先在上方选择种子实体并执行子图遍历，或先导入内置标准样本。
          </div>
        )}
      </div>
    </div>
  );
}
