import { useEffect, useRef } from "react";
import cytoscape from "cytoscape";
import dagre from "cytoscape-dagre";
import type { ProvenanceGraphCanvasProps } from "./contracts";

cytoscape.use(dagre);

export function ProvenanceGraphCanvas({
  nodes,
  edges,
  includeCandidates,
  layout,
  onSelectEntity,
  onSelectRelation,
}: ProvenanceGraphCanvasProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!containerRef.current) return;
    const visibleEdges = includeCandidates
      ? edges
      : edges.filter((e) => e.certainty === "DETERMINISTIC");

    const cy = cytoscape({
      container: containerRef.current,
      elements: [
        ...nodes.map((n) => ({
          data: {
            id: n.entity_id,
            label: `[${n.entity_type}] ${n.display_label}`,
            entityType: n.entity_type,
            state: n.resolution_state,
          },
        })),
        ...visibleEdges.map((e) => ({
          data: {
            id: e.relation_id,
            source: e.src_entity_id,
            target: e.dst_entity_id,
            label: `${e.relation_type} (${e.evidence_count})`,
            certainty: e.certainty,
          },
        })),
      ],
      style: [
        {
          selector: "node",
          style: {
            label: "data(label)",
            "background-color": "#1e293b",
            "border-width": 2,
            "border-color": "#3b82f6",
            color: "#e2e8f0",
            "font-size": 11,
          },
        },
        {
          selector: 'node[state = "PROVISIONAL"]',
          style: {
            "border-style": "dashed",
            "border-color": "#f59e0b",
          },
        },
        {
          selector: "edge",
          style: {
            label: "data(label)",
            "curve-style": "bezier",
            "target-arrow-shape": "triangle",
            "line-color": "#60a5fa",
            "target-arrow-color": "#60a5fa",
            width: 2,
            color: "#cbd5e1",
            "font-size": 10,
          },
        },
        {
          selector: 'edge[certainty = "CANDIDATE"]',
          style: {
            "line-style": "dashed",
            "line-color": "#f59e0b",
            "target-arrow-color": "#f59e0b",
          },
        },
      ],
      layout:
        layout === "dagre"
          ? ({ name: "dagre", rankDir: "LR" } as cytoscape.LayoutOptions)
          : { name: "cose" },
    });

    cy.on("tap", "node", (evt) => onSelectEntity(String(evt.target.id())));
    cy.on("tap", "edge", (evt) => onSelectRelation(String(evt.target.id())));

    return () => cy.destroy();
  }, [nodes, edges, includeCandidates, layout, onSelectEntity, onSelectRelation]);

  return <div ref={containerRef} style={{ width: "100%", height: "540px" }} />;
}
