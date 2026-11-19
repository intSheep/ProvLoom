import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { queryApi } from "../api/client";
import {
  useEntitiesSearchQuery,
  useGraphTraverseQuery,
  useRelationEvidenceQuery,
} from "../api/hooks";
import type {
  Direction,
  EntityDto,
  GraphTraverseRequest,
  RelationDto,
  RelationType,
} from "../api/types";
import { JsonViewer } from "../components/common/JsonViewer";
import { EntityTypePill, ResolutionStatePill } from "../components/common/StatusPill";
import type { GraphLayoutMode } from "../components/contracts";
import { RelationEvidenceDrawer } from "../components/evidence-drawer/RelationEvidenceDrawer";
import { ProvenanceGraphCanvas } from "../components/graph-canvas/ProvenanceGraphCanvas";
import { useConsoleContext } from "../state/ConsoleContext";

const ALL_RELATION_TYPES: RelationType[] = [
  "RUNS",
  "SPAWNS",
  "READS",
  "WRITES",
  "CONNECTS_TO",
  "AUTHENTICATES_TO",
  "ACCESSES",
  "RESOLVES",
];

export function GraphWorkbenchPage() {
  const { scope, timeRange, showNotice } = useConsoleContext();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const urlSeed = searchParams.get("seed");

  const [maxDepth, setMaxDepth] = useState(2);
  const [direction, setDirection] = useState<Direction>("BOTH");
  const [includeCandidates, setIncludeCandidates] = useState(false);
  const [selectedRelTypes, setSelectedRelTypes] = useState<RelationType[]>([]);
  const [layout, setLayout] = useState<GraphLayoutMode>("dagre");
  const [seedFilter, setSeedFilter] = useState("");

  const [selectedEntityId, setSelectedEntityId] = useState<string | null>(null);
  const [selectedRelationId, setSelectedRelationId] = useState<string | null>(null);
  const [expandedNodes, setExpandedNodes] = useState<EntityDto[]>([]);
  const [expandedEdges, setExpandedEdges] = useState<RelationDto[]>([]);
  const [isExpanding, setIsExpanding] = useState(false);
  const [anyTruncated, setAnyTruncated] = useState(false);

  const entitiesQ = useEntitiesSearchQuery(scope, { limit: 200 });
  const entityOptions = entitiesQ.data?.items ?? [];

  const activeSeedId = useMemo(() => {
    if (urlSeed) return urlSeed;
    const proc = entityOptions.find((e) => e.entity_type === "PROCESS");
    return proc?.entity_id ?? entityOptions[0]?.entity_id ?? "";
  }, [urlSeed, entityOptions]);

  const filteredSeedOptions = useMemo(() => {
    const q = seedFilter.trim().toLowerCase();
    if (!q) return entityOptions;
    return entityOptions.filter(
      (e) =>
        e.display_label.toLowerCase().includes(q) ||
        e.entity_type.toLowerCase().includes(q) ||
        e.entity_id.toLowerCase().includes(q),
    );
  }, [entityOptions, seedFilter]);

  const traverseReq = useMemo<GraphTraverseRequest | null>(() => {
    if (!activeSeedId) return null;
    return {
      seed_entity_id: activeSeedId,
      time_range: timeRange,
      max_depth: maxDepth,
      direction,
      relation_types: selectedRelTypes.length ? selectedRelTypes : null,
      include_candidates: includeCandidates,
      max_nodes: 200,
      max_edges: 500,
    };
  }, [activeSeedId, timeRange, maxDepth, direction, selectedRelTypes, includeCandidates]);

  const traverseQ = useGraphTraverseQuery(scope, traverseReq);
  const evidenceQ = useRelationEvidenceQuery(scope, selectedRelationId);

  // Reset incremental overlay when base traversal changes.
  useEffect(() => {
    if (!traverseQ.data) return;
    setExpandedNodes(traverseQ.data.nodes);
    setExpandedEdges(traverseQ.data.edges);
    setAnyTruncated(traverseQ.data.truncated);
  }, [traverseQ.data]);

  const handleExpandEntity = useCallback(
    async (entityId: string) => {
      setIsExpanding(true);
      try {
        const sub = await queryApi.traverseGraph(scope, {
          seed_entity_id: entityId,
          time_range: timeRange,
          max_depth: 1,
          direction,
          relation_types: selectedRelTypes.length ? selectedRelTypes : null,
          include_candidates: includeCandidates,
          max_nodes: 200,
          max_edges: 500,
        });
        let addedNodes = 0;
        setExpandedNodes((prev) => {
          const map = new Map(prev.map((n) => [n.entity_id, n]));
          for (const n of sub.nodes) {
            if (!map.has(n.entity_id)) addedNodes++;
            map.set(n.entity_id, n);
          }
          return Array.from(map.values());
        });
        setExpandedEdges((prev) => {
          const map = new Map(prev.map((e) => [e.relation_id, e]));
          for (const e of sub.edges) {
            map.set(e.relation_id, e);
          }
          return Array.from(map.values());
        });
        if (sub.truncated) setAnyTruncated(true);
        setSelectedEntityId(entityId);
        showNotice(
          "info",
          `已从选中节点增量展开 1 跳邻居：新增 ${addedNodes} 个节点（总计 ${sub.nodes.length} 节点 / ${sub.edges.length} 边局部子图）。`,
        );
      } catch (err) {
        showNotice("error", err instanceof Error ? err.message : "增量展开失败");
      } finally {
        setIsExpanding(false);
      }
    },
    [scope, timeRange, direction, selectedRelTypes, includeCandidates, showNotice],
  );

  const selectedNode = useMemo(
    () => expandedNodes.find((n) => n.entity_id === selectedEntityId) ?? null,
    [expandedNodes, selectedEntityId],
  );

  const selectedRelation = useMemo(
    () => expandedEdges.find((e) => e.relation_id === selectedRelationId) ?? null,
    [expandedEdges, selectedRelationId],
  );

  function toggleRelationType(rt: RelationType) {
    setSelectedRelTypes((prev) =>
      prev.includes(rt) ? prev.filter((item) => item !== rt) : [...prev, rt],
    );
  }

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-base font-semibold m-0">交互式溯源关系图谱与原始证据链</h1>
          <p className="text-xs text-[var(--pl-text-muted)] m-0 mt-0.5">
            单击边反查全部终端/网络原始日志（AC-06/07）；双击节点增量展开 1 跳邻居；实线=DETERMINISTIC，琥珀虚线=CANDIDATE（AC-09）。
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            disabled={!activeSeedId || traverseQ.isFetching}
            onClick={() => void traverseQ.refetch()}
            className="px-3 py-1.5 rounded-md bg-[var(--pl-accent)] text-white text-xs font-semibold cursor-pointer disabled:opacity-60"
          >
            {traverseQ.isFetching ? "遍历中…" : "重新遍历子图"}
          </button>
        </div>
      </div>

      <div className="pl-surface rounded-lg p-3 space-y-2.5">
        <div className="flex flex-wrap items-end gap-3">
          <label className="flex flex-col gap-1 text-xs">
            <span className="text-[var(--pl-text-muted)]">过滤种子列表</span>
            <input
              type="search"
              value={seedFilter}
              onChange={(e) => setSeedFilter(e.target.value)}
              placeholder="输入关键字过滤实体…"
              className="pl-input w-40"
            />
          </label>

          <label className="flex flex-col gap-1 text-xs flex-1 min-w-[240px]">
            <span className="text-[var(--pl-text-muted)]">种子实体 (Seed Entity)</span>
            <select
              aria-label="Seed Entity"
              value={activeSeedId}
              onChange={(e) => {
                setSelectedEntityId(null);
                setSelectedRelationId(null);
                setSearchParams(e.target.value ? { seed: e.target.value } : {});
              }}
              className="pl-input font-mono-code"
            >
              {filteredSeedOptions.length === 0 ? (
                <option value="">暂无匹配实体</option>
              ) : (
                filteredSeedOptions.map((ent) => (
                  <option key={ent.entity_id} value={ent.entity_id}>
                    [{ent.entity_type}] {ent.display_label} ({ent.resolution_state})
                  </option>
                ))
              )}
            </select>
          </label>

          <label className="flex flex-col gap-1 text-xs">
            <span className="text-[var(--pl-text-muted)]">深度 (1–6 跳)</span>
            <select
              aria-label="Max Depth"
              value={maxDepth}
              onChange={(e) => setMaxDepth(Number(e.target.value))}
              className="pl-input font-mono-code"
            >
              {[1, 2, 3, 4, 5, 6].map((d) => (
                <option key={d} value={d}>
                  {d} 跳
                </option>
              ))}
            </select>
          </label>

          <label className="flex flex-col gap-1 text-xs">
            <span className="text-[var(--pl-text-muted)]">遍历方向</span>
            <select
              aria-label="Traversal Direction"
              value={direction}
              onChange={(e) => setDirection(e.target.value as Direction)}
              className="pl-input font-mono-code"
            >
              <option value="BOTH">双向 (BOTH)</option>
              <option value="OUTBOUND">出边 (OUTBOUND)</option>
              <option value="INBOUND">入边 (INBOUND)</option>
            </select>
          </label>

          <label className="inline-flex items-center gap-1.5 text-xs pb-1.5 cursor-pointer">
            <input
              type="checkbox"
              checked={includeCandidates}
              onChange={(e) => setIncludeCandidates(e.target.checked)}
            />
            <span>包含 CANDIDATE 候选边</span>
          </label>
        </div>

        <div className="flex flex-wrap items-center gap-1.5 text-[11px]">
          <span className="text-[var(--pl-text-muted)] mr-1">关系过滤:</span>
          {ALL_RELATION_TYPES.map((rt) => {
            const active = selectedRelTypes.includes(rt);
            return (
              <button
                key={rt}
                type="button"
                aria-pressed={active}
                onClick={() => toggleRelationType(rt)}
                className={[
                  "px-2 py-0.5 rounded border font-mono-code cursor-pointer transition-colors",
                  active
                    ? "border-[var(--pl-accent)] bg-[var(--pl-accent-soft)] text-[var(--pl-accent)] font-semibold"
                    : "border-[var(--pl-border)] bg-[var(--pl-surface-alt)] text-[var(--pl-text-muted)]",
                ].join(" ")}
              >
                {rt}
              </button>
            );
          })}
          {selectedRelTypes.length > 0 && (
            <button
              type="button"
              onClick={() => setSelectedRelTypes([])}
              className="px-2 py-0.5 text-[11px] text-[var(--pl-accent)] hover:underline cursor-pointer"
            >
              清空筛选
            </button>
          )}
        </div>
      </div>

      {traverseQ.isError && (
        <div role="alert" className="rounded-md border border-red-500/60 bg-red-500/10 p-3 text-xs text-red-400">
          图谱遍历失败：{traverseQ.error.message}
        </div>
      )}

      {anyTruncated && (
        <div className="rounded-md border border-amber-500/60 bg-amber-500/10 px-3 py-2 text-xs text-amber-500">
          图遍历触及护栏上限（max_nodes=200 / max_edges=500，truncated=true）。建议缩小深度、收窄时间窗或限定关系类型。
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 items-start">
        <div className="lg:col-span-8 pl-surface rounded-lg overflow-hidden">
          <ProvenanceGraphCanvas
            nodes={expandedNodes}
            edges={expandedEdges}
            seedEntityId={activeSeedId || null}
            selectedEntityId={selectedEntityId}
            selectedRelationId={selectedRelationId}
            includeCandidates={includeCandidates}
            layout={layout}
            onLayoutChange={setLayout}
            onSelectEntity={(id) => {
              setSelectedEntityId(id);
              setSelectedRelationId(null);
            }}
            onExpandEntity={(id) => void handleExpandEntity(id)}
            onSelectRelation={(rid) => {
              setSelectedRelationId(rid);
              setSelectedEntityId(null);
            }}
          />
        </div>

        <div className="lg:col-span-4 space-y-3">
          {selectedNode && (
            <div className="pl-surface rounded-lg p-3.5 space-y-2.5 text-xs">
              <div className="flex items-start justify-between gap-2">
                <div className="space-y-1 min-w-0">
                  <div className="flex flex-wrap items-center gap-1.5">
                    <EntityTypePill type={selectedNode.entity_type} />
                    <ResolutionStatePill state={selectedNode.resolution_state} />
                  </div>
                  <div className="font-mono-code font-semibold break-all">
                    {selectedNode.display_label}
                  </div>
                  <div className="font-mono-code text-[11px] text-[var(--pl-text-muted)] break-all">
                    {selectedNode.entity_id}
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => setSelectedEntityId(null)}
                  className="px-2 py-0.5 rounded border border-[var(--pl-border)] text-[11px] cursor-pointer"
                >
                  清除
                </button>
              </div>

              <div className="flex flex-wrap gap-2">
                <button
                  type="button"
                  disabled={isExpanding}
                  onClick={() => void handleExpandEntity(selectedNode.entity_id)}
                  className="px-2.5 py-1 rounded bg-[var(--pl-accent)] text-white text-[11px] font-semibold cursor-pointer disabled:opacity-60"
                >
                  {isExpanding ? "展开中…" : "增量展开 1 跳"}
                </button>
                <button
                  type="button"
                  onClick={() => setSearchParams({ seed: selectedNode.entity_id })}
                  className="px-2.5 py-1 rounded border border-[var(--pl-border-strong)] bg-[var(--pl-surface-alt)] text-[11px] cursor-pointer"
                >
                  设为主种子
                </button>
                <button
                  type="button"
                  onClick={() =>
                    navigate(`/entities?entityId=${encodeURIComponent(selectedNode.entity_id)}`)
                  }
                  className="px-2.5 py-1 rounded border border-[var(--pl-border-strong)] bg-[var(--pl-surface-alt)] text-[11px] cursor-pointer"
                >
                  实体生命周期详情
                </button>
              </div>

              <JsonViewer
                title="节点属性 (attributes)"
                value={selectedNode.attributes}
                maxHeightClass="max-h-36"
              />
            </div>
          )}

          <RelationEvidenceDrawer
            relation={selectedRelation}
            evidences={evidenceQ.data?.items ?? []}
            isLoading={evidenceQ.isLoading}
            error={evidenceQ.error}
            onClose={() => setSelectedRelationId(null)}
          />
        </div>
      </div>
    </div>
  );
}
