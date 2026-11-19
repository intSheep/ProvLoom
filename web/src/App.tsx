import { useEffect, useState } from "react";
import { buildScopeHeaders } from "./api/client";
import type {
  AccessScopeContext,
  EntityDto,
  NormalizedEventSummary,
  PageResponse,
  RelationEvidenceDetail,
  SubgraphResponse,
} from "./api/types";
import { ProvenanceGraphCanvas } from "./components/ProvenanceGraphCanvas";

export function App() {
  const [scope, setScope] = useState<AccessScopeContext>({ tenantId: "default" });
  const [start, setStart] = useState("2026-11-18T00:00:00Z");
  const [end, setEnd] = useState("2026-11-19T00:00:00Z");
  const [tab, setTab] = useState<"events" | "entities" | "graph">("graph");
  const [events, setEvents] = useState<NormalizedEventSummary[]>([]);
  const [entities, setEntities] = useState<EntityDto[]>([]);
  const [subgraph, setSubgraph] = useState<SubgraphResponse | null>(null);
  const [includeCandidates, setIncludeCandidates] = useState(false);
  const [evidences, setEvidences] = useState<RelationEvidenceDetail[]>([]);

  async function api<T>(path: string, init?: RequestInit): Promise<T> {
    const res = await fetch(path, {
      ...init,
      headers: { ...buildScopeHeaders(scope), ...(init?.headers ?? {}) },
    });
    if (!res.ok) throw new Error(await res.text());
    return (await res.json()) as T;
  }

  async function seedExamples() {
    await api("/api/v1/ops/batches/examples", { method: "POST" });
    await loadEntities();
  }

  async function loadEvents() {
    const page = await api<PageResponse<NormalizedEventSummary>>("/api/v1/events/search", {
      method: "POST",
      body: JSON.stringify({ time_range: { start_time: start, end_time: end }, limit: 100 }),
    });
    setEvents(page.items);
  }

  async function loadEntities() {
    const page = await api<PageResponse<EntityDto>>("/api/v1/entities/search", {
      method: "POST",
      body: JSON.stringify({ limit: 100 }),
    });
    setEntities(page.items);
    if (page.items[0]) {
      await traverse(page.items[0].entity_id, includeCandidates);
    }
  }

  async function traverse(seedId: string, withCand: boolean) {
    const sub = await api<SubgraphResponse>("/api/v1/graph/traverse", {
      method: "POST",
      body: JSON.stringify({
        seed_entity_id: seedId,
        time_range: { start_time: start, end_time: end },
        max_depth: 2,
        include_candidates: withCand,
      }),
    });
    setSubgraph(sub);
  }

  async function loadRelationEvidence(relationId: string) {
    const page = await api<PageResponse<RelationEvidenceDetail>>(
      `/api/v1/relations/${relationId}/evidence`,
    );
    setEvidences(page.items);
  }

  useEffect(() => {
    void loadEntities();
  }, []);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-4">
      <header className="flex flex-wrap items-center justify-between gap-3 pb-4 border-b border-slate-800">
        <strong>ProvLoom Console</strong>
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <input
            value={scope.tenantId}
            onChange={(e) => setScope({ ...scope, tenantId: e.target.value })}
            placeholder="Tenant"
            className="bg-slate-900 border border-slate-700 rounded px-2 py-1"
          />
          <input
            value={start}
            onChange={(e) => setStart(e.target.value)}
            className="bg-slate-900 border border-slate-700 rounded px-2 py-1"
          />
          <input
            value={end}
            onChange={(e) => setEnd(e.target.value)}
            className="bg-slate-900 border border-slate-700 rounded px-2 py-1"
          />
          <button
            type="button"
            onClick={() => void seedExamples()}
            className="bg-blue-600 px-3 py-1 rounded"
          >
            Seed Examples
          </button>
        </div>
      </header>

      <nav className="flex gap-2 py-3">
        <button type="button" onClick={() => { setTab("graph"); void loadEntities(); }}>
          Provenance Graph
        </button>
        <button type="button" onClick={() => { setTab("events"); void loadEvents(); }}>
          OCSF Events
        </button>
        <button type="button" onClick={() => { setTab("entities"); void loadEntities(); }}>
          Entities
        </button>
      </nav>

      {tab === "graph" && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div className="lg:col-span-2 border border-slate-800 rounded">
            <div className="p-2 border-b border-slate-800 flex items-center gap-3 text-xs">
              <label className="flex items-center gap-1">
                <input
                  type="checkbox"
                  checked={includeCandidates}
                  onChange={(e) => {
                    setIncludeCandidates(e.target.checked);
                    if (subgraph) void traverse(subgraph.seed_entity_id, e.target.checked);
                  }}
                />
                Include CANDIDATE edges
              </label>
            </div>
            <ProvenanceGraphCanvas
              nodes={subgraph?.nodes ?? []}
              edges={subgraph?.edges ?? []}
              includeCandidates={includeCandidates}
              layout="dagre"
              onSelectEntity={(id) => void traverse(id, includeCandidates)}
              onSelectRelation={(rid) => void loadRelationEvidence(rid)}
            />
          </div>
          <aside className="border border-slate-800 rounded p-3 text-xs overflow-auto max-h-[580px]">
            <h3 className="font-semibold mb-2">Relation Raw Evidence ({evidences.length})</h3>
            {evidences.map((ev) => (
              <pre key={ev.evidence_id} className="bg-slate-900 p-2 rounded mb-2 whitespace-pre-wrap">
                {`[${ev.evidence_role}] ${ev.source_id}\n${ev.raw_payload}`}
              </pre>
            ))}
          </aside>
        </div>
      )}

      {tab === "events" && (
        <pre className="text-xs bg-slate-900 p-3 rounded overflow-auto">
          {JSON.stringify(events, null, 2)}
        </pre>
      )}

      {tab === "entities" && (
        <pre className="text-xs bg-slate-900 p-3 rounded overflow-auto">
          {JSON.stringify(entities, null, 2)}
        </pre>
      )}
    </div>
  );
}
