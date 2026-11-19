import type { ColumnDef } from "@tanstack/react-table";
import { useEffect, useMemo, useState } from "react";
import { apiFetch, buildScopeHeaders } from "../api/client";
import { useMappingsQuery } from "../api/hooks";
import type { MappingSpecSummary } from "../api/types";
import { DataTable } from "../components/common/DataTable";
import { JsonViewer } from "../components/common/JsonViewer";
import { useConsoleContext } from "../state/ConsoleContext";

type PresetId =
  | "events_search"
  | "get_event"
  | "entities_search"
  | "get_entity"
  | "entity_relations"
  | "traverse_graph"
  | "relation_evidence"
  | "metrics";

interface PresetMeta {
  id: PresetId;
  method: "GET" | "POST";
  label: string;
  pathTemplate: string;
}

const PRESETS: PresetMeta[] = [
  { id: "events_search", method: "POST", label: "search_events", pathTemplate: "/api/v1/events/search" },
  { id: "get_event", method: "GET", label: "get_event", pathTemplate: "/api/v1/events/{event_id}?include_raw=true" },
  { id: "entities_search", method: "POST", label: "search_entities", pathTemplate: "/api/v1/entities/search" },
  { id: "get_entity", method: "GET", label: "get_entity", pathTemplate: "/api/v1/entities/{entity_id}" },
  {
    id: "entity_relations",
    method: "GET",
    label: "get_entity_relations",
    pathTemplate:
      "/api/v1/entities/{entity_id}/relations?start_time={start}&end_time={end}&direction=BOTH&include_candidates=false",
  },
  { id: "traverse_graph", method: "POST", label: "traverse_graph", pathTemplate: "/api/v1/graph/traverse" },
  {
    id: "relation_evidence",
    method: "GET",
    label: "get_relation_evidence",
    pathTemplate: "/api/v1/relations/{relation_id}/evidence",
  },
  { id: "metrics", method: "GET", label: "ops/metrics", pathTemplate: "/api/v1/ops/metrics/summary" },
];

export function ApiPlaygroundPage() {
  const { scope, timeRange } = useConsoleContext();
  const mappingsQ = useMappingsQuery(scope);
  const [ruleSearch, setRuleSearch] = useState("");

  const [presetId, setPresetId] = useState<PresetId>("events_search");
  const [resourceId, setResourceId] = useState("");
  const [bodyText, setBodyText] = useState("");
  const [responseMeta, setResponseMeta] = useState<string>("");
  const [responseData, setResponseData] = useState<unknown>(null);
  const [isSending, setIsSending] = useState(false);

  const activePreset = PRESETS.find((p) => p.id === presetId) ?? PRESETS[0];

  useEffect(() => {
    if (presetId === "events_search") {
      setBodyText(JSON.stringify({ time_range: timeRange, limit: 10 }, null, 2));
    } else if (presetId === "entities_search") {
      setBodyText(
        JSON.stringify({ entity_types: ["PROCESS", "HOST"], limit: 20 }, null, 2),
      );
    } else if (presetId === "traverse_graph") {
      setBodyText(
        JSON.stringify(
          {
            seed_entity_id: resourceId || "00000000-0000-0000-0000-000000000000",
            time_range: timeRange,
            max_depth: 2,
            direction: "BOTH",
            include_candidates: false,
          },
          null,
          2,
        ),
      );
    } else {
      setBodyText("");
    }
  }, [presetId, timeRange, resourceId]);

  const resolvedPath = useMemo(() => {
    return activePreset.pathTemplate
      .replace("{event_id}", encodeURIComponent(resourceId || "<event_id>"))
      .replace("{entity_id}", encodeURIComponent(resourceId || "<entity_id>"))
      .replace("{relation_id}", encodeURIComponent(resourceId || "<relation_id>"))
      .replace("{start}", encodeURIComponent(timeRange.start_time))
      .replace("{end}", encodeURIComponent(timeRange.end_time));
  }, [activePreset, resourceId, timeRange]);

  const curlSnippet = useMemo(() => {
    const headers = buildScopeHeaders(scope);
    const headerFlags = Object.entries(headers)
      .map(([k, v]) => `-H '${k}: ${v}'`)
      .join(" ");
    if (activePreset.method === "POST") {
      const compactBody = bodyText.replace(/\s+/g, " ").trim();
      return `curl -X POST 'http://127.0.0.1:8000${resolvedPath}' ${headerFlags} -d '${compactBody}'`;
    }
    return `curl 'http://127.0.0.1:8000${resolvedPath}' ${headerFlags}`;
  }, [scope, activePreset.method, resolvedPath, bodyText]);

  async function handleSend() {
    setIsSending(true);
    const t0 = performance.now();
    try {
      const res = await apiFetch<unknown>(
        resolvedPath,
        scope,
        activePreset.method === "POST" ? { method: "POST", body: bodyText } : undefined,
      );
      const ms = (performance.now() - t0).toFixed(1);
      setResponseMeta(`200 OK · ${ms} ms`);
      setResponseData(res);
    } catch (err) {
      const ms = (performance.now() - t0).toFixed(1);
      setResponseMeta(`ERROR · ${ms} ms`);
      setResponseData(err instanceof Error ? err.message : String(err));
    } finally {
      setIsSending(false);
    }
  }

  const filteredMappings = useMemo(() => {
    const items = mappingsQ.data ?? [];
    const q = ruleSearch.trim().toLowerCase();
    if (!q) return items;
    return items.filter(
      (r) =>
        r.rule_id.toLowerCase().includes(q) ||
        r.parser_id.toLowerCase().includes(q) ||
        String(r.class_uid).includes(q) ||
        (r.event_code?.toLowerCase().includes(q) ?? false),
    );
  }, [mappingsQ.data, ruleSearch]);

  const mappingColumns = useMemo<ColumnDef<MappingSpecSummary, unknown>[]>(
    () => [
      {
        accessorKey: "rule_id",
        header: "Rule ID",
        cell: ({ getValue }) => (
          <span className="font-mono-code text-xs font-medium">{String(getValue())}</span>
        ),
      },
      {
        accessorKey: "parser_id",
        header: "Parser",
        cell: ({ getValue }) => <span className="font-mono-code text-xs">{String(getValue())}</span>,
      },
      {
        accessorKey: "event_code",
        header: "Event Code",
        cell: ({ getValue }) => (
          <span className="font-mono-code text-xs text-[var(--pl-text-muted)]">
            {String(getValue() ?? "*")}
          </span>
        ),
      },
      {
        accessorKey: "class_uid",
        header: "OCSF Class",
        cell: ({ row }) => (
          <span className="font-mono-code text-xs px-1.5 py-0.5 rounded border border-[var(--pl-border)] bg-[var(--pl-surface-alt)]">
            {row.original.class_uid} · act={row.original.activity_id}
          </span>
        ),
      },
      {
        accessorKey: "rule_version",
        header: "版本",
        cell: ({ getValue }) => (
          <span className="font-mono-code text-xs text-[var(--pl-text-muted)]">
            v{String(getValue())}
          </span>
        ),
      },
    ],
    [],
  );

  const needsId = activePreset.pathTemplate.includes("{event_id}") ||
    activePreset.pathTemplate.includes("{entity_id}") ||
    activePreset.pathTemplate.includes("{relation_id}");

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-base font-semibold m-0">标准查询 API 契约沙盒与 OCSF 映射字典</h1>
        <p className="text-xs text-[var(--pl-text-muted)] m-0 mt-0.5">
          实时验证携带当前 AccessScope（X-Tenant-Id / X-Allowed-Sources）与 TimeRange 护栏的 7 大核心查询契约（AC-10）。
        </p>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-12 gap-4 items-start">
        <div className="xl:col-span-6 pl-surface rounded-lg p-4 space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h2 className="text-sm font-semibold m-0">
              已加载 YAML OCSF 映射规则 ({filteredMappings.length})
            </h2>
            <input
              type="search"
              value={ruleSearch}
              onChange={(e) => setRuleSearch(e.target.value)}
              placeholder="搜 rule_id / parser / class_uid…"
              className="pl-input w-52 text-xs"
            />
          </div>

          <DataTable
            caption="活跃 OCSF YAML 映射规则表"
            data={filteredMappings}
            columns={mappingColumns}
            getRowId={(r) => `${r.rule_id}-${r.rule_version}`}
            isLoading={mappingsQ.isLoading}
            maxHeightClass="max-h-[540px]"
          />
        </div>

        <div className="xl:col-span-6 pl-surface rounded-lg p-4 space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h2 className="text-sm font-semibold m-0">REST API 实时请求验证</h2>
            <a
              href="/docs"
              target="_blank"
              rel="noreferrer"
              className="text-xs text-[var(--pl-accent)] hover:underline font-mono-code"
            >
              OpenAPI Swagger (/docs) ↗
            </a>
          </div>

          <div className="flex flex-wrap items-end gap-2">
            <label className="flex flex-col gap-1 text-xs flex-1 min-w-[220px]">
              <span className="text-[var(--pl-text-muted)]">接口预设 (QueryService / Ops)</span>
              <select
                aria-label="API Preset"
                value={presetId}
                onChange={(e) => setPresetId(e.target.value as PresetId)}
                className="pl-input font-mono-code"
              >
                {PRESETS.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.method} · {p.label}
                  </option>
                ))}
              </select>
            </label>

            {needsId && (
              <label className="flex flex-col gap-1 text-xs flex-1 min-w-[200px]">
                <span className="text-[var(--pl-text-muted)]">目标 UUID (event / entity / relation)</span>
                <input
                  type="text"
                  value={resourceId}
                  onChange={(e) => setResourceId(e.target.value)}
                  placeholder="粘贴 UUID…"
                  className="pl-input font-mono-code"
                />
              </label>
            )}

            <button
              type="button"
              disabled={isSending}
              onClick={() => void handleSend()}
              className="px-4 py-1.5 rounded-md bg-[var(--pl-accent)] text-white text-xs font-semibold cursor-pointer disabled:opacity-60"
            >
              {isSending ? "发送中…" : "发送请求"}
            </button>
          </div>

          <div className="pl-surface-alt rounded px-2.5 py-1.5 text-[11px] font-mono-code text-[var(--pl-text-muted)] break-all">
            {activePreset.method} {resolvedPath}
          </div>

          {activePreset.method === "POST" && (
            <textarea
              rows={7}
              value={bodyText}
              onChange={(e) => setBodyText(e.target.value)}
              className="pl-input w-full font-mono-code resize-y"
              aria-label="Request JSON Body"
            />
          )}

          <JsonViewer title="等效 cURL（含当前 AccessScope Header）" value={null} rawText={curlSnippet} maxHeightClass="max-h-24" />

          <JsonViewer
            title={responseMeta ? `响应结果 · ${responseMeta}` : "响应结果"}
            value={responseData}
            rawText={typeof responseData === "string" ? responseData : undefined}
            emptyText="点击「发送请求」查看携带当前 AccessScope 的 API 实时响应。"
            maxHeightClass="max-h-80"
          />
        </div>
      </div>
    </div>
  );
}
