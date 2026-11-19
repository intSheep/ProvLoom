import type { ColumnDef } from "@tanstack/react-table";
import { useMemo, useState } from "react";
import { useEventDetailQuery, useEventsSearchQuery } from "../api/hooks";
import type { EventSearchRequest, NormalizedEventSummary } from "../api/types";
import { DataTable } from "../components/common/DataTable";
import { NormalizationStatusPill } from "../components/common/StatusPill";
import { EventTripleDiffModal } from "../components/json-diff/EventTripleDiffModal";
import { useConsoleContext } from "../state/ConsoleContext";

const OCSF_CLASS_OPTIONS: Array<{ value: string; label: string }> = [
  { value: "", label: "全部 OCSF Class" },
  { value: "1007", label: "1007 · Process Activity" },
  { value: "1001", label: "1001 · File System Activity" },
  { value: "4001", label: "4001 · Network Activity" },
  { value: "3002", label: "3002 · Authentication" },
  { value: "4003", label: "4003 · DNS Activity" },
  { value: "6001", label: "6001 · Web Resources Activity" },
  { value: "6002", label: "6002 · Application Lifecycle" },
  { value: "6003", label: "6003 · API Activity" },
  { value: "5001", label: "5001 · Inventory Info" },
  { value: "0", label: "0 · Unsupported Passthrough" },
];

export function OcsfExplorerPage() {
  const { scope, timeRange } = useConsoleContext();

  const [classUid, setClassUid] = useState("");
  const [sourceFilter, setSourceFilter] = useState("");
  const [fieldKey, setFieldKey] = useState("");
  const [fieldVal, setFieldVal] = useState("");
  const [includeFallback, setIncludeFallback] = useState(true);
  const [limit, setLimit] = useState(100);
  const [selectedEventId, setSelectedEventId] = useState<string | null>(null);

  const req = useMemo<EventSearchRequest>(() => {
    const k = fieldKey.trim();
    const v = fieldVal.trim();
    let parsedVal: string | number | boolean = v;
    if (v === "true") parsedVal = true;
    else if (v === "false") parsedVal = false;
    else if (v !== "" && !Number.isNaN(Number(v))) parsedVal = Number(v);

    return {
      time_range: timeRange,
      class_uids: classUid !== "" ? [Number(classUid)] : null,
      sources: sourceFilter.trim()
        ? sourceFilter
            .split(",")
            .map((s) => s.trim())
            .filter(Boolean)
        : null,
      field_equals: k && v !== "" ? { [k]: parsedVal } : null,
      include_fallback: includeFallback,
      limit,
    };
  }, [timeRange, classUid, sourceFilter, fieldKey, fieldVal, includeFallback, limit]);

  const eventsQ = useEventsSearchQuery(scope, req);
  const detailQ = useEventDetailQuery(scope, selectedEventId);

  const items = eventsQ.data?.items ?? [];
  const mappedCount = items.filter((e) => e.normalization_status === "MAPPED").length;
  const fallbackCount = items.length - mappedCount;

  const columns = useMemo<ColumnDef<NormalizedEventSummary, unknown>[]>(
    () => [
      {
        accessorKey: "event_time",
        header: "事件时间 (UTC)",
        cell: ({ getValue }) => <span className="font-mono-code text-xs">{String(getValue())}</span>,
      },
      {
        accessorKey: "source_id",
        header: "Source",
        cell: ({ getValue }) => <span className="font-mono-code font-medium">{String(getValue())}</span>,
      },
      {
        accessorKey: "class_uid",
        header: "OCSF Class",
        cell: ({ row }) => (
          <span className="font-mono-code text-xs px-1.5 py-0.5 rounded border border-[var(--pl-border)] bg-[var(--pl-surface-alt)]">
            {row.original.class_uid} · act={row.original.activity_id} (v{row.original.ocsf_version})
          </span>
        ),
      },
      {
        accessorKey: "normalization_status",
        header: "标准化状态",
        cell: ({ getValue }) => (
          <NormalizationStatusPill status={getValue() as NormalizedEventSummary["normalization_status"]} />
        ),
      },
      {
        accessorKey: "original_event_uid",
        header: "Original UID",
        cell: ({ getValue }) => (
          <span className="font-mono-code text-xs text-[var(--pl-text-muted)]">
            {String(getValue() ?? "-")}
          </span>
        ),
      },
      {
        id: "actions",
        header: "三栏对照",
        enableSorting: false,
        cell: ({ row }) => (
          <button
            type="button"
            onClick={(e) => {
              e.stopPropagation();
              setSelectedEventId(row.original.event_id);
            }}
            className="px-2.5 py-1 rounded border border-[var(--pl-border-strong)] bg-[var(--pl-surface-alt)] hover:border-[var(--pl-accent)] text-xs cursor-pointer"
          >
            查看对照
          </button>
        ),
      },
    ],
    [],
  );

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-base font-semibold m-0">OCSF v1.3.0 事件检索与三栏映射对照</h1>
          <p className="text-xs text-[var(--pl-text-muted)] m-0 mt-0.5">
            验证标准字段映射、unmapped_fields 扩展槽位与不支持事件 Passthrough 兜底（AC-02）。
          </p>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono-code">
          <span className="px-2 py-1 rounded border border-[var(--pl-border)] bg-[var(--pl-surface)]">
            当前命中 {items.length} 条（MAPPED {mappedCount} / PASSTHROUGH {fallbackCount}）
          </span>
          <button
            type="button"
            onClick={() => void eventsQ.refetch()}
            className="px-3 py-1.5 rounded-md bg-[var(--pl-accent)] text-white font-semibold cursor-pointer"
          >
            {eventsQ.isFetching ? "查询中…" : "刷新检索"}
          </button>
        </div>
      </div>

      <div className="pl-surface rounded-lg p-3 flex flex-wrap items-end gap-3">
        <label className="flex flex-col gap-1 text-xs">
          <span className="text-[var(--pl-text-muted)]">OCSF Class UID</span>
          <select
            aria-label="OCSF Class Filter"
            value={classUid}
            onChange={(e) => setClassUid(e.target.value)}
            className="pl-input font-mono-code"
          >
            {OCSF_CLASS_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </select>
        </label>

        <label className="flex flex-col gap-1 text-xs">
          <span className="text-[var(--pl-text-muted)]">Sources (逗号分隔)</span>
          <input
            type="text"
            value={sourceFilter}
            onChange={(e) => setSourceFilter(e.target.value)}
            placeholder="edr-sysmon, edge-fw-01"
            className="pl-input w-44 font-mono-code"
          />
        </label>

        <label className="flex flex-col gap-1 text-xs">
          <span className="text-[var(--pl-text-muted)]">OCSF 字段路径 (field_equals)</span>
          <input
            type="text"
            value={fieldKey}
            onChange={(e) => setFieldKey(e.target.value)}
            placeholder="如 api.operation"
            className="pl-input w-40 font-mono-code"
          />
        </label>

        <label className="flex flex-col gap-1 text-xs">
          <span className="text-[var(--pl-text-muted)]">字段期望值</span>
          <input
            type="text"
            value={fieldVal}
            onChange={(e) => setFieldVal(e.target.value)}
            placeholder="如 ExportInvoices"
            className="pl-input w-40 font-mono-code"
          />
        </label>

        <label className="flex flex-col gap-1 text-xs">
          <span className="text-[var(--pl-text-muted)]">单页上限</span>
          <select
            aria-label="单页上限"
            value={limit}
            onChange={(e) => setLimit(Number(e.target.value))}
            className="pl-input font-mono-code"
          >
            <option value={50}>50</option>
            <option value={100}>100</option>
            <option value={250}>250</option>
            <option value={500}>500</option>
          </select>
        </label>

        <label className="inline-flex items-center gap-1.5 text-xs pb-1.5 cursor-pointer">
          <input
            type="checkbox"
            checked={includeFallback}
            onChange={(e) => setIncludeFallback(e.target.checked)}
          />
          <span>包含未映射兜底事件 (class_uid=0)</span>
        </label>
      </div>

      {eventsQ.isError && (
        <div role="alert" className="rounded-md border border-red-500/60 bg-red-500/10 p-3 text-xs text-red-400">
          查询事件失败：{eventsQ.error.message}
        </div>
      )}

      {eventsQ.data?.truncated && (
        <div className="rounded-md border border-amber-500/60 bg-amber-500/10 px-3 py-2 text-xs text-amber-500">
          当前结果集已触及单页上限（truncated=true），请收窄时间范围或过滤条件以查看全部记录。
        </div>
      )}

      <DataTable
        caption="标准化 OCSF 事件检索列表"
        data={items}
        columns={columns}
        getRowId={(r) => r.event_id}
        selectedRowId={selectedEventId}
        onRowClick={(row) => setSelectedEventId(row.event_id)}
        isLoading={eventsQ.isLoading}
        emptyMessage="当前时间窗与过滤条件下暂无 OCSF 事件。可点击顶部「对齐数据时间窗」或先导入样本。"
      />

      <EventTripleDiffModal
        open={Boolean(selectedEventId)}
        event={detailQ.data ?? null}
        isLoading={detailQ.isLoading}
        error={detailQ.error}
        onClose={() => setSelectedEventId(null)}
      />
    </div>
  );
}
