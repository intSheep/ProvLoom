import type { ColumnDef } from "@tanstack/react-table";
import { useEffect, useId, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import {
  useBatchesQuery,
  useFailuresQuery,
  useRawImportMutation,
  useReplayMutation,
  useRetryFailuresMutation,
  useSampleImportMutation,
} from "../api/hooks";
import type { IngestBatchDto, PipelineFailureDto, PipelineStage } from "../api/types";
import { DataTable } from "../components/common/DataTable";
import { BatchStatusPill, StagePill } from "../components/common/StatusPill";
import { useConsoleContext } from "../state/ConsoleContext";

const SOURCE_TYPES = [
  "sysmon",
  "zeek_conn",
  "zeek_dns",
  "firewall",
  "auth",
  "app",
  "asset",
  "custom_unknown",
];

export function IngestionDebugPage() {
  const { scope, showNotice, alignTimeBounds } = useConsoleContext();
  const [searchParams, setSearchParams] = useSearchParams();
  const selectedBatchId = searchParams.get("batchId") ?? "";
  const [stageFilter, setStageFilter] = useState<PipelineStage | "">("");

  const [mode, setMode] = useState<"raw" | "uri">("raw");
  const [sourceId, setSourceId] = useState("debug-sysmon-01");
  const [sourceType, setSourceType] = useState("sysmon");
  const [adapterType, setAdapterType] = useState("jsonl");
  const [rawText, setRawText] = useState("");
  const [sourceUri, setSourceUri] = useState("tests/fixtures/examples/sysmon_sample.jsonl");

  const replayDialogRef = useRef<HTMLDialogElement | null>(null);
  const replayTitleId = useId();

  const batchesQ = useBatchesQuery(scope, 50);
  const failuresQ = useFailuresQuery(scope, {
    batchId: selectedBatchId || undefined,
    stage: stageFilter || undefined,
    limit: 100,
  });

  const rawImportMut = useRawImportMutation(scope);
  const sampleImportMut = useSampleImportMutation(scope);
  const retryMut = useRetryFailuresMutation(scope);
  const replayMut = useReplayMutation(scope);

  // Safari fallback for replay confirmation modal light-dismiss.
  useEffect(() => {
    const dlg = replayDialogRef.current;
    if (!dlg || "closedBy" in HTMLDialogElement.prototype) return;
    const onClick = (e: MouseEvent) => {
      if (e.target !== dlg) return;
      const r = dlg.getBoundingClientRect();
      const inside =
        e.clientX >= r.left && e.clientX <= r.right && e.clientY >= r.top && e.clientY <= r.bottom;
      if (!inside) dlg.close();
    };
    dlg.addEventListener("click", onClick);
    return () => dlg.removeEventListener("click", onClick);
  }, []);

  async function handleFileSelect(file: File | undefined) {
    if (!file) return;
    setRawText(await file.text());
    if (file.name.endsWith(".csv")) setAdapterType("csv");
    else if (file.name.endsWith(".json")) setAdapterType("json");
    else setAdapterType("jsonl");
  }

  async function handleSubmitIngest(e: React.FormEvent) {
    e.preventDefault();
    try {
      const receipt =
        mode === "raw"
          ? await rawImportMut.mutateAsync({
              source_id: sourceId.trim(),
              source_type: sourceType,
              adapter_type: adapterType,
              raw_text: rawText,
            })
          : await sampleImportMut.mutateAsync({
              source_id: sourceId.trim(),
              source_type: sourceType,
              adapter_type: adapterType,
              source_uri: sourceUri.trim(),
            });
      showNotice(
        receipt.failed_count > 0 ? "info" : "success",
        `接入完成 (batch=${receipt.batch_id.slice(0, 8)}…)：总计 ${receipt.total_count}，新增 ${receipt.accepted_count}，幂等去重 ${receipt.duplicate_count}，失败 ${receipt.failed_count}`,
      );
      await alignTimeBounds();
    } catch (err) {
      showNotice("error", err instanceof Error ? err.message : "提交接入失败");
    }
  }

  async function handleRetry() {
    try {
      const res = await retryMut.mutateAsync(selectedBatchId || undefined);
      showNotice(
        "success",
        `重试完成：尝试 ${res.attempted} 条，恢复成功 ${res.succeeded} 条，仍失败 ${res.failed} 条。`,
      );
    } catch (err) {
      showNotice("error", err instanceof Error ? err.message : "重试失败");
    }
  }

  async function handleReplayConfirm() {
    replayDialogRef.current?.close();
    try {
      const res = await replayMut.mutateAsync({
        batch_ids: selectedBatchId ? [selectedBatchId] : undefined,
      });
      showNotice(
        "success",
        `确定性重建完成：重放原始事件 ${res.replayed_raw_events} 条 → 重建实体 ${res.rebuilt_entities} 个，关系 ${res.rebuilt_relations} 条。`,
      );
    } catch (err) {
      showNotice("error", err instanceof Error ? err.message : "重放重建失败");
    }
  }

  const batchColumns = useMemo<ColumnDef<IngestBatchDto, unknown>[]>(
    () => [
      {
        accessorKey: "received_at",
        header: "接收时间",
        cell: ({ getValue }) => <span className="font-mono-code text-xs">{String(getValue())}</span>,
      },
      {
        accessorKey: "source_id",
        header: "Source ID",
        cell: ({ getValue }) => <span className="font-mono-code font-medium">{String(getValue())}</span>,
      },
      {
        accessorKey: "source_type",
        header: "Source Type",
        cell: ({ row }) => (
          <span className="font-mono-code text-xs">
            {row.original.source_type} ({row.original.adapter_type})
          </span>
        ),
      },
      {
        accessorKey: "accepted_count",
        header: "新增",
        cell: ({ getValue }) => (
          <span className="font-mono-code text-emerald-500">{String(getValue())}</span>
        ),
      },
      {
        accessorKey: "duplicate_count",
        header: "去重",
        cell: ({ getValue }) => <span className="font-mono-code">{String(getValue())}</span>,
      },
      {
        accessorKey: "failed_count",
        header: "失败",
        cell: ({ getValue }) => {
          const n = Number(getValue());
          return <span className={`font-mono-code ${n > 0 ? "text-red-500 font-bold" : ""}`}>{n}</span>;
        },
      },
      {
        accessorKey: "status",
        header: "状态",
        cell: ({ getValue }) => <BatchStatusPill status={getValue() as IngestBatchDto["status"]} />,
      },
    ],
    [],
  );

  const failureColumns = useMemo<ColumnDef<PipelineFailureDto, unknown>[]>(
    () => [
      {
        accessorKey: "occurred_at",
        header: "发生时间",
        cell: ({ getValue }) => <span className="font-mono-code text-xs">{String(getValue())}</span>,
      },
      {
        accessorKey: "stage",
        header: "失败阶段",
        cell: ({ getValue }) => <StagePill stage={getValue() as PipelineStage} />,
      },
      {
        accessorKey: "error_code",
        header: "错误码",
        cell: ({ getValue }) => <span className="font-mono-code text-xs">{String(getValue())}</span>,
      },
      {
        accessorKey: "error_message",
        header: "错误详情",
        cell: ({ getValue }) => <span className="text-xs break-words">{String(getValue())}</span>,
      },
      {
        accessorKey: "retry_count",
        header: "重试",
        cell: ({ row }) => (
          <span className="font-mono-code text-xs">
            {row.original.retry_count} {row.original.retryable ? "(可重试)" : "(不可重试)"}
          </span>
        ),
      },
      {
        accessorKey: "raw_snippet",
        header: "原始片段",
        cell: ({ getValue }) => (
          <code className="font-mono-code text-[11px] break-all text-[var(--pl-text-muted)]">
            {String(getValue() ?? "-")}
          </code>
        ),
      },
    ],
    [],
  );

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-base font-semibold m-0">数据接入、幂等审计与确定性重放台</h1>
          <p className="text-xs text-[var(--pl-text-muted)] m-0 mt-0.5">
            验证原始日志不可变留存（AC-01）、SHA-256 重复拦截（AC-08）与死信恢复重放。
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            disabled={retryMut.isPending}
            onClick={() => void handleRetry()}
            className="px-3 py-1.5 rounded-md border border-[var(--pl-border-strong)] bg-[var(--pl-surface)] hover:border-[var(--pl-accent)] text-xs font-medium cursor-pointer disabled:opacity-60"
          >
            {retryMut.isPending ? "重试中…" : "重试可恢复失败项"}
          </button>
          <button
            type="button"
            disabled={replayMut.isPending}
            onClick={() => replayDialogRef.current?.showModal()}
            className="px-3 py-1.5 rounded-md border border-red-500/60 bg-red-500/15 text-red-400 hover:bg-red-500/25 text-xs font-semibold cursor-pointer disabled:opacity-60"
          >
            {replayMut.isPending ? "重建中…" : "从原始日志全量重建图"}
          </button>
        </div>
      </div>

      <form onSubmit={(e) => void handleSubmitIngest(e)} className="pl-surface rounded-lg p-4 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h2 className="text-sm font-semibold m-0">样本接入调试</h2>
          <div className="inline-flex rounded-md border border-[var(--pl-border-strong)] bg-[var(--pl-code-bg)] p-0.5 text-xs">
            <button
              type="button"
              onClick={() => setMode("raw")}
              className={`px-2.5 py-1 rounded cursor-pointer ${mode === "raw" ? "bg-[var(--pl-accent)] text-white font-semibold" : "text-[var(--pl-text-muted)]"}`}
            >
              粘贴 / 上传文件
            </button>
            <button
              type="button"
              onClick={() => setMode("uri")}
              className={`px-2.5 py-1 rounded cursor-pointer ${mode === "uri" ? "bg-[var(--pl-accent)] text-white font-semibold" : "text-[var(--pl-text-muted)]"}`}
            >
              服务端路径导入
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          <label className="flex flex-col gap-1 text-xs">
            <span className="text-[var(--pl-text-muted)]">Source ID</span>
            <input
              value={sourceId}
              onChange={(e) => setSourceId(e.target.value)}
              required
              className="pl-input font-mono-code"
            />
          </label>
          <label className="flex flex-col gap-1 text-xs">
            <span className="text-[var(--pl-text-muted)]">Source Type</span>
            <select
              value={sourceType}
              onChange={(e) => setSourceType(e.target.value)}
              className="pl-input font-mono-code"
            >
              {SOURCE_TYPES.map((st) => (
                <option key={st} value={st}>
                  {st}
                </option>
              ))}
            </select>
          </label>
          <label className="flex flex-col gap-1 text-xs">
            <span className="text-[var(--pl-text-muted)]">Adapter 格式</span>
            <select
              value={adapterType}
              onChange={(e) => setAdapterType(e.target.value)}
              className="pl-input font-mono-code"
            >
              <option value="jsonl">jsonl</option>
              <option value="json">json</option>
              <option value="csv">csv</option>
              <option value="asset">asset</option>
            </select>
          </label>
          {mode === "raw" ? (
            <label className="flex flex-col gap-1 text-xs">
              <span className="text-[var(--pl-text-muted)]">从本地文件读取</span>
              <input
                type="file"
                accept=".json,.jsonl,.csv,.log,.txt"
                onChange={(e) => void handleFileSelect(e.target.files?.[0])}
                className="pl-input text-xs file:mr-2 file:rounded file:border-0 file:bg-[var(--pl-surface-alt)] file:px-2 file:py-0.5 file:text-xs"
              />
            </label>
          ) : (
            <label className="flex flex-col gap-1 text-xs">
              <span className="text-[var(--pl-text-muted)]">服务端 Source URI</span>
              <input
                value={sourceUri}
                onChange={(e) => setSourceUri(e.target.value)}
                required
                className="pl-input font-mono-code"
              />
            </label>
          )}
        </div>

        {mode === "raw" && (
          <div className="space-y-2">
            <textarea
              rows={4}
              value={rawText}
              onChange={(e) => setRawText(e.target.value)}
              required
              placeholder='粘贴 JSONL / JSON / CSV 原始日志，例如: {"EventRecordID":"9901","EventID":7,"UtcTime":"2026-11-18T08:01:00Z","Computer":"win01.corp.local","ImageLoaded":"C:\\Temp\\evil.dll"}'
              className="pl-input w-full font-mono-code resize-y"
            />
            <div className="flex flex-wrap items-center gap-2 text-xs">
              <span className="text-[var(--pl-text-muted)]">快捷调试样本：</span>
              <button
                type="button"
                onClick={() => {
                  setSourceId("edr-sysmon");
                  setSourceType("sysmon");
                  setAdapterType("jsonl");
                  setRawText(
                    '{"EventRecordID":"9999","EventID":7,"UtcTime":"2026-11-18T08:03:00Z","Computer":"win01.corp.local","ImageLoaded":"C:\\\\Temp\\\\evil.dll"}',
                  );
                }}
                className="px-2 py-1 rounded border border-[var(--pl-border)] bg-[var(--pl-surface-alt)] hover:border-[var(--pl-accent)] cursor-pointer"
              >
                填充 Sysmon ImageLoad (Passthrough 兜底)
              </button>
              <button
                type="button"
                onClick={() => {
                  setSourceId("broken-feed");
                  setSourceType("sysmon");
                  setAdapterType("jsonl");
                  setRawText('{"broken_json": ');
                }}
                className="px-2 py-1 rounded border border-[var(--pl-border)] bg-[var(--pl-surface-alt)] hover:border-[var(--pl-accent)] cursor-pointer"
              >
                填充畸形日志 (测试死信留痕)
              </button>
            </div>
          </div>
        )}

        <div className="flex items-center gap-3">
          <button
            type="submit"
            disabled={rawImportMut.isPending || sampleImportMut.isPending}
            className="px-4 py-1.5 rounded-md bg-[var(--pl-accent)] text-white text-xs font-semibold cursor-pointer disabled:opacity-60"
          >
            {rawImportMut.isPending || sampleImportMut.isPending
              ? "执行流水线中…"
              : "提交接入并执行流水线"}
          </button>
        </div>
      </form>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold m-0">批次幂等审计 ({batchesQ.data?.items.length ?? 0})</h2>
            {selectedBatchId && (
              <button
                type="button"
                onClick={() => setSearchParams({})}
                className="text-xs text-[var(--pl-accent)] hover:underline cursor-pointer"
              >
                清除批次过滤
              </button>
            )}
          </div>
          <DataTable
            caption="数据接入批次幂等审计表"
            data={batchesQ.data?.items ?? []}
            columns={batchColumns}
            getRowId={(r) => r.batch_id}
            selectedRowId={selectedBatchId || null}
            onRowClick={(b) =>
              setSearchParams(b.batch_id === selectedBatchId ? {} : { batchId: b.batch_id })
            }
            isLoading={batchesQ.isLoading}
            maxHeightClass="max-h-[420px]"
          />
        </div>

        <div className="space-y-2">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h2 className="text-sm font-semibold m-0">
              流水线失败留痕 (pipeline_failures)
            </h2>
            <select
              aria-label="按失败阶段筛选"
              value={stageFilter}
              onChange={(e) => setStageFilter(e.target.value as PipelineStage | "")}
              className="pl-input text-xs"
            >
              <option value="">全部阶段</option>
              <option value="INGEST">INGEST</option>
              <option value="PARSE">PARSE</option>
              <option value="NORMALIZE">NORMALIZE</option>
              <option value="ENTITY">ENTITY</option>
              <option value="GRAPH">GRAPH</option>
            </select>
          </div>
          <DataTable
            caption="流水线异常与死信记录表"
            data={failuresQ.data?.items ?? []}
            columns={failureColumns}
            getRowId={(r) => r.failure_id}
            isLoading={failuresQ.isLoading}
            maxHeightClass="max-h-[420px]"
            emptyMessage="当前过滤条件下无失败死信记录。"
          />
        </div>
      </div>

      <dialog
        ref={replayDialogRef}
        {...({ closedby: "any" } as Record<string, string>)}
        aria-labelledby={replayTitleId}
        className="pl-dialog w-[min(92vw,480px)]"
      >
        <div className="p-4 space-y-3">
          <h3 id={replayTitleId} className="text-sm font-semibold m-0">
            确认执行确定性重放重建？
          </h3>
          <p className="text-xs text-[var(--pl-text-muted)] m-0 leading-relaxed">
            将从不可变 <code className="font-mono-code">raw_events</code> 重新解析、标准化、
            归一实体并重建图谱关系（{selectedBatchId ? `限定批次 ${selectedBatchId}` : "当前租户全量"}
            ）。已有图谱投影将被安全替换。
          </p>
          <div className="flex items-center justify-end gap-2 pt-2">
            <button
              type="button"
              autoFocus
              onClick={() => replayDialogRef.current?.close()}
              className="px-3 py-1.5 rounded-md border border-[var(--pl-border-strong)] bg-[var(--pl-surface-alt)] text-xs font-medium cursor-pointer"
            >
              取消
            </button>
            <button
              type="button"
              onClick={() => void handleReplayConfirm()}
              className="px-3 py-1.5 rounded-md bg-red-600 hover:bg-red-700 text-white text-xs font-semibold cursor-pointer"
            >
              确认重建
            </button>
          </div>
        </div>
      </dialog>
    </div>
  );
}
