import type { ColumnDef } from "@tanstack/react-table";
import { useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { useBatchesQuery, useMetricsQuery } from "../api/hooks";
import type { IngestBatchDto } from "../api/types";
import { DataTable } from "../components/common/DataTable";
import { BatchStatusPill } from "../components/common/StatusPill";
import { useConsoleContext } from "../state/ConsoleContext";

export function OverviewPage() {
  const { scope } = useConsoleContext();
  const navigate = useNavigate();
  const metricsQ = useMetricsQuery(scope);
  const batchesQ = useBatchesQuery(scope, 30);

  const snap = metricsQ.data;

  const kpiCards = useMemo(() => {
    if (!snap) return [];
    const totalAttempt = snap.ingested_total + snap.duplicate_total;
    const dedupRate =
      totalAttempt > 0 ? ((snap.duplicate_total / totalAttempt) * 100).toFixed(1) : "0.0";
    const parseTotal = snap.parse_success_total + snap.parse_failed_total;
    const parseRate =
      parseTotal > 0 ? ((snap.parse_success_total / parseTotal) * 100).toFixed(1) : "100.0";
    const deadLetters =
      snap.ingest_failed_total + snap.parse_failed_total + snap.normalize_failed_total;

    return [
      {
        label: "原始接入新增 (Accepted)",
        value: String(snap.ingested_total),
        sub: `累计接收 ${totalAttempt} 条记录`,
      },
      {
        label: "幂等去重 / 重复率",
        value: `${snap.duplicate_total} (${dedupRate}%)`,
        sub: "SHA-256 指纹命中",
      },
      {
        label: "解析成功率",
        value: `${parseRate}%`,
        sub: `${snap.parse_success_total} 成功 · ${snap.parse_failed_total} 失败`,
      },
      {
        label: "OCSF 映射 / 兜底保留",
        value: `${snap.normalized_mapped_total} / ${snap.normalized_fallback_total}`,
        sub: "Passthrough (class_uid=0) 零静默丢弃",
      },
      {
        label: "实体确定性合并",
        value: String(snap.entity_merges_total),
        sub: "附带 EntityMergeAudit 依据",
      },
      {
        label: "确定性事实边 (DETERMINISTIC)",
        value: String(snap.deterministic_relations_total),
        sub: "实线因果关系",
      },
      {
        label: "候选推断边 (CANDIDATE)",
        value: String(snap.candidate_relations_total),
        sub: "虚线琥珀色线索",
      },
      {
        label: "异常死信留痕 (Failures)",
        value: String(deadLetters),
        sub: `接入 ${snap.ingest_failed_total} · 解析 ${snap.parse_failed_total} · 映射 ${snap.normalize_failed_total}`,
        alert: deadLetters > 0,
      },
      {
        label: "检测规则与命中 (RuleMatch)",
        value: `${snap.detection_matches_total} 命中`,
        sub: `支持规则 ${snap.detection_rules_supported_total} / 总计 ${snap.detection_rules_total}`,
      },
      {
        label: "调查线索 (Signal / 候选组)",
        value: `${snap.signals_created_total} / ${snap.candidate_groups_created_total}`,
        sub: `聚合 ${snap.signals_aggregated_total} · 幂等去重 ${snap.signals_deduplicated_total}`,
      },
    ];
  }, [snap]);

  const batchColumns = useMemo<ColumnDef<IngestBatchDto, unknown>[]>(
    () => [
      {
        accessorKey: "received_at",
        header: "接收时间 (UTC)",
        cell: ({ getValue }) => (
          <span className="font-mono-code text-xs">{String(getValue())}</span>
        ),
      },
      {
        accessorKey: "source_id",
        header: "Source ID",
        cell: ({ getValue }) => (
          <span className="font-mono-code font-medium">{String(getValue())}</span>
        ),
      },
      {
        id: "adapter",
        header: "类型 / 适配器",
        accessorFn: (row) => `${row.source_type}/${row.adapter_type}`,
        cell: ({ row }) => (
          <span className="font-mono-code text-xs px-1.5 py-0.5 rounded border border-[var(--pl-border)] bg-[var(--pl-surface-alt)]">
            {row.original.source_type}/{row.original.adapter_type}
          </span>
        ),
      },
      {
        accessorKey: "total_count",
        header: "总计",
        cell: ({ getValue }) => <span className="font-mono-code">{String(getValue())}</span>,
      },
      {
        accessorKey: "accepted_count",
        header: "新增",
        cell: ({ getValue }) => (
          <span className="font-mono-code text-emerald-500 font-semibold">
            {String(getValue())}
          </span>
        ),
      },
      {
        accessorKey: "duplicate_count",
        header: "幂等去重",
        cell: ({ getValue }) => (
          <span className="font-mono-code text-[var(--pl-text-muted)]">
            {String(getValue())}
          </span>
        ),
      },
      {
        accessorKey: "failed_count",
        header: "失败",
        cell: ({ getValue }) => {
          const n = Number(getValue());
          return (
            <span className={`font-mono-code ${n > 0 ? "text-red-500 font-semibold" : ""}`}>
              {n}
            </span>
          );
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

  const normTotal = snap
    ? snap.normalized_mapped_total + snap.normalized_fallback_total + snap.normalize_failed_total
    : 0;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-base font-semibold m-0">流水线可观测性概览 (PRD §5)</h1>
          <p className="text-xs text-[var(--pl-text-muted)] m-0 mt-0.5">
            当前租户 <code className="font-mono-code">{scope.tenantId}</code>{" "}
            的实时接入、标准化与图谱投影健康指标。
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => {
              void metricsQ.refetch();
              void batchesQ.refetch();
            }}
            className="px-3 py-1.5 rounded-md border border-[var(--pl-border-strong)] bg-[var(--pl-surface)] hover:border-[var(--pl-accent)] text-xs font-medium cursor-pointer"
          >
            {metricsQ.isFetching || batchesQ.isFetching ? "刷新中…" : "刷新指标"}
          </button>
          <a
            href="/metrics"
            target="_blank"
            rel="noreferrer"
            className="px-3 py-1.5 rounded-md border border-[var(--pl-border)] bg-[var(--pl-surface-alt)] text-xs font-mono-code text-[var(--pl-text-muted)] hover:text-[var(--pl-text)] no-underline"
          >
            /metrics (Prometheus)
          </a>
        </div>
      </div>

      {metricsQ.isError && (
        <div role="alert" className="rounded-md border border-red-500/60 bg-red-500/10 p-3 text-xs text-red-400">
          获取可观测指标失败：{metricsQ.error.message}
        </div>
      )}

      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-3">
        {metricsQ.isLoading
          ? Array.from({ length: 8 }).map((_, i) => (
              <div key={i} className="pl-surface rounded-lg p-3.5 animate-pulse h-24" />
            ))
          : kpiCards.map((card) => (
              <div
                key={card.label}
                className={[
                  "pl-surface rounded-lg p-3.5 space-y-1",
                  card.alert ? "border-amber-500/70" : "",
                ].join(" ")}
              >
                <div className="text-[11px] text-[var(--pl-text-muted)] font-medium">
                  {card.label}
                </div>
                <div className="text-xl font-bold font-mono-code tracking-tight">
                  {card.value}
                </div>
                <div className="text-[11px] text-[var(--pl-text-muted)]">{card.sub}</div>
              </div>
            ))}
      </div>

      {snap && normTotal > 0 && (
        <div className="pl-surface rounded-lg p-3.5 space-y-2">
          <div className="flex items-center justify-between text-xs">
            <span className="font-semibold">OCSF 标准化分布</span>
            <span className="font-mono-code text-[11px] text-[var(--pl-text-muted)]">
              MAPPED {((snap.normalized_mapped_total / normTotal) * 100).toFixed(1)}% · FALLBACK{" "}
              {((snap.normalized_fallback_total / normTotal) * 100).toFixed(1)}% · FAILED{" "}
              {((snap.normalize_failed_total / normTotal) * 100).toFixed(1)}%
            </span>
          </div>
          <div className="h-2.5 w-full rounded-full overflow-hidden flex bg-[var(--pl-surface-alt)]">
            <div
              className="bg-emerald-500"
              style={{ width: `${(snap.normalized_mapped_total / normTotal) * 100}%` }}
              title={`Mapped: ${snap.normalized_mapped_total}`}
            />
            <div
              className="bg-amber-500"
              style={{ width: `${(snap.normalized_fallback_total / normTotal) * 100}%` }}
              title={`Passthrough Fallback: ${snap.normalized_fallback_total}`}
            />
            <div
              className="bg-red-500"
              style={{ width: `${(snap.normalize_failed_total / normTotal) * 100}%` }}
              title={`Failed: ${snap.normalize_failed_total}`}
            />
          </div>
        </div>
      )}

      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold m-0">最近接入批次 (点击行前往接入与异常台)</h2>
          <button
            type="button"
            onClick={() => navigate("/ingestion")}
            className="text-xs text-[var(--pl-accent)] hover:underline cursor-pointer"
          >
            管理全部批次与死信 →
          </button>
        </div>

        <DataTable
          caption="最近数据接入批次审计表"
          data={batchesQ.data?.items ?? []}
          columns={batchColumns}
          getRowId={(r) => r.batch_id}
          isLoading={batchesQ.isLoading}
          onRowClick={(batch) => navigate(`/ingestion?batchId=${batch.batch_id}`)}
          emptyMessage="暂无接入批次。点击右上角「导入内置标准样本」快速初始化数据。"
        />
      </div>
    </div>
  );
}
