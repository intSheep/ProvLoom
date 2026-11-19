import type { ColumnDef } from "@tanstack/react-table";
import { useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { useEntitiesSearchQuery, useEntityDetailQuery } from "../api/hooks";
import type {
  EntityDto,
  EntitySearchRequest,
  EntityType,
  ResolutionState,
} from "../api/types";
import { DataTable } from "../components/common/DataTable";
import { JsonViewer } from "../components/common/JsonViewer";
import { EntityTypePill, ResolutionStatePill } from "../components/common/StatusPill";
import { useConsoleContext } from "../state/ConsoleContext";

const ENTITY_TYPES: EntityType[] = [
  "HOST",
  "PROCESS",
  "USER",
  "FILE",
  "NETWORK_ENDPOINT",
  "SERVICE",
  "CONTAINER",
];

export function EntityInspectorPage() {
  const { scope, timeRange } = useConsoleContext();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();

  const selectedEntityId = searchParams.get("entityId");
  const [entityType, setEntityType] = useState<EntityType | "">("");
  const [resolutionState, setResolutionState] = useState<ResolutionState | "">("");
  const [identifierQuery, setIdentifierQuery] = useState("");
  const [scopeByTime, setScopeByTime] = useState(false);

  const req = useMemo<EntitySearchRequest>(
    () => ({
      time_range: scopeByTime ? timeRange : null,
      entity_types: entityType ? [entityType] : null,
      resolution_states: resolutionState ? [resolutionState] : null,
      identifier_query: identifierQuery.trim() || null,
      limit: 200,
    }),
    [scopeByTime, timeRange, entityType, resolutionState, identifierQuery],
  );

  const entitiesQ = useEntitiesSearchQuery(scope, req);
  const detailQ = useEntityDetailQuery(scope, selectedEntityId);

  const columns = useMemo<ColumnDef<EntityDto, unknown>[]>(
    () => [
      {
        accessorKey: "entity_type",
        header: "类型",
        cell: ({ getValue }) => <EntityTypePill type={getValue() as EntityType} />,
      },
      {
        accessorKey: "display_label",
        header: "显示名称",
        cell: ({ getValue }) => (
          <span className="font-mono-code text-xs font-semibold break-all">
            {String(getValue())}
          </span>
        ),
      },
      {
        accessorKey: "resolution_state",
        header: "归一状态",
        cell: ({ getValue }) => <ResolutionStatePill state={getValue() as ResolutionState} />,
      },
      {
        id: "lifecycle",
        header: "生命周期窗口",
        accessorFn: (row) => row.valid_from ?? "",
        cell: ({ row }) => (
          <span className="font-mono-code text-[11px] text-[var(--pl-text-muted)]">
            {row.original.valid_from || row.original.valid_to
              ? `${row.original.valid_from ?? "∞"} → ${row.original.valid_to ?? "active"}`
              : "持久 / 未限定"}
          </span>
        ),
      },
      {
        id: "actions",
        header: "图谱",
        enableSorting: false,
        cell: ({ row }) => (
          <button
            type="button"
            onClick={(e) => {
              e.stopPropagation();
              navigate(`/graph?seed=${encodeURIComponent(row.original.entity_id)}`);
            }}
            className="px-2 py-1 rounded bg-[var(--pl-accent)] text-white text-[11px] font-medium cursor-pointer whitespace-nowrap"
          >
            查图谱
          </button>
        ),
      },
    ],
    [navigate],
  );

  const detail = detailQ.data;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-base font-semibold m-0">实体目录、作用域生命周期与合并审计</h1>
          <p className="text-xs text-[var(--pl-text-muted)] m-0 mt-0.5">
            检查 7 类实体的多维标识绑定、PID/DHCP 时效窗口与 EntityMergeAudit（AC-03 / AC-09）。
          </p>
        </div>
        <button
          type="button"
          onClick={() => void entitiesQ.refetch()}
          className="px-3 py-1.5 rounded-md border border-[var(--pl-border-strong)] bg-[var(--pl-surface)] text-xs font-medium cursor-pointer"
        >
          {entitiesQ.isFetching ? "检索中…" : "刷新实体"}
        </button>
      </div>

      <div className="pl-surface rounded-lg p-3 flex flex-wrap items-end gap-3">
        <label className="flex flex-col gap-1 text-xs">
          <span className="text-[var(--pl-text-muted)]">实体类型 (7 类)</span>
          <select
            aria-label="Entity Type"
            value={entityType}
            onChange={(e) => setEntityType(e.target.value as EntityType | "")}
            className="pl-input font-mono-code"
          >
            <option value="">全部实体类型</option>
            {ENTITY_TYPES.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
        </label>

        <label className="flex flex-col gap-1 text-xs">
          <span className="text-[var(--pl-text-muted)]">归一状态</span>
          <select
            aria-label="Resolution State"
            value={resolutionState}
            onChange={(e) => setResolutionState(e.target.value as ResolutionState | "")}
            className="pl-input font-mono-code"
          >
            <option value="">全部状态</option>
            <option value="RESOLVED">RESOLVED (强键唯一)</option>
            <option value="SCOPED_TEMPORAL">SCOPED_TEMPORAL (作用域时效)</option>
            <option value="PROVISIONAL">PROVISIONAL (暂存独立)</option>
          </select>
        </label>

        <label className="flex flex-col gap-1 text-xs flex-1 min-w-[220px]">
          <span className="text-[var(--pl-text-muted)]">标识关键字搜索</span>
          <input
            type="search"
            value={identifierQuery}
            onChange={(e) => setIdentifierQuery(e.target.value)}
            placeholder="搜 IP / PID / ProcessGuid / 主机名 / SHA256…"
            className="pl-input font-mono-code"
          />
        </label>

        <label className="inline-flex items-center gap-1.5 text-xs pb-1.5 cursor-pointer">
          <input
            type="checkbox"
            checked={scopeByTime}
            onChange={(e) => setScopeByTime(e.target.checked)}
          />
          <span>仅限全局时间窗活跃实体</span>
        </label>
      </div>

      {entitiesQ.isError && (
        <div role="alert" className="rounded-md border border-red-500/60 bg-red-500/10 p-3 text-xs text-red-400">
          检索实体失败：{entitiesQ.error.message}
        </div>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-12 gap-4 items-start">
        <div className="xl:col-span-7">
          <DataTable
            caption="实体目录与生命周期列表"
            data={entitiesQ.data?.items ?? []}
            columns={columns}
            getRowId={(r) => r.entity_id}
            selectedRowId={selectedEntityId}
            onRowClick={(ent) => setSearchParams({ entityId: ent.entity_id })}
            isLoading={entitiesQ.isLoading}
            maxHeightClass="max-h-[620px]"
          />
        </div>

        <aside className="xl:col-span-5 pl-surface rounded-lg p-4 space-y-3 text-xs">
          {!selectedEntityId ? (
            <div className="py-10 text-center text-[var(--pl-text-muted)]">
              点击左侧任意实体，查看其绑定的多维标识（EntityIdentifier）、时效窗口与合并审计记录。
            </div>
          ) : detailQ.isLoading ? (
            <div className="py-10 text-center text-[var(--pl-text-muted)]">
              正在加载实体详情与合并审计…
            </div>
          ) : detailQ.isError ? (
            <div className="rounded border border-red-500/50 bg-red-500/10 p-3 text-red-400">
              加载实体详情失败：{detailQ.error.message}
            </div>
          ) : !detail ? (
            <div className="py-8 text-center text-[var(--pl-text-muted)]">未找到实体。</div>
          ) : (
            <>
              <div className="flex flex-wrap items-start justify-between gap-2 pb-2 border-b border-[var(--pl-border)]">
                <div className="space-y-1 min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <EntityTypePill type={detail.entity.entity_type} />
                    <ResolutionStatePill state={detail.entity.resolution_state} />
                  </div>
                  <h2 className="text-sm font-semibold font-mono-code m-0 break-all">
                    {detail.entity.display_label}
                  </h2>
                  <div className="text-[11px] font-mono-code text-[var(--pl-text-muted)] break-all">
                    id: {detail.entity.entity_id}
                  </div>
                  {detail.entity.canonical_key && (
                    <div className="text-[11px] font-mono-code text-[var(--pl-text-muted)] break-all">
                      canonical_key: {detail.entity.canonical_key}
                    </div>
                  )}
                </div>

                <button
                  type="button"
                  onClick={() =>
                    navigate(`/graph?seed=${encodeURIComponent(detail.entity.entity_id)}`)
                  }
                  className="px-3 py-1.5 rounded-md bg-[var(--pl-accent)] text-white font-semibold cursor-pointer shrink-0"
                >
                  在图谱中展开
                </button>
              </div>

              {detail.entity.resolution_state === "PROVISIONAL" && (
                <div className="rounded-md border border-dashed border-amber-500/70 bg-amber-500/10 p-2.5 text-[11.5px] leading-relaxed">
                  <strong>防误合隔离说明（PROVISIONAL）：</strong>
                  该实体缺少全局权威强键或宿主作用域上下文（例如仅有短主机名、孤立内网 IP 或裸进程名），
                  已按领域不变式保持独立节点，严禁仅凭名称相似强行合并。
                </div>
              )}

              <JsonViewer
                title="实体属性 (attributes)"
                value={detail.entity.attributes}
                maxHeightClass="max-h-40"
              />

              <div className="space-y-1.5">
                <h3 className="text-xs font-semibold m-0">
                  绑定标识与时效窗口 ({detail.identifiers.length})
                </h3>
                <div className="pl-table-scroll max-h-48">
                  <table className="w-full text-[11px] border-collapse">
                    <thead>
                      <tr className="bg-[var(--pl-surface-alt)] text-[var(--pl-text-muted)]">
                        <th className="p-1.5 text-left">Namespace</th>
                        <th className="p-1.5 text-left">Value</th>
                        <th className="p-1.5 text-left">权威</th>
                        <th className="p-1.5 text-left">窗口</th>
                      </tr>
                    </thead>
                    <tbody>
                      {detail.identifiers.map((ident) => (
                        <tr key={ident.identifier_id} className="border-t border-[var(--pl-border)]">
                          <td className="p-1.5 font-mono-code">{ident.id_namespace}</td>
                          <td className="p-1.5 font-mono-code break-all">{ident.id_value}</td>
                          <td className="p-1.5">{ident.is_authoritative ? "权威" : "辅键"}</td>
                          <td className="p-1.5 font-mono-code text-[var(--pl-text-muted)]">
                            {ident.valid_from || ident.valid_to
                              ? `${ident.valid_from ?? "∞"} ~ ${ident.valid_to ?? "active"}`
                              : "持久"}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              <div className="space-y-1.5">
                <h3 className="text-xs font-semibold m-0">
                  实体合并审计记录 ({detail.merges.length})
                </h3>
                {detail.merges.length === 0 ? (
                  <div className="pl-surface-alt rounded p-2.5 text-[11px] text-[var(--pl-text-muted)]">
                    无跨实体合并记录（首次强键/作用域建立或保持 PROVISIONAL 独立）。
                  </div>
                ) : (
                  detail.merges.map((m) => (
                    <div key={m.merge_id} className="pl-surface-alt rounded p-2.5 space-y-1.5">
                      <div className="flex flex-wrap justify-between gap-1 font-mono-code text-[11px]">
                        <span className="font-semibold text-[var(--pl-accent)]">
                          {m.merge_rule_id}
                        </span>
                        <span className="text-[var(--pl-text-muted)]">{m.merged_at}</span>
                      </div>
                      <div className="text-[11px] font-mono-code text-[var(--pl-text-muted)]">
                        source={m.source_entity_id} → target={m.target_entity_id}
                      </div>
                      <JsonViewer
                        title="match_basis"
                        value={m.match_basis}
                        maxHeightClass="max-h-28"
                      />
                    </div>
                  ))
                )}
              </div>
            </>
          )}
        </aside>
      </div>
    </div>
  );
}
