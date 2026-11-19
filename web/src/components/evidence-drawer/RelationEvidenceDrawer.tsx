import { JsonViewer } from "../common/JsonViewer";
import { CertaintyPill } from "../common/StatusPill";
import type { RelationEvidenceDrawerProps } from "../contracts";

export function RelationEvidenceDrawer({
  relation,
  evidences,
  isLoading = false,
  error = null,
  onClose,
}: RelationEvidenceDrawerProps) {
  if (!relation) {
    return (
      <aside className="pl-surface rounded-lg p-4 text-xs text-[var(--pl-text-muted)] space-y-2">
        <h3 className="text-sm font-semibold text-[var(--pl-text)] m-0">
          关系证据链反查 (Evidence Inspector)
        </h3>
        <p className="m-0 leading-relaxed">
          点击图谱画布中的任意有向边，即可调用{" "}
          <code className="font-mono-code">get_relation_evidence</code> 反查支撑该边的全部终端事件、
          Zeek / 防火墙五元组关联依据与不可变原始日志文本。
        </p>
      </aside>
    );
  }

  return (
    <aside className="pl-surface rounded-lg overflow-hidden flex flex-col max-h-[680px]">
      <div className="flex items-start justify-between gap-2 px-3.5 py-2.5 border-b border-[var(--pl-border)] bg-[var(--pl-surface-alt)]">
        <div className="space-y-1 min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <strong className="text-sm font-mono-code">{relation.relation_type}</strong>
            <CertaintyPill certainty={relation.certainty} />
            <span className="text-[11px] font-mono-code text-[var(--pl-text-muted)]">
              聚合证据 {relation.evidence_count} 条
            </span>
          </div>
          <div className="text-[11px] font-mono-code text-[var(--pl-text-muted)] truncate">
            rule: {relation.correlation_rule_id}
          </div>
          <div className="text-[11px] font-mono-code text-[var(--pl-text-muted)]">
            {relation.first_seen_at} → {relation.last_seen_at}
          </div>
        </div>
        <button
          type="button"
          onClick={onClose}
          className="px-2 py-0.5 rounded border border-[var(--pl-border-strong)] text-[11px] cursor-pointer shrink-0"
          aria-label="关闭证据抽屉"
        >
          清除
        </button>
      </div>

      <div className="p-3.5 overflow-y-auto space-y-3 text-xs">
        <JsonViewer
          title="关联依据 (correlation_basis)"
          value={relation.correlation_basis}
          maxHeightClass="max-h-44"
        />

        <div className="space-y-2">
          <div className="font-semibold text-xs flex items-center justify-between">
            <span>反向追溯原始日志 ({evidences.length})</span>
            {relation.evidence_count > evidences.length && !isLoading && (
              <span className="text-[11px] text-amber-500">
                当前 AccessScope 仅授权可见 {evidences.length}/{relation.evidence_count} 条
              </span>
            )}
          </div>

          {isLoading ? (
            <div className="py-6 text-center text-[var(--pl-text-muted)]">
              正在查询关系证据链…
            </div>
          ) : error ? (
            <div className="rounded border border-red-500/50 bg-red-500/10 p-2 text-red-400">
              查询证据失败：{error.message}
            </div>
          ) : evidences.length === 0 ? (
            <div className="py-4 text-center text-[var(--pl-text-muted)]">
              当前授权数据源范围下无可展示的证据记录。
            </div>
          ) : (
            evidences.map((ev) => (
              <div
                key={ev.evidence_id}
                className="pl-surface-alt rounded-md p-2.5 space-y-2"
              >
                <div className="flex flex-wrap items-center justify-between gap-1.5 text-[11px] font-mono-code">
                  <span className="px-1.5 py-0.5 rounded bg-[var(--pl-accent-soft)] text-[var(--pl-accent)] font-semibold">
                    {ev.evidence_role}
                  </span>
                  <span className="text-[var(--pl-text-muted)]">
                    source={ev.source_id} · class={ev.ocsf_class_uid}
                  </span>
                </div>
                <div className="text-[11px] font-mono-code text-[var(--pl-text-muted)]">
                  observed_at: {ev.observed_at} · raw_id: {ev.raw_event_id}
                </div>
                <JsonViewer
                  title={`raw_payload (${ev.source_id})`}
                  value={null}
                  rawText={ev.raw_payload}
                  maxHeightClass="max-h-36"
                />
                {Object.keys(ev.match_detail).length > 0 && (
                  <JsonViewer
                    title="match_detail"
                    value={ev.match_detail}
                    maxHeightClass="max-h-28"
                  />
                )}
              </div>
            ))
          )}
        </div>
      </div>
    </aside>
  );
}
