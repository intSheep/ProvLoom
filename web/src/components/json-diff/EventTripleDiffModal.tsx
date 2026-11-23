import { useEffect, useId, useRef } from "react";
import { JsonViewer } from "../common/JsonViewer";
import { NormalizationStatusPill } from "../common/StatusPill";
import type { EventTripleDiffProps } from "../contracts";

export function EventTripleDiffModal({
  event,
  isLoading = false,
  error = null,
  open,
  onClose,
}: EventTripleDiffProps) {
  const dialogRef = useRef<HTMLDialogElement | null>(null);
  const titleId = useId();

  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;

    if (open && !dialog.open) {
      dialog.showModal();
    } else if (!open && dialog.open) {
      dialog.close();
    }
  }, [open]);

  // Safari fallback for <dialog closedby="any"> light-dismiss without false triggers on text drag.
  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog || "closedBy" in HTMLDialogElement.prototype) return;

    const isOutside = (e: PointerEvent) => {
      const r = dialog.getBoundingClientRect();
      return e.clientX < r.left || e.clientX > r.right || e.clientY < r.top || e.clientY > r.bottom;
    };

    let pressedOutside = false;
    const onPointerDown = (e: PointerEvent) => {
      pressedOutside = isOutside(e);
    };
    const onPointerUp = (e: PointerEvent) => {
      if (pressedOutside && isOutside(e)) {
        dialog.close();
      }
      pressedOutside = false;
    };

    dialog.addEventListener("pointerdown", onPointerDown);
    dialog.addEventListener("pointerup", onPointerUp);
    return () => {
      dialog.removeEventListener("pointerdown", onPointerDown);
      dialog.removeEventListener("pointerup", onPointerUp);
    };
  }, []);

  const unmappedCount = event ? Object.keys(event.unmapped_fields).length : 0;

  return (
    <dialog
      ref={dialogRef}
      {...({ closedby: "any" } as Record<string, string>)}
      aria-labelledby={titleId}
      onClose={onClose}
      className="pl-dialog w-[min(94vw,1340px)]"
    >
      <div className="flex flex-col max-h-[88vh]">
        <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-3 border-b border-[var(--pl-border)] bg-[var(--pl-surface-alt)]">
          <div className="min-w-0 space-y-1">
            <h3 id={titleId} className="text-sm font-semibold m-0 truncate">
              事件三栏溯源对照 (Raw Log ↔ OCSF v1.4.0 ↔ Unmapped)
            </h3>
            {event && (
              <div className="flex flex-wrap items-center gap-2 text-[11px] font-mono-code text-[var(--pl-text-muted)]">
                <NormalizationStatusPill status={event.normalization_status} />
                <span>rule={event.mapping_rule_id}</span>
                <span>class_uid={event.class_uid}</span>
                <span>ocsf={event.ocsf_version}</span>
                <span>original_uid={event.original_event_uid ?? "-"}</span>
                <span>unmapped_keys={unmappedCount}</span>
              </div>
            )}
          </div>
          <button
            type="button"
            onClick={() => dialogRef.current?.close()}
            className="px-3 py-1 rounded-md border border-[var(--pl-border-strong)] bg-[var(--pl-surface)] hover:border-[var(--pl-accent)] text-xs font-medium cursor-pointer"
          >
            关闭 (Esc)
          </button>
        </div>

        <div className="p-4 overflow-y-auto flex-1">
          {isLoading ? (
            <div className="py-12 text-center text-xs text-[var(--pl-text-muted)]">
              正在加载事件原始载荷与 OCSF 明细…
            </div>
          ) : error ? (
            <div className="rounded-md border border-red-500/50 bg-red-500/10 p-3 text-xs text-red-400">
              加载事件详情失败：{error.message}
            </div>
          ) : !event ? (
            <div className="py-12 text-center text-xs text-[var(--pl-text-muted)]">
              未找到对应的标准化事件。
            </div>
          ) : (
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
              <div className="space-y-2 min-w-0">
                <div className="text-xs font-semibold flex items-center justify-between">
                  <span>1. 不可变原始日志 (raw_events)</span>
                  <span className="text-[11px] font-mono-code text-[var(--pl-text-muted)]">
                    {event.raw ? event.raw.source_type : "missing"}
                  </span>
                </div>
                {event.raw && (
                  <div className="pl-surface-alt rounded p-2 text-[11px] font-mono-code space-y-0.5 text-[var(--pl-text-muted)]">
                    <div className="truncate" title={event.raw.raw_event_id}>
                      raw_event_id: {event.raw.raw_event_id}
                    </div>
                    <div className="truncate" title={event.raw.raw_fingerprint}>
                      sha256: {event.raw.raw_fingerprint}
                    </div>
                    <div>
                      source: {event.raw.source_id} · ingested: {event.raw.ingested_at}
                    </div>
                  </div>
                )}
                <JsonViewer
                  title="raw_payload"
                  value={null}
                  rawText={event.raw?.raw_payload ?? "(无原始载荷)"}
                  maxHeightClass="max-h-[420px]"
                />
              </div>

              <div className="space-y-2 min-w-0">
                <div className="text-xs font-semibold flex items-center justify-between">
                  <span>2. 标准 OCSF v{event.ocsf_version} 载荷</span>
                  <span className="text-[11px] font-mono-code text-[var(--pl-text-muted)]">
                    cat={event.category_uid} · cls={event.class_uid} · act={event.activity_id}
                  </span>
                </div>
                <JsonViewer
                  title="ocsf_payload (关键溯源字段已高亮)"
                  value={event.ocsf_payload}
                  highlightKeys={["version", "original_uid", "raw_event_id", "class_uid", "unmapped"]}
                  maxHeightClass="max-h-[490px]"
                />
              </div>

              <div className="space-y-2 min-w-0">
                <div className="text-xs font-semibold flex items-center justify-between">
                  <span>3. 未映射扩展字段 (unmapped_fields)</span>
                  <span className="text-[11px] font-mono-code text-[var(--pl-text-muted)]">
                    {unmappedCount} 个保留键
                  </span>
                </div>
                <JsonViewer
                  title="unmapped_fields (零静默丢弃保障)"
                  value={event.unmapped_fields}
                  maxHeightClass="max-h-[490px]"
                />
              </div>
            </div>
          )}
        </div>
      </div>
    </dialog>
  );
}
