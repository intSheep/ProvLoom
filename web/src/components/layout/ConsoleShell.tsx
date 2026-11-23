import { useState } from "react";
import { NavLink, Outlet } from "react-router-dom";
import { useConsoleContext } from "../../state/ConsoleContext";
import { ThemeToggle } from "./ThemeToggle";

interface NavItem {
  to: string;
  badge: string;
  label: string;
  desc: string;
}

const NAV_ITEMS: NavItem[] = [
  { to: "/overview", badge: "01", label: "流水线概览", desc: "可观测性指标与接入批次" },
  { to: "/ingestion", badge: "02", label: "接入与重放", desc: "样本导入、去重与死信恢复" },
  { to: "/events", badge: "03", label: "OCSF 事件台", desc: "标准化检索与三栏对照" },
  { to: "/entities", badge: "04", label: "实体生命周期", desc: "作用域归一与合并审计" },
  { to: "/graph", badge: "05", label: "溯源关系图谱", desc: "多跳遍历与证据链反查" },
  { to: "/detection", badge: "06", label: "检测与线索台", desc: "Sigma 编译、命中与 Signal" },
  { to: "/playground", badge: "07", label: "API 与映射字典", desc: "契约沙盒与 YAML 规则" },
];

export function ConsoleShell() {
  const {
    scope,
    setScope,
    timeRange,
    setTimeRange,
    notice,
    clearNotice,
    alignTimeBounds,
    isAligningBounds,
    seedExamples,
    isSeedingExamples,
  } = useConsoleContext();

  const [sourcesInput, setSourcesInput] = useState(() => scope.allowedSources?.join(", ") ?? "");

  function applySourcesText(raw: string) {
    setSourcesInput(raw);
    const list = raw
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    setScope({
      tenantId: scope.tenantId,
      allowedSources: list.length ? list : undefined,
    });
  }

  return (
    <div className="min-h-screen flex flex-col bg-[var(--pl-bg)] text-[var(--pl-text)]">
      <header className="sticky top-0 z-30 border-b border-[var(--pl-border)] bg-[var(--pl-surface)] px-4 py-2.5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2.5">
            <span
              className="inline-block w-2.5 h-2.5 rounded-full bg-[var(--pl-ok)] shadow-[0_0_8px_var(--pl-ok)]"
              aria-hidden="true"
            />
            <strong className="text-[15px] tracking-tight">ProvLoom</strong>
            <span className="rounded border border-[var(--pl-border)] bg-[var(--pl-surface-alt)] px-2 py-0.5 text-[11px] font-mono-code text-[var(--pl-text-muted)]">
              OCSF v1.4.0 · Provenance Workbench
            </span>
          </div>

          <div
            role="region"
            aria-label="Global Query Guardrails"
            className="flex flex-wrap items-end gap-2"
          >
            <label className="flex flex-col gap-0.5 text-[11px] text-[var(--pl-text-muted)]">
              <span>Tenant ID</span>
              <input
                type="text"
                value={scope.tenantId}
                onChange={(e) => setScope({ ...scope, tenantId: e.target.value })}
                placeholder="default"
                className="pl-input w-28 font-mono-code"
              />
            </label>

            <label className="flex flex-col gap-0.5 text-[11px] text-[var(--pl-text-muted)]">
              <span>Allowed Sources (逗号分隔)</span>
              <input
                type="text"
                value={sourcesInput}
                onChange={(e) => applySourcesText(e.target.value)}
                placeholder="全部授权源"
                className="pl-input w-44 font-mono-code"
              />
            </label>

            <label className="flex flex-col gap-0.5 text-[11px] text-[var(--pl-text-muted)]">
              <span>Start (UTC)</span>
              <input
                type="text"
                value={timeRange.start_time}
                onChange={(e) => setTimeRange({ ...timeRange, start_time: e.target.value })}
                className="pl-input w-56 font-mono-code"
              />
            </label>

            <label className="flex flex-col gap-0.5 text-[11px] text-[var(--pl-text-muted)]">
              <span>End (UTC)</span>
              <input
                type="text"
                value={timeRange.end_time}
                onChange={(e) => setTimeRange({ ...timeRange, end_time: e.target.value })}
                className="pl-input w-56 font-mono-code"
              />
            </label>

            <button
              type="button"
              disabled={isAligningBounds}
              onClick={() => void alignTimeBounds()}
              className="px-2.5 py-1.5 rounded-md border border-[var(--pl-border-strong)] bg-[var(--pl-surface-alt)] hover:border-[var(--pl-accent)] text-xs font-medium cursor-pointer disabled:opacity-60"
            >
              {isAligningBounds ? "对齐中…" : "对齐数据时间窗"}
            </button>

            <button
              type="button"
              disabled={isSeedingExamples}
              onClick={() => void seedExamples()}
              className="px-3 py-1.5 rounded-md bg-[var(--pl-accent)] hover:opacity-90 text-white text-xs font-semibold cursor-pointer disabled:opacity-60"
            >
              {isSeedingExamples ? "导入中…" : "导入内置标准样本"}
            </button>

            <ThemeToggle />
          </div>
        </div>
      </header>

      <div className="flex-1 flex flex-col lg:flex-row min-h-0">
        <nav
          aria-label="Console Navigation"
          className="lg:w-60 shrink-0 border-b lg:border-b-0 lg:border-r border-[var(--pl-border)] bg-[var(--pl-surface)] p-2.5 flex lg:flex-col justify-between gap-2 overflow-x-auto"
        >
          <div className="flex lg:flex-col gap-1 min-w-max lg:min-w-0">
            {NAV_ITEMS.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                className={({ isActive }) =>
                  [
                    "flex items-start gap-2.5 rounded-md px-2.5 py-2 border transition-colors",
                    isActive
                      ? "bg-[var(--pl-accent-soft)] border-[var(--pl-accent)] text-[var(--pl-text)]"
                      : "border-transparent text-[var(--pl-text-muted)] hover:bg-[var(--pl-surface-alt)] hover:text-[var(--pl-text)]",
                  ].join(" ")
                }
              >
                <span className="font-mono-code text-[10px] px-1.5 py-0.5 rounded bg-[var(--pl-surface-alt)] border border-[var(--pl-border)] mt-0.5">
                  {item.badge}
                </span>
                <span className="flex flex-col">
                  <span className="text-xs font-semibold leading-tight">{item.label}</span>
                  <span className="hidden lg:inline text-[11px] opacity-80 mt-0.5">
                    {item.desc}
                  </span>
                </span>
              </NavLink>
            ))}
          </div>

          <div className="hidden lg:block rounded-md border border-[var(--pl-border)] bg-[var(--pl-surface-alt)] p-2.5 text-[11px] space-y-1.5">
            <div className="font-semibold text-[var(--pl-text)]">认知诚实图例 (Invariants)</div>
            <div className="flex items-center gap-2 text-[var(--pl-text-muted)]">
              <span className="inline-block w-5 border-t-2 border-blue-500" />
              <span>DETERMINISTIC 事实边</span>
            </div>
            <div className="flex items-center gap-2 text-[var(--pl-text-muted)]">
              <span className="inline-block w-5 border-t-2 border-dashed border-amber-500" />
              <span>CANDIDATE 候选边 (?)</span>
            </div>
            <div className="flex items-center gap-2 text-[var(--pl-text-muted)]">
              <span className="inline-block w-3.5 h-3 border border-dashed border-amber-500 rounded-xs" />
              <span>PROVISIONAL 独立实体</span>
            </div>
          </div>
        </nav>

        <main className="flex-1 min-w-0 p-4 lg:p-5 space-y-4">
          {notice && (
            <div
              role={notice.kind === "error" ? "alert" : "status"}
              className={[
                "flex items-center justify-between gap-3 rounded-md border px-3 py-2 text-xs",
                notice.kind === "error"
                  ? "border-red-500/60 bg-red-500/10 text-red-400"
                  : notice.kind === "success"
                    ? "border-emerald-500/60 bg-emerald-500/10 text-emerald-500"
                    : "border-blue-500/60 bg-blue-500/10 text-blue-400",
              ].join(" ")}
            >
              <span>{notice.message}</span>
              <button
                type="button"
                onClick={clearNotice}
                className="px-2 py-0.5 rounded border border-current/30 text-[11px] cursor-pointer"
                aria-label="关闭提示"
              >
                关闭
              </button>
            </div>
          )}

          <Outlet />
        </main>
      </div>
    </div>
  );
}
