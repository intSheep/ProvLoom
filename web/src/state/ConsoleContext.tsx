import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { opsApi } from "../api/client";
import { useSeedExamplesMutation } from "../api/hooks";
import type { AccessScopeContext, TimeRange } from "../api/types";

export type ThemePreference = "system" | "light" | "dark";
export type ResolvedTheme = "light" | "dark";

export interface ConsoleNotice {
  kind: "info" | "success" | "error";
  message: string;
}

interface ConsoleContextValue {
  scope: AccessScopeContext;
  setScope: (next: AccessScopeContext) => void;
  timeRange: TimeRange;
  setTimeRange: (next: TimeRange) => void;
  themePreference: ThemePreference;
  resolvedTheme: ResolvedTheme;
  systemTheme: ResolvedTheme;
  setThemePreference: (next: ThemePreference) => void;
  notice: ConsoleNotice | null;
  showNotice: (kind: ConsoleNotice["kind"], message: string) => void;
  clearNotice: () => void;
  alignTimeBounds: () => Promise<void>;
  isAligningBounds: boolean;
  seedExamples: () => Promise<void>;
  isSeedingExamples: boolean;
}

const DEFAULT_SCOPE: AccessScopeContext = { tenantId: "default" };
const DEFAULT_TIME_RANGE: TimeRange = {
  start_time: "2026-11-18T00:00:00Z",
  end_time: "2026-11-19T00:00:00Z",
};

const SCOPE_STORAGE_KEY = "provloom.console.scope";
const RANGE_STORAGE_KEY = "provloom.console.timeRange";

function readStoredJson<T>(key: string, fallback: T): T {
  try {
    const raw = sessionStorage.getItem(key);
    return raw ? (JSON.parse(raw) as T) : fallback;
  } catch {
    return fallback;
  }
}

function readStoredTheme(): ThemePreference {
  try {
    const val = localStorage.getItem("color-scheme");
    if (val === "light" || val === "dark") return val;
  } catch {
    // Ignore storage access errors in restricted browsing contexts.
  }
  return "system";
}

function getSystemTheme(): ResolvedTheme {
  if (typeof window === "undefined" || typeof window.matchMedia !== "function") {
    return "dark";
  }
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

function applyThemeToMeta(pref: ThemePreference, resolved: ResolvedTheme) {
  const meta = document.querySelector<HTMLMetaElement>('meta[name="color-scheme"]');
  if (meta) {
    meta.content = pref === "system" ? "light dark" : pref;
  }
  document.documentElement.dataset.resolvedTheme = resolved;
}

const ConsoleContext = createContext<ConsoleContextValue | null>(null);

export function ConsoleProvider({ children }: { children: ReactNode }) {
  const [scope, setScopeState] = useState<AccessScopeContext>(() =>
    readStoredJson(SCOPE_STORAGE_KEY, DEFAULT_SCOPE),
  );
  const [timeRange, setTimeRangeState] = useState<TimeRange>(() =>
    readStoredJson(RANGE_STORAGE_KEY, DEFAULT_TIME_RANGE),
  );
  const [themePreference, setThemePreferenceState] = useState<ThemePreference>(readStoredTheme);
  const [systemTheme, setSystemTheme] = useState<ResolvedTheme>(getSystemTheme);
  const [notice, setNotice] = useState<ConsoleNotice | null>(null);
  const [isAligningBounds, setIsAligningBounds] = useState(false);

  const resolvedTheme: ResolvedTheme =
    themePreference === "system" ? systemTheme : themePreference;

  useEffect(() => {
    applyThemeToMeta(themePreference, resolvedTheme);
  }, [themePreference, resolvedTheme]);

  useEffect(() => {
    if (typeof window === "undefined" || typeof window.matchMedia !== "function") return;
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    const onChange = (e: MediaQueryListEvent) => {
      // Never delete an explicit stored preference when OS scheme happens to match it.
      setSystemTheme(e.matches ? "dark" : "light");
    };
    mq.addEventListener("change", onChange);
    return () => mq.removeEventListener("change", onChange);
  }, []);

  useEffect(() => {
    const onStorage = (e: StorageEvent) => {
      if (e.key === "color-scheme") {
        setThemePreferenceState(
          e.newValue === "light" || e.newValue === "dark" ? e.newValue : "system",
        );
      }
    };
    window.addEventListener("storage", onStorage);
    return () => window.removeEventListener("storage", onStorage);
  }, []);

  const setThemePreference = useCallback((next: ThemePreference) => {
    setThemePreferenceState(next);
    try {
      if (next === "system") {
        localStorage.removeItem("color-scheme");
      } else {
        localStorage.setItem("color-scheme", next);
      }
    } catch {
      // Theme still applies to current session when storage is blocked.
    }
  }, []);

  const setScope = useCallback((next: AccessScopeContext) => {
    setScopeState(next);
    try {
      sessionStorage.setItem(SCOPE_STORAGE_KEY, JSON.stringify(next));
    } catch {
      // Ignore storage failures.
    }
  }, []);

  const setTimeRange = useCallback((next: TimeRange) => {
    setTimeRangeState(next);
    try {
      sessionStorage.setItem(RANGE_STORAGE_KEY, JSON.stringify(next));
    } catch {
      // Ignore storage failures.
    }
  }, []);

  const showNotice = useCallback((kind: ConsoleNotice["kind"], message: string) => {
    setNotice({ kind, message });
  }, []);

  const clearNotice = useCallback(() => setNotice(null), []);

  const seedMutation = useSeedExamplesMutation(scope);

  const alignTimeBounds = useCallback(async () => {
    setIsAligningBounds(true);
    try {
      const bounds = await opsApi.getTimeBounds(scope);
      if (!bounds) {
        showNotice("info", "当前租户尚无标准化事件，请先导入内置样本或原始日志。");
        return;
      }
      setTimeRange(bounds);
      showNotice("success", `已对齐数据时间窗: ${bounds.start_time} ~ ${bounds.end_time}`);
    } catch (err) {
      showNotice("error", err instanceof Error ? err.message : "对齐时间窗失败");
    } finally {
      setIsAligningBounds(false);
    }
  }, [scope, setTimeRange, showNotice]);

  const seedExamples = useCallback(async () => {
    try {
      const res = await seedMutation.mutateAsync();
      const bounds = await opsApi.getTimeBounds(scope);
      if (bounds) {
        setTimeRange(bounds);
      }
      showNotice(
        "success",
        `内置标准样本导入完成：批次 ${res.batches_loaded} 个，新增 ${res.accepted_total} 条，幂等去重 ${res.duplicate_total} 条，失败 ${res.failed_total} 条。`,
      );
    } catch (err) {
      showNotice("error", err instanceof Error ? err.message : "导入样本失败");
    }
  }, [scope, seedMutation, setTimeRange, showNotice]);

  const value = useMemo<ConsoleContextValue>(
    () => ({
      scope,
      setScope,
      timeRange,
      setTimeRange,
      themePreference,
      resolvedTheme,
      systemTheme,
      setThemePreference,
      notice,
      showNotice,
      clearNotice,
      alignTimeBounds,
      isAligningBounds,
      seedExamples,
      isSeedingExamples: seedMutation.isPending,
    }),
    [
      scope,
      setScope,
      timeRange,
      setTimeRange,
      themePreference,
      resolvedTheme,
      systemTheme,
      setThemePreference,
      notice,
      showNotice,
      clearNotice,
      alignTimeBounds,
      isAligningBounds,
      seedExamples,
      seedMutation.isPending,
    ],
  );

  return <ConsoleContext.Provider value={value}>{children}</ConsoleContext.Provider>;
}

export function useConsoleContext(): ConsoleContextValue {
  const ctx = useContext(ConsoleContext);
  if (!ctx) {
    throw new Error("useConsoleContext must be used inside ConsoleProvider");
  }
  return ctx;
}
