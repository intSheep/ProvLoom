import { useConsoleContext, type ThemePreference } from "../../state/ConsoleContext";

export function ThemeToggle() {
  const { themePreference, systemTheme, setThemePreference } = useConsoleContext();

  const options: Array<{ value: ThemePreference; label: string; title: string }> = [
    {
      value: "system",
      label: systemTheme === "dark" ? "自动·暗" : "自动·亮",
      title: `跟随系统 (${systemTheme === "dark" ? "当前深色" : "当前浅色"})`,
    },
    { value: "light", label: "浅色", title: "固定浅色主题" },
    { value: "dark", label: "深色", title: "固定深色主题" },
  ];

  return (
    <div
      role="group"
      aria-label="主题切换"
      className="inline-flex items-center rounded-md border border-[var(--pl-border-strong)] bg-[var(--pl-code-bg)] p-0.5 text-[11px]"
    >
      {options.map((opt) => {
        const active = themePreference === opt.value;
        return (
          <button
            key={opt.value}
            type="button"
            aria-pressed={active}
            title={opt.title}
            onClick={() => setThemePreference(opt.value)}
            className={[
              "px-2 py-1 rounded transition-colors cursor-pointer whitespace-nowrap",
              active
                ? "bg-[var(--pl-accent)] text-white font-semibold"
                : "text-[var(--pl-text-muted)] hover:text-[var(--pl-text)]",
            ].join(" ")}
          >
            {opt.label}
          </button>
        );
      })}
    </div>
  );
}
