import { useState } from "react";

interface JsonViewerProps {
  title?: string;
  value: unknown;
  rawText?: string;
  maxHeightClass?: string;
  highlightKeys?: string[];
  emptyText?: string;
}

export function JsonViewer({
  title,
  value,
  rawText,
  maxHeightClass = "max-h-96",
  highlightKeys,
  emptyText = "(空)",
}: JsonViewerProps) {
  const [copied, setCopied] = useState(false);

  const formatted =
    rawText !== undefined
      ? rawText
      : value === undefined || value === null
        ? emptyText
        : typeof value === "string"
          ? value
          : JSON.stringify(value, null, 2);

  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(formatted);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard API may be unavailable outside secure context.
    }
  }

  const lines = formatted.split("\n");
  const highlightSet = highlightKeys?.length ? new Set(highlightKeys) : null;

  return (
    <div className="pl-code-box rounded-md overflow-hidden flex flex-col">
      <div className="flex items-center justify-between gap-2 px-3 py-1.5 border-b border-[var(--pl-border)] bg-[var(--pl-surface-alt)] text-[11px]">
        <span className="font-semibold text-[var(--pl-text-muted)] truncate">
          {title ?? "JSON"}
        </span>
        <button
          type="button"
          onClick={() => void handleCopy()}
          className="px-2 py-0.5 rounded border border-[var(--pl-border-strong)] hover:bg-[var(--pl-surface)] text-[11px] cursor-pointer"
        >
          {copied ? "已复制" : "复制"}
        </button>
      </div>
      <div className={`overflow-auto p-2.5 text-[11.5px] leading-relaxed ${maxHeightClass}`}>
        {lines.map((line, idx) => {
          const isHighlighted =
            highlightSet !== null &&
            Array.from(highlightSet).some((key) => line.includes(`"${key}":`));
          return (
            <div
              key={idx}
              className={
                isHighlighted
                  ? "bg-blue-500/15 border-l-2 border-[var(--pl-accent)] pl-1.5 -ml-1.5 rounded-r whitespace-pre-wrap break-all"
                  : "whitespace-pre-wrap break-all"
              }
            >
              {line || " "}
            </div>
          );
        })}
      </div>
    </div>
  );
}
