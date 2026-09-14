import type { ReactNode } from "react";

export interface TabItem {
  key: string;
  label: string;
  /** Rendered after the label — the users screen shows counts here. */
  count?: number;
  icon?: ReactNode;
}

/// Two variants per §4: `pill` for a segmented control, `underline` for page
/// sections. Both drive the same state, so a screen can change its mind
/// without changing its logic.
export default function Tabs({
  items,
  value,
  onChange,
  variant = "pill",
  className = "",
}: {
  items: TabItem[];
  value: string;
  onChange: (key: string) => void;
  variant?: "pill" | "underline";
  className?: string;
}) {
  if (variant === "underline") {
    return (
      <div className={`flex gap-4 border-b border-border ${className}`}>
        {items.map((t) => (
          <button
            key={t.key}
            onClick={() => onChange(t.key)}
            className={`flex items-center gap-1.5 pb-2 -mb-px text-[12px] font-medium
              border-b-2 transition-colors ${
                value === t.key
                  ? "border-accent text-accent"
                  : "border-transparent text-muted hover:text-text"
              }`}
          >
            {t.icon}
            {t.label}
            {t.count !== undefined && (
              <span className="font-mono text-[10px] text-faint">{t.count}</span>
            )}
          </button>
        ))}
      </div>
    );
  }

  return (
    <div
      className={`inline-flex gap-0.5 p-0.5 bg-surface-2 border border-border
        rounded-control ${className}`}
    >
      {items.map((t) => (
        <button
          key={t.key}
          onClick={() => onChange(t.key)}
          className={`flex items-center gap-1.5 px-2.5 h-7 rounded-[6px] text-[12px]
            font-medium transition-colors ${
              value === t.key
                ? "bg-surface text-text shadow-sm"
                : "text-muted hover:text-text"
            }`}
        >
          {t.icon}
          {t.label}
          {t.count !== undefined && (
            <span className="font-mono text-[10px] text-faint">{t.count}</span>
          )}
        </button>
      ))}
    </div>
  );
}
