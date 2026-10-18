import type { ReactNode } from "react";

/// Label is mono caps, value is Sora with tabular numerals so a changing
/// figure does not shift width, per §4.
export default function StatTile({
  label,
  value,
  sub,
  spark,
  className = "",
}: {
  label: string;
  value: ReactNode;
  sub?: ReactNode;
  /** Optional 120×26 sparkline, bottom-right. */
  spark?: ReactNode;
  className?: string;
}) {
  return (
    <div
      className={`bg-surface border border-border rounded-card shadow-sm p-3.5
        flex flex-col gap-1 ${className}`}
    >
      <span className="font-mono text-[11px] uppercase tracking-wider text-muted">
        {label}
      </span>
      <div className="flex items-end justify-between gap-2">
        <span className="font-display text-[22px] leading-none font-semibold text-text tabular-nums whitespace-nowrap">
          {value}
        </span>
        {spark && <div className="shrink-0">{spark}</div>}
      </div>
      {sub && <span className="text-[11px] text-muted">{sub}</span>}
    </div>
  );
}
