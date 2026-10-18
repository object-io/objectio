import type { ReactNode } from "react";
import { seriesColor } from "./chart-series";

/// Frame for a chart, per §4: title and subtitle top-left, legend top-right and
/// only when there is more than one series, chart beneath.
export default function ChartCard({
  title,
  subtitle,
  legend,
  action,
  children,
  className = "",
}: {
  title: string;
  subtitle?: string;
  /** Rendered top-right. Pass nothing for a single-series chart. */
  legend?: ReactNode;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <div
      className={`bg-surface border border-border rounded-card shadow-sm p-4 ${className}`}
    >
      <div className="flex items-start justify-between gap-3 mb-3">
        <div className="min-w-0">
          <h3 className="text-[13px] font-medium text-text">{title}</h3>
          {subtitle && <p className="text-[11px] text-muted">{subtitle}</p>}
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {legend}
          {action}
        </div>
      </div>
      {children}
    </div>
  );
}

/// Legend entry matching the series colour. Kept here so a chart cannot drift
/// from its own legend.
export function LegendDot({ index, label, dark = false }: { index: number; label: string; dark?: boolean }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-[11px] text-muted">
      <span
        className="w-2 h-2 rounded-full"
        style={{ background: seriesColor(index, dark) }}
      />
      {label}
    </span>
  );
}
