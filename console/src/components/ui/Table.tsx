import type { ReactNode } from "react";

export interface Column {
  key: string;
  label: string;
  /** Right-align numerics; the mockups do this for sizes and counts. */
  align?: "left" | "right";
  className?: string;
}

/// Loading and empty are built in rather than left to each page, per §4 —
/// they were the two states pages most often skipped, so a slow or empty
/// response showed as a bare frame.
export default function Table({
  columns,
  children,
  loading = false,
  empty,
  footer,
  className = "",
}: {
  columns: Column[];
  children?: ReactNode;
  loading?: boolean;
  /** Shown when not loading and no rows were provided. */
  empty?: ReactNode;
  footer?: ReactNode;
  className?: string;
}) {
  const isEmpty = !loading && !children;
  return (
    <div
      className={`bg-surface border border-border rounded-card shadow-sm overflow-hidden ${className}`}
    >
      <table className="w-full border-collapse">
        <thead>
          <tr className="bg-surface-2">
            {columns.map((c) => (
              <th
                key={c.key}
                className={`px-3.5 py-2 font-mono text-[11px] uppercase tracking-wider
                  text-muted font-normal ${
                    c.align === "right" ? "text-right" : "text-left"
                  } ${c.className ?? ""}`}
              >
                {c.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {loading && (
            <tr>
              <td colSpan={columns.length} className="px-3.5">
                <div className="h-16 flex items-center">
                  <div className="h-0.5 w-full bg-surface-2 rounded overflow-hidden">
                    <div className="h-full w-1/3 bg-accent animate-[loading-bar_1.2s_ease-in-out_infinite]" />
                  </div>
                </div>
              </td>
            </tr>
          )}
          {isEmpty && (
            <tr>
              <td
                colSpan={columns.length}
                className="px-3.5 py-8 text-center text-[12px] text-muted"
              >
                {empty ?? "Nothing here yet"}
              </td>
            </tr>
          )}
          {!loading && children}
        </tbody>
      </table>
      {footer && (
        <div className="px-3.5 py-2 border-t border-border text-[11px] text-muted">
          {footer}
        </div>
      )}
    </div>
  );
}

/// Body row. Action buttons in the last cell are revealed on hover, per §4.
export function Row({
  children,
  className = "",
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <tr className={`group border-t border-border hover:bg-surface-2 ${className}`}>
      {children}
    </tr>
  );
}

export function Cell({
  children,
  align = "left",
  className = "",
  colSpan,
}: {
  children?: ReactNode;
  align?: "left" | "right";
  className?: string;
  colSpan?: number;
}) {
  return (
    <td
      colSpan={colSpan}
      className={`px-3.5 py-2 h-9 text-[12px] text-text-2 ${
        align === "right" ? "text-right" : "text-left"
      } ${className}`}
    >
      {children}
    </td>
  );
}
