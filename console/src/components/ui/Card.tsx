import type { ReactNode } from "react";

/// Surface container per §4. The optional header is a mono 11px caps title
/// with a right-hand action slot, which is the pattern every panel in the
/// mockups uses.
export default function Card({
  title,
  action,
  children,
  className = "",
  bodyClassName = "p-4",
}: {
  title?: string;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
}) {
  return (
    <div
      className={`bg-surface border border-border rounded-card shadow-sm ${className}`}
    >
      {(title || action) && (
        <div className="flex items-center justify-between px-4 py-2.5 border-b border-border">
          {title && (
            <h3 className="font-mono text-[11px] uppercase tracking-wider text-muted">
              {title}
            </h3>
          )}
          {action}
        </div>
      )}
      <div className={bodyClassName}>{children}</div>
    </div>
  );
}
