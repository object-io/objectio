import type { ReactNode } from "react";

/// Small neutral token for identifiers — pools, tenants, tags. `mono` per §4,
/// because the things it usually holds are identifiers rather than prose.
export default function Chip({
  children,
  mono = false,
  className = "",
}: {
  children: ReactNode;
  mono?: boolean;
  className?: string;
}) {
  return (
    <span
      className={`inline-flex items-center px-1.5 py-px rounded-[5px] text-[11px]
        bg-surface-2 border border-border text-text-2
        ${mono ? "font-mono" : ""} ${className}`}
    >
      {children}
    </span>
  );
}
