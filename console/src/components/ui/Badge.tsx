import type { ReactNode } from "react";

export type BadgeKind = "ok" | "warn" | "err" | "info" | "neutral";

/// Status is never colour alone — every badge carries a 5px dot, per §2.
const KINDS: Record<BadgeKind, { wrap: string; dot: string }> = {
  ok: { wrap: "bg-ok-soft text-ok", dot: "bg-ok" },
  warn: { wrap: "bg-warn-soft text-warn", dot: "bg-warn-dot" },
  err: { wrap: "bg-err-soft text-err", dot: "bg-err" },
  info: { wrap: "bg-info-soft text-info", dot: "bg-info" },
  neutral: { wrap: "bg-surface-2 text-muted", dot: "bg-faint" },
};

export default function Badge({
  kind = "neutral",
  children,
  className = "",
}: {
  kind?: BadgeKind;
  children: ReactNode;
  className?: string;
}) {
  const k = KINDS[kind];
  return (
    <span
      className={`inline-flex items-center gap-1.5 px-1.5 py-px rounded-[5px]
        text-[11px] font-medium ${k.wrap} ${className}`}
    >
      <span className={`w-[5px] h-[5px] rounded-full ${k.dot}`} />
      {children}
    </span>
  );
}
