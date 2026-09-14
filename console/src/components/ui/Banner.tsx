import { CheckCircle2, AlertTriangle, XCircle } from "lucide-react";
import type { ReactNode } from "react";

export type BannerKind = "ok" | "warn" | "err";

const KINDS: Record<BannerKind, { wrap: string; Icon: typeof CheckCircle2 }> = {
  ok: { wrap: "bg-ok-soft border-ok/25 text-ok", Icon: CheckCircle2 },
  warn: { wrap: "bg-warn-soft border-warn/25 text-warn", Icon: AlertTriangle },
  err: { wrap: "bg-err-soft border-err/25 text-err", Icon: XCircle },
};

/// Soft-background notice with an icon and optional action slot, per §4.
export default function Banner({
  kind = "warn",
  title,
  children,
  action,
  className = "",
}: {
  kind?: BannerKind;
  title?: string;
  children?: ReactNode;
  action?: ReactNode;
  className?: string;
}) {
  const { wrap, Icon } = KINDS[kind];
  return (
    <div
      className={`flex items-start gap-2.5 px-3 py-2.5 rounded-card border ${wrap} ${className}`}
    >
      <Icon size={16} className="shrink-0 mt-px" />
      <div className="flex-1 min-w-0">
        {title && <p className="text-[12px] font-medium">{title}</p>}
        {children && <div className="text-[11px] opacity-90">{children}</div>}
      </div>
      {action}
    </div>
  );
}
