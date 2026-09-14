/// 6px track per §4. The fill changes meaning at the thresholds the handoff
/// fixes — 75% is attention, 90% is a problem — so a bar that is merely full
/// does not read the same as one that is nearly out of room.
export default function CapacityBar({
  used,
  total,
  label,
  className = "",
}: {
  used: number;
  total: number;
  label?: string;
  className?: string;
}) {
  const pct = total > 0 ? Math.min(100, (used / total) * 100) : 0;
  const fill = pct >= 90 ? "bg-err" : pct >= 75 ? "bg-warn-dot" : "bg-accent";
  return (
    <div className={className}>
      <div className="h-1.5 w-full rounded-full bg-surface-2 overflow-hidden">
        <div
          className={`h-full rounded-full ${fill}`}
          style={{ width: `${pct}%` }}
          role="progressbar"
          aria-valuenow={Math.round(pct)}
          aria-valuemin={0}
          aria-valuemax={100}
        />
      </div>
      {label && <p className="mt-1 text-[11px] text-muted">{label}</p>}
    </div>
  );
}
