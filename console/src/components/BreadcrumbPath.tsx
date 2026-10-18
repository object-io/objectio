interface Props {
  /// Topology path segments in order, e.g. ["us-east", "us-east-1a", "dc1", "rack-a"].
  /// Empty or missing segments are rendered as "—" to keep alignment stable.
  segments: (string | null | undefined)[];
  /// Muted separator character between segments.
  sep?: string;
  className?: string;
}

export default function BreadcrumbPath({
  segments,
  sep = "/",
  className = "",
}: Props) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 font-mono text-[11px] text-muted ${className}`}
    >
      {segments.map((s, i) => (
        <span key={i} className="inline-flex items-center gap-1.5">
          <span className={s ? "text-text-2" : "text-faint"}>
            {s || "—"}
          </span>
          {i < segments.length - 1 && (
            <span className="text-faint">{sep}</span>
          )}
        </span>
      ))}
    </span>
  );
}
