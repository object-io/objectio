interface Props {
  status: "healthy" | "warning" | "error" | "unknown";
  label?: string;
}

const styles = {
  healthy: "bg-ok-soft text-ok",
  warning: "bg-warn-soft text-warn",
  error: "bg-err-soft text-err",
  unknown: "bg-surface-2 text-text-2",
};

const dots = {
  healthy: "bg-ok",
  warning: "bg-warn-dot",
  error: "bg-err",
  unknown: "bg-faint",
};

export default function StatusBadge({ status, label }: Props) {
  return (
    <span
      className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[11px] font-medium ${styles[status]}`}
    >
      <span className={`w-1 h-1 rounded-full ${dots[status]}`} />
      {label || status}
    </span>
  );
}
