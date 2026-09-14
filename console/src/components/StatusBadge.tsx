interface Props {
  status: "healthy" | "warning" | "error" | "unknown";
  label?: string;
}

const styles = {
  healthy: "bg-green-100 text-green-800",
  warning: "bg-yellow-100 text-yellow-800",
  error: "bg-red-100 text-red-800",
  unknown: "bg-surface-2 text-text-2",
};

const dots = {
  healthy: "bg-green-500",
  warning: "bg-yellow-500",
  error: "bg-red-500",
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
