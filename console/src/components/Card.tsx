interface Props {
  title?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
  headerAction?: React.ReactNode;
}

export default function Card({ title, children, className = "", headerAction }: Props) {
  return (
    <div className={`bg-surface border border-border rounded-xl overflow-hidden ${className}`}>
      {title && (
        <div className="px-4 py-2.5 bg-surface-2 border-b border-border flex items-center justify-between">
          <h3 className="text-[11px] font-medium text-muted uppercase tracking-wider">{title}</h3>
          {headerAction}
        </div>
      )}
      <div className="p-4">{children}</div>
    </div>
  );
}
