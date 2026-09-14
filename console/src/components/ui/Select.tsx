import type { ReactNode, SelectHTMLAttributes } from "react";

interface Props extends SelectHTMLAttributes<HTMLSelectElement> {
  /** 11px/600 label rendered above the control, matching Input. */
  label?: ReactNode;
  hint?: ReactNode;
  error?: string;
}

/// Same 32px control and focus treatment as Input. Four pages were each
/// hand-rolling a select with slightly different padding and radius, which is
/// how a form ends up with controls that do not line up.
export default function Select({ label, hint, error, className = "", children, ...rest }: Props) {
  return (
    <div>
      {label && (
        <label className="block text-[11px] font-semibold text-text-2 mb-1">{label}</label>
      )}
      <select
        {...rest}
        className={`w-full h-8 px-2.5 bg-surface text-text border rounded-control text-[13px]
          focus:outline-none focus:border-accent focus:ring-2 focus:ring-accent-soft
          ${error ? "border-err" : "border-border-strong"} ${className}`}
      >
        {children}
      </select>
      {error ? (
        <p className="mt-1 text-[11px] text-err">{error}</p>
      ) : hint ? (
        <p className="mt-1 text-[11px] text-faint">{hint}</p>
      ) : null}
    </div>
  );
}
