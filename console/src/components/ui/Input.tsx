import type { InputHTMLAttributes, ReactNode } from "react";

interface Props extends InputHTMLAttributes<HTMLInputElement> {
  /** 11px/600 label rendered above the control. */
  label?: string;
  /** Leading icon, 13px, sits at left-2.5. */
  icon?: ReactNode;
  hint?: string;
  error?: string;
}

/// 32px control per HANDOFF §4. Focus is a soft accent ring plus an accent
/// border, so the state reads without relying on colour alone.
export default function Input({ label, icon, hint, error, className = "", ...rest }: Props) {
  return (
    <div>
      {label && (
        <label className="block text-[11px] font-semibold text-text-2 mb-1">{label}</label>
      )}
      <div className="relative">
        {icon && (
          <span className="absolute left-2.5 top-1/2 -translate-y-1/2 text-faint pointer-events-none">
            {icon}
          </span>
        )}
        <input
          {...rest}
          className={`w-full h-8 ${icon ? "pl-8" : "pl-2.5"} pr-2.5 bg-surface text-text
            border border-border-strong rounded-control text-[13px]
            placeholder:text-faint focus:outline-none focus:border-accent
            focus:ring-2 focus:ring-accent-soft ${error ? "border-err" : ""} ${className}`}
        />
      </div>
      {error ? (
        <p className="mt-1 text-[11px] text-err">{error}</p>
      ) : hint ? (
        <p className="mt-1 text-[11px] text-faint">{hint}</p>
      ) : null}
    </div>
  );
}
