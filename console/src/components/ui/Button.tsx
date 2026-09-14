import type { ButtonHTMLAttributes, ReactNode } from "react";

export type ButtonVariant = "primary" | "secondary" | "ghost" | "danger" | "accent";
export type ButtonSize = "md" | "sm";

interface Props extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  /** Leading icon; render a lucide icon at 13–15px. */
  icon?: ReactNode;
  children?: ReactNode;
}

/// Per HANDOFF §4. `primary` is ink-on-paper and inverts under the dark theme,
/// which is why it uses the primary tokens rather than a fixed colour — it is
/// the one primary button on a screen. `accent` is the blue action; `danger`
/// is destructive only.
const VARIANTS: Record<ButtonVariant, string> = {
  primary:
    "bg-primary text-primary-fg hover:bg-primary-hover border border-transparent",
  secondary:
    "bg-surface text-text border border-border-strong hover:bg-surface-2",
  ghost: "bg-transparent text-muted border border-transparent hover:bg-surface-2 hover:text-text",
  danger: "bg-err text-white border border-transparent hover:opacity-90",
  accent: "bg-accent text-accent-fg border border-transparent hover:opacity-90",
};

const SIZES: Record<ButtonSize, string> = {
  md: "h-8 px-3 text-[12px]",
  sm: "h-7 px-2.5 text-[11px]",
};

export default function Button({
  variant = "secondary",
  size = "md",
  icon,
  children,
  className = "",
  ...rest
}: Props) {
  return (
    <button
      {...rest}
      className={`inline-flex items-center justify-center gap-1.5 rounded-control font-medium
        transition-colors disabled:opacity-40 disabled:cursor-not-allowed
        focus:outline-none focus-visible:ring-2 focus-visible:ring-accent-soft
        ${VARIANTS[variant]} ${SIZES[size]} ${className}`}
    >
      {icon}
      {children}
    </button>
  );
}
