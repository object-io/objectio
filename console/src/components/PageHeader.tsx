interface Props {
  title: string;
  description?: string;
  action?: React.ReactNode;
}

export default function PageHeader({ title, description, action }: Props) {
  // Sizes measured off the artboards rather than guessed: the page title is
  // Sora 600 at 20px (the mock's "Dashboard" is 94 CSS px wide, which only
  // lands at 20px), the description IBM Plex Sans at 12px. The console had
  // been shipping a 15px body-font title, which is the main reason a screen
  // read as a different design even where the content matched.
  return (
    <div className="flex items-start justify-between gap-4 mb-5">
      <div className="min-w-0">
        <h1 className="font-display text-[20px] leading-tight font-semibold text-text">
          {title}
        </h1>
        {description && (
          <p className="text-[12px] text-muted mt-1">{description}</p>
        )}
      </div>
      {action && <div className="shrink-0">{action}</div>}
    </div>
  );
}
