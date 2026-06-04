import { Icon, type IconName } from "@/components/icon";

/** Honest placeholder for navigation tabs that aren't built yet. */
export function Placeholder({
  title,
  icon,
  note,
}: {
  title: string;
  icon: IconName;
  note: string;
}) {
  return (
    <div className="argus-rise">
      <h1 className="text-2xl font-bold tracking-tight">{title}</h1>
      <div className="mt-8 flex flex-col items-center justify-center rounded-xl border border-dashed border-line bg-surface py-20 text-center">
        <span className="flex h-14 w-14 items-center justify-center rounded-2xl bg-surface-2 text-muted">
          <Icon name={icon} size={28} />
        </span>
        <h2 className="mt-4 text-lg font-semibold">Not built yet</h2>
        <p className="mt-1 max-w-sm text-sm text-muted">{note}</p>
        <span className="mt-3 rounded-full border border-line px-3 py-1 text-xs font-medium text-muted">
          Roadmap
        </span>
      </div>
    </div>
  );
}
