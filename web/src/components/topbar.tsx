import { Icon } from "@/components/icon";

export function TopBar() {
  return (
    <header className="flex h-16 items-center gap-3 border-b border-line bg-surface px-5">
      <button
        type="button"
        aria-label="History"
        className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-line text-muted transition-colors hover:bg-surface-2 hover:text-fg"
      >
        <Icon name="clock" size={17} />
      </button>

      <div className="flex max-w-2xl flex-1 items-center gap-2 rounded-lg border border-line bg-surface-2 px-3 py-2 text-sm text-muted">
        <Icon name="search" size={16} />
        <span>Search assets, IPs, CVEs…</span>
      </div>

      <div className="ml-auto flex items-center gap-2">
        <button
          type="button"
          className="hidden items-center gap-2 rounded-lg border border-line px-3 py-1.5 text-sm text-fg transition-colors hover:bg-surface-2 sm:flex"
        >
          <Icon name="clock" size={14} /> Last 7 Days <Icon name="chevron" size={14} />
        </button>
        <span className="inline-flex items-center gap-1.5 rounded-full border border-line px-2.5 py-1 text-xs text-muted">
          <span className="argus-pulse h-2 w-2 rounded-full bg-accent" /> Live
        </span>
        <div className="flex h-9 w-9 items-center justify-center rounded-full bg-accent text-sm font-semibold text-white">
          A
        </div>
      </div>
    </header>
  );
}
