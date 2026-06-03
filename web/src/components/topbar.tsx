import { Icon } from "@/components/icon";

export function TopBar() {
  return (
    <header className="flex h-16 items-center gap-4 border-b border-line bg-surface/40 px-6 backdrop-blur">
      <div>
        <h1 className="text-sm font-medium">Exposure Overview</h1>
        <p className="text-xs text-muted">Continuous asset discovery &amp; risk</p>
      </div>
      <div className="ml-auto flex items-center gap-3">
        <div className="hidden w-72 items-center gap-2 rounded-lg border border-line bg-surface px-3 py-1.5 text-sm text-muted lg:flex">
          <Icon name="search" size={15} />
          <span>Search assets…</span>
        </div>
        <span className="inline-flex items-center gap-2 rounded-full border border-line bg-surface px-3 py-1.5 text-xs text-muted">
          <span className="argus-pulse h-2 w-2 rounded-full bg-accent" /> Live
        </span>
      </div>
    </header>
  );
}
