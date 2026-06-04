// Shared loading / error states for the data-backed views.

export function LoadingState() {
  return (
    <div className="space-y-6">
      <div className="h-9 w-44 animate-pulse rounded-lg bg-surface" />
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <div key={i} className="h-28 animate-pulse rounded-xl border border-line bg-surface" />
        ))}
      </div>
      <div className="h-72 animate-pulse rounded-xl border border-line bg-surface" />
    </div>
  );
}

export function ErrorState({ message }: { message: string }) {
  return (
    <div className="rounded-xl border border-crit/30 bg-crit/5 p-6">
      <div className="flex items-center gap-2 font-medium text-crit">
        <span className="h-2 w-2 rounded-full bg-crit" /> argus-api unreachable
      </div>
      <p className="mt-2 text-sm text-muted">{message}</p>
      <p className="mt-3 font-mono text-xs text-muted">
        Start it with <span className="text-fg">cargo run -p argus-api</span> (expects
        http://127.0.0.1:8088)
      </p>
    </div>
  );
}
