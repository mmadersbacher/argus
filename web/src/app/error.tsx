"use client";

// App-Router error boundary: a render throw anywhere in a route segment lands
// here instead of blanking the app. Minimal in-design card with a retry.

export default function Error({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <div className="argus-rise">
      <div className="rounded-xl border border-crit/30 bg-crit/5 p-6">
        <div className="flex items-center gap-2 font-medium text-crit">
          <span className="h-2 w-2 rounded-full bg-crit" /> Something went wrong
        </div>
        <p className="mt-2 text-sm text-muted">
          {error.message || "An unexpected error interrupted this view."}
        </p>
        <button
          type="button"
          onClick={reset}
          className="mt-4 rounded-lg border border-line px-3 py-1.5 text-sm text-fg transition-colors hover:bg-surface-2"
        >
          Try again
        </button>
      </div>
    </div>
  );
}
