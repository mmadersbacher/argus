"use client";

// App-Router error boundary: a render throw anywhere in a route segment lands
// here instead of blanking the app. In-design crit-accented panel with retry.

import { Icon } from "@/components/icon";
import { Button } from "@/components/ui";

export default function Error({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <div className="argus-rise mx-auto max-w-lg pt-10">
      <div className="rounded-xl border border-crit/25 bg-surface p-6 shadow-[0_1px_2px_rgba(16,24,40,0.05)]">
        <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-crit/10 text-crit">
          <Icon name="alert" size={18} />
        </div>
        <h2 className="mt-3 text-sm font-semibold text-fg">
          Something went wrong
        </h2>
        <p className="mt-1 text-sm text-muted">
          {error.message || "An unexpected error interrupted this view."}
        </p>
        <div className="mt-4">
          <Button variant="secondary" size="sm" onClick={reset}>
            Try again
          </Button>
        </div>
      </div>
    </div>
  );
}
