"use client";
import { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";
import { cx } from "./internal";
import { Portal } from "./overlay-core";

type Tone = "default" | "ok" | "warn" | "danger";
type ToastMsg = { id: number; title: string; description?: string; tone: Tone };
type ToastInput = { title: string; description?: string; tone?: Tone; duration?: number };

const ToastCtx = createContext<{ toast: (o: ToastInput) => void } | null>(null);

const toneRing: Record<Tone, string> = {
  default: "border-line", ok: "border-ok/30", warn: "border-warn/30", danger: "border-crit/30",
};

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [items, setItems] = useState<ToastMsg[]>([]);
  const seq = useRef(0);
  const timers = useRef<Map<number, ReturnType<typeof setTimeout>>>(new Map());
  const toast = useCallback((o: ToastInput) => {
    const id = ++seq.current;
    setItems((xs) => [...xs, { id, title: o.title, description: o.description, tone: o.tone ?? "default" }]);
    const ms = o.duration ?? 4000;
    const t = setTimeout(() => {
      setItems((xs) => xs.filter((x) => x.id !== id));
      timers.current.delete(id);
    }, ms);
    timers.current.set(id, t);
  }, []);
  useEffect(() => () => { timers.current.forEach(clearTimeout); }, []);
  return (
    <ToastCtx.Provider value={{ toast }}>
      {children}
      <Portal>
        <div className="fixed right-4 top-4 z-[60] flex w-80 flex-col gap-2"
          role="region" aria-live="polite" aria-label="Notifications">
          {items.map((t) => (
            <div key={t.id}
              className={cx("argus-slide rounded-lg border bg-surface px-4 py-3 shadow-lg", toneRing[t.tone])}>
              <p className="text-sm font-semibold text-fg">{t.title}</p>
              {t.description ? <p className="mt-0.5 text-xs text-muted">{t.description}</p> : null}
            </div>
          ))}
        </div>
      </Portal>
    </ToastCtx.Provider>
  );
}

export function useToast() {
  const ctx = useContext(ToastCtx);
  if (!ctx) throw new Error("useToast must be used within <ToastProvider>");
  return ctx;
}
