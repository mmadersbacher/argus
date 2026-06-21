"use client";

import { useCallback, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { Modal } from "@/components/ui";
import { Icon } from "@/components/icon";
import { useTheme, type Theme } from "@/components/theme";

// ---------------------------------------------------------------------------
// Command registry
// ---------------------------------------------------------------------------

type CommandGroup = "Navigation" | "Actions";

interface Command {
  id: string;
  label: string;
  group: CommandGroup;
  run: () => void;
}

// Theme cycle: light -> dark -> system -> light
const THEME_CYCLE: Theme[] = ["light", "dark", "system"];

function useCommands(): Command[] {
  const router = useRouter();
  const { theme, setTheme } = useTheme();

  return useMemo(() => {
    function cycleTheme() {
      const idx = THEME_CYCLE.indexOf(theme);
      const next = THEME_CYCLE[(idx + 1) % THEME_CYCLE.length];
      setTheme(next);
    }

    return [
      // Navigation routes
      {
        id: "nav-overview",
        label: "Overview",
        group: "Navigation" as const,
        run: () => router.push("/"),
      },
      {
        id: "nav-assets",
        label: "Assets",
        group: "Navigation" as const,
        run: () => router.push("/assets"),
      },
      {
        id: "nav-vulns",
        label: "Vulns",
        group: "Navigation" as const,
        run: () => router.push("/vulns"),
      },
      {
        id: "nav-risk",
        label: "Risk",
        group: "Navigation" as const,
        run: () => router.push("/risk"),
      },
      {
        id: "nav-network",
        label: "Network",
        group: "Navigation" as const,
        run: () => router.push("/network"),
      },
      {
        id: "nav-graph",
        label: "Graph",
        group: "Navigation" as const,
        run: () => router.push("/graph"),
      },
      {
        id: "nav-policy",
        label: "Policy",
        group: "Navigation" as const,
        run: () => router.push("/policy"),
      },
      {
        id: "nav-reports",
        label: "Reports",
        group: "Navigation" as const,
        run: () => router.push("/reports"),
      },
      {
        id: "nav-settings",
        label: "Settings",
        group: "Navigation" as const,
        run: () => router.push("/settings"),
      },
      // Actions
      {
        id: "action-scan",
        label: "Start scan",
        group: "Actions" as const,
        run: () => router.push("/assets"),
      },
      {
        id: "action-theme",
        label: "Toggle theme",
        group: "Actions" as const,
        run: cycleTheme,
      },
    ];
  }, [router, theme, setTheme]);
}

// ---------------------------------------------------------------------------
// Inner palette body — mounted fresh on each open (resets state automatically)
// ---------------------------------------------------------------------------

function PaletteBody({ onClose }: { onClose: () => void }) {
  const commands = useCommands();
  const [query, setQuery] = useState("");
  // unclamped cursor; clamped at render time
  const [activeIdx, setActiveIdx] = useState(0);

  // Filter commands by substring match on label or group (case-insensitive)
  const filtered = useMemo(() => {
    if (!query.trim()) return commands;
    const lower = query.toLowerCase();
    return commands.filter(
      (c) =>
        c.label.toLowerCase().includes(lower) ||
        c.group.toLowerCase().includes(lower),
    );
  }, [commands, query]);

  // Clamp activeIdx at render time — no effect or setState cascade needed
  const safeActiveIdx =
    filtered.length === 0 ? 0 : Math.min(activeIdx, filtered.length - 1);

  const runActive = useCallback(() => {
    const cmd = filtered[safeActiveIdx];
    if (cmd) {
      cmd.run();
      onClose();
    }
  }, [filtered, safeActiveIdx, onClose]);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === "ArrowDown") {
        e.preventDefault();
        setActiveIdx((i) => (i + 1) % Math.max(1, filtered.length));
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        setActiveIdx(
          (i) =>
            (i - 1 + Math.max(1, filtered.length)) %
            Math.max(1, filtered.length),
        );
      } else if (e.key === "Enter") {
        e.preventDefault();
        runActive();
      }
    },
    [filtered.length, runActive],
  );

  // Group filtered commands for display
  const groups = Array.from(new Set(filtered.map((c) => c.group)));

  return (
    <div className="flex flex-col gap-3" onKeyDown={handleKeyDown}>
      <div className="relative">
        <span className="pointer-events-none absolute inset-y-0 left-3 flex items-center text-muted">
          <Icon name="search" size={15} />
        </span>
        <input
          autoFocus
          placeholder="Search commands..."
          value={query}
          onChange={(e) => {
            setQuery(e.target.value);
            setActiveIdx(0);
          }}
          className="h-9 w-full rounded-lg border border-line bg-surface pl-8 pr-3 text-sm text-fg transition-colors placeholder:text-faint focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/20"
          aria-label="Search commands"
          aria-autocomplete="list"
          aria-controls="command-palette-listbox"
          aria-activedescendant={
            filtered[safeActiveIdx]
              ? `cmd-opt-${filtered[safeActiveIdx].id}`
              : undefined
          }
        />
      </div>

      <div
        id="command-palette-listbox"
        role="listbox"
        aria-label="Commands"
        className="max-h-72 overflow-y-auto"
      >
        {filtered.length === 0 ? (
          <p className="px-2 py-4 text-center text-sm text-muted">
            No commands found
          </p>
        ) : (
          groups.map((group) => {
            const groupCmds = filtered.filter((c) => c.group === group);
            return (
              <div key={group}>
                <p className="px-2 py-1.5 text-[11px] font-semibold uppercase tracking-widest text-muted">
                  {group}
                </p>
                {groupCmds.map((cmd) => {
                  const globalIdx = filtered.indexOf(cmd);
                  const isActive = globalIdx === safeActiveIdx;
                  return (
                    <button
                      key={cmd.id}
                      id={`cmd-opt-${cmd.id}`}
                      role="option"
                      aria-selected={isActive}
                      type="button"
                      onMouseEnter={() => setActiveIdx(globalIdx)}
                      onClick={() => {
                        cmd.run();
                        onClose();
                      }}
                      className={
                        "flex w-full items-center gap-2 rounded-lg px-3 py-2 text-left text-sm transition-colors " +
                        (isActive
                          ? "bg-accent text-white"
                          : "text-fg hover:bg-surface-2")
                      }
                    >
                      {cmd.label}
                    </button>
                  );
                })}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// CommandPalette — controlled open/close gate
// ---------------------------------------------------------------------------

export function CommandPalette({
  open,
  onClose,
}: {
  open: boolean;
  onClose: () => void;
}) {
  if (!open) return null;

  return (
    <Modal title="Command palette" onClose={onClose} size="md">
      <PaletteBody onClose={onClose} />
    </Modal>
  );
}
