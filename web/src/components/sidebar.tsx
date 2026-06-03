import { Icon, type IconName } from "@/components/icon";

const nav: { label: string; icon: IconName; active?: boolean }[] = [
  { label: "Dashboard", icon: "grid", active: true },
  { label: "Assets", icon: "server" },
  { label: "Vulnerabilities", icon: "alert" },
  { label: "Risk", icon: "activity" },
  { label: "Policies", icon: "shield" },
  { label: "Settings", icon: "sliders" },
];

export function Sidebar() {
  return (
    <aside className="hidden w-60 shrink-0 flex-col border-r border-line bg-surface/60 backdrop-blur md:flex">
      <div className="flex h-16 items-center gap-2.5 border-b border-line px-5">
        <span className="text-accent">
          <Icon name="eye" size={22} />
        </span>
        <span className="text-lg font-semibold tracking-wide">ARGUS</span>
        <span className="ml-auto font-mono text-[10px] text-muted">v0.1</span>
      </div>
      <nav className="flex-1 space-y-1 px-3 py-4">
        {nav.map((it) => (
          <a
            key={it.label}
            href="#"
            className={`group flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors ${
              it.active
                ? "bg-surface-2 text-fg"
                : "text-muted hover:bg-surface-2/60 hover:text-fg"
            }`}
          >
            <span className={it.active ? "text-accent" : ""}>
              <Icon name={it.icon} />
            </span>
            {it.label}
          </a>
        ))}
      </nav>
      <div className="border-t border-line px-5 py-4 text-[11px] text-muted">
        Cyber Exposure Management
      </div>
    </aside>
  );
}
