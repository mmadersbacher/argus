// Minimal inline icon set (no icon dependency). Stroke-based, 24x24.

export type IconName =
  | "grid"
  | "server"
  | "alert"
  | "activity"
  | "shield"
  | "sliders"
  | "search"
  | "network"
  | "cpu"
  | "smartphone"
  | "cloud"
  | "chevron"
  | "bug"
  | "gauge"
  | "menu"
  | "x"
  | "external"
  | "file"
  | "logout"
  | "graph";

export function Icon({ name, size = 18 }: { name: IconName; size?: number }) {
  const common = {
    width: size,
    height: size,
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: 1.7,
    strokeLinecap: "round" as const,
    strokeLinejoin: "round" as const,
    // Icons are always decorative — the accessible name lives on the
    // surrounding button/link (aria-label) or adjacent text.
    "aria-hidden": true,
    focusable: "false" as const,
  };
  switch (name) {
    case "grid":
      return (
        <svg {...common}>
          <rect x="3" y="3" width="7" height="7" rx="1.5" />
          <rect x="14" y="3" width="7" height="7" rx="1.5" />
          <rect x="3" y="14" width="7" height="7" rx="1.5" />
          <rect x="14" y="14" width="7" height="7" rx="1.5" />
        </svg>
      );
    case "server":
      return (
        <svg {...common}>
          <rect x="3" y="4" width="18" height="7" rx="2" />
          <rect x="3" y="13" width="18" height="7" rx="2" />
          <path d="M7 7.5h.01M7 16.5h.01" />
        </svg>
      );
    case "alert":
      return (
        <svg {...common}>
          <path d="M12 3 2.5 20h19L12 3Z" />
          <path d="M12 10v4M12 17h.01" />
        </svg>
      );
    case "activity":
      return (
        <svg {...common}>
          <path d="M3 12h4l2.5 7 5-14 2.5 7h4" />
        </svg>
      );
    case "shield":
      return (
        <svg {...common}>
          <path d="M12 3 5 6v6c0 4 3 7 7 8 4-1 7-4 7-8V6l-7-3Z" />
        </svg>
      );
    case "sliders":
      return (
        <svg {...common}>
          <path d="M4 7h16M4 12h16M4 17h16" />
          <circle cx="9" cy="7" r="2" fill="currentColor" stroke="none" />
          <circle cx="15" cy="12" r="2" fill="currentColor" stroke="none" />
          <circle cx="8" cy="17" r="2" fill="currentColor" stroke="none" />
        </svg>
      );
    case "search":
      return (
        <svg {...common}>
          <circle cx="11" cy="11" r="7" />
          <path d="m20 20-3-3" />
        </svg>
      );
    case "network":
      return (
        <svg {...common}>
          <path d="M5 12.5a10 10 0 0 1 14 0" />
          <path d="M8.2 16a5 5 0 0 1 7.6 0" />
          <circle cx="12" cy="19" r="1.1" fill="currentColor" stroke="none" />
        </svg>
      );
    case "cpu":
      return (
        <svg {...common}>
          <rect x="6" y="6" width="12" height="12" rx="2" />
          <rect x="9.5" y="9.5" width="5" height="5" rx="1" />
          <path d="M9 3v3M15 3v3M9 18v3M15 18v3M3 9h3M3 15h3M18 9h3M18 15h3" />
        </svg>
      );
    case "smartphone":
      return (
        <svg {...common}>
          <rect x="7" y="3" width="10" height="18" rx="2.5" />
          <path d="M11 18h2" />
        </svg>
      );
    case "cloud":
      return (
        <svg {...common}>
          <path d="M7 18a4 4 0 0 1 .6-8A5.5 5.5 0 0 1 18 11.5 3.5 3.5 0 0 1 17.5 18H7Z" />
        </svg>
      );
    case "chevron":
      return (
        <svg {...common}>
          <path d="m6 9 6 6 6-6" />
        </svg>
      );
    case "bug":
      return (
        <svg {...common}>
          <rect x="8" y="8" width="8" height="11" rx="4" />
          <path d="m9.3 7.3-1.8-2M14.7 7.3l1.8-2" />
          <path d="M8 11.5H4.5M8 15H5M16 11.5h3.5M16 15h3" />
        </svg>
      );
    case "gauge":
      return (
        <svg {...common}>
          <path d="M3.4 18.5a10 10 0 1 1 17.2 0" />
          <path d="m12 14 4-4.5" />
          <circle cx="12" cy="14" r="1" fill="currentColor" stroke="none" />
        </svg>
      );
    case "menu":
      return (
        <svg {...common}>
          <path d="M4 7h16M4 12h16M4 17h16" />
        </svg>
      );
    case "x":
      return (
        <svg {...common}>
          <path d="m6 6 12 12M18 6 6 18" />
        </svg>
      );
    case "external":
      return (
        <svg {...common}>
          <path d="M10 5.5H6.5A1.5 1.5 0 0 0 5 7v10.5A1.5 1.5 0 0 0 6.5 19H17a1.5 1.5 0 0 0 1.5-1.5V14" />
          <path d="M14 4.5h5.5V10" />
          <path d="M19.5 4.5 11 13" />
        </svg>
      );
    case "file":
      return (
        <svg {...common}>
          <path d="M13.5 3.5H7A1.5 1.5 0 0 0 5.5 5v14A1.5 1.5 0 0 0 7 20.5h10a1.5 1.5 0 0 0 1.5-1.5V8.5z" />
          <path d="M13.5 3.5v5h5" />
          <path d="M9 13h6M9 16.5h6" />
        </svg>
      );
    case "logout":
      return (
        <svg {...common}>
          <path d="M10 4.5H6A1.5 1.5 0 0 0 4.5 6v12A1.5 1.5 0 0 0 6 19.5h4" />
          <path d="m15.5 8 4 4-4 4" />
          <path d="M19.5 12H9.5" />
        </svg>
      );
    case "graph":
      return (
        <svg {...common}>
          <circle cx="6" cy="6.5" r="2.3" />
          <circle cx="18" cy="9" r="2.3" />
          <circle cx="9.5" cy="18" r="2.3" />
          <path d="M8 7.3 15.8 8.5M7.2 8.4 8.6 15.8M11.4 16.8 16.3 10.7" />
        </svg>
      );
    default:
      return null;
  }
}
