import type { ReactNode, SVGProps } from "react";

export type IconName =
  | "dashboard" | "projects" | "websites" | "agents" | "code" | "security"
  | "testing" | "deploy" | "integrations" | "settings" | "docs" | "support"
  | "search" | "bell" | "sun" | "moon" | "chevron" | "plus" | "folder"
  | "scan" | "more" | "refresh" | "trash" | "check" | "warning" | "activity"
  | "file" | "function" | "class" | "interface" | "close" | "external" | "user";

const common: SVGProps<SVGSVGElement> = {
  viewBox: "0 0 24 24",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 1.8,
  strokeLinecap: "round",
  strokeLinejoin: "round",
  "aria-hidden": true,
};

function shape(name: IconName): ReactNode {
  switch (name) {
    case "dashboard": return <><path d="M3 10.5 12 3l9 7.5"/><path d="M5.5 9.5V21h13V9.5"/><path d="M9 21v-6h6v6"/></>;
    case "projects":
    case "folder": return <path d="M3.5 6.5h6l2 2h9v11h-17z"/>;
    case "websites": return <><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18"/></>;
    case "agents": return <><rect x="5" y="7" width="14" height="11" rx="3"/><path d="M9 3h6M12 3v4M2.5 11v4M21.5 11v4M9 12h.01M15 12h.01M9 15h6"/></>;
    case "code": return <><path d="m8 7-5 5 5 5M16 7l5 5-5 5M14 4l-4 16"/></>;
    case "security":
    case "scan": return <><path d="M12 3 20 6v5c0 5-3.4 8.2-8 10-4.6-1.8-8-5-8-10V6z"/><path d="m9 12 2 2 4-4"/></>;
    case "testing": return <><path d="M9 3h6M10 3v5l-5 9a2 2 0 0 0 1.8 3h10.4A2 2 0 0 0 19 17l-5-9V3"/><path d="M8 15h8"/></>;
    case "deploy": return <><path d="M14 4c3-1 5-1 6-1 0 1 0 3-1 6l-5 5-4-4z"/><path d="m10 14-3 3M7 11l-3 1-1 3 4 1M13 17l-1 4-3-1 1-3"/></>;
    case "integrations": return <><path d="M8 3v5M16 3v5M5 8h14v3a7 7 0 0 1-14 0z"/><path d="M12 18v3"/></>;
    case "settings": return <><circle cx="12" cy="12" r="3"/><path d="M19 12a7 7 0 0 0-.1-1l2-1.5-2-3.4-2.4 1a8 8 0 0 0-1.7-1L14.5 3h-5l-.4 3.1a8 8 0 0 0-1.7 1l-2.4-1-2 3.4L5.1 11a7 7 0 0 0 0 2L3 14.5l2 3.4 2.4-1a8 8 0 0 0 1.7 1l.4 3.1h5l.4-3.1a8 8 0 0 0 1.7-1l2.4 1 2-3.4-2.1-1.5a7 7 0 0 0 .1-1z"/></>;
    case "docs": return <><path d="M4 5c3-1 5-.5 8 1.5V21c-3-2-5-2.5-8-1.5zM20 5c-3-1-5-.5-8 1.5V21c3-2 5-2.5 8-1.5z"/></>;
    case "support": return <><circle cx="12" cy="12" r="9"/><path d="M8 8a4 4 0 1 1 6 3.5c-1.5.8-2 1.5-2 2.5M12 18h.01"/></>;
    case "search": return <><circle cx="11" cy="11" r="6.5"/><path d="m16 16 5 5"/></>;
    case "bell": return <><path d="M6 10a6 6 0 0 1 12 0v5l2 2H4l2-2z"/><path d="M10 20h4"/></>;
    case "sun": return <><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M2 12h2M20 12h2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M19.1 4.9l-1.4 1.4M6.3 17.7l-1.4 1.4"/></>;
    case "moon": return <path d="M20 15.2A8 8 0 0 1 8.8 4a8.5 8.5 0 1 0 11.2 11.2z"/>;
    case "chevron": return <path d="m9 6 6 6-6 6"/>;
    case "plus": return <path d="M12 5v14M5 12h14"/>;
    case "more": return <><circle cx="5" cy="12" r="1"/><circle cx="12" cy="12" r="1"/><circle cx="19" cy="12" r="1"/></>;
    case "refresh": return <><path d="M20 7v5h-5"/><path d="M19 12a7 7 0 1 0-2 5"/></>;
    case "trash": return <><path d="M4 7h16M9 7V4h6v3M7 7l1 14h8l1-14M10 11v6M14 11v6"/></>;
    case "check": return <path d="m5 12 4 4 10-10"/>;
    case "warning": return <><path d="M12 3 2.5 20h19z"/><path d="M12 9v4M12 17h.01"/></>;
    case "activity": return <path d="M3 12h4l2-6 4 12 2-6h6"/>;
    case "file": return <><path d="M6 3h8l4 4v14H6z"/><path d="M14 3v5h5"/></>;
    case "function": return <path d="M15 4c-3 0-4 2-4.5 5L9 18c-.3 2-1 3-3 3M7 10h8"/>;
    case "class": return <><rect x="4" y="4" width="16" height="16" rx="2"/><path d="M8 9h8M8 13h5M8 17h8"/></>;
    case "interface": return <><circle cx="6" cy="6" r="2"/><circle cx="18" cy="6" r="2"/><circle cx="12" cy="18" r="2"/><path d="M8 7.5l3 8M16 7.5l-3 8M8 6h8"/></>;
    case "close": return <path d="m6 6 12 12M18 6 6 18"/>;
    case "external": return <><path d="M13 5h6v6M19 5l-8 8"/><path d="M17 13v6H5V7h6"/></>;
    case "user": return <><circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/></>;
  }
}

export function Icon({ name, size = 20, className }: { name: IconName; size?: number; className?: string }) {
  return <svg {...common} width={size} height={size} className={className}>{shape(name)}</svg>;
}
