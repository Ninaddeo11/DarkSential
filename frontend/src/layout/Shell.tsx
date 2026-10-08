import { useState } from "react";
import { Link, NavLink, Outlet, useLocation } from "react-router";
import { OperationalVisual } from "../visuals/OperationalVisual";
import { TopBar } from "../components/TopBar";
import { useLive } from "../live/LiveContext";
import { NexusAccess } from "../components/NexusAccess";
import { PageTransition } from "../components/PageTransition";

interface NavItem {
  to: string;
  label: string;
  icon: string; // SVG path data (24x24)
  end?: boolean;
}

const NAV: NavItem[] = [
  { to: "/overview", label: "Overview", end: true, icon: "M3 12l9-8 9 8M5 10v10h5v-6h4v6h5V10" },
  { to: "/devices", label: "Devices", icon: "M4 5h16v10H4zM8 19h8M12 15v4" },
  { to: "/events", label: "Events", icon: "M4 6h16M4 12h10M4 18h13" },
  { to: "/intel", label: "Threat intel", icon: "M12 3l8 4v5c0 5-3.5 8-8 9-4.5-1-8-4-8-9V7z" },
  { to: "/actors", label: "Actors", icon: "M12 12a4 4 0 100-8 4 4 0 000 8M4 21a8 8 0 0116 0M19 4l2 2-2 2" },
  { to: "/malware", label: "Malware", icon: "M8 8h8v8H8zM12 3v5M12 16v5M3 12h5M16 12h5M5 5l3 3M16 16l3 3M19 5l-3 3M8 16l-3 3" },
  { to: "/vulnerabilities", label: "Vulnerabilities", icon: "M12 3l10 18H2zM12 9v5M12 17v1" },
  { to: "/dark-web", label: "Dark web", icon: "M12 3a9 9 0 100 18 9 9 0 000-18M3 12h18M12 3c5 5 5 13 0 18-5-5-5-13 0-18" },
  { to: "/response", label: "Response", icon: "M6 11V7a6 6 0 0112 0v4M5 11h14v9H5z" },
  { to: "/evaluation", label: "Evaluation", icon: "M4 20V10M10 20V4M16 20v-7M22 20H2" },
];

/** Page frame: top bar, sidebar navigation and the routed page. */
export function Shell() {
  const live = useLive();
  const [navOpen, setNavOpen] = useState(false);
  const location = useLocation();
  const nodes = Object.values(live.state.nodes);
  const badge: Record<string, number> = {
    "/response": nodes.filter((n) => n.quarantined).length,
    "/devices": nodes.filter((n) => n.level === "critical").length,
  };
  return (
    <div className="app-shell flex h-full flex-col">
      <TopBar
        health={live.health}
        link={live.link}
        me={live.me}
        nodes={live.state.nodes}
        rate={live.rate}
        onLogin={live.login}
        onLogout={live.logout}
      />
      {live.error && (
        <div className="bg-critical/15 px-4 py-1.5 text-xs text-critical">Backend: {live.error}</div>
      )}
      {live.health?.deployment === "hosted" && (
        <div className="bg-medium/10 px-4 py-1.5 text-xs text-medium">
          Hosted mode: no lab, no live stream. Run the virtual lab (`make lab-up`) for the live view.
        </div>
      )}
      <button className="mobile-nav-toggle btn" aria-expanded={navOpen} aria-controls="command-navigation" onClick={() => setNavOpen(!navOpen)}>Navigation</button>
      <div className="flex min-h-0 flex-1 flex-col md:flex-row">
        <nav
          id="command-navigation"
          aria-label="Main"
          data-open={navOpen}
          className="command-nav flex shrink-0 gap-1 overflow-x-auto border-b border-ink-700/70 bg-ink-900/60 p-2 md:w-48 md:flex-col md:border-r md:border-b-0"
        >
          <div className="nav-caption">OPERATIONS / NEXUS</div>
          {NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              data-active={(item.to === "/overview" && location.pathname === "/dashboard") || (item.to === "/intel" && location.pathname === "/threat-intel") ? "true" : undefined}
              onClick={() => setNavOpen(false)}
              className={({ isActive }) =>
                `flex items-center gap-2.5 rounded-md px-2.5 py-2 text-xs whitespace-nowrap transition ${
                  isActive
                    ? "bg-signal/12 font-semibold text-signal"
                    : "text-ink-300 hover:bg-ink-800 hover:text-ink-100"
                }`
              }
            >
              <svg width="16" height="16" viewBox="0 0 24 24" aria-hidden="true" className="shrink-0">
                <path d={item.icon} fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinejoin="round" />
              </svg>
              <span className="flex-1">{item.label}</span>
              {(badge[item.to] ?? 0) > 0 && (
                <span
                  className={`chip ${item.to === "/response" ? "bg-quarantine/20 text-quarantine" : "bg-critical/20 text-critical"}`}
                >
                  {badge[item.to]}
                </span>
              )}
            </NavLink>
          ))}
          <div className="nav-footer"><Link to="/intelligence" className="scope-navigation">INTELLIGENCE EXPLORER &#8599;</Link><span className="text-signal">{"\u25c7"}</span> SECURITY OPERATIONS<br /><span>IoT intelligence workspace</span><div className="sidebar-link-state"><span className={`status-light ${live.link === "live" ? "live-dot" : ""}`} data-state={live.link} />{live.link === "live" ? "STREAM CONNECTED" : live.link === "connecting" ? "STREAM CONNECTING" : "STREAM DISCONNECTED"}</div></div>
        </nav>
        <main className="scroll-thin min-h-0 min-w-0 flex-1 overflow-y-auto">
          {live.authNeeded ? (
            <div className="grid h-full place-items-center p-6">
              <NexusAccess embedded />
            </div>
          ) : (
            <PageTransition id={location.pathname} className="page-content"><Outlet /></PageTransition>
          )}
        </main>
      </div>
    </div>
  );
}

/** Consistent page header. */
export function PageHeader({ title, subtitle, children }: { title: string; subtitle?: string; children?: React.ReactNode }) {
  return (
    <div className="page-header flex flex-wrap items-end justify-between gap-3 px-4 pt-4 pb-3">
      <div className="page-heading-with-visual">
        <OperationalVisual />
        <div>
        <p className="section-eyebrow">DARKNET SENTINEL / INTELLIGENCE OPERATIONS</p>
        <h1 className="text-lg font-semibold tracking-tight">{title}</h1>
        {subtitle && <p className="mt-0.5 text-xs text-ink-400">{subtitle}</p>}
        </div>
      </div>
      {children && <div className="flex flex-wrap items-center gap-2">{children}</div>}
    </div>
  );
}
