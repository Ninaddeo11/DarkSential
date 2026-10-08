import { NavLink, Outlet } from "react-router";
import { TopBar } from "../components/TopBar";
import { useLive } from "../live/LiveContext";

interface NavItem {
  to: string;
  label: string;
  icon: string; // SVG path data (24x24)
  end?: boolean;
}

const NAV: NavItem[] = [
  { to: "/", label: "Overview", end: true, icon: "M3 12l9-8 9 8M5 10v10h5v-6h4v6h5V10" },
  { to: "/devices", label: "Devices", icon: "M4 5h16v10H4zM8 19h8M12 15v4" },
  { to: "/events", label: "Events", icon: "M4 6h16M4 12h10M4 18h13" },
  { to: "/intel", label: "Threat intel", icon: "M12 3l8 4v5c0 5-3.5 8-8 9-4.5-1-8-4-8-9V7z" },
  { to: "/response", label: "Response", icon: "M6 11V7a6 6 0 0112 0v4M5 11h14v9H5z" },
  { to: "/evaluation", label: "Evaluation", icon: "M4 20V10M10 20V4M16 20v-7M22 20H2" },
];

/** Page frame: top bar, sidebar navigation and the routed page. */
export function Shell() {
  const live = useLive();
  const nodes = Object.values(live.state.nodes);
  const badge: Record<string, number> = {
    "/response": nodes.filter((n) => n.quarantined).length,
    "/devices": nodes.filter((n) => n.level === "critical").length,
  };
  return (
    <div className="flex h-full flex-col">
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
      <div className="flex min-h-0 flex-1 flex-col md:flex-row">
        <nav
          aria-label="Main"
          className="flex shrink-0 gap-1 overflow-x-auto border-b border-ink-700/70 bg-ink-900/60 p-2 md:w-48 md:flex-col md:border-r md:border-b-0"
        >
          {NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
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
        </nav>
        <main className="scroll-thin min-h-0 min-w-0 flex-1 overflow-y-auto">
          {live.authNeeded ? (
            <div className="grid h-full place-items-center p-6">
              <div className="panel max-w-sm p-5 text-center">
                <h2 className="mb-1 text-sm font-semibold">Sign in required</h2>
                <p className="text-xs text-ink-300">
                  This deployment requires authentication for all reads. Use the Sign in button
                  above with your admin or viewer token, or an OIDC access token.
                </p>
              </div>
            </div>
          ) : (
            <Outlet />
          )}
        </main>
      </div>
    </div>
  );
}

/** Consistent page header. */
export function PageHeader({ title, subtitle, children }: { title: string; subtitle?: string; children?: React.ReactNode }) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-3 px-4 pt-4 pb-3">
      <div>
        <h1 className="text-lg font-semibold tracking-tight">{title}</h1>
        {subtitle && <p className="mt-0.5 text-xs text-ink-400">{subtitle}</p>}
      </div>
      {children && <div className="flex flex-wrap items-center gap-2">{children}</div>}
    </div>
  );
}
