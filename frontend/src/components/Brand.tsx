import { Link } from "react-router";
export function Brand({ compact = false }: { compact?: boolean }) {
  return <Link to="/" className={`nexus-brand ${compact ? "brand-compact" : ""}`} aria-label="Darknet Sentinel Nexus home"><svg width="36" height="36" viewBox="0 0 24 24" aria-hidden="true"><path d="M12 2 21 7v10l-9 5-9-5V7z M12 6l5 3v4c0 3-3 5-5 6-2-1-5-3-5-6V9z M9 12l2 2 4-4" fill="none" stroke="currentColor" strokeWidth="1.3" /></svg><span><strong>DARKNET SENTINEL NEXUS</strong><small>{compact ? "IOT COMMAND CENTER" : "THREAT INTELLIGENCE SYSTEM"}</small></span></Link>;
}
