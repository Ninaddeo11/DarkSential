import { useState, type FormEvent } from "react";
import type { Liveness, Me } from "../api/types";
import type { LinkState } from "../live/socket";
import { LEVEL_COLOR, QUARANTINE_COLOR } from "../viz/colors";
import type { NodeState } from "../live/store";

const LINK: Record<LinkState, { text: string; cls: string }> = {
  live: { text: "LIVE", cls: "bg-low" },
  connecting: { text: "CONNECTING", cls: "bg-medium" },
  offline: { text: "RECONNECTING", cls: "bg-high" },
  unauthorized: { text: "SIGN IN", cls: "bg-critical" },
};

interface Props {
  health: Liveness | null;
  link: LinkState;
  me: Me | null;
  nodes: Record<string, NodeState>;
  rate: number;
  onLogin: (secret: string) => Promise<void>;
  onLogout: () => void;
}

export function TopBar({ health, link, me, nodes, rate, onLogin, onLogout }: Props) {
  const all = Object.values(nodes);
  const count = (pred: (n: NodeState) => boolean) => all.filter(pred).length;
  const stats = [
    { label: "devices", value: all.length, color: "#dce6f2" },
    { label: "critical", value: count((n) => n.level === "critical"), color: LEVEL_COLOR.critical },
    { label: "high", value: count((n) => n.level === "high"), color: LEVEL_COLOR.high },
    { label: "quarantined", value: count((n) => n.quarantined), color: QUARANTINE_COLOR },
  ];
  return (
    <header className="flex flex-wrap items-center gap-x-5 gap-y-2 border-b border-ink-700/70 bg-ink-900/90 px-4 py-2.5">
      <div className="flex items-center gap-2.5">
        <svg width="22" height="22" viewBox="0 0 24 24" aria-hidden="true">
          <path d="M12 2 21 7v10l-9 5-9-5V7z" fill="none" stroke="#38d6f5" strokeWidth="1.6" />
          <circle cx="12" cy="12" r="3" fill="#38d6f5" />
        </svg>
        <div>
          <h1 className="text-sm leading-tight font-semibold tracking-wide">Darknet Sentinel Nexus</h1>
          <p className="text-[10px] leading-tight tracking-[0.18em] text-ink-400 uppercase">
            IoT command center
          </p>
        </div>
      </div>

      {health && (
        <span className={`chip ${health.dry_run ? "bg-low/15 text-low" : "bg-critical/20 text-critical"}`}>
          {health.dry_run ? "dry run" : "enforcing"}
        </span>
      )}
      <span className="flex items-center gap-1.5 text-[10px] font-semibold tracking-widest text-ink-300">
        <span className={`h-2 w-2 rounded-full ${LINK[link].cls} ${link === "live" ? "live-dot" : ""}`} />
        {LINK[link].text}
        {link === "live" && <span className="font-mono font-normal text-ink-400">{rate.toFixed(1)} ev/s</span>}
      </span>

      <dl className="flex gap-4">
        {stats.map((s) => (
          <div key={s.label} className="text-center">
            <dd className="font-mono text-base leading-tight font-semibold" style={{ color: s.color }}>
              {s.value}
            </dd>
            <dt className="text-[9px] tracking-widest text-ink-400 uppercase">{s.label}</dt>
          </div>
        ))}
      </dl>

      <div className="ml-auto">
        <Account me={me} onLogin={onLogin} onLogout={onLogout} />
      </div>
    </header>
  );
}

function Account({ me, onLogin, onLogout }: Pick<Props, "me" | "onLogin" | "onLogout">) {
  const [open, setOpen] = useState(false);
  const [secret, setSecret] = useState("");
  const [error, setError] = useState<string | null>(null);

  if (me && me.source !== "anonymous") {
    return (
      <div className="flex items-center gap-2 text-xs">
        <span className={`chip ${me.role === "operator" ? "bg-signal/15 text-signal" : "bg-ink-700 text-ink-300"}`}>
          {me.role}
        </span>
        <span className="text-ink-300">{me.sub}</span>
        <button className="btn px-2 py-1" onClick={onLogout}>
          Sign out
        </button>
      </div>
    );
  }
  if (me && !me.login_enabled) {
    return <span className="text-[11px] text-ink-400">read-only (login not configured)</span>;
  }
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      await onLogin(secret);
      setSecret("");
      setOpen(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };
  return open ? (
    <form onSubmit={submit} className="flex items-center gap-2">
      <input
        className="input w-56"
        type="password"
        autoComplete="current-password"
        placeholder="Admin or viewer token"
        value={secret}
        onChange={(e) => setSecret(e.target.value)}
        autoFocus
      />
      <button className="btn" type="submit" disabled={!secret}>
        Sign in
      </button>
      <button className="btn px-2" type="button" onClick={() => setOpen(false)} aria-label="Cancel">
        ✕
      </button>
      {error && <span className="text-[11px] text-critical">{error}</span>}
    </form>
  ) : (
    <button className="btn" onClick={() => setOpen(true)}>
      Sign in
    </button>
  );
}
