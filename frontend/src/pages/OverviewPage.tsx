import { lazy, Suspense, useCallback, useMemo, useState } from "react";
import { Link } from "react-router";
import { Inspector } from "../components/Inspector";
import { Legend } from "../components/Legend";
import { summarize } from "../components/Timeline";
import { PageHeader } from "../layout/Shell";
import { useLive } from "../live/LiveContext";
import { LEVEL_COLOR, QUARANTINE_COLOR } from "../viz/colors";

const Graph3D = lazy(() => import("../components/Graph3D").then((m) => ({ default: m.Graph3D })));

const ALERT_TYPES = new Set(["ANOMALY_DETECTED", "THREAT_CORRELATED", "QUARANTINE_COMPLETED"]);

export function OverviewPage() {
  const { state, role, health, rate } = useLive();
  const [selected, setSelected] = useState<string | null>(null);
  const onSelect = useCallback((id: string | null) => setSelected(id), []);
  const nodes = Object.values(state.nodes);
  const count = (pred: (n: (typeof nodes)[number]) => boolean) => nodes.filter(pred).length;
  const alerts = useMemo(
    () => state.events.filter((e) => ALERT_TYPES.has(e.type)).slice(-8).reverse(),
    [state.events],
  );
  const tiles = [
    { label: "Devices", value: nodes.length, color: "#dce6f2" },
    { label: "Critical", value: count((n) => n.level === "critical"), color: LEVEL_COLOR.critical },
    { label: "High", value: count((n) => n.level === "high"), color: LEVEL_COLOR.high },
    { label: "Quarantined", value: count((n) => n.quarantined), color: QUARANTINE_COLOR },
    { label: "Unknown trust", value: count((n) => n.device.trust === "unknown"), color: "#93a4bb" },
    { label: "Events / s", value: rate.toFixed(1), color: "#38d6f5" },
  ];
  const selectedNode = selected ? state.nodes[selected] : undefined;

  return (
    <div className="flex h-full flex-col">
      <PageHeader
        title="Overview"
        subtitle="Live state of the lab network: risk, quarantines and the latest alerts."
      />
      <div className="grid grid-cols-2 gap-3 px-4 sm:grid-cols-3 xl:grid-cols-6">
        {tiles.map((t) => (
          <div key={t.label} className="panel px-3 py-2.5">
            <div className="font-mono text-2xl leading-tight font-semibold" style={{ color: t.color }}>
              {t.value}
            </div>
            <div className="text-[10px] tracking-widest text-ink-400 uppercase">{t.label}</div>
          </div>
        ))}
      </div>
      <div className="grid min-h-0 flex-1 grid-cols-1 gap-3 p-4 xl:grid-cols-[1fr_380px]">
        <section className="panel relative min-h-[420px] overflow-hidden">
          <Suspense fallback={<p className="p-4 text-xs text-ink-400">Loading 3D view…</p>}>
            <Graph3D nodes={state.nodes} selected={selected} onSelect={onSelect} />
          </Suspense>
          {nodes.length === 0 && (
            <p className="pointer-events-none absolute inset-x-0 top-1/2 text-center text-xs text-ink-400">
              No devices yet. Start the virtual lab: <code>make lab-up</code>
            </p>
          )}
          <p className="pointer-events-none absolute bottom-2 left-3 text-[10px] text-ink-400">
            drag to orbit · scroll to zoom · click a device to inspect
          </p>
        </section>
        <div className="flex min-h-0 flex-col gap-3">
          {selectedNode ? (
            <div className="min-h-[360px] flex-1">
              <Inspector
                node={selectedNode}
                role={role}
                dryRun={health?.dry_run ?? true}
                onClose={() => setSelected(null)}
              />
            </div>
          ) : (
            <>
              <section className="panel">
                <div className="panel-title">
                  Latest alerts
                  <Link to="/events" className="text-signal normal-case hover:underline">
                    all events →
                  </Link>
                </div>
                <ul className="space-y-1 px-3 pb-3">
                  {alerts.length === 0 && <li className="text-xs text-ink-400">No alerts yet.</li>}
                  {alerts.map((e) => {
                    const n = e.node_id ? state.nodes[e.node_id] : undefined;
                    return (
                      <li key={e.seq} className="text-xs">
                        <Link
                          to={e.node_id ? `/devices/${e.node_id}` : "/events"}
                          className="block rounded px-1.5 py-1 hover:bg-ink-800"
                        >
                          <span className="font-mono text-[10px] text-ink-400">
                            {new Date(e.ts).toLocaleTimeString([], { hour12: false })}
                          </span>{" "}
                          <span className="font-semibold">{n?.device.hostname ?? n?.device.ip ?? "—"}</span>{" "}
                          <span className="text-ink-300">{summarize(e)}</span>
                        </Link>
                      </li>
                    );
                  })}
                </ul>
              </section>
              <Legend />
            </>
          )}
        </div>
      </div>
    </div>
  );
}
