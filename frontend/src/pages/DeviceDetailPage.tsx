import { useEffect, useState } from "react";
import { Link, useParams } from "react-router";
import { api } from "../api/client";
import type { Detection, Quarantine, RiskDetail, RiskLevel } from "../api/types";
import { Controls } from "../components/Inspector";
import { RiskWaterfall, ShapChart } from "../components/RiskCharts";
import { RiskHistory } from "../components/RiskHistory";
import { ThreatGraph } from "../components/ThreatGraph";
import { summarize } from "../components/Timeline";
import { useLive } from "../live/LiveContext";
import { LEVEL_TEXT, nodeColor } from "../viz/colors";

export function DeviceDetailPage() {
  const { nodeId = "" } = useParams();
  const { state, role, health } = useLive();
  const node = state.nodes[nodeId];
  const [risk, setRisk] = useState<RiskDetail | null>(null);
  const [detections, setDetections] = useState<Detection[]>([]);
  const [active, setActive] = useState<Quarantine | null>(null);
  const [thresholds, setThresholds] = useState<Partial<Record<RiskLevel, number>> | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .riskModel()
      .then((m) => setThresholds(m.linear.thresholds))
      .catch(() => setThresholds(null));
  }, []);

  useEffect(() => {
    let cancelled = false;
    Promise.all([api.risk(nodeId), api.detections(nodeId, 50), api.quarantines()])
      .then(([r, ds, qs]) => {
        if (cancelled) return;
        setRisk(r);
        setDetections(ds);
        setActive(qs.find((q) => q.node_id === nodeId && q.status === "active") ?? null);
        setError(null);
      })
      .catch((e: unknown) => !cancelled && setError(e instanceof Error ? e.message : String(e)));
    return () => {
      cancelled = true;
    };
  }, [nodeId, node?.lastEventSeq]);

  if (!node) {
    return (
      <div className="p-6 text-sm">
        <p className="text-ink-300">Device {nodeId} is not known (yet).</p>
        <Link to="/devices" className="text-signal hover:underline">
          ← back to devices
        </Link>
      </div>
    );
  }
  const d = node.device;
  const latest = risk?.latest ?? null;
  const color = nodeColor(node.level, node.quarantined);
  const events = state.events.filter((e) => e.node_id === nodeId).slice(-15).reverse();
  const attrs = d.attributes as Record<string, unknown>;

  return (
    <div className="space-y-3 p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <Link to="/devices" className="text-xs text-signal hover:underline">
            ← Devices
          </Link>
          <h1 className="mt-1 flex items-center gap-2 text-lg font-semibold">
            <span className="h-3 w-3 rounded-full" style={{ background: color }} />
            {d.hostname ?? d.ip ?? nodeId}
            {node.quarantined && <span className="chip bg-quarantine/15 text-quarantine">quarantined</span>}
          </h1>
          <p className="font-mono text-[11px] text-ink-400">{nodeId}</p>
        </div>
        {latest && (
          <div className="text-right">
            <div className={`font-mono text-3xl font-semibold ${LEVEL_TEXT[latest.level]}`}>
              {latest.score.toFixed(1)}
            </div>
            <div className="text-[10px] tracking-widest text-ink-400 uppercase">
              {latest.level} · {latest.action.replace(/_/g, " ")}
            </div>
          </div>
        )}
      </div>
      {error && <p className="text-xs text-critical">{error}</p>}

      <div className="grid gap-3 lg:grid-cols-3">
        <section className="panel">
          <div className="panel-title">Identity</div>
          <dl className="grid grid-cols-[92px_1fr] gap-x-2 gap-y-1.5 px-3 pb-3 text-xs">
            <dt className="text-ink-400">IP</dt>
            <dd className="font-mono">{d.ip ?? "—"}</dd>
            <dt className="text-ink-400">Vendor</dt>
            <dd>{d.vendor ?? "—"}</dd>
            <dt className="text-ink-400">OUI</dt>
            <dd className="font-mono">{d.oui ?? "—"}</dd>
            <dt className="text-ink-400">Trust</dt>
            <dd>
              {d.trust}
              {d.randomized_mac ? " · randomized MAC" : ""}
            </dd>
            <dt className="text-ink-400">Seen via</dt>
            <dd>{d.sources.join(", ") || "—"}</dd>
            <dt className="text-ink-400">First seen</dt>
            <dd>{d.first_seen ? new Date(d.first_seen).toLocaleString() : "—"}</dd>
            <dt className="text-ink-400">Last seen</dt>
            <dd>{d.last_seen ? new Date(d.last_seen).toLocaleString() : "—"}</dd>
            {typeof attrs.fw === "string" && (
              <>
                <dt className="text-ink-400">Firmware</dt>
                <dd className="font-mono">{attrs.fw as string}</dd>
              </>
            )}
            {typeof attrs.state === "string" && (
              <>
                <dt className="text-ink-400">Reports</dt>
                <dd>{attrs.state as string}</dd>
              </>
            )}
          </dl>
        </section>

        <section className="panel">
          <div className="panel-title">Services &amp; CPE guesses</div>
          <ul className="space-y-1 px-3 pb-2 font-mono text-[11px]">
            {d.services.length === 0 && <li className="text-ink-400">No services discovered.</li>}
            {d.services.map((s) => (
              <li key={s.port_proto}>
                {s.port_proto} <span className="text-ink-300">{[s.product, s.version].filter(Boolean).join(" ")}</span>
              </li>
            ))}
          </ul>
          <ul className="space-y-1 border-t border-ink-800 px-3 py-2 font-mono text-[10px] text-ink-300">
            {d.cpes.length === 0 && <li className="text-ink-400">No CPE guesses.</li>}
            {d.cpes.map((c) => (
              <li key={c.cpe} title={`basis ${c.basis}, service ${c.service}`}>
                {c.cpe.split(":").slice(3, 6).join(":")} <span className="text-ink-400">conf {c.confidence}</span>
              </li>
            ))}
          </ul>
        </section>

        <section className="panel flex flex-col">
          <div className="panel-title">Operator actions</div>
          <div className="flex-1" />
          <Controls
            nodeId={nodeId}
            approved={d.trust === "approved"}
            active={active}
            role={role}
            dryRun={health?.dry_run ?? true}
            onChanged={setActive}
          />
        </section>
      </div>

      <div className="grid gap-3 xl:grid-cols-2">
        <section className="panel">
          <div className="panel-title">Risk explanation</div>
          {latest ? (
            <div className="space-y-2 px-3 pb-3">
              <div className="max-w-lg">
                <RiskWaterfall contributions={latest.contributions} score={latest.score} />
              </div>
              <p className="text-xs leading-relaxed text-ink-300">{latest.explanation}</p>
              <p className="text-[10px] text-ink-400">
                trigger {latest.trigger} · {new Date(latest.ts).toLocaleString()}
              </p>
            </div>
          ) : (
            <p className="px-3 pb-3 text-xs text-ink-400">Not assessed yet.</p>
          )}
        </section>
        <section className="panel">
          <div className="panel-title">Risk history</div>
          <div className="px-3 pb-3">
            <RiskHistory history={risk?.history ?? []} thresholds={thresholds} />
          </div>
        </section>
      </div>

      <div className="grid gap-3 xl:grid-cols-2">
        <section className="panel">
          <div className="panel-title">Threat graph &amp; evidence</div>
          {latest ? (
            <>
              <ThreatGraph paths={latest.evidence_paths} />
              <ul className="space-y-1 px-3 pb-3">
                {latest.factors
                  .flatMap((f) => f.evidence.map((e) => ({ f: f.name, e })))
                  .map(({ f, e }, i) => (
                    <li key={`${f}-${i}`} className="text-[11px] text-ink-300">
                      <span className="text-ink-400">{f.replace(/_/g, " ")}:</span> {e.summary}
                    </li>
                  ))}
              </ul>
            </>
          ) : (
            <p className="px-3 pb-3 text-xs text-ink-400">No assessment yet.</p>
          )}
        </section>
        <section className="panel">
          <div className="panel-title">
            ML comparison (XGBoost · SHAP)
            {latest?.ml && (
              <span className="font-mono text-xs normal-case text-ink-300">
                p(attack) {(latest.ml.probability * 100).toFixed(0)}%
              </span>
            )}
          </div>
          <div className="px-3 pb-3">
            {latest?.ml ? (
              <div className="max-w-lg">
                <ShapChart ml={latest.ml} />
              </div>
            ) : (
              <p className="text-xs text-ink-400">No model opinion: no traffic window in the lookback.</p>
            )}
            <p className="mt-1 text-[10px] text-ink-400">
              For comparison only; decisions come from the transparent linear model.
            </p>
          </div>
        </section>
      </div>

      <div className="grid gap-3 xl:grid-cols-2">
        <section className="panel">
          <div className="panel-title">Detections</div>
          <ul className="scroll-thin max-h-72 space-y-1 overflow-y-auto px-3 pb-3 text-[11px]">
            {detections.length === 0 && <li className="text-ink-400">No detections.</li>}
            {detections.map((x) => (
              <li key={x.id}>
                <span className="font-mono text-ink-400">{new Date(x.ts).toLocaleTimeString()}</span>{" "}
                <span className="font-semibold">{x.rule_id ?? x.kind}</span>{" "}
                <span className="text-ink-300">{x.summary}</span>
                {x.techniques.length > 0 && <span className="ml-1 text-ink-400">[{x.techniques.join(", ")}]</span>}
              </li>
            ))}
          </ul>
        </section>
        <section className="panel">
          <div className="panel-title">
            Recent events
            <Link to={`/events?device=${nodeId}`} className="text-signal normal-case hover:underline">
              all →
            </Link>
          </div>
          <ul className="space-y-1 px-3 pb-3 text-[11px]">
            {events.length === 0 && <li className="text-ink-400">No events since the page loaded.</li>}
            {events.map((e) => (
              <li key={e.seq}>
                <span className="font-mono text-ink-400">{new Date(e.ts).toLocaleTimeString()}</span>{" "}
                <span className="font-semibold">{e.type.replace(/_/g, " ").toLowerCase()}</span>{" "}
                <span className="text-ink-300">{summarize(e)}</span>
              </li>
            ))}
          </ul>
        </section>
      </div>
    </div>
  );
}
