import { useEffect, useState } from "react";
import { Link } from "react-router";
import { api, ApiError } from "../api/client";
import type { Quarantine, RiskDetail, Role } from "../api/types";
import type { NodeState } from "../live/store";
import { LEVEL_TEXT, nodeColor } from "../viz/colors";
import { RiskWaterfall, ShapChart } from "./RiskCharts";
import { ThreatGraph } from "./ThreatGraph";

interface Props {
  node: NodeState;
  role: Role | null;
  dryRun: boolean;
  onClose: () => void;
}

/** Everything about one device: identity, live risk + explanation (waterfall,
 * SHAP, evidence graph) and the operator controls. Refetches when the device's
 * newest event changes. */
export function Inspector({ node, role, dryRun, onClose }: Props) {
  const id = node.device.node_id;
  const [risk, setRisk] = useState<RiskDetail | null>(null);
  const [active, setActive] = useState<Quarantine | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    Promise.all([api.risk(id), api.quarantines()])
      .then(([r, qs]) => {
        if (cancelled) return;
        setRisk(r);
        setActive(qs.find((q) => q.node_id === id && q.status === "active") ?? null);
        setError(null);
      })
      .catch((e: unknown) => !cancelled && setError(e instanceof Error ? e.message : String(e)));
    return () => {
      cancelled = true;
    };
  }, [id, node.lastEventSeq]);

  const d = node.device;
  const latest = risk?.latest ?? null;
  const color = nodeColor(node.level, node.quarantined);
  const attrs = d.attributes as Record<string, unknown>;

  return (
    <aside className="panel flex max-h-full flex-col overflow-hidden">
      <div className="flex items-start justify-between gap-2 border-b border-ink-700/70 px-3 py-2.5">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span className="h-2.5 w-2.5 shrink-0 rounded-full" style={{ background: color }} />
            <h2 className="truncate text-sm font-semibold">{d.hostname ?? d.ip ?? id}</h2>
          </div>
          <p className="mt-0.5 truncate font-mono text-[10px] text-ink-400">{id}</p>
        </div>
        <div className="flex shrink-0 gap-1.5">
          <Link to={`/devices/${id}`} className="btn px-2 py-1">
            Open full page
          </Link>
          <button className="btn px-2 py-1" onClick={onClose} aria-label="Close inspector">
            ✕
          </button>
        </div>
      </div>

      <div className="scroll-thin flex-1 space-y-3 overflow-y-auto py-3">
        <dl className="grid grid-cols-[88px_1fr] gap-x-2 gap-y-1 px-3 text-xs">
          <dt className="text-ink-400">IP</dt>
          <dd className="font-mono">{d.ip ?? "—"}</dd>
          <dt className="text-ink-400">Vendor</dt>
          <dd className="truncate">{d.vendor ?? "—"}</dd>
          <dt className="text-ink-400">Trust</dt>
          <dd>
            <span className={`chip ${d.trust === "approved" ? "bg-low/15 text-low" : "bg-ink-700 text-ink-300"}`}>
              {d.trust}
            </span>
            {d.randomized_mac && <span className="chip ml-1 bg-medium/15 text-medium">random MAC</span>}
          </dd>
          <dt className="text-ink-400">Services</dt>
          <dd className="truncate font-mono text-[11px]">
            {d.services.length
              ? d.services.map((s) => `${s.port_proto}${s.product ? ` ${s.product}${s.version ? ` ${s.version}` : ""}` : ""}`).join(", ")
              : "—"}
          </dd>
          <dt className="text-ink-400">Seen via</dt>
          <dd>{d.sources.join(", ") || "—"}</dd>
          {typeof attrs.state === "string" && (
            <>
              <dt className="text-ink-400">Reports</dt>
              <dd>{attrs.state as string}</dd>
            </>
          )}
        </dl>

        <section>
          <div className="panel-title">
            Risk
            {latest && (
              <span className={`font-mono text-xs normal-case ${LEVEL_TEXT[latest.level]}`}>
                {latest.score.toFixed(1)} · {latest.level} · {latest.action.replace(/_/g, " ")}
              </span>
            )}
          </div>
          {error && <p className="px-3 text-xs text-critical">{error}</p>}
          {latest ? (
            <div className="space-y-2 px-3">
              <RiskWaterfall contributions={latest.contributions} score={latest.score} />
              <p className="text-xs leading-relaxed text-ink-300">{latest.explanation}</p>
              <p className="text-[10px] text-ink-400">
                trigger {latest.trigger} · {new Date(latest.ts).toLocaleTimeString()}
              </p>
            </div>
          ) : (
            !error && <p className="px-3 text-xs text-ink-400">Not assessed yet.</p>
          )}
        </section>

        {latest && (
          <section>
            <div className="panel-title">
              ML comparison (XGBoost · SHAP)
              {latest.ml && (
                <span className="font-mono text-xs normal-case text-ink-300">
                  p(attack) {(latest.ml.probability * 100).toFixed(0)}%
                </span>
              )}
            </div>
            {latest.ml ? (
              <div className="px-3">
                <ShapChart ml={latest.ml} />
                <p className="mt-1 text-[10px] text-ink-400">
                  For comparison only: the decision above comes from the transparent linear model.
                </p>
              </div>
            ) : (
              <p className="px-3 text-xs text-ink-400">
                No model opinion: no traffic window for this device in the lookback.
              </p>
            )}
          </section>
        )}

        {latest && (
          <section>
            <div className="panel-title">Threat graph</div>
            <ThreatGraph paths={latest.evidence_paths} />
            <ul className="space-y-1 px-3">
              {latest.factors
                .flatMap((f) => f.evidence.map((e) => ({ f: f.name, e })))
                .slice(0, 6)
                .map(({ f, e }, i) => (
                  <li key={`${f}-${i}`} className="text-[11px] text-ink-300">
                    <span className="text-ink-400">{f.replace(/_/g, " ")}:</span> {e.summary}
                  </li>
                ))}
            </ul>
          </section>
        )}
      </div>

      <Controls
        nodeId={id}
        approved={d.trust === "approved"}
        active={active}
        role={role}
        dryRun={dryRun}
        onChanged={(q) => setActive(q)}
      />
    </aside>
  );
}

export interface ControlsProps {
  nodeId: string;
  approved: boolean;
  active: Quarantine | null;
  role: Role | null;
  dryRun: boolean;
  onChanged: (q: Quarantine | null) => void;
}

export function Controls({ nodeId, approved, active, role, dryRun, onChanged }: ControlsProps) {
  const [reason, setReason] = useState("");
  const [minutes, setMinutes] = useState(30);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);

  if (role !== "operator") {
    return (
      <footer className="border-t border-ink-700/70 px-3 py-2 text-[11px] text-ink-400">
        Sign in as an operator to quarantine, release or approve.
      </footer>
    );
  }

  const run = async (label: string, fn: () => Promise<unknown>) => {
    setBusy(true);
    setMsg(null);
    try {
      await fn();
      setMsg({ ok: true, text: label });
      setReason("");
    } catch (e) {
      setMsg({ ok: false, text: e instanceof ApiError ? e.message : String(e) });
    } finally {
      setBusy(false);
    }
  };

  const valid = reason.trim().length >= 3;
  return (
    <footer className="space-y-2 border-t border-ink-700/70 px-3 py-2.5">
      <div className="flex gap-2">
        <input
          className="input"
          placeholder="Reason (required, audited)"
          value={reason}
          maxLength={500}
          onChange={(e) => setReason(e.target.value)}
        />
        {!active && (
          <select
            className="input w-24"
            value={minutes}
            onChange={(e) => setMinutes(Number(e.target.value))}
            aria-label="Quarantine duration"
          >
            {[5, 15, 30, 60, 240].map((m) => (
              <option key={m} value={m}>
                {m} min
              </option>
            ))}
          </select>
        )}
      </div>
      <div className="flex flex-wrap gap-2">
        {active ? (
          <button
            className="btn btn-ok"
            disabled={busy || !valid}
            onClick={() =>
              run("Released", async () => {
                await api.release(active.id, reason.trim());
                onChanged(null);
              })
            }
          >
            Release quarantine
          </button>
        ) : (
          <button
            className="btn btn-danger"
            disabled={busy || !valid}
            onClick={() =>
              run(dryRun ? "Quarantined (dry run)" : "Quarantined", async () =>
                onChanged(await api.quarantine(nodeId, reason.trim(), minutes)),
              )
            }
          >
            Quarantine{dryRun ? " (dry run)" : ""}
          </button>
        )}
        {!approved && (
          <button className="btn" disabled={busy} onClick={() => run("Approved", () => api.approve(nodeId))}>
            Approve device
          </button>
        )}
      </div>
      {active && (
        <p className="text-[11px] text-quarantine">
          Quarantined by {active.actor} until {new Date(active.expires_at).toLocaleTimeString()}
          {active.dry_run ? " (dry run)" : ""}
        </p>
      )}
      {msg && <p className={`text-[11px] ${msg.ok ? "text-low" : "text-critical"}`}>{msg.text}</p>}
    </footer>
  );
}
