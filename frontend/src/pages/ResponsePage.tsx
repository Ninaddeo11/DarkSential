import { useEffect, useState } from "react";
import { Link } from "react-router";
import { api } from "../api/client";
import type { AuditEntry, AuditVerify, Quarantine } from "../api/types";
import { PageHeader } from "../layout/Shell";
import { useLive } from "../live/LiveContext";

const OUTCOME: Record<string, string> = {
  ok: "text-low",
  dry_run: "text-signal",
  refused: "text-high",
  skipped: "text-medium",
  failed: "text-critical",
};

export function ResponsePage() {
  const { state } = useLive();
  const [quarantines, setQuarantines] = useState<Quarantine[]>([]);
  const [audit, setAudit] = useState<AuditEntry[]>([]);
  const [verify, setVerify] = useState<AuditVerify | null>(null);
  const [tab, setTab] = useState<"active" | "all">("active");
  const [error, setError] = useState<string | null>(null);

  // Refresh when quarantine-related events arrive.
  const lastResponseSeq = state.events
    .filter((e) => e.type.startsWith("QUARANTINE") || e.type === "DEVICE_RESTORED")
    .at(-1)?.seq;
  useEffect(() => {
    Promise.all([api.quarantinesByStatus(), api.audit(150)])
      .then(([qs, au]) => {
        setQuarantines(qs);
        setAudit(au);
        setError(null);
      })
      .catch((e: unknown) => setError(String(e)));
  }, [lastResponseSeq]);

  const shown = tab === "active" ? quarantines.filter((q) => q.status === "active") : quarantines;
  const label = (nodeId: string) => {
    const n = state.nodes[nodeId];
    return n?.device.hostname ?? n?.device.ip ?? nodeId;
  };

  return (
    <div className="space-y-3 pb-4">
      <PageHeader title="Incident response center" subtitle="Quarantines and the hash-chained audit log of every action.">
        <button className="btn command-action" onClick={() => api.auditVerify().then(setVerify).catch((e: unknown) => setError(String(e)))}>
          Verify audit chain
        </button>
      </PageHeader>
      {error && <p className="px-4 text-xs text-critical">{error}</p>}
      {verify && (
        <p className={`mx-4 rounded-md px-3 py-2 text-xs ${verify.ok ? "bg-low/10 text-low" : "bg-critical/15 text-critical"}`}>
          {verify.ok
            ? `Audit chain intact: ${verify.entries} entries, head ${verify.head.slice(0, 16)}…`
            : `Audit chain BROKEN at entry ${verify.first_bad_id} (${verify.entries} entries checked)`}
        </p>
      )}

      <section className="panel mx-4">
        <div className="panel-title">
          Quarantines
          <span className="flex gap-1 normal-case">
            {(["active", "all"] as const).map((t) => (
              <button
                key={t}
                onClick={() => setTab(t)}
                className={`rounded px-2 py-0.5 text-[11px] ${tab === t ? "bg-signal/15 text-signal" : "text-ink-400 hover:text-ink-100"}`}
              >
                {t === "active" ? `active (${quarantines.filter((q) => q.status === "active").length})` : `all (${quarantines.length})`}
              </button>
            ))}
          </span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead className="text-[10px] tracking-wider text-ink-400 uppercase">
              <tr>
                <th className="px-3 py-1.5 text-left">#</th>
                <th className="px-3 py-1.5 text-left">Device</th>
                <th className="px-3 py-1.5 text-left">Status</th>
                <th className="px-3 py-1.5 text-left">By</th>
                <th className="px-3 py-1.5 text-left">Reason</th>
                <th className="px-3 py-1.5 text-left">Started</th>
                <th className="px-3 py-1.5 text-left">Expires / released</th>
              </tr>
            </thead>
            <tbody>
              {shown.map((q) => (
                <tr key={q.id} className="border-t border-ink-800">
                  <td className="px-3 py-1.5 font-mono text-ink-400">{q.id}</td>
                  <td className="px-3 py-1.5">
                    <Link to={`/devices/${q.node_id}`} className="text-signal hover:underline">
                      {label(q.node_id)}
                    </Link>{" "}
                    <span className="font-mono text-[10px] text-ink-400">{q.ip}</span>
                  </td>
                  <td className="px-3 py-1.5">
                    <span className={`chip ${q.status === "active" ? "bg-quarantine/15 text-quarantine" : "bg-ink-700 text-ink-300"}`}>
                      {q.status}
                      {q.dry_run ? " · dry run" : ""}
                    </span>
                  </td>
                  <td className="px-3 py-1.5 font-mono text-[11px]">{q.actor}</td>
                  <td className="max-w-80 truncate px-3 py-1.5 text-ink-300" title={q.reason}>
                    {q.reason}
                  </td>
                  <td className="px-3 py-1.5 text-ink-400">{new Date(q.started_at).toLocaleString()}</td>
                  <td className="px-3 py-1.5 text-ink-400">
                    {q.released_at
                      ? `${new Date(q.released_at).toLocaleTimeString()} by ${q.released_by ?? "?"}`
                      : new Date(q.expires_at).toLocaleTimeString()}
                  </td>
                </tr>
              ))}
              {shown.length === 0 && (
                <tr>
                  <td colSpan={7} className="empty-state px-3 py-4 text-center text-ink-400">
                    <span className="empty-shield" aria-hidden="true">{"\u25c7"}</span>
                    {tab === "active" ? "No active quarantines." : "No quarantines yet."}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      <section className="panel mx-4">
        <div className="panel-title">Forensic audit ledger / newest first</div>
        <div className="scroll-thin max-h-[480px] overflow-auto">
          <table className="audit-table w-full text-xs">
            <thead><tr>{["#", "Timestamp", "Actor", "Action", "Status", "Target", "Payload", "Hash"].map(h => <th key={h}>{h}</th>)}</tr></thead>
            <tbody>
              {audit.map((a) => (
                <tr key={a.id} className="border-t border-ink-800 align-top">
                  <td className="px-3 py-1.5 font-mono text-ink-400">{a.id}</td>
                  <td className="px-2 py-1.5 whitespace-nowrap text-ink-400">{new Date(a.ts).toLocaleString()}</td>
                  <td className="px-2 py-1.5 font-mono text-[11px]">{a.actor}</td>
                  <td className="px-2 py-1.5">{a.action}</td>
                  <td className={`px-2 py-1.5 ${OUTCOME[a.outcome] ?? ""}`}>{a.outcome}</td>
                  <td className="px-2 py-1.5">
                    {a.node_id && (
                      <Link to={`/devices/${a.node_id}`} className="text-signal hover:underline">
                        {label(a.node_id)}
                      </Link>
                    )}
                  </td>
                  <td className="max-w-96 truncate px-2 py-1.5 font-mono text-[10px] text-ink-400" title={JSON.stringify(a.details)}>
                    {JSON.stringify(a.details)}
                  </td>
                  <td className="px-3 py-1.5 font-mono text-[10px] text-ink-600">{a.hash.slice(0, 10)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
