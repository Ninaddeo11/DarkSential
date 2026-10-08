import { useEffect, useState } from "react";
import { api } from "../api/client";
import type { FeedsStatus } from "../api/types";

const POLL_MS = 30_000;

function age(iso: string | null): string {
  if (!iso) return "never";
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 90) return `${Math.round(s)}s ago`;
  if (s < 5400) return `${Math.round(s / 60)}m ago`;
  if (s < 129600) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

/** Threat-feed health: last run, result and object counts per feed. */
export function FeedHealth() {
  const [status, setStatus] = useState<FeedsStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    const load = () =>
      api
        .feeds()
        .then((s) => {
          if (!cancelled) {
            setStatus(s);
            setError(null);
          }
        })
        .catch((e: unknown) => !cancelled && setError(e instanceof Error ? e.message : String(e)));
    void load();
    const id = window.setInterval(load, POLL_MS);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, []);

  return (
    <section className="panel">
      <div className="panel-title">
        Feed health
        {status && <span className="font-mono text-ink-400 normal-case">{status.graph_backend ?? ""}</span>}
      </div>
      {error && <p className="px-3 pb-2 text-xs text-critical">{error}</p>}
      <table className="w-full text-[11px]">
        <tbody>
          {status?.feeds.map((f) => {
            const run = f.last_run;
            const state = !f.enabled
              ? "off"
              : f.running
                ? "running"
                : run?.status ?? (f.requires ? "no key" : "pending");
            const tone =
              state === "success"
                ? "bg-low"
                : state === "running" || state === "pending"
                  ? "bg-signal"
                  : state === "off" || state === "no key"
                    ? "bg-ink-600"
                    : "bg-critical";
            return (
              <tr key={f.name} className="border-t border-ink-800" title={run?.error ?? undefined}>
                <td className="py-1 pl-3">
                  <span className={`mr-2 inline-block h-1.5 w-1.5 rounded-full ${tone}`} />
                  {f.name}
                </td>
                <td className="text-ink-400"><span className="chip">{state}</span><br />{f.mode}</td>
                <td className="font-mono text-ink-300">{run ? `${run.objects}` : "–"}</td>
                <td className="pr-3 text-right text-ink-400">{age(f.last_success_at)}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </section>
  );
}
