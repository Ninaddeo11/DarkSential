import { useMemo, useRef, useState, type UIEvent } from "react";
import type { DsnEvent, EventType } from "../generated/events";
import { EVENT_TYPES } from "../generated/events";
import type { NodeState } from "../live/store";

const ROW = 30;
const OVERSCAN = 8;

const TYPE_STYLE: Record<EventType, string> = {
  DEVICE_CONNECTED: "text-signal",
  DEVICE_PROFILED: "text-ink-300",
  ANOMALY_DETECTED: "text-high",
  THREAT_CORRELATED: "text-critical",
  RISK_UPDATED: "text-medium",
  QUARANTINE_STARTED: "text-quarantine",
  QUARANTINE_COMPLETED: "text-quarantine",
  RECOVERY_STARTED: "text-low",
  DEVICE_RESTORED: "text-low",
};

export function summarize(e: DsnEvent): string {
  switch (e.type) {
    case "DEVICE_CONNECTED":
      return `${e.payload.returning ? "returned" : "new"} via ${e.payload.source}${e.payload.ip ? ` · ${e.payload.ip}` : ""}`;
    case "DEVICE_PROFILED":
      return `${e.payload.services.length} services · ${e.payload.cpes.length} CPE guesses`;
    case "ANOMALY_DETECTED":
      return e.payload.summary;
    case "THREAT_CORRELATED":
      return e.payload.summary;
    case "RISK_UPDATED":
      return `${e.payload.previous_score ?? "–"} → ${e.payload.score} (${e.payload.level}, ${e.payload.action.replace(/_/g, " ")})`;
    case "QUARANTINE_STARTED":
      return `${e.payload.minutes} min by ${e.payload.actor}: ${e.payload.reason}`;
    case "QUARANTINE_COMPLETED":
      return e.payload.ok
        ? `blocked ${e.payload.ip ?? ""}${e.payload.dry_run ? " (dry run)" : ""}`
        : `failed: ${e.payload.refused ?? e.payload.error ?? "unknown"}`;
    case "RECOVERY_STARTED":
      return `${e.payload.actor}: ${e.payload.reason}`;
    case "DEVICE_RESTORED":
      return `released ${e.payload.ip ?? ""}`;
  }
}

interface Props {
  events: DsnEvent[];
  nodes: Record<string, NodeState>;
  selected: string | null;
  onSelect: (id: string) => void;
  /** Start filtered to the selected device (e.g. /events?device=…). */
  initialOnlySelected?: boolean;
}

/** Newest-first event log. Virtualized: only visible rows are in the DOM, so the
 * 5,000-event buffer costs the same as 20 rows. */
export function Timeline({ events, nodes, selected, onSelect, initialOnlySelected = false }: Props) {
  const [hidden, setHidden] = useState<Set<EventType>>(new Set());
  const [onlySelected, setOnlySelected] = useState(initialOnlySelected);
  const [scrollTop, setScrollTop] = useState(0);
  const [height, setHeight] = useState(240);
  const box = useRef<HTMLDivElement>(null);

  const rows = useMemo(() => {
    const out: DsnEvent[] = [];
    for (let i = events.length - 1; i >= 0; i--) {
      const e = events[i];
      if (!e || hidden.has(e.type)) continue;
      if (onlySelected && selected && e.node_id !== selected) continue;
      out.push(e);
    }
    return out;
  }, [events, hidden, onlySelected, selected]);

  const first = Math.max(0, Math.floor(scrollTop / ROW) - OVERSCAN);
  const last = Math.min(rows.length, Math.ceil((scrollTop + height) / ROW) + OVERSCAN);
  const onScroll = (ev: UIEvent<HTMLDivElement>) => {
    setScrollTop(ev.currentTarget.scrollTop);
    setHeight(ev.currentTarget.clientHeight);
  };

  return (
    <section className="panel flex h-full min-h-0 flex-col">
      <div className="panel-title">
        <span>
          Event timeline <span className="ml-1 font-mono text-ink-400 normal-case">{rows.length}</span>
        </span>
        <label className="flex items-center gap-1 text-[10px] font-normal tracking-normal normal-case">
          <input
            type="checkbox"
            checked={onlySelected}
            disabled={!selected}
            onChange={(e) => setOnlySelected(e.target.checked)}
          />
          selected device only
        </label>
      </div>
      <div className="flex flex-wrap gap-1 px-3 pb-2">
        {EVENT_TYPES.map((t) => (
          <button
            key={t}
            className={`chip border border-ink-700 ${hidden.has(t) ? "text-ink-600 line-through" : TYPE_STYLE[t]}`}
            onClick={() => {
              const next = new Set(hidden);
              if (next.has(t)) next.delete(t);
              else next.add(t);
              setHidden(next);
            }}
          >
            {t.replace(/_/g, " ").toLowerCase()}
          </button>
        ))}
      </div>
      <div ref={box} className="scroll-thin relative min-h-0 flex-1 overflow-y-auto" onScroll={onScroll}>
        <div style={{ height: rows.length * ROW }}>
          {rows.slice(first, last).map((e, i) => {
            const n = e.node_id ? nodes[e.node_id] : undefined;
            const who = n?.device.hostname ?? n?.device.ip ?? e.node_id?.slice(0, 12) ?? "—";
            return (
              <button
                key={e.seq}
                className={`absolute left-0 flex w-full items-center gap-2 px-3 text-left text-[11px] hover:bg-ink-800 ${
                  e.node_id === selected ? "bg-ink-800/70" : ""
                }`}
                style={{ top: (first + i) * ROW, height: ROW }}
                onClick={() => e.node_id && onSelect(e.node_id)}
              >
                <span className="w-16 shrink-0 font-mono text-ink-400">
                  {new Date(e.ts).toLocaleTimeString([], { hour12: false })}
                </span>
                <span className={`w-36 shrink-0 truncate font-semibold ${TYPE_STYLE[e.type]}`}>
                  {e.type.replace(/_/g, " ")}
                </span>
                <span className="w-24 shrink-0 truncate text-ink-100">{who}</span>
                <span className="truncate text-ink-300">{summarize(e)}</span>
              </button>
            );
          })}
        </div>
        {rows.length === 0 && <p className="px-3 py-4 text-xs text-ink-400">No events yet.</p>}
      </div>
    </section>
  );
}
