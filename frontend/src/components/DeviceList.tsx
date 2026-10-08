import { useMemo } from "react";
import type { NodeState } from "../live/store";
import { nodeColor } from "../viz/colors";

interface Props {
  nodes: Record<string, NodeState>;
  selected: string | null;
  onSelect: (id: string) => void;
}

/** Devices ranked by risk: the keyboard-accessible way to pick a device. */
export function DeviceList({ nodes, selected, onSelect }: Props) {
  const rows = useMemo(
    () =>
      Object.values(nodes).sort(
        (a, b) =>
          Number(b.quarantined) - Number(a.quarantined) ||
          (b.score ?? -1) - (a.score ?? -1) ||
          (a.device.hostname ?? a.device.node_id).localeCompare(b.device.hostname ?? b.device.node_id),
      ),
    [nodes],
  );
  return (
    <section className="panel flex min-h-0 flex-1 flex-col">
      <div className="panel-title">
        Devices <span className="font-mono text-ink-400 normal-case">{rows.length}</span>
      </div>
      <ul className="scroll-thin min-h-0 flex-1 overflow-y-auto pb-2">
        {rows.map((n) => {
          const id = n.device.node_id;
          const color = nodeColor(n.level, n.quarantined);
          return (
            <li key={id}>
              <button
                onClick={() => onSelect(id)}
                className={`flex w-full items-center gap-2 px-3 py-1.5 text-left text-xs hover:bg-ink-800 ${
                  id === selected ? "bg-ink-800" : ""
                }`}
                aria-pressed={id === selected}
              >
                <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: color }} />
                <span className="min-w-0 flex-1">
                  <span className="block truncate">{n.device.hostname ?? n.device.ip ?? id}</span>
                  <span className="block truncate font-mono text-[10px] text-ink-400">
                    {n.device.ip ?? "—"} · {n.device.vendor?.split(/[ ,]/)[0] ?? "unknown vendor"}
                  </span>
                </span>
                {n.quarantined && <span className="chip bg-quarantine/15 text-quarantine">quar.</span>}
                <span className="w-8 text-right font-mono" style={{ color }}>
                  {n.score !== null ? n.score.toFixed(0) : "–"}
                </span>
              </button>
            </li>
          );
        })}
      </ul>
    </section>
  );
}
