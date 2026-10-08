import { useMemo, useState } from "react";
import { useNavigate } from "react-router";
import { PageHeader } from "../layout/Shell";
import { useLive } from "../live/LiveContext";
import type { NodeState } from "../live/store";
import { LEVEL_TEXT, nodeColor } from "../viz/colors";

type SortKey = "risk" | "name" | "ip" | "vendor" | "seen";

const LEVEL_FILTERS = ["all", "critical", "high", "medium", "low", "unscored"] as const;

function name(n: NodeState): string {
  return n.device.hostname ?? n.device.ip ?? n.device.node_id;
}

export function DevicesPage() {
  const { state } = useLive();
  const navigate = useNavigate();
  const [query, setQuery] = useState("");
  const [level, setLevel] = useState<(typeof LEVEL_FILTERS)[number]>("all");
  const [onlyQuarantined, setOnlyQuarantined] = useState(false);
  const [onlyUnknown, setOnlyUnknown] = useState(false);
  const [sort, setSort] = useState<SortKey>("risk");

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    const list = Object.values(state.nodes).filter((n) => {
      const d = n.device;
      if (q && ![d.hostname, d.ip, d.vendor, d.node_id].some((v) => v?.toLowerCase().includes(q))) return false;
      if (level === "unscored" ? n.level !== null : level !== "all" && n.level !== level) return false;
      if (onlyQuarantined && !n.quarantined) return false;
      if (onlyUnknown && d.trust !== "unknown") return false;
      return true;
    });
    const by: Record<SortKey, (a: NodeState, b: NodeState) => number> = {
      risk: (a, b) => (b.score ?? -1) - (a.score ?? -1) || name(a).localeCompare(name(b)),
      name: (a, b) => name(a).localeCompare(name(b)),
      ip: (a, b) => (a.device.ip ?? "").localeCompare(b.device.ip ?? "", undefined, { numeric: true }),
      vendor: (a, b) => (a.device.vendor ?? "~").localeCompare(b.device.vendor ?? "~"),
      seen: (a, b) => b.device.last_seen.localeCompare(a.device.last_seen),
    };
    return list.sort(by[sort]);
  }, [state.nodes, query, level, onlyQuarantined, onlyUnknown, sort]);

  const header = (key: SortKey, label: string, cls = "") => (
    <th className={`px-3 py-2 text-left font-semibold ${cls}`}>
      <button
        onClick={() => setSort(key)}
        className={`uppercase tracking-wider ${sort === key ? "text-signal" : "text-ink-400 hover:text-ink-100"}`}
        aria-sort={sort === key ? "descending" : "none"}
      >
        {label}
        {sort === key ? " ↓" : ""}
      </button>
    </th>
  );

  return (
    <div>
      <PageHeader title="Devices" subtitle={`${rows.length} of ${Object.keys(state.nodes).length} devices`}>
        <input
          className="input w-56"
          placeholder="Search name, IP, vendor, id"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          aria-label="Search devices"
        />
        <select
          className="input w-32"
          value={level}
          onChange={(e) => setLevel(e.target.value as (typeof LEVEL_FILTERS)[number])}
          aria-label="Risk level"
        >
          {LEVEL_FILTERS.map((l) => (
            <option key={l} value={l}>
              {l === "all" ? "all levels" : l}
            </option>
          ))}
        </select>
        <label className="flex items-center gap-1.5 text-xs text-ink-300">
          <input type="checkbox" checked={onlyQuarantined} onChange={(e) => setOnlyQuarantined(e.target.checked)} />
          quarantined
        </label>
        <label className="flex items-center gap-1.5 text-xs text-ink-300">
          <input type="checkbox" checked={onlyUnknown} onChange={(e) => setOnlyUnknown(e.target.checked)} />
          unknown trust
        </label>
      </PageHeader>
      <div className="px-4 pb-4">
        <div className="panel overflow-x-auto">
          <table className="w-full text-xs">
            <thead className="border-b border-ink-700 text-[10px]">
              <tr>
                {header("risk", "Risk")}
                {header("name", "Device")}
                {header("ip", "IP")}
                {header("vendor", "Vendor")}
                <th className="px-3 py-2 text-left font-semibold tracking-wider text-ink-400 uppercase">Trust</th>
                <th className="px-3 py-2 text-left font-semibold tracking-wider text-ink-400 uppercase">Services</th>
                {header("seen", "Last seen", "text-right")}
              </tr>
            </thead>
            <tbody>
              {rows.map((n) => {
                const d = n.device;
                const color = nodeColor(n.level, n.quarantined);
                return (
                  <tr
                    key={d.node_id}
                    onClick={() => navigate(`/devices/${d.node_id}`)}
                    onKeyDown={(e) => e.key === "Enter" && navigate(`/devices/${d.node_id}`)}
                    tabIndex={0}
                    className="cursor-pointer border-b border-ink-800 hover:bg-ink-800 focus:bg-ink-800 focus:outline-none"
                  >
                    <td className="px-3 py-2">
                      <span className="flex items-center gap-2">
                        <span className="h-2 w-2 rounded-full" style={{ background: color }} />
                        <span className={`font-mono ${n.level ? LEVEL_TEXT[n.level] : "text-ink-400"}`}>
                          {n.score !== null ? n.score.toFixed(1) : "–"}
                        </span>
                        {n.quarantined && <span className="chip bg-quarantine/15 text-quarantine">quarantined</span>}
                      </span>
                    </td>
                    <td className="px-3 py-2">
                      <div className="font-medium">{name(n)}</div>
                      <div className="font-mono text-[10px] text-ink-400">{d.node_id}</div>
                    </td>
                    <td className="px-3 py-2 font-mono">{d.ip ?? "—"}</td>
                    <td className="max-w-48 truncate px-3 py-2 text-ink-300">{d.vendor ?? "—"}</td>
                    <td className="px-3 py-2">
                      <span className={`chip ${d.trust === "approved" ? "bg-low/15 text-low" : "bg-ink-700 text-ink-300"}`}>
                        {d.trust}
                      </span>
                      {d.randomized_mac && <span className="chip ml-1 bg-medium/15 text-medium">random MAC</span>}
                    </td>
                    <td className="max-w-56 truncate px-3 py-2 font-mono text-[11px] text-ink-300">
                      {d.services.map((s) => s.port_proto).join(", ") || "—"}
                    </td>
                    <td className="px-3 py-2 text-right text-ink-400">
                      {d.last_seen ? new Date(d.last_seen).toLocaleTimeString() : "—"}
                    </td>
                  </tr>
                );
              })}
              {rows.length === 0 && (
                <tr>
                  <td colSpan={7} className="px-3 py-6 text-center text-ink-400">
                    No devices match.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
