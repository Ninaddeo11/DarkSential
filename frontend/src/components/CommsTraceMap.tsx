// Geographic trace of the devices in active communication with an indicator.
// Country outlines: Natural Earth 1:110m via world-atlas, drawn offline with d3-geo.
import { geoEquirectangular, geoPath } from "d3-geo";
import type { Feature, FeatureCollection, Geometry } from "geojson";
import { useEffect, useMemo, useRef, useState } from "react";
import { feature } from "topojson-client";
import type { GeometryCollection, Topology } from "topojson-specification";
import world from "world-atlas/countries-110m.json";
import type { Scenario, SimCommDevice } from "../sim/scenario";

const W = 900;
const H = 520;
const DEFAULT_LABEL = { dx: 14, dy: -10, anchor: "start" } as const;

type Country = Feature<Geometry, { name: string }>;

const countries = (() => {
  const topo = world as unknown as Topology<{ countries: GeometryCollection<{ name: string }> }>;
  return (feature(topo, topo.objects.countries) as FeatureCollection<Geometry, { name: string }>).features;
})();

export function CommsTraceMap({ scenario, selected, onSelect }: { scenario: Scenario; selected: string | null; onSelect: (id: string) => void }) {
  const { ioc, comms, map } = scenario;
  const highlight = new Set(comms.map((d) => d.countryId));
  const { path, project } = useMemo(() => {
    const [[x0, y0], [x1, y1]] = map.extent;
    const box: Feature = {
      type: "Feature",
      properties: {},
      // Clockwise ring: d3-geo reads a counter-clockwise ring as "everything but this box".
      geometry: { type: "Polygon", coordinates: [[[x0, y0], [x0, y1], [x1, y1], [x1, y0], [x0, y0]]] },
    };
    const projection = geoEquirectangular().fitExtent([[0, 0], [W, H]], box);
    return {
      path: geoPath(projection),
      project: (lon: number, lat: number) => projection([lon, lat]) ?? [0, 0],
    };
  }, [map.extent]);
  // The indicator sits over open sea (map.hub): its hosting location is masked.
  const HUB = project(map.hub[0], map.hub[1]);
  const shipment = scenario.report.consignment;
  const consignment = shipment ? project(shipment.lon, shipment.lat) : null;
  return (
      <svg viewBox={`0 0 ${W} ${H}`} className="h-full w-full rounded-md bg-ink-950" preserveAspectRatio="xMidYMid meet" role="img"
        aria-label={`Devices in active communication with ${ioc}: ${comms.map((d) => `${d.name} in ${d.city}, ${d.country}`).join("; ")}`}>
        <defs>
          <clipPath id="trace-clip"><rect width={W} height={H} /></clipPath>
        </defs>
        <g clipPath="url(#trace-clip)">
          {countries.map((c: Country, i) => (
            <path key={`${String(c.id)}-${i}`} d={path(c) ?? ""}
              fill={highlight.has(String(c.id)) ? "rgba(244,63,94,0.20)" : "#0e1520"}
              stroke={highlight.has(String(c.id)) ? "#f43f5e" : "#2b3a4f"} strokeWidth={highlight.has(String(c.id)) ? 1.1 : 0.5} />
          ))}
          {map.countryLabels.map((l) => {
            const [x, y] = project(l.lon, l.lat);
            return <text key={l.name} x={x} y={y} fontSize={13} fill="#f43f5e" fontWeight={700} letterSpacing={2.5}>{l.name}</text>;
          })}

          {consignment && shipment && (
            <g>
              <rect x={consignment[0] - 4} y={consignment[1] - 4} width={8} height={8} fill="#fbbf24" transform={`rotate(45 ${consignment[0]} ${consignment[1]})`} />
              <text x={consignment[0] + 9} y={consignment[1] + 4} fontSize={10} fill="#fbbf24">{shipment.id} consignment</text>
            </g>
          )}

          {/* Links: device <-> indicator, with packets moving both ways */}
          {comms.map((d, i) => {
            const [x, y] = project(d.lon, d.lat);
            const mx = (x + HUB[0]) / 2 + (i - 1) * 45;
            const my = Math.min(y, HUB[1]) - 70 + i * 18;
            const arc = `M${x},${y} Q${mx},${my} ${HUB[0]},${HUB[1]}`;
            const active = selected === null || selected === d.id;
            const dur = `${Math.max(0.9, 60 / Math.sqrt(d.ppm * 4)).toFixed(2)}s`;
            return (
              <g key={d.id} opacity={active ? 1 : 0.35}>
                <path id={`arc-${i}`} d={arc} fill="none" stroke="#f43f5e" strokeWidth={1.6} strokeDasharray="6 5">
                  <animate attributeName="stroke-dashoffset" from="22" to="0" dur="1s" repeatCount="indefinite" />
                </path>
                <circle r={3.2} fill="#ffd166">
                  <animateMotion dur={dur} repeatCount="indefinite" path={arc} />
                </circle>
                <circle r={2.6} fill="#38d6f5">
                  <animateMotion dur={dur} begin="0.4s" repeatCount="indefinite" keyPoints="1;0" keyTimes="0;1" calcMode="linear" path={arc} />
                </circle>
              </g>
            );
          })}

          {/* Devices */}
          {comms.map((d) => {
            const [x, y] = project(d.lon, d.lat);
            const isSel = selected === d.id;
            const { dx, dy, anchor } = d.label ?? DEFAULT_LABEL;
            return (
              <g key={d.id} className="cursor-pointer" onClick={() => onSelect(d.id)} role="button" tabIndex={0}
                onKeyDown={(e) => e.key === "Enter" && onSelect(d.id)} aria-label={`${d.name}, ${d.city}, ${d.country}`}>
                <circle cx={x} cy={y} r={9} fill="none" stroke="#f43f5e" strokeWidth={1.2}>
                  <animate attributeName="r" values="5;16;5" dur="2s" repeatCount="indefinite" />
                  <animate attributeName="opacity" values="1;0;1" dur="2s" repeatCount="indefinite" />
                </circle>
                <circle cx={x} cy={y} r={isSel ? 6.5 : 5} fill="#f43f5e" stroke="#fff" strokeWidth={isSel ? 2 : 1} />
                <text x={x + dx} y={y + dy} fontSize={12} fill="#fff" fontWeight={700} textAnchor={anchor}>{d.name}</text>
                <text x={x + dx} y={y + dy + 13} fontSize={10} fill="#dce6f2" textAnchor={anchor}>{d.city}, {d.country} · {d.ip}</text>
              </g>
            );
          })}

          {/* The indicator */}
          <g>
            <circle cx={HUB[0]} cy={HUB[1]} r={22} fill="rgba(244,63,94,0.12)" stroke="#f43f5e" strokeWidth={1}>
              <animate attributeName="r" values="18;30;18" dur="2.6s" repeatCount="indefinite" />
            </circle>
            <rect x={HUB[0] - 11} y={HUB[1] - 11} width={22} height={22} rx={4} fill="#0a1018" stroke="#f43f5e" strokeWidth={2} />
            <text x={HUB[0]} y={HUB[1] + 4} fontSize={11} fill="#f43f5e" textAnchor="middle" fontWeight={800}>C2</text>
            <text x={HUB[0]} y={HUB[1] - 32} fontSize={13} fill="#fff" textAnchor="middle" fontWeight={700} fontFamily="monospace">{ioc}</text>
            <text x={HUB[0]} y={HUB[1] + 38} fontSize={9.5} fill="#93a4bb" textAnchor="middle">{scenario.report.hosting.split(" (")[0]} · location masked</text>
          </g>
        </g>
        <text x={W - 10} y={H - 10} fontSize={9} fill="#6b7f99" textAnchor="end">Natural Earth 1:110m · simulated scenario</text>
      </svg>
  );
}

/** The devices on the trace map, with live packet counters. */
export function CommsDeviceTable({ scenario, selected, onSelect }: { scenario: Scenario; selected: string | null; onSelect: (id: string) => void }) {
  // Live counters: packets exchanged since the trace opened.
  const [elapsed, setElapsed] = useState(0);
  useEffect(() => {
    const id = window.setInterval(() => setElapsed((s) => s + 1), 1000);
    return () => window.clearInterval(id);
  }, []);
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-xs">
        <thead className="text-left text-[10px] tracking-widest text-ink-400 uppercase">
          <tr><th className="py-1">Device</th><th>Location</th><th>Address</th><th>Type</th><th>Channel</th><th>Packets</th><th>Status</th></tr>
        </thead>
        <tbody>
          {scenario.comms.map((d) => (
            <DeviceRow key={d.id} d={d} elapsed={elapsed} selected={selected === d.id} onSelect={onSelect} />
          ))}
        </tbody>
      </table>
    </div>
  );
}

interface Flow {
  id: number;
  ts: number;
  device: SimCommDevice;
  outbound: boolean;
  proto: string;
  bytes: number;
  kind: string;
}

const KINDS_OUT = ["C2 beacon", "Heartbeat", "Exfil chunk", "Task result", "Keep-alive"];
const KINDS_IN = ["Command", "Payload chunk", "Config update", "Task", "ACK"];

/** Live packet flows between the devices and the indicator (simulated). */
export function TrafficLog({ scenario }: { scenario: Scenario }) {
  const [flows, setFlows] = useState<Flow[]>([]);
  const [total, setTotal] = useState(0);
  const seq = useRef(0); // survives effect re-runs, so row keys stay unique
  useEffect(() => {
    setFlows([]);
    setTotal(0);
    const tick = () => {
      // Busier devices (higher packets/min) appear more often.
      const weights = scenario.comms.map((d) => d.ppm);
      let roll = Math.random() * weights.reduce((a, b) => a + b, 0);
      const device = scenario.comms.find((_, i) => (roll -= weights[i]!) < 0) ?? scenario.comms[0]!;
      const outbound = Math.random() < 0.55;
      const flow: Flow = {
        id: ++seq.current,
        ts: Date.now(),
        device,
        outbound,
        proto: device.channel.split(/[ →]/)[0] ?? "TCP",
        bytes: outbound ? 120 + Math.floor(Math.random() * 1800) : 300 + Math.floor(Math.random() * 14_000),
        kind: (outbound ? KINDS_OUT : KINDS_IN)[Math.floor(Math.random() * 5)]!,
      };
      setFlows((list) => [flow, ...list].slice(0, 14));
      setTotal((n) => n + flow.bytes);
    };
    for (let i = 0; i < 6; i++) tick();
    const timer = window.setInterval(tick, 650);
    return () => window.clearInterval(timer);
  }, [scenario]);
  return (
    <div>
      <div className="mb-1 flex items-center justify-between text-[10px] tracking-widest text-ink-400 uppercase">
        <span><span className="live-dot mr-1.5 inline-block h-1.5 w-1.5 rounded-full bg-critical" />Live traffic</span>
        <span className="font-mono normal-case">{(total / 1024).toFixed(1)} KiB since trace start</span>
      </div>
      <div className="scroll-thin max-h-64 overflow-y-auto rounded-md bg-ink-950/70 px-2 py-1 font-mono text-[11px]">
        {flows.map((f) => (
          <div key={f.id} className="grid grid-cols-[72px_1fr_90px_110px_70px] gap-2 border-b border-ink-800/60 py-0.5">
            <span className="text-ink-400">{new Date(f.ts).toLocaleTimeString([], { hour12: false })}</span>
            <span className="truncate">
              {f.outbound ? (
                <>{f.device.ip} <span className="text-critical">→</span> {scenario.ioc}</>
              ) : (
                <>{scenario.ioc} <span className="text-signal">→</span> {f.device.ip}</>
              )}
              <span className="text-ink-400"> · {f.device.name}, {f.device.country}</span>
            </span>
            <span className="text-ink-300">{f.proto}</span>
            <span className={f.outbound ? "text-high" : "text-signal"}>{f.kind}</span>
            <span className="text-right text-ink-300">{f.bytes.toLocaleString()} B</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function DeviceRow({ d, elapsed, selected, onSelect }: { d: SimCommDevice; elapsed: number; selected: boolean; onSelect: (id: string) => void }) {
  const packets = Math.round(d.ppm * 37 + (d.ppm / 60) * elapsed); // 37 min of history before the trace opened
  return (
    <tr className={`cursor-pointer border-t border-ink-800 align-top ${selected ? "bg-critical/10" : ""}`} onClick={() => onSelect(d.id)}>
      <td className="py-1.5 pr-2 font-semibold">{d.name}<div className="text-[10px] font-normal text-ink-400">{d.role}</div></td>
      <td className="pr-2">{d.city}, <b className="text-critical">{d.country}</b><div className="font-mono text-[10px] text-ink-400">{d.lat.toFixed(4)}, {d.lon.toFixed(4)}</div></td>
      <td className="pr-2 font-mono">{d.ip}</td>
      <td className="pr-2">{d.type}</td>
      <td className="pr-2 font-mono text-ink-300">{d.channel}</td>
      <td className="pr-2 font-mono">{packets.toLocaleString()}<div className="text-[10px] text-ink-400">{d.ppm}/min</div></td>
      <td><span className="chip bg-critical/15 text-critical"><span className="live-dot mr-1 inline-block h-1.5 w-1.5 rounded-full bg-critical" />active</span></td>
    </tr>
  );
}
