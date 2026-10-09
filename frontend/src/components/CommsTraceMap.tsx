// Geographic trace of the devices in active communication with an indicator.
// Country outlines: Natural Earth 1:110m via world-atlas, drawn offline with d3-geo.
import { geoEquirectangular, geoPath } from "d3-geo";
import type { Feature, FeatureCollection, Geometry } from "geojson";
import { useEffect, useMemo, useState } from "react";
import { feature } from "topojson-client";
import type { GeometryCollection, Topology } from "topojson-specification";
import world from "world-atlas/countries-110m.json";
import { COMMS, REPORT, type SimCommDevice } from "../sim/scenario";

const W = 900;
const H = 520;
// View: eastern Europe to Sri Lanka, Moscow to the equator.
const EXTENT: [[number, number], [number, number]] = [[18, -4], [104, 66]];
// The indicator is drawn over open ocean: its hosting location is masked, and
// placing it over land would imply a country.
const HUB_LONLAT: [number, number] = [60, 11];
const HIGHLIGHT = new Set(COMMS.map((d) => d.countryId));

type Country = Feature<Geometry, { name: string }>;

const countries = (() => {
  const topo = world as unknown as Topology<{ countries: GeometryCollection<{ name: string }> }>;
  return (feature(topo, topo.objects.countries) as FeatureCollection<Geometry, { name: string }>).features;
})();

export function CommsTraceMap({ ioc, selected, onSelect }: { ioc: string; selected: string | null; onSelect: (id: string) => void }) {
  const { path, project } = useMemo(() => {
    const [[x0, y0], [x1, y1]] = EXTENT;
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
  }, []);
  const HUB = project(HUB_LONLAT[0], HUB_LONLAT[1]);

  const consignment = project(REPORT.consignment.lon, REPORT.consignment.lat);
  return (
      <svg viewBox={`0 0 ${W} ${H}`} className="h-full w-full rounded-md bg-ink-950" preserveAspectRatio="xMidYMid meet" role="img"
        aria-label={`Devices in active communication with ${ioc}: ${COMMS.map((d) => `${d.name} in ${d.city}, ${d.country}`).join("; ")}`}>
        <defs>
          <clipPath id="trace-clip"><rect width={W} height={H} /></clipPath>
        </defs>
        <g clipPath="url(#trace-clip)">
          {countries.map((c: Country, i) => (
            <path key={`${String(c.id)}-${i}`} d={path(c) ?? ""}
              fill={HIGHLIGHT.has(String(c.id)) ? "rgba(244,63,94,0.20)" : "#0e1520"}
              stroke={HIGHLIGHT.has(String(c.id)) ? "#f43f5e" : "#2b3a4f"} strokeWidth={HIGHLIGHT.has(String(c.id)) ? 1.1 : 0.5} />
          ))}
          {/* Country labels */}
          <text x={project(60, 61)[0]} y={project(60, 61)[1]} fontSize={15} fill="#f43f5e" fontWeight={700} letterSpacing={3}>RUSSIA</text>
          <text x={project(83.2, 10.6)[0]} y={project(83.2, 10.6)[1]} fontSize={12} fill="#f43f5e" fontWeight={700} letterSpacing={2}>SRI LANKA</text>

          {/* Consignment position (Arabian Sea) */}
          <g>
            <rect x={consignment[0] - 4} y={consignment[1] - 4} width={8} height={8} fill="#fbbf24" transform={`rotate(45 ${consignment[0]} ${consignment[1]})`} />
            <text x={consignment[0] + 9} y={consignment[1] + 4} fontSize={10} fill="#fbbf24">NX-0427 consignment</text>
          </g>

          {/* Links: device <-> indicator, with packets moving both ways */}
          {COMMS.map((d, i) => {
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
          {COMMS.map((d, i) => {
            const [x, y] = project(d.lon, d.lat);
            const isSel = selected === d.id;
            // Colombo and Kandy are ~100 km apart: label one left/below, one right/below.
            const dx = i === 1 ? -14 : 14;
            const dy = i === 0 ? -10 : 24;
            const anchor = i === 1 ? "end" : "start";
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
            <text x={HUB[0]} y={HUB[1] + 38} fontSize={9.5} fill="#93a4bb" textAnchor="middle">bulletproof hosting · location masked</text>
          </g>
        </g>
        <text x={W - 10} y={H - 10} fontSize={9} fill="#6b7f99" textAnchor="end">Natural Earth 1:110m · simulated scenario</text>
      </svg>
  );
}

/** The devices on the trace map, with live packet counters. */
export function CommsDeviceTable({ selected, onSelect }: { selected: string | null; onSelect: (id: string) => void }) {
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
          {COMMS.map((d) => (
            <DeviceRow key={d.id} d={d} elapsed={elapsed} selected={selected === d.id} onSelect={onSelect} />
          ))}
        </tbody>
      </table>
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
