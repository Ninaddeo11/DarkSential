import { formatCoordinate, type Scenario } from "../sim/scenario";

const when = (iso: string) => new Date(iso).toLocaleString();

/** Investigation report for a simulated indicator (see sim/scenario.ts, sim/generate.ts). */
export function SimInvestigation({ scenario }: { scenario: Scenario }) {
  const REPORT = scenario.report;
  const c = REPORT.consignment;
  const btcIn = REPORT.transfers
    .filter((t) => t.asset === "BTC" && t.to.startsWith("bc1qsim…e5cr"))
    .reduce((sum, t) => sum + t.amount, 0);
  const xmr = REPORT.transfers.filter((t) => t.asset === "XMR").reduce((sum, t) => sum + t.amount, 0);
  return (
    <section className="panel space-y-4 p-4" aria-label="Investigation report">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="section-eyebrow">INVESTIGATION / INDICATOR DOSSIER</p>
          <h2 className="mt-1 font-mono text-lg font-semibold">{REPORT.ioc}</h2>
          <p className="mt-0.5 text-xs text-ink-400">
            {REPORT.hosting}{REPORT.actor ? ` · operated by ${REPORT.actor}` : ""} · active {when(REPORT.firstSeen)} – {when(REPORT.lastSeen)}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className="chip bg-medium/15 text-medium">Simulated scenario</span>
          <div className="text-right">
            <div className="font-mono text-3xl font-semibold text-critical">{REPORT.score}</div>
            <div className="text-[10px] tracking-widest text-critical uppercase">{REPORT.verdict}</div>
          </div>
        </div>
      </div>

      <div className="grid gap-3 sm:grid-cols-4">
        {(REPORT.transfers.length
          ? [
              ["Malware families", String(REPORT.malware.length)],
              ["Crypto transfers", String(REPORT.transfers.length)],
              ["XMR mined", `${xmr.toFixed(2)} XMR`],
              ["BTC into escrow", `${btcIn.toFixed(2)} BTC`],
            ]
          : [
              ["Malware families", String(REPORT.malware.length)],
              ["Malicious subdomains", String(REPORT.subdomains.length)],
              ["Active devices", String(scenario.comms.length)],
              ["Risk score", `${REPORT.score} / 100`],
            ]
        ).map(([k, v]) => (
          <div key={k} className="rounded-md border border-ink-700/70 px-3 py-2">
            <div className="font-mono text-lg font-semibold">{v}</div>
            <div className="text-[10px] tracking-widest text-ink-400 uppercase">{k}</div>
          </div>
        ))}
      </div>

      <div>
        <div className="panel-title px-0">Malware served from this address</div>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead className="text-left text-[10px] tracking-widest text-ink-400 uppercase">
              <tr><th className="py-1">Family</th><th>Type</th><th>Role</th><th>ATT&amp;CK</th><th>First seen</th></tr>
            </thead>
            <tbody>
              {REPORT.malware.map((m) => (
                <tr key={m.family} className="border-t border-ink-800 align-top">
                  <td className="py-1.5 pr-2 font-semibold text-quarantine">{m.family}</td>
                  <td className="pr-2">{m.type}</td>
                  <td className="pr-2 text-ink-300">{m.role}</td>
                  <td className="pr-2">{m.techniques.map((t) => <span key={t} className="technical-badge">{t}</span>)}</td>
                  <td className="font-mono text-ink-400">{m.firstSeen}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {REPORT.subdomains.length > 0 && (
        <div>
          <div className="panel-title px-0">Malicious subdomains resolving to this address</div>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead className="text-left text-[10px] tracking-widest text-ink-400 uppercase">
                <tr><th className="py-1">Subdomain</th><th>Verdict</th><th>Associated malware</th><th>First seen</th></tr>
              </thead>
              <tbody>
                {REPORT.subdomains.map((s) => (
                  <tr key={s.host} className="border-t border-ink-800">
                    <td className="py-1.5 pr-2 font-mono">{s.host}</td>
                    <td className="pr-2"><span className="chip bg-critical/15 text-critical">malicious</span></td>
                    <td className="pr-2 font-semibold text-quarantine">{s.malware}</td>
                    <td className="font-mono text-ink-400">{when(s.firstSeen)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {REPORT.transfers.length > 0 && <div>
        <div className="panel-title px-0">Crypto activity: money trail</div>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead className="text-left text-[10px] tracking-widest text-ink-400 uppercase">
              <tr><th className="py-1">Time</th><th>Amount</th><th>From</th><th>To</th><th>Activity</th><th>Tx</th></tr>
            </thead>
            <tbody>
              {REPORT.transfers.map((t) => (
                <tr key={t.tx} className="border-t border-ink-800">
                  <td className="py-1.5 pr-2 font-mono text-ink-400">{when(t.ts)}</td>
                  <td className={`pr-2 font-mono font-semibold ${t.asset === "XMR" ? "text-high" : "text-medium"}`}>
                    {t.amount.toFixed(2)} {t.asset}
                  </td>
                  <td className="pr-2 font-mono">{t.from}</td>
                  <td className="pr-2 font-mono">{t.to}</td>
                  <td className="pr-2 text-ink-300">{t.note}</td>
                  <td className="font-mono text-ink-400" title={t.tx}>{t.tx.slice(0, 8)}…{t.tx.slice(-6)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>}

      {c && <div className="grid gap-3 lg:grid-cols-[1fr_1.2fr]">
        <div>
          <div className="panel-title px-0">Narcotics consignment {c.id}</div>
          <dl className="grid grid-cols-[110px_1fr] gap-x-2 gap-y-1.5 text-xs">
            <dt className="text-ink-400">Coordinates</dt>
            <dd className="font-mono font-semibold text-critical">{formatCoordinate(c.lat, c.lon)}</dd>
            <dt className="text-ink-400">Region</dt>
            <dd>{c.region}</dd>
            <dt className="text-ink-400">Status</dt>
            <dd>{c.status} · last fix {when(c.lastFix)}</dd>
            <dt className="text-ink-400">Payment</dt>
            <dd className="font-mono">{c.payment}</dd>
            <dt className="text-ink-400">Advertised on</dt>
            <dd>{c.listing}</dd>
            <dt className="text-ink-400">Linked actor</dt>
            <dd>{REPORT.actor}</dd>
          </dl>
        </div>
        <CoordinatePlot lat={c.lat} lon={c.lon} label={c.id} />
      </div>}

      <p className="text-[10px] leading-relaxed text-ink-400">
        Simulated result generated for demonstration. It is not threat intelligence about this address.
      </p>
    </section>
  );
}

/** Equirectangular lat/long grid with the consignment's position. */
function CoordinatePlot({ lat, lon, label }: { lat: number; lon: number; label: string }) {
  // Zoom on a 60° x 40° window around the point.
  const x0 = lon - 30;
  const y0 = lat + 20;
  const sx = (v: number) => ((v - x0) / 60) * 300;
  const sy = (v: number) => ((y0 - v) / 40) * 200;
  const lonLines = Array.from({ length: 7 }, (_, i) => Math.ceil(x0 / 10) * 10 + i * 10).filter((v) => v <= x0 + 60);
  const latLines = Array.from({ length: 5 }, (_, i) => Math.floor(y0 / 10) * 10 - i * 10).filter((v) => v >= y0 - 40);
  const px = sx(lon);
  const py = sy(lat);
  return (
    <svg viewBox="0 0 300 200" className="w-full max-w-md rounded-md border border-ink-700/70 bg-ink-950" role="img"
      aria-label={`Consignment ${label} at ${formatCoordinate(lat, lon)}`}>
      {lonLines.map((v) => (
        <g key={`lon${v}`}>
          <line x1={sx(v)} y1={0} x2={sx(v)} y2={200} stroke="#1d2939" strokeWidth={0.6} />
          <text x={sx(v) + 2} y={196} fontSize={7} fill="#6b7f99">{v}°E</text>
        </g>
      ))}
      {latLines.map((v) => (
        <g key={`lat${v}`}>
          <line x1={0} y1={sy(v)} x2={300} y2={sy(v)} stroke="#1d2939" strokeWidth={0.6} />
          <text x={2} y={sy(v) - 2} fontSize={7} fill="#6b7f99">{v}°N</text>
        </g>
      ))}
      <line x1={px} y1={0} x2={px} y2={200} stroke="#f43f5e" strokeWidth={0.5} strokeDasharray="3 3" />
      <line x1={0} y1={py} x2={300} y2={py} stroke="#f43f5e" strokeWidth={0.5} strokeDasharray="3 3" />
      <circle cx={px} cy={py} r={9} fill="none" stroke="#f43f5e" strokeWidth={1}>
        <animate attributeName="r" values="5;14;5" dur="2.4s" repeatCount="indefinite" />
        <animate attributeName="opacity" values="1;0.1;1" dur="2.4s" repeatCount="indefinite" />
      </circle>
      <circle cx={px} cy={py} r={3.5} fill="#f43f5e" />
      <text x={px + 8} y={py - 8} fontSize={9} fill="#f43f5e" fontWeight={600}>{label}</text>
      <text x={px + 8} y={py + 3} fontSize={7} fill="#dce6f2">{formatCoordinate(lat, lon)}</text>
      <text x={296} y={10} fontSize={7} fill="#6b7f99" textAnchor="end">COORDINATE PLOT · SIMULATED</text>
    </svg>
  );
}
