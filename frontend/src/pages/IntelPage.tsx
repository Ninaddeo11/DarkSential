import { useEffect, useState, type FormEvent } from "react";
import { api, ApiError } from "../api/client";
import type { CveMatch, RelatedThreat, Rule } from "../api/types";
import { FeedHealth } from "../components/FeedHealth";
import { ThreatGraph } from "../components/ThreatGraph";
import { PageHeader } from "../layout/Shell";

const SEVERITY: Record<string, string> = {
  critical: "text-critical",
  high: "text-high",
  medium: "text-medium",
  low: "text-low",
};

export function IntelPage() {
  const [counts, setCounts] = useState<Record<string, number> | null>(null);
  const [rules, setRules] = useState<Rule[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.graphCounts().then(setCounts).catch((e: unknown) => setError(String(e)));
    api.rules().then(setRules).catch(() => setRules([]));
  }, []);

  return (
    <div className="space-y-3 pb-4">
      <PageHeader
        title="Threat intelligence"
        subtitle="Feeds, the threat graph, indicator and CVE lookups, and the detection rules mapped to ATT&CK."
      />
      {error && <p className="px-4 text-xs text-critical">{error}</p>}
      {counts && (
        <div className="grid grid-cols-2 gap-3 px-4 sm:grid-cols-4 xl:grid-cols-6">
          {Object.entries(counts).map(([k, v]) => (
            <div key={k} className="panel px-3 py-2">
              <div className="font-mono text-xl font-semibold">{v.toLocaleString()}</div>
              <div className="text-[10px] tracking-widest text-ink-400 uppercase">{k}</div>
            </div>
          ))}
        </div>
      )}
      <div className="grid gap-3 px-4 xl:grid-cols-2">
        <IocLookup />
        <CveLookup />
      </div>
      <div className="grid gap-3 px-4 xl:grid-cols-[360px_1fr]">
        <FeedHealth />
        <section className="panel">
          <div className="panel-title">Detection rules → ATT&amp;CK</div>
          <table className="w-full text-xs">
            <tbody>
              {rules.map((r) => (
                <tr key={r.id} className="border-t border-ink-800 align-top">
                  <td className="py-1.5 pl-3 font-mono text-[11px]">{r.id}</td>
                  <td className={`px-2 py-1.5 ${SEVERITY[r.severity] ?? ""}`}>{r.severity}</td>
                  <td className="px-2 py-1.5 font-mono text-[11px] text-signal">{r.techniques.join(", ")}</td>
                  <td className="py-1.5 pr-3 text-ink-300">{r.rationale}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      </div>
    </div>
  );
}

function IocLookup() {
  const [ioc, setIoc] = useState("162.243.103.246");
  const [result, setResult] = useState<RelatedThreat[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      setResult(await api.relatedThreats(ioc.trim()));
    } catch (err) {
      setResult(null);
      setError(err instanceof ApiError ? err.message : String(err));
    }
  };
  return (
    <section className="panel">
      <div className="panel-title">Indicator lookup</div>
      <form onSubmit={submit} className="flex gap-2 px-3 pb-2">
        <input
          className="input"
          value={ioc}
          onChange={(e) => setIoc(e.target.value)}
          placeholder="IP, domain, URL or hash"
          aria-label="Indicator"
          maxLength={2000}
        />
        <button className="btn" type="submit" disabled={!ioc.trim()}>
          Look up
        </button>
      </form>
      {error && <p className="px-3 pb-2 text-xs text-critical">{error}</p>}
      {result && result.length === 0 && <p className="px-3 pb-3 text-xs text-ink-400">No related threats.</p>}
      {result && result.length > 0 && (
        <>
          <ul className="space-y-1 px-3 pb-2 text-xs">
            {result.map((t) => (
              <li key={t.threat_id}>
                <span className="font-semibold">{t.name ?? t.threat_id}</span>{" "}
                <span className="text-ink-400">
                  {t.label} · {t.hops} hop{t.hops === 1 ? "" : "s"} · {t.sources.join(", ")}
                  {t.confidence !== null ? ` · confidence ${t.confidence}` : ""}
                </span>
              </li>
            ))}
          </ul>
          <ThreatGraph paths={result.map((t) => t.path)} />
        </>
      )}
    </section>
  );
}

function CveLookup() {
  const [cpe, setCpe] = useState("cpe:2.3:a:embedthis:goahead:3.6.4:*:*:*:*:*:*:*");
  const [result, setResult] = useState<CveMatch[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      setResult(await api.cves(cpe.trim()));
    } catch (err) {
      setResult(null);
      setError(err instanceof ApiError ? err.message : String(err));
    }
  };
  return (
    <section className="panel">
      <div className="panel-title">CVEs for a product (CPE 2.3)</div>
      <form onSubmit={submit} className="flex gap-2 px-3 pb-2">
        <input
          className="input font-mono"
          value={cpe}
          onChange={(e) => setCpe(e.target.value)}
          aria-label="CPE"
          maxLength={512}
        />
        <button className="btn" type="submit" disabled={!cpe.trim()}>
          Look up
        </button>
      </form>
      {error && <p className="px-3 pb-2 text-xs text-critical">{error}</p>}
      {result && result.length === 0 && <p className="px-3 pb-3 text-xs text-ink-400">No matching CVEs.</p>}
      {result && result.length > 0 && (
        <table className="mb-2 w-full text-xs">
          <tbody>
            {result.map((c) => (
              <tr key={c.cve} className="border-t border-ink-800">
                <td className="py-1.5 pl-3 font-mono">{c.cve}</td>
                <td className="px-2">{c.cvss_score ?? "–"} {c.cvss_severity ?? ""}</td>
                <td className="px-2">
                  {c.kev ? <span className="chip bg-critical/15 text-critical">CISA KEV</span> : "not in KEV"}
                </td>
                <td className="pr-3 text-ink-400">{c.match} match</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
