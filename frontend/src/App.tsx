import { useEffect, useState } from "react";
import { fetchLiveness, fetchReadiness, type Liveness, type Readiness } from "./api";

const POLL_MS = 5000;

export function App() {
  const [live, setLive] = useState<Liveness | null>(null);
  const [ready, setReady] = useState<Readiness | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    const poll = async () => {
      try {
        const [l, r] = await Promise.all([fetchLiveness(), fetchReadiness()]);
        if (!cancelled) {
          setLive(l);
          setReady(r);
          setError(null);
        }
      } catch (e) {
        if (!cancelled) setError(e instanceof Error ? e.message : "unreachable");
      }
    };
    void poll();
    const id = window.setInterval(poll, POLL_MS);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, []);

  return (
    <main>
      <header>
        <h1>Darknet Sentinel Nexus</h1>
        {live && (
          <span className={live.dry_run ? "badge safe" : "badge danger"}>
            {live.dry_run ? "DRY RUN" : "ENFORCING"}
          </span>
        )}
      </header>

      {error && <p className="error">Backend unreachable: {error}</p>}

      {live && (
        <p className="meta">
          v{live.version} · env {live.env} · feeds {live.offline_mode ? "offline (mocks)" : "online"}
        </p>
      )}

      {ready && (
        <section>
          <h2>Dependencies — {ready.status}</h2>
          <table>
            <thead>
              <tr>
                <th>Check</th>
                <th>Status</th>
                <th>Detail</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(ready.checks).map(([name, check]) => (
                <tr key={name}>
                  <td>{name}</td>
                  <td className={`status ${check.status}`}>{check.status}</td>
                  <td>{check.detail ?? ""}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}
      <footer>Phase 0 scaffold — the 3D command center lands in Phase 6.</footer>
    </main>
  );
}
