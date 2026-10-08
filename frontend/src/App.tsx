import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState, useSyncExternalStore } from "react";
import { api, ApiError, getToken, setToken } from "./api/client";
import type { Liveness, Me } from "./api/types";
import { DeviceList } from "./components/DeviceList";
import { FeedHealth } from "./components/FeedHealth";
import { Inspector } from "./components/Inspector";
import { Timeline } from "./components/Timeline";
import { TopBar } from "./components/TopBar";
import { connectLive, type LinkState } from "./live/socket";
import { LiveStore } from "./live/store";
import { LEVEL_COLOR, QUARANTINE_COLOR, UNSCORED_COLOR } from "./viz/colors";

// three.js is the heaviest dependency: load the 3D view as its own chunk.
const Graph3D = lazy(() => import("./components/Graph3D").then((m) => ({ default: m.Graph3D })));

const store = new LiveStore();

async function loadSnapshot(): Promise<void> {
  const [devices, risks, quarantines, events] = await Promise.all([
    api.devices(),
    api.risks(),
    api.quarantines(),
    api.events(1000),
  ]);
  store.reset({ devices, risks, quarantines, events });
}

export function App() {
  const state = useSyncExternalStore(store.subscribe, store.getState);
  const [health, setHealth] = useState<Liveness | null>(null);
  const [me, setMe] = useState<Me | null>(null);
  const [authNeeded, setAuthNeeded] = useState(false);
  const [link, setLink] = useState<LinkState>("connecting");
  const [selected, setSelected] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [session, setSession] = useState(0); // bump to reconnect after login/logout

  useEffect(() => {
    api.health().then(setHealth).catch(() => setHealth(null));
  }, []);

  // Who am I + initial snapshot (re-run after login/logout).
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const who = await api.me();
        if (cancelled) return;
        setMe(who);
        setAuthNeeded(false);
        await loadSnapshot();
        if (!cancelled) setError(null);
      } catch (e) {
        if (cancelled) return;
        if (e instanceof ApiError && e.status === 401) {
          setToken(null);
          setMe(null);
          setAuthNeeded(true);
        } else {
          setError(e instanceof Error ? e.message : String(e));
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [session]);

  // Live stream, resumed from the newest seq the store holds.
  useEffect(() => {
    if (authNeeded || health?.deployment === "hosted") return;
    return connectLive({
      token: getToken,
      lastSeq: () => store.getState().lastSeq,
      onEvents: (batch) => store.ingest(batch),
      onResync: () => void loadSnapshot().catch((e: unknown) => setError(String(e))),
      onState: setLink,
    });
  }, [session, authNeeded, health?.deployment]);

  // New or re-profiled devices: refresh the device list (debounced).
  const refreshTimer = useRef<number | undefined>(undefined);
  const lastSeen = useRef(0);
  useEffect(() => {
    const fresh = state.events.filter(
      (e) => e.seq > lastSeen.current && (e.type === "DEVICE_CONNECTED" || e.type === "DEVICE_PROFILED"),
    );
    lastSeen.current = state.lastSeq;
    if (!fresh.length) return;
    window.clearTimeout(refreshTimer.current);
    refreshTimer.current = window.setTimeout(() => {
      api
        .devices()
        .then((list) => list.forEach((d) => store.upsertDevice(d)))
        .catch(() => undefined);
    }, 800);
  }, [state.events, state.lastSeq]);

  // Events per second over a 5 s sliding window.
  const [rate, setRate] = useState(0);
  const samples = useRef<Array<[number, number]>>([]);
  useEffect(() => {
    const id = window.setInterval(() => {
      const now = Date.now();
      samples.current.push([now, store.getState().received]);
      samples.current = samples.current.filter(([t]) => now - t <= 5000);
      const oldest = samples.current[0];
      if (!oldest) return;
      const [t0, n0] = oldest;
      setRate(now > t0 ? ((store.getState().received - n0) * 1000) / (now - t0) : 0);
    }, 1000);
    return () => window.clearInterval(id);
  }, []);

  const login = useCallback(async (secret: string) => {
    const s = await api.login(secret);
    setToken(s.access_token);
    setSession((n) => n + 1);
  }, []);
  const logout = useCallback(() => {
    setToken(null);
    setMe(null);
    setSession((n) => n + 1);
  }, []);

  const selectedNode = selected ? state.nodes[selected] : undefined;
  const onSelect = useCallback((id: string | null) => setSelected(id), []);
  const nodeCount = useMemo(() => Object.keys(state.nodes).length, [state.nodes]);

  return (
    <div className="flex h-full flex-col">
      <TopBar
        health={health}
        link={authNeeded ? "unauthorized" : link}
        me={me}
        nodes={state.nodes}
        rate={rate}
        onLogin={login}
        onLogout={logout}
      />
      {error && <div className="bg-critical/15 px-4 py-1.5 text-xs text-critical">Backend: {error}</div>}
      {health?.deployment === "hosted" && (
        <div className="bg-medium/10 px-4 py-1.5 text-xs text-medium">
          Hosted mode: no lab, no live stream. Run the virtual lab (`make lab-up`) for the live view.
        </div>
      )}

      {authNeeded ? (
        <div className="grid flex-1 place-items-center p-6">
          <div className="panel max-w-sm p-5 text-center">
            <h2 className="mb-1 text-sm font-semibold">Sign in required</h2>
            <p className="text-xs text-ink-300">
              This deployment requires authentication for all reads. Use the Sign in button above
              with your admin or viewer token, or an OIDC access token from your identity provider.
            </p>
          </div>
        </div>
      ) : (
        <main className="grid min-h-0 flex-1 grid-cols-1 gap-3 p-3 lg:grid-cols-[260px_1fr] xl:grid-cols-[260px_1fr_380px] xl:grid-rows-[1fr_34%]">
          <div className="flex min-h-0 flex-col gap-3 lg:row-span-2">
            <DeviceList nodes={state.nodes} selected={selected} onSelect={onSelect} />
            <FeedHealth />
            <Legend />
          </div>

          <section className="panel relative min-h-[360px] overflow-hidden">
            <Suspense fallback={<p className="p-4 text-xs text-ink-400">Loading 3D view…</p>}>
              <Graph3D nodes={state.nodes} selected={selected} onSelect={onSelect} />
            </Suspense>
            {nodeCount === 0 && (
              <p className="pointer-events-none absolute inset-x-0 top-1/2 text-center text-xs text-ink-400">
                No devices yet. Start the virtual lab: <code>make lab-up</code>
              </p>
            )}
            <p className="pointer-events-none absolute bottom-2 left-3 text-[10px] text-ink-400">
              drag to orbit · scroll to zoom · click a device to inspect
            </p>
          </section>

          <div className="min-h-[300px] xl:row-span-2 xl:min-h-0">
            {selectedNode ? (
              <Inspector
                node={selectedNode}
                role={me?.source === "anonymous" ? null : (me?.role ?? null)}
                dryRun={health?.dry_run ?? true}
                onClose={() => setSelected(null)}
              />
            ) : (
              <div className="panel grid h-full place-items-center p-6 text-center text-xs text-ink-400">
                Select a device in the graph or the timeline to see its risk explanation, threat
                graph and controls.
              </div>
            )}
          </div>

          <div className="min-h-[260px] xl:min-h-0">
            <Timeline events={state.events} nodes={state.nodes} selected={selected} onSelect={onSelect} />
          </div>
        </main>
      )}
    </div>
  );
}

function Legend() {
  const items = [
    ...Object.entries(LEVEL_COLOR).map(([k, c]) => ({ label: k, color: c })),
    { label: "quarantined", color: QUARANTINE_COLOR },
    { label: "not scored", color: UNSCORED_COLOR },
  ];
  return (
    <section className="panel">
      <div className="panel-title">Legend</div>
      <ul className="grid grid-cols-3 gap-1.5 px-3 pb-2 text-[10px] text-ink-300">
        {items.map((i) => (
          <li key={i.label} className="flex items-center gap-2">
            <span className="h-2.5 w-2.5 rounded-full" style={{ background: i.color }} />
            {i.label}
          </li>
        ))}
      </ul>
      <p className="px-3 pb-3 text-[10px] leading-relaxed text-ink-400">
        Size grows with risk. A pulse marks new activity; quarantined devices keep pulsing.
      </p>
    </section>
  );
}
