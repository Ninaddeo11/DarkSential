// App-wide live state, shared by every page: who is signed in, the backend's
// mode, the REST snapshot + Socket.IO stream (one connection for all pages), and
// the events-per-second meter. Pages read it with useLive().
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  useSyncExternalStore,
  type ReactNode,
} from "react";
import { api, ApiError, getToken, setToken } from "../api/client";
import type { Liveness, Me, Role } from "../api/types";
import { connectLive, type LinkState } from "./socket";
import { LiveStore, type LiveState } from "./store";

export const store = new LiveStore();

async function loadSnapshot(): Promise<void> {
  const [devices, risks, quarantines, events] = await Promise.all([
    api.devices(),
    api.risks(),
    api.quarantines(),
    api.events(1000),
  ]);
  store.reset({ devices, risks, quarantines, events });
}

interface LiveValue {
  state: LiveState;
  health: Liveness | null;
  me: Me | null;
  /** Role of a signed-in user (null when anonymous). */
  role: Role | null;
  authNeeded: boolean;
  link: LinkState;
  rate: number;
  error: string | null;
  login: (secret: string) => Promise<void>;
  logout: () => void;
  reload: () => void;
}

const Ctx = createContext<LiveValue | null>(null);

export function useLive(): LiveValue {
  const value = useContext(Ctx);
  if (!value) throw new Error("useLive() outside <LiveProvider>");
  return value;
}

export function LiveProvider({ children }: { children: ReactNode }) {
  const state = useSyncExternalStore(store.subscribe, store.getState);
  const [health, setHealth] = useState<Liveness | null>(null);
  const [me, setMe] = useState<Me | null>(null);
  const [authNeeded, setAuthNeeded] = useState(false);
  const [link, setLink] = useState<LinkState>("connecting");
  const [error, setError] = useState<string | null>(null);
  const [session, setSession] = useState(0); // bump to reload after login/logout

  useEffect(() => {
    api.health().then(setHealth).catch(() => setHealth(null));
  }, []);

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

  useEffect(() => {
    if (authNeeded || !health || health.deployment === "hosted") return;
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
      (e) =>
        e.seq > lastSeen.current && (e.type === "DEVICE_CONNECTED" || e.type === "DEVICE_PROFILED"),
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
  const reload = useCallback(() => setSession((n) => n + 1), []);

  const value = useMemo<LiveValue>(
    () => ({
      state,
      health,
      me,
      role: me && me.source !== "anonymous" ? me.role : null,
      authNeeded,
      link: authNeeded ? "unauthorized" : link,
      rate,
      error,
      login,
      logout,
      reload,
    }),
    [state, health, me, authNeeded, link, rate, error, login, logout, reload],
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}
