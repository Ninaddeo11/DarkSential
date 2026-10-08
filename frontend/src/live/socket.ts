// Live event stream over Socket.IO. Reconnects automatically (with backoff and
// jitter from socket.io-client); every (re)connect sends the last seq the store
// holds, so the server replays exactly what was missed. If the gap is older than
// the server's buffer it sends `resync` and the app reloads its REST snapshot.
import { io, type Socket } from "socket.io-client";
import type { DsnEvent } from "../generated/events";

export type LinkState = "connecting" | "live" | "offline" | "unauthorized";

export interface LiveLinkOptions {
  token: () => string | null;
  lastSeq: () => number;
  onEvents: (batch: DsnEvent[]) => void;
  onResync: () => void;
  onState: (state: LinkState) => void;
}

export function connectLive(opts: LiveLinkOptions): () => void {
  const socket: Socket = io({
    path: "/api/socket.io",
    transports: ["websocket", "polling"],
    reconnection: true,
    reconnectionDelay: 1000,
    reconnectionDelayMax: 15000,
    randomizationFactor: 0.5,
    // A function, so each reconnect sends the *current* token and seq.
    auth: (cb) => cb({ token: opts.token() ?? undefined, after_seq: opts.lastSeq() }),
  });
  opts.onState("connecting");
  socket.on("connect", () => opts.onState("live"));
  socket.on("disconnect", () => opts.onState("offline"));
  socket.on("connect_error", (err: Error) => {
    opts.onState(err.message === "unauthorized" ? "unauthorized" : "offline");
  });
  socket.on("events", (batch: DsnEvent[]) => {
    if (Array.isArray(batch) && batch.length) opts.onEvents(batch);
  });
  socket.on("resync", () => opts.onResync());
  return () => {
    socket.removeAllListeners();
    socket.disconnect();
  };
}
