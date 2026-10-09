// The indicator under investigation, shared by every page and every window of
// the app: enter an IP once (trace or lookup) and Overview, Threat intel,
// Malware, Actors and Dark web all show it. Kept in localStorage (survives
// reloads, and other windows get a "storage" event) and also broadcast on a
// BroadcastChannel, so a second screen follows along live.
import { useSyncExternalStore } from "react";

const KEY = "dsn.activeIndicator";
const listeners = new Set<() => void>();
let current: string | null = read();

function read(): string | null {
  try {
    return localStorage.getItem(KEY);
  } catch {
    return null; // storage blocked: this window only
  }
}

function emit(): void {
  listeners.forEach((l) => l());
}

let channel: BroadcastChannel | null = null;
try {
  channel = new BroadcastChannel("dsn-indicator");
  channel.onmessage = (e: MessageEvent<string | null>) => {
    if (e.data !== current) {
      current = e.data;
      emit();
    }
  };
} catch {
  channel = null;
}

if (typeof window !== "undefined") {
  window.addEventListener("storage", (e) => {
    if (e.key === KEY && e.newValue !== current) {
      current = e.newValue;
      emit();
    }
  });
}

export function getActiveIndicator(): string | null {
  return current;
}

export function setActiveIndicator(value: string | null): void {
  const next = value?.trim() || null;
  if (next === current) return;
  current = next;
  try {
    if (next) localStorage.setItem(KEY, next);
    else localStorage.removeItem(KEY);
  } catch {
    /* storage blocked: the channel still syncs open windows */
  }
  channel?.postMessage(next);
  emit();
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function useActiveIndicator(): string | null {
  return useSyncExternalStore(subscribe, getActiveIndicator, () => null);
}
