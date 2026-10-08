// Small 3D force-directed layout (no dependency): pairwise repulsion, springs on
// edges, weak centering, damping. Positions are seeded from a hash of the node
// id, so the same network always settles into the same shape (no jumping
// between reloads), and new devices appear without reshuffling the others.

export type Vec3 = [number, number, number];

export interface LayoutNode {
  id: string;
  pos: Vec3;
  vel: Vec3;
  fixed: boolean;
}

export interface LayoutOptions {
  repulsion: number;
  spring: number;
  restLength: number;
  centering: number;
  damping: number;
  maxSpeed: number;
  maxRadius: number;
}

export const DEFAULTS: LayoutOptions = {
  repulsion: 4,
  spring: 0.08,
  restLength: 4.2,
  centering: 0.01,
  damping: 0.8,
  maxSpeed: 0.5,
  maxRadius: 8, // keeps every device inside the default camera view
};

export function hash(s: string): number {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

/** Deterministic point on a (flattened) sphere shell, from the id. */
export function seed(id: string, radius = 4): Vec3 {
  const h = hash(id);
  const u = (h & 0xffff) / 0xffff;
  const v = ((h >>> 16) & 0xffff) / 0xffff;
  const theta = 2 * Math.PI * u;
  const phi = Math.acos(2 * v - 1);
  return [
    radius * Math.sin(phi) * Math.cos(theta),
    radius * Math.cos(phi) * 0.6,
    radius * Math.sin(phi) * Math.sin(theta),
  ];
}

export function makeNode(id: string, fixedAt?: Vec3): LayoutNode {
  return { id, pos: fixedAt ?? seed(id), vel: [0, 0, 0], fixed: fixedAt !== undefined };
}

interface Acc {
  x: number;
  y: number;
  z: number;
}

/** One integration step. Returns the total kinetic energy (≈0 when settled). */
export function step(
  nodes: LayoutNode[],
  edges: Array<[string, string]>,
  o: LayoutOptions = DEFAULTS,
): number {
  const force = new Map<string, Acc>();
  for (const n of nodes) force.set(n.id, { x: 0, y: 0, z: 0 });
  const byId = new Map(nodes.map((n) => [n.id, n]));

  nodes.forEach((a, i) => {
    const fa = force.get(a.id) as Acc;
    for (const b of nodes.slice(i + 1)) {
      const fb = force.get(b.id) as Acc;
      const dx = a.pos[0] - b.pos[0];
      const dy = a.pos[1] - b.pos[1];
      const dz = a.pos[2] - b.pos[2];
      const dist2 = Math.max(0.01, dx * dx + dy * dy + dz * dz);
      const f = o.repulsion / dist2 / Math.sqrt(dist2);
      fa.x += dx * f;
      fa.y += dy * f;
      fa.z += dz * f;
      fb.x -= dx * f;
      fb.y -= dy * f;
      fb.z -= dz * f;
    }
  });

  for (const [ia, ib] of edges) {
    const a = byId.get(ia);
    const b = byId.get(ib);
    if (!a || !b) continue;
    const fa = force.get(a.id) as Acc;
    const fb = force.get(b.id) as Acc;
    const dx = b.pos[0] - a.pos[0];
    const dy = b.pos[1] - a.pos[1];
    const dz = b.pos[2] - a.pos[2];
    const dist = Math.max(0.01, Math.hypot(dx, dy, dz));
    const f = (o.spring * (dist - o.restLength)) / dist;
    fa.x += dx * f;
    fa.y += dy * f;
    fa.z += dz * f;
    fb.x -= dx * f;
    fb.y -= dy * f;
    fb.z -= dz * f;
  }

  let energy = 0;
  for (const n of nodes) {
    if (n.fixed) continue;
    const f = force.get(n.id) as Acc;
    let vx = (n.vel[0] + f.x - n.pos[0] * o.centering) * o.damping;
    let vy = (n.vel[1] + f.y - n.pos[1] * o.centering) * o.damping;
    let vz = (n.vel[2] + f.z - n.pos[2] * o.centering) * o.damping;
    const speed = Math.hypot(vx, vy, vz);
    if (speed > o.maxSpeed) {
      const k = o.maxSpeed / speed;
      vx *= k;
      vy *= k;
      vz *= k;
    }
    let [px, py, pz] = [n.pos[0] + vx, n.pos[1] + vy, n.pos[2] + vz];
    const r = Math.hypot(px, py, pz);
    if (r > o.maxRadius) {
      const k = o.maxRadius / r;
      px *= k;
      py *= k;
      pz *= k;
      // Velocity = the movement that actually happened, so a node pressed against
      // the boundary loses its outward push and the layout can settle.
      vx = px - n.pos[0];
      vy = py - n.pos[1];
      vz = pz - n.pos[2];
    }
    n.vel = [vx, vy, vz];
    n.pos = [px, py, pz];
    energy += vx * vx + vy * vy + vz * vz;
  }
  return energy;
}
