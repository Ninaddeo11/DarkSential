import { LEVEL_COLOR, QUARANTINE_COLOR, UNSCORED_COLOR } from "../viz/colors";

export function Legend() {
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
