import { useNavigate, useSearchParams } from "react-router";
import { Timeline } from "../components/Timeline";
import { PageHeader } from "../layout/Shell";
import { useLive } from "../live/LiveContext";

export function EventsPage() {
  const { state } = useLive();
  const [params, setParams] = useSearchParams();
  const navigate = useNavigate();
  const device = params.get("device");
  const n = device ? state.nodes[device] : undefined;
  return (
    <div className="flex h-full flex-col">
      <PageHeader
        title="Events"
        subtitle={`Live event stream (last ${state.events.length.toLocaleString()} kept in the browser).`}
      >
        {device && (
          <button className="btn" onClick={() => setParams({})}>
            Showing {n?.device.hostname ?? device} · clear
          </button>
        )}
      </PageHeader>
      <div className="min-h-[480px] flex-1 px-4 pb-4">
        <Timeline
          key={device ?? "all"}
          events={state.events}
          nodes={state.nodes}
          selected={device}
          initialOnlySelected={Boolean(device)}
          onSelect={(id) => navigate(`/devices/${id}`)}
        />
      </div>
    </div>
  );
}
