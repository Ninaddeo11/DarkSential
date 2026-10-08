import { Link, Route, Routes } from "react-router";
import { Shell } from "./layout/Shell";
import { LiveProvider } from "./live/LiveContext";
import { DeviceDetailPage } from "./pages/DeviceDetailPage";
import { DevicesPage } from "./pages/DevicesPage";
import { EvaluationPage } from "./pages/EvaluationPage";
import { EventsPage } from "./pages/EventsPage";
import { IntelPage } from "./pages/IntelPage";
import { OverviewPage } from "./pages/OverviewPage";
import { ResponsePage } from "./pages/ResponsePage";

/** Routes. One LiveProvider (one Socket.IO connection, one store) serves every page. */
export function App() {
  return (
    <LiveProvider>
      <Routes>
        <Route element={<Shell />}>
          <Route index element={<OverviewPage />} />
          <Route path="devices" element={<DevicesPage />} />
          <Route path="devices/:nodeId" element={<DeviceDetailPage />} />
          <Route path="events" element={<EventsPage />} />
          <Route path="intel" element={<IntelPage />} />
          <Route path="response" element={<ResponsePage />} />
          <Route path="evaluation" element={<EvaluationPage />} />
          <Route path="*" element={<NotFound />} />
        </Route>
      </Routes>
    </LiveProvider>
  );
}

function NotFound() {
  return (
    <div className="grid h-full place-items-center p-6 text-center">
      <div>
        <p className="font-mono text-3xl text-ink-400">404</p>
        <p className="mt-1 text-sm text-ink-300">No such page.</p>
        <Link to="/" className="mt-2 inline-block text-xs text-signal hover:underline">
          Back to the overview
        </Link>
      </div>
    </div>
  );
}
