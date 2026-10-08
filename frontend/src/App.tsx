import { lazy, Suspense } from "react";
import { Link, Route, Routes } from "react-router";
import { PublicShell } from "./layout/PublicShell";
import { Shell } from "./layout/Shell";
import { LiveProvider } from "./live/LiveContext";
import { DarkWebEnvironment, WorldProvider } from "./visuals/DarkWebEnvironment";
import { AccessPage } from "./pages/AccessPage";
import { DeviceDetailPage } from "./pages/DeviceDetailPage";
import { DevicesPage } from "./pages/DevicesPage";
import { EvaluationPage } from "./pages/EvaluationPage";
import { EventsPage } from "./pages/EventsPage";
import { IntelPage } from "./pages/IntelPage";
import { OverviewPage } from "./pages/OverviewPage";
import { ResponsePage } from "./pages/ResponsePage";

const LandingPage = lazy(() => import("./pages/LandingPage").then(m=>({default:m.LandingPage})));
const AboutPage = lazy(() => import("./pages/AboutPage").then(m=>({default:m.AboutPage})));
const CategoriesPage = lazy(() => import("./pages/CategoriesPage").then(m=>({default:m.CategoriesPage})));
const IntelligenceWorkspace = lazy(() => import("./pages/IntelligenceWorkspace").then(m=>({default:m.IntelligenceWorkspace})));
const VulnerabilitiesPage = lazy(() => import("./pages/VulnerabilitiesPage").then(m=>({default:m.VulnerabilitiesPage})));

/** Routes. One LiveProvider (one Socket.IO connection, one store) serves every page. */
export function App() {
  return (
    <LiveProvider>
      <WorldProvider>
      <div id="nexus-app" className="nexus-app">
      <DarkWebEnvironment />
      <div className="application-layer">
      <Suspense fallback={<div className="route-loading" role="status">Loading Nexus workspace...</div>}>
      <Routes>
        <Route element={<PublicShell />}>
          <Route index element={<LandingPage />} />
          <Route path="landing" element={<LandingPage />} />
          <Route path="about" element={<AboutPage />} />
          <Route path="intelligence" element={<CategoriesPage />} />
          <Route path="access" element={<AccessPage />} />
          <Route path="login" element={<AccessPage />} />
        </Route>
        <Route element={<Shell />}>
          <Route path="dashboard" element={<OverviewPage />} />
          <Route path="actors" element={<IntelligenceWorkspace kind="actors" />} />
          <Route path="malware" element={<IntelligenceWorkspace kind="malware" />} />
          <Route path="dark-web" element={<IntelligenceWorkspace kind="dark-web" />} />
          <Route path="vulnerabilities" element={<VulnerabilitiesPage />} />
          <Route path="overview" element={<OverviewPage />} />
          <Route path="threat-intel" element={<IntelPage />} />
          <Route path="devices" element={<DevicesPage />} />
          <Route path="devices/:nodeId" element={<DeviceDetailPage />} />
          <Route path="events" element={<EventsPage />} />
          <Route path="intel" element={<IntelPage />} />
          <Route path="response" element={<ResponsePage />} />
          <Route path="evaluation" element={<EvaluationPage />} />
          <Route path="*" element={<NotFound />} />
        </Route>
      </Routes>
      </Suspense>
      </div>
      </div>
      </WorldProvider>
    </LiveProvider>
  );
}

function NotFound() {
  return (
    <div className="grid h-full place-items-center p-6 text-center">
      <div>
        <p className="font-mono text-3xl text-ink-400">404</p>
        <p className="mt-1 text-sm text-ink-300">No such page.</p>
        <Link to="/overview" className="mt-2 inline-block text-xs text-signal hover:underline">
          Back to the overview
        </Link>
      </div>
    </div>
  );
}
