# Continuous intelligence world

The existing React/Vite application, cyan hexagonal identity, REST authentication, Socket.IO store, operational graphs, filters and routes remain the foundation. Framer Motion is the only added dependency. All new models and lighting are procedural; there are no external textures, fonts, model downloads or browser secrets.

## Implementation

`DarkWebEnvironment` is mounted above the router outlets. Its single background Canvas remains mounted when navigating between landing, intelligence, About, Access and operational workspaces. Data visualization canvases inside operational graphs remain separate because they represent actual API evidence.

- `worldModel.ts` defines stable artifact identities, depth, category and motion.
- `ThreatObject.tsx` builds solid metallic weapons, sealed laboratory packages, containers, vehicles, server racks, phones, terminals and crypto artifacts.
- `DarkWebWorldEngine.tsx` supplies procedural environment reflections, physical lighting, shadowing, distance fog, restrained bloom and depth of field. Objects drift independently. Faint signals connect their moving positions. Pointer, scroll and route changes adjust the camera without remounting it.
- `WorldWindow` opens the UI onto the shared world instead of creating a scene per section. The landing research index provides eight category routes. Buttons and keyboard focus highlight relevant objects. Metadata appears only on object hover. Foreground controls remain usable above the renderer.
- `PageTransition` fades route content independently of the world. `AnimatedValue` and the posture gauge animate actual data updates.
- `/access` and `/login` use `NexusAccess`, which calls the existing token/OIDC login flow. Protected workspaces use the same entry component. Read-only deployments clearly show that authentication is not configured.

Mobile uses six representative objects, fewer particles, DPR 1, and no postprocessing or shadows. Tablet uses ten objects; desktop uses sixteen with capped DPR and postprocessing resolution. Sustained low frame rate first reduces desktop quality, then switches to demand rendering if performance remains poor. The same Canvas stays mounted. Low-memory devices, Save-Data, unavailable WebGL, renderer failure and context loss use a CSS/SVG atmospheric fallback. Hidden tabs pause rendering; reduced motion uses demand rendering and static atmosphere.

Artifacts and association signals are fictional research illustrations, not observed threats. Only existing API responses supply statistics. Missing data shows an em dash; online status requires a successful health response.

## Build and hosting

Run `npm ci`, `npm run build`, and `npm test` from `frontend`. On Windows with PowerShell script execution disabled, use `npm.cmd`. The build includes the TypeScript check. No public environment variables were introduced.

The existing root `vercel.json` defines Vite and FastAPI services, SPA rewrites, and same-origin `/api/*` routing. Its CSP permits the procedural world and inline styles used by motion. Configure server-only credentials as described in README. `DSN_API_PROXY` only selects a local development/preview backend.

Hosted mode deliberately has no lab runtime or intelligence graph. Lab-data endpoints return 503; the site reports unavailable evidence and remains usable. Local hosted-mode verification does not validate MQTT ingestion, enforcement, real OIDC providers or an actual Vercel deployment.

## Browser verification

`frontend/scripts/browser-qa.mjs` uses Node's WebSocket client and a Chromium DevTools endpoint on port 9224. Start Chromium with a dedicated profile under `frontend/node_modules`, then start Vite or production preview with its API proxy targeting an isolated hosted-mode backend:

```sh
node scripts/browser-qa.mjs http://127.0.0.1:4175
```

Checks cover persistent Canvas identity across public and operational routes, category controls, scrolling, dashboard reset, filters, entry CTA, desktop, tablet and mobile layouts, navigation, reduced motion, hidden tabs, unavailable WebGL, context loss, browser exceptions and failed assets. Screenshots and the JSON report are written to ignored `frontend/node_modules/.nexus-review`. `browser-review.mjs` captures an individual page for visual inspection.

Software WebGL is used in this workspace. The browser scheduling sample includes adaptive static mode and is not a rendered-frame-rate measurement or hardware GPU performance guarantee.

The isolated authentication browser check (`browser-auth-qa.mjs`) verifies invalid-token errors, a real viewer session, workspace entry, sign-out and embedded reauthentication. Supply a temporary test token file and an isolated backend; do not use production credentials. The local Python environment includes hosted dependencies only; lab auth/realtime tests require the optional SQLAlchemy and Socket.IO dependencies.


`browser-csp-qa.mjs` applies the frontend response headers from `vercel.json` to local production documents and checks landing, About, Access and workspace deep links for blocked rendering or CSP errors. Local verification passed: production build, 16 frontend tests, three Vercel entrypoint tests, responsive route/fallback checks and real viewer authentication. No live deployment was performed.
