import { lazy, Suspense } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { ConsoleShell } from "./components/layout/ConsoleShell";
import { ApiPlaygroundPage } from "./pages/ApiPlaygroundPage";
import { DetectionPage } from "./pages/DetectionPage";
import { EntityInspectorPage } from "./pages/EntityInspectorPage";
import { IngestionDebugPage } from "./pages/IngestionDebugPage";
import { OcsfExplorerPage } from "./pages/OcsfExplorerPage";
import { OverviewPage } from "./pages/OverviewPage";
import { ConsoleProvider } from "./state/ConsoleContext";

const GraphWorkbenchPage = lazy(() =>
  import("./pages/GraphWorkbenchPage").then((m) => ({ default: m.GraphWorkbenchPage })),
);

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      staleTime: 10_000,
      refetchOnWindowFocus: false,
    },
  },
});

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <ConsoleProvider>
        <BrowserRouter>
          <Routes>
            <Route element={<ConsoleShell />}>
              <Route index element={<Navigate to="/overview" replace />} />
              <Route path="/overview" element={<OverviewPage />} />
              <Route path="/ingestion" element={<IngestionDebugPage />} />
              <Route path="/events" element={<OcsfExplorerPage />} />
              <Route path="/entities" element={<EntityInspectorPage />} />
              <Route
                path="/graph"
                element={
                  <Suspense
                    fallback={
                      <div className="p-6 text-xs text-[var(--pl-text-muted)]">
                        正在加载图谱工作台…
                      </div>
                    }
                  >
                    <GraphWorkbenchPage />
                  </Suspense>
                }
              />
              <Route path="/detection" element={<DetectionPage />} />
              <Route path="/playground" element={<ApiPlaygroundPage />} />
              <Route path="*" element={<Navigate to="/overview" replace />} />
            </Route>
          </Routes>
        </BrowserRouter>
      </ConsoleProvider>
    </QueryClientProvider>
  );
}
