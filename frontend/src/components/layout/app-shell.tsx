import { Suspense, useEffect } from 'react';
import { Outlet } from 'react-router';
import { Sidebar } from './sidebar.tsx';
import { Header } from './header.tsx';
import { Breadcrumbs } from './breadcrumbs.tsx';
import { AuthGuard } from './auth-guard.tsx';
import { ErrorBoundary } from './error-boundary.tsx';
import { ToastContainer } from './toast-container.tsx';
import { LoadingSkeleton } from '@/components/loading-skeleton.tsx';
import { useWebSocketStore } from '@/stores/websocket-store.ts';
import { useWebSocketSync } from '@/hooks/use-websocket.ts';

function WebSocketProvider({ children }: { children: React.ReactNode }) {
  const init = useWebSocketStore((s) => s.init);
  useEffect(() => init(), [init]);
  useWebSocketSync();
  return <>{children}</>;
}

export function AppShell() {
  return (
    <AuthGuard>
      <WebSocketProvider>
        <div className="flex h-screen overflow-hidden">
          <Sidebar />
          <div className="flex flex-1 flex-col overflow-hidden">
            <Header />
            <Breadcrumbs />
            <main className="flex-1 overflow-y-auto">
              <ErrorBoundary>
                <Suspense fallback={<LoadingSkeleton />}>
                  <Outlet />
                </Suspense>
              </ErrorBoundary>
            </main>
          </div>
        </div>
        <ToastContainer />
      </WebSocketProvider>
    </AuthGuard>
  );
}
