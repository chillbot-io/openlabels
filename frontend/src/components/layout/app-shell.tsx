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
          <a
            href="#main-content"
            className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-[200] focus:rounded-md focus:bg-primary-600 focus:px-4 focus:py-2 focus:text-white focus:outline-none"
          >
            Skip to main content
          </a>
          <Sidebar />
          <div className="flex flex-1 flex-col overflow-hidden">
            <Header />
            <Breadcrumbs />
            <main id="main-content" className="flex-1 overflow-y-auto" tabIndex={-1}>
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
