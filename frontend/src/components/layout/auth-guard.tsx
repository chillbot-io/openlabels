import { useEffect, type ReactNode } from 'react';
import { useAuthStore } from '@/stores/auth-store.ts';
import { LoadingSkeleton } from '@/components/loading-skeleton.tsx';

export function AuthGuard({ children }: { children: ReactNode }) {
  const { isAuthenticated, isLoading, checkAuth } = useAuthStore();

  useEffect(() => {
    checkAuth();
    // eslint-disable-next-line react-hooks/exhaustive-deps -- run once on mount
  }, []);

  if (isLoading) return <LoadingSkeleton />;

  if (!isAuthenticated) {
    // apiFetch already redirects to /api/v1/auth/login on 401,
    // so we just render nothing while the navigation happens.
    return null;
  }

  return <>{children}</>;
}
