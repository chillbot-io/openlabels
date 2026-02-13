import { useEffect, type ReactNode } from 'react';
import { useAuthStore } from '@/stores/auth-store.ts';
import { LoadingSkeleton } from '@/components/loading-skeleton.tsx';

export function AuthGuard({ children }: { children: ReactNode }) {
  const { isAuthenticated, isLoading, checkAuth } = useAuthStore();

  useEffect(() => {
    checkAuth();
  }, [checkAuth]);

  useEffect(() => {
    if (!isLoading && !isAuthenticated) {
      window.location.href = '/api/v1/auth/login';
    }
  }, [isLoading, isAuthenticated]);

  if (isLoading) return <LoadingSkeleton />;

  if (!isAuthenticated) {
    return null;
  }

  return <>{children}</>;
}
