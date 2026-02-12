import { useEffect, type ReactNode } from 'react';
import { useAuthStore } from '@/stores/auth-store.ts';
import { LoadingSkeleton } from '@/components/loading-skeleton.tsx';

export function AuthGuard({ children }: { children: ReactNode }) {
  const { isAuthenticated, isLoading, checkAuth } = useAuthStore();

  useEffect(() => {
    checkAuth();
  }, [checkAuth]);

  if (isLoading) return <LoadingSkeleton />;

  if (!isAuthenticated) {
    window.location.href = '/api/v1/auth/login';
    return null;
  }

  return <>{children}</>;
}
