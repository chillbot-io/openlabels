import { useEffect, useState } from 'react';
import { Navigate } from 'react-router';
import { targetsApi } from '@/api/endpoints/targets.ts';
import { LoadingSkeleton } from '@/components/loading-skeleton.tsx';

/**
 * Root redirect: checks if any scan targets exist.
 * If none → first-run, go to /setup wizard.
 * If targets exist → go to /dashboard.
 */
export function Component() {
  const [destination, setDestination] = useState<string | null>(null);

  useEffect(() => {
    targetsApi
      .list({ page: 1, page_size: 1 })
      .then((resp) => {
        setDestination(resp.items.length > 0 ? '/dashboard' : '/setup');
      })
      .catch(() => {
        // On error (e.g. 401 — not logged in), let dashboard's auth guard handle it
        setDestination('/dashboard');
      });
  }, []);

  if (!destination) return <LoadingSkeleton />;
  return <Navigate to={destination} replace />;
}
