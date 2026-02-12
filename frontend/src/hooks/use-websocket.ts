import { useEffect } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { wsClient } from '@/lib/websocket.ts';
import { useUIStore } from '@/stores/ui-store.ts';
import type { ScanJob, WSScanProgress } from '@/api/types.ts';

export function useWebSocketSync() {
  const queryClient = useQueryClient();
  const addToast = useUIStore((s) => s.addToast);

  useEffect(() => {
    const unsubscribers = [
      wsClient.subscribe('scan_progress', (raw) => {
        const data = raw as WSScanProgress;
        queryClient.setQueryData(['scans', data.scan_id], (old: ScanJob | undefined) =>
          old ? { ...old, progress: data.progress, files_scanned: data.progress.files_scanned } : old,
        );
      }),

      wsClient.subscribe('scan_completed', (raw) => {
        const data = raw as { scan_id: string };
        queryClient.invalidateQueries({ queryKey: ['scans'] });
        queryClient.invalidateQueries({ queryKey: ['scans', data.scan_id] });
        queryClient.invalidateQueries({ queryKey: ['dashboard'] });
        addToast({ level: 'info', message: 'Scan completed' });
      }),

      wsClient.subscribe('scan_failed', (raw) => {
        const data = raw as { scan_id: string; error: string };
        queryClient.invalidateQueries({ queryKey: ['scans'] });
        queryClient.invalidateQueries({ queryKey: ['scans', data.scan_id] });
        addToast({ level: 'error', message: 'Scan failed', description: data.error });
      }),

      wsClient.subscribe('label_applied', () => {
        queryClient.invalidateQueries({ queryKey: ['results'] });
        queryClient.invalidateQueries({ queryKey: ['labels'] });
      }),

      wsClient.subscribe('remediation_completed', () => {
        queryClient.invalidateQueries({ queryKey: ['remediation'] });
        addToast({ level: 'success', message: 'Remediation action completed' });
      }),

      wsClient.subscribe('job_status', () => {
        queryClient.invalidateQueries({ queryKey: ['monitoring', 'jobs'] });
      }),

      wsClient.subscribe('health_update', () => {
        queryClient.invalidateQueries({ queryKey: ['health'] });
      }),
    ];

    return () => unsubscribers.forEach((unsub) => unsub());
  }, [queryClient, addToast]);
}
