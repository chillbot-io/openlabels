import { useEffect, useRef, useState } from 'react';

export interface LiveFinding {
  file_path: string;
  risk_score: number;
  risk_tier: string;
  entity_counts: Record<string, number>;
  timestamp: number;
}

/**
 * Connect to the per-scan WebSocket endpoint to receive live findings.
 * Only active while the scan is running.
 */
export function useScanWebSocket(scanId: string | undefined, isRunning: boolean) {
  const [findings, setFindings] = useState<LiveFinding[]>([]);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    if (!scanId || !isRunning) return;

    const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${protocol}//${location.host}/ws/scans/${scanId}`);
    wsRef.current = ws;

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data as string) as { type: string; [key: string]: unknown };
        if (msg.type === 'file_result') {
          const finding: LiveFinding = {
            file_path: msg.file_path as string,
            risk_score: msg.risk_score as number,
            risk_tier: msg.risk_tier as string,
            entity_counts: (msg.entity_counts as Record<string, number>) ?? {},
            timestamp: Date.now(),
          };
          setFindings((prev) => [finding, ...prev].slice(0, 200));
        }
      } catch {
        // ignore malformed messages
      }
    };

    ws.onerror = () => ws.close();

    return () => {
      ws.close();
      wsRef.current = null;
    };
  }, [scanId, isRunning]);

  // Reset when scan changes
  useEffect(() => {
    setFindings([]);
  }, [scanId]);

  return findings;
}
