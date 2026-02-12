import { create } from 'zustand';
import { wsClient } from '@/lib/websocket.ts';

interface WebSocketState {
  connected: boolean;
  init: () => () => void;
}

export const useWebSocketStore = create<WebSocketState>((set) => ({
  connected: false,

  init: () => {
    wsClient.connect();
    const unsub = wsClient.subscribe('_connection', (data) => {
      set({ connected: (data as { connected: boolean }).connected });
    });
    return () => {
      unsub();
      wsClient.disconnect();
    };
  },
}));
