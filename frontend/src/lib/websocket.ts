type EventHandler = (data: unknown) => void;

const KNOWN_EVENT_TYPES = new Set([
  'scan_progress',
  'scan_completed',
  'scan_failed',
  'label_applied',
  'remediation_completed',
  'job_status',
  'health_update',
  'file_access',
]);

class OpenLabelsWebSocket {
  private ws: WebSocket | null = null;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private reconnectDelay = 1000;
  private maxReconnectDelay = 30000;
  private listeners = new Map<string, Set<EventHandler>>();
  private _connected = false;

  get connected() {
    return this._connected;
  }

  connect() {
    if (this.ws?.readyState === WebSocket.OPEN) return;

    // Close any socket in CONNECTING or CLOSING state to prevent duplicates
    if (this.ws) {
      this.ws.onclose = null;
      this.ws.close();
      this.ws = null;
    }

    const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
    this.ws = new WebSocket(`${protocol}//${location.host}/ws/events`);

    this.ws.onopen = () => {
      this._connected = true;
      this.reconnectDelay = 1000;
      this.listeners.get('_connection')?.forEach((h) => h({ connected: true }));
    };

    this.ws.onmessage = (event) => {
      try {
        const message = JSON.parse(event.data as string) as { type: string; data: unknown };
        if (typeof message.type !== 'string' || !KNOWN_EVENT_TYPES.has(message.type)) return;
        const handlers = this.listeners.get(message.type);
        handlers?.forEach((handler) => handler(message.data));
      } catch {
        // ignore malformed messages
      }
    };

    this.ws.onclose = () => {
      this._connected = false;
      this.listeners.get('_connection')?.forEach((h) => h({ connected: false }));
      this.scheduleReconnect();
    };

    this.ws.onerror = () => {
      this.ws?.close();
    };
  }

  disconnect() {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    this.ws?.close();
    this.ws = null;
    this._connected = false;
  }

  subscribe(eventType: string, handler: EventHandler): () => void {
    if (!this.listeners.has(eventType)) {
      this.listeners.set(eventType, new Set());
    }
    this.listeners.get(eventType)!.add(handler);
    return () => {
      this.listeners.get(eventType)?.delete(handler);
    };
  }

  private scheduleReconnect() {
    if (this.reconnectTimer) return;
    const delay = this.reconnectDelay;
    this.reconnectDelay = Math.min(this.reconnectDelay * 2, this.maxReconnectDelay);
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.connect();
    }, delay);
  }
}

export const wsClient = new OpenLabelsWebSocket();
