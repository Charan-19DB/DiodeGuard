/**
 * websocket.js — Real-time bidirectional feed connection to DiodeGuard Backend
 */

const BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';
const WS_URL = BASE_URL.replace(/^http/, 'ws') + '/api/ws';

export function connectSocWebSocket(onEvent) {
  let ws = null;
  let isClosed = false;
  let retryTimeout = null;

  function connect() {
    try {
      ws = new WebSocket(WS_URL);

      ws.onopen = () => {
        console.log('[DiodeGuard WS] 🟢 Connected to real-time SOC event stream.');
      };

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          if (onEvent) onEvent(msg);
        } catch (err) {
          console.error('[DiodeGuard WS] Parse error:', err);
        }
      };

      ws.onerror = (err) => {
        console.warn('[DiodeGuard WS] Stream error:', err);
      };

      ws.onclose = () => {
        if (!isClosed) {
          console.log('[DiodeGuard WS] 🔄 Stream disconnected. Reconnecting in 3s...');
          retryTimeout = setTimeout(connect, 3000);
        }
      };
    } catch (err) {
      console.warn('[DiodeGuard WS] Connection failed:', err);
      if (!isClosed) retryTimeout = setTimeout(connect, 5000);
    }
  }

  connect();

  return () => {
    isClosed = true;
    if (retryTimeout) clearTimeout(retryTimeout);
    if (ws) ws.close();
  };
}
