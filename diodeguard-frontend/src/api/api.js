/**
 * api.js — All HTTP calls to the DiodeGuard FastAPI backend
 * Base URL is configurable via VITE_API_URL environment variable
 */

const BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

function getHeaders() {
  const token = localStorage.getItem('dg_token');
  return {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };
}

async function request(method, path, body = null) {
  const res = await fetch(`${BASE_URL}${path}`, {
    method,
    headers: getHeaders(),
    ...(body ? { body: JSON.stringify(body) } : {}),
  });

  if (res.status === 401 && path !== '/api/auth/login') {
    localStorage.removeItem('dg_token');
    localStorage.removeItem('dg_user');
    window.location.href = '/login';
    return;
  }

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: `HTTP ${res.status}` }));
    let errorMsg = `HTTP ${res.status}`;
    if (typeof err.detail === 'string') {
      errorMsg = err.detail;
    } else if (Array.isArray(err.detail)) {
      errorMsg = err.detail.map((d) => d.msg || JSON.stringify(d)).join('; ');
    } else if (typeof err.message === 'string') {
      errorMsg = err.message;
    }
    throw new Error(errorMsg);
  }

  if (res.status === 204) return null;
  return res.json();
}

// ─── Auth ────────────────────────────────────────────────────────
export const auth = {
  register: (data) => request('POST', '/api/auth/register', data),
  login:    (data) => request('POST', '/api/auth/login', data),
  me:       ()     => request('GET',  '/api/auth/me'),
};

// ─── Alerts ──────────────────────────────────────────────────────
export const alerts = {
  list: (params = {}) => {
    const q = new URLSearchParams(params).toString();
    return request('GET', `/api/alerts/${q ? '?' + q : ''}`);
  },
  get:         (id)  => request('GET',   `/api/alerts/${id}`),
  acknowledge: (id)  => request('PATCH', `/api/alerts/${id}/acknowledge`, { acknowledged: true }),
};

// ─── Threats ─────────────────────────────────────────────────────
export const threats = {
  list: (params = {}) => {
    const q = new URLSearchParams(params).toString();
    return request('GET', `/api/threats/${q ? '?' + q : ''}`);
  },
  get: (id) => request('GET', `/api/threats/${id}`),
};

// ─── Traffic ─────────────────────────────────────────────────────
export const traffic = {
  list:   (params = {}) => {
    const q = new URLSearchParams(params).toString();
    return request('GET', `/api/traffic/${q ? '?' + q : ''}`);
  },
  get:    (flowId) => request('GET', `/api/traffic/${flowId}`),
  ingest: (flow)   => request('POST', '/api/traffic/ingest', flow),
};

// ─── Detection ───────────────────────────────────────────────────
export const detection = {
  predict: (flow) => request('POST', '/api/detection/predict', { flow }),
  list:    ()     => request('GET',  '/api/detection/'),
};

// ─── Dashboard ───────────────────────────────────────────────────
export const dashboard = {
  summary:  ()          => request('GET', '/api/dashboard/summary'),
  timeline: (hours = 24) => request('GET', `/api/dashboard/timeline?hours=${hours}`),
};

// ─── Users (Admin) ───────────────────────────────────────────────
export const users = {
  list:       ()          => request('GET',    '/api/users/'),
  get:        (id)        => request('GET',    `/api/users/${id}`),
  updateRole: (id, role)  => request('PATCH',  `/api/users/${id}/role`, { role }),
  deactivate: (id)        => request('DELETE', `/api/users/${id}`),
};

// ─── Mock data (used when backend is unavailable) ─────────────────
export const MOCK_SUMMARY = {
  total_alerts: 1284,
  critical_alerts: 23,
  high_alerts: 87,
  medium_alerts: 341,
  low_alerts: 833,
  unacknowledged: 142,
  total_flows: 48293,
  alerts_last_24h: 156,
  top_threat_class: 'DDoS',
  detection_rate: 2.66,
};

export const MOCK_ALERTS = Array.from({ length: 12 }, (_, i) => ({
  id: `alert-${i}`,
  flow_id: `flow-${1000 + i}`,
  timestamp: new Date(Date.now() - i * 300000).toISOString(),
  threat_class: ['DDoS','BotnetC2','DGA','EncryptedMalware','Recon','Exfiltration'][i % 6],
  confidence_score: 0.75 + Math.random() * 0.24,
  severity: ['Critical','High','High','Medium','Medium','Low','Low','Critical','High','Medium','Low','High'][i],
  evidence: { packets_per_sec: Math.floor(Math.random() * 15000), src_ip_entropy: +(Math.random()).toFixed(2) },
  src_ip: `10.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*254)+1}`,
  dst_ip: '203.0.113.5',
  src_port: Math.floor(Math.random() * 60000) + 1024,
  dst_port: [80, 443, 53, 4444, 22, 6667][i % 6],
  protocol: ['TCP','UDP','TCP','TCP','TCP','UDP'][i % 6],
  acknowledged: i > 8,
  acknowledged_at: i > 8 ? new Date().toISOString() : null,
  created_at: new Date(Date.now() - i * 300000).toISOString(),
}));
