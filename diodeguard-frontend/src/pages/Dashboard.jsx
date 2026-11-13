import { useEffect, useState } from 'react';
import { dashboard as dashboardApi, alerts as alertsApi, MOCK_SUMMARY, MOCK_ALERTS } from '../api/api';
import { connectSocWebSocket } from '../api/websocket';
import { TrafficAreaChart, ThreatDistributionChart } from '../components/TrafficChart';
import AlertCard from '../components/AlertCard';

const USE_MOCK = import.meta.env.VITE_USE_MOCK === 'true';

const STAT_CARDS = (s) => [
  { label: 'Total Alerts',     value: s.total_alerts,     icon: '🚨', cls: 'stat-card--blue'     },
  { label: 'Critical',         value: s.critical_alerts,  icon: '🔴', cls: 'stat-card--critical'  },
  { label: 'High',             value: s.high_alerts,      icon: '🟠', cls: 'stat-card--high'      },
  { label: 'Unacknowledged',   value: s.unacknowledged,   icon: '⏳', cls: 'stat-card--medium'    },
  { label: 'Total Flows',      value: s.total_flows?.toLocaleString(), icon: '🌐', cls: 'stat-card--blue' },
  { label: 'Alerts (24h)',     value: s.alerts_last_24h,  icon: '📅', cls: 'stat-card--purple'    },
  { label: 'Detection Rate',   value: `${s.detection_rate}%`, icon: '📊', cls: 'stat-card--accent' },
  { label: 'Top Threat',       value: s.top_threat_class || '—', icon: '🎯', cls: 'stat-card--purple' },
];

export default function Dashboard() {
  const [summary, setSummary]   = useState(null);
  const [timeline, setTimeline] = useState([]);
  const [recent, setRecent]     = useState([]);
  const [loading, setLoading]   = useState(true);

  const fetchData = async () => {
    try {
      if (USE_MOCK) {
        setSummary(MOCK_SUMMARY);
        setTimeline(Array.from({ length: 24 }, (_, i) => ({
          timestamp: new Date(Date.now() - (23 - i) * 3600000).toISOString(),
          count: Math.floor(Math.random() * 30),
        })));
        setRecent(MOCK_ALERTS.slice(0, 6));
      } else {
        const [s, t, a] = await Promise.all([
          dashboardApi.summary(),
          dashboardApi.timeline(24),
          alertsApi.list({ limit: 6, acknowledged: false }),
        ]);
        setSummary(s); setTimeline(t); setRecent(a);
      }
    } catch {
      setSummary(MOCK_SUMMARY);
      setRecent(MOCK_ALERTS.slice(0, 6));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 10000); // live poll fallback every 10s

    // Real-time WebSocket event listener
    const disconnectWs = connectSocWebSocket((event) => {
      if (event.type === 'NEW_ALERT' && event.data) {
        const newAlert = event.data;
        setRecent((prev) => [newAlert, ...prev.slice(0, 5)]);
        setSummary((prev) => {
          if (!prev) return prev;
          const sevKey = `${(newAlert.severity || 'low').toLowerCase()}_alerts`;
          return {
            ...prev,
            total_alerts: (prev.total_alerts || 0) + 1,
            unacknowledged: (prev.unacknowledged || 0) + 1,
            alerts_last_24h: (prev.alerts_last_24h || 0) + 1,
            [sevKey]: (prev[sevKey] || 0) + 1,
          };
        });
      } else if (event.type === 'ALERT_ACKNOWLEDGED' && event.data) {
        setRecent((prev) => prev.map((a) => a.id === event.data.alert_id ? { ...a, acknowledged: true } : a));
      }
    });

    return () => {
      clearInterval(interval);
      disconnectWs();
    };
  }, []);

  const handleAck = async (id) => {
    try { await alertsApi.acknowledge(id); } catch {}
    setRecent((prev) => prev.map((a) => a.id === id ? { ...a, acknowledged: true } : a));
  };

  if (loading) return <div className="loading-center"><div className="spinner" /></div>;

  const cards = STAT_CARDS(summary || MOCK_SUMMARY);

  // Threat distribution from recent
  const threatDist = Object.entries(
    recent.reduce((acc, a) => { acc[a.threat_class] = (acc[a.threat_class] || 0) + 1; return acc; }, {})
  ).map(([threat_class, count]) => ({ threat_class, count }));

  return (
    <div>
      <div className="page-header">
        <div className="page-title-group">
          <h1 className="page-title">Security Dashboard</h1>
          <p className="page-subtitle">Real-time threat overview · Auto-refresh every 10s</p>
        </div>
        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
          <div className="status-dot" />
          <span style={{ fontSize: '0.8125rem', color: 'var(--text-muted)' }}>Live</span>
        </div>
      </div>

      {/* Stat Cards */}
      <div className="stat-cards">
        {cards.map(({ label, value, icon, cls }) => (
          <div key={label} className={`stat-card ${cls}`}>
            <div className="stat-label">{label}</div>
            <div className="stat-value">{value}</div>
            <div className="stat-icon">{icon}</div>
          </div>
        ))}
      </div>

      {/* Charts */}
      <div className="grid-2" style={{ marginBottom: '1.5rem' }}>
        <div className="card">
          <h3 style={{ marginBottom: '1rem' }}>⚡ Alert Timeline (24h)</h3>
          <TrafficAreaChart data={timeline} />
        </div>
        <div className="card">
          <h3 style={{ marginBottom: '1rem' }}>🎯 Threat Distribution</h3>
          <ThreatDistributionChart data={threatDist} />
        </div>
      </div>

      {/* Recent Alerts */}
      <div className="card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
          <h3>🚨 Recent Alerts</h3>
          <a href="/alerts" style={{ fontSize: '0.8125rem', color: 'var(--brand-primary)' }}>View all →</a>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          {recent.length === 0 ? (
            <div className="empty-state">
              <div className="empty-state-icon">✅</div>
              <p>No active alerts. System is clean.</p>
            </div>
          ) : (
            recent.map((a) => <AlertCard key={a.id} alert={a} onAcknowledge={handleAck} />)
          )}
        </div>
      </div>
    </div>
  );
}
