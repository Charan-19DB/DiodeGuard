import { useEffect, useState } from 'react';
import { alerts as alertsApi, MOCK_ALERTS } from '../api/api';
import { connectSocWebSocket } from '../api/websocket';
import AlertCard from '../components/AlertCard';

const USE_MOCK = import.meta.env.VITE_USE_MOCK === 'true';
const SEVERITIES  = ['All', 'Critical', 'High', 'Medium', 'Low'];
const THREATS     = ['All', 'DDoS', 'BotnetC2', 'DGA', 'EncryptedMalware', 'Recon', 'Exfiltration'];
const ACK_OPTIONS = [{ label: 'All', value: '' }, { label: 'Unacknowledged', value: 'false' }, { label: 'Acknowledged', value: 'true' }];

export default function Alerts() {
  const [data, setData]         = useState([]);
  const [loading, setLoading]   = useState(true);
  const [severity, setSeverity] = useState('All');
  const [threat, setThreat]     = useState('All');
  const [ack, setAck]           = useState('false');

  const fetchAlerts = async () => {
    try {
      if (USE_MOCK) {
        setData(MOCK_ALERTS);
      } else {
        const params = {};
        if (severity !== 'All') params.severity = severity;
        if (threat !== 'All')   params.threat_class = threat;
        if (ack !== '')         params.acknowledged = ack;
        params.limit = 100;
        const res = await alertsApi.list(params);
        setData(res);
      }
    } catch { setData(MOCK_ALERTS); }
    finally { setLoading(false); }
  };

  useEffect(() => { fetchAlerts(); }, [severity, threat, ack]);

  // Live polling fallback & WebSocket stream
  useEffect(() => {
    const id = setInterval(fetchAlerts, 8000);

    const disconnectWs = connectSocWebSocket((event) => {
      if (event.type === 'NEW_ALERT' && event.data) {
        setData((prev) => {
          // If already exists, do not duplicate
          if (prev.some((a) => a.id === event.data.id || a.flow_id === event.data.flow_id)) return prev;
          return [event.data, ...prev];
        });
      } else if (event.type === 'ALERT_ACKNOWLEDGED' && event.data) {
        setData((prev) => prev.map((a) => a.id === event.data.alert_id ? { ...a, acknowledged: true } : a));
      }
    });

    return () => {
      clearInterval(id);
      disconnectWs();
    };
  }, [severity, threat, ack]);

  const handleAck = async (id) => {
    try { await alertsApi.acknowledge(id); } catch {}
    setData((prev) => prev.map((a) => a.id === id ? { ...a, acknowledged: true } : a));
  };

  // Apply mock filters locally
  const filtered = USE_MOCK ? data.filter((a) => {
    if (severity !== 'All' && a.severity !== severity) return false;
    if (threat !== 'All'   && a.threat_class !== threat) return false;
    if (ack === 'false' && a.acknowledged)  return false;
    if (ack === 'true'  && !a.acknowledged) return false;
    return true;
  }) : data;

  return (
    <div>
      <div className="page-header">
        <div className="page-title-group">
          <h1 className="page-title">Alerts</h1>
          <p className="page-subtitle">All detected security alerts · Live refresh every 8s</p>
        </div>
        <span style={{ fontSize: '0.875rem', color: 'var(--text-muted)' }}>
          {filtered.length} alert{filtered.length !== 1 ? 's' : ''}
        </span>
      </div>

      <div className="filters-bar">
        <select id="filter-severity" className="filter-select" value={severity} onChange={(e) => setSeverity(e.target.value)}>
          {SEVERITIES.map((s) => <option key={s}>{s}</option>)}
        </select>
        <select id="filter-threat" className="filter-select" value={threat} onChange={(e) => setThreat(e.target.value)}>
          {THREATS.map((t) => <option key={t}>{t}</option>)}
        </select>
        <select id="filter-ack" className="filter-select" value={ack} onChange={(e) => setAck(e.target.value)}>
          {ACK_OPTIONS.map((o) => <option key={o.label} value={o.value}>{o.label}</option>)}
        </select>
      </div>

      {loading ? (
        <div className="loading-center"><div className="spinner" /></div>
      ) : filtered.length === 0 ? (
        <div className="empty-state">
          <div className="empty-state-icon">✅</div>
          <p>No alerts match the current filters.</p>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          {filtered.map((a) => <AlertCard key={a.id} alert={a} onAcknowledge={handleAck} />)}
        </div>
      )}
    </div>
  );
}
