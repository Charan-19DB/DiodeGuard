import { useEffect, useState } from 'react';
import { threats as threatsApi, MOCK_ALERTS } from '../api/api';
import ThreatCard from '../components/ThreatCard';

const USE_MOCK = import.meta.env.VITE_USE_MOCK === 'true';
const THREAT_CLASSES = ['All', 'DDoS', 'BotnetC2', 'DGA', 'EncryptedMalware', 'Recon', 'Exfiltration'];
const SEVERITIES     = ['All', 'Critical', 'High', 'Medium', 'Low'];

export default function Threats() {
  const [data, setData]         = useState([]);
  const [loading, setLoading]   = useState(true);
  const [threat, setThreat]     = useState('All');
  const [severity, setSeverity] = useState('All');

  const fetchThreats = async () => {
    try {
      if (USE_MOCK) {
        setData(MOCK_ALERTS.filter((a) => a.confidence_score >= 0.75));
      } else {
        const params = { limit: 100 };
        if (threat !== 'All')   params.threat_class = threat;
        if (severity !== 'All') params.severity = severity;
        setData(await threatsApi.list(params));
      }
    } catch { setData(MOCK_ALERTS); }
    finally { setLoading(false); }
  };

  useEffect(() => { fetchThreats(); }, [threat, severity]);

  const filtered = USE_MOCK ? data.filter((a) => {
    if (threat !== 'All'   && a.threat_class !== threat) return false;
    if (severity !== 'All' && a.severity !== severity) return false;
    return true;
  }) : data;

  return (
    <div>
      <div className="page-header">
        <div className="page-title-group">
          <h1 className="page-title">Threats</h1>
          <p className="page-subtitle">Classified high-confidence detections (≥75%)</p>
        </div>
        <span style={{ fontSize: '0.875rem', color: 'var(--text-muted)' }}>
          {filtered.length} threat{filtered.length !== 1 ? 's' : ''}
        </span>
      </div>

      <div className="filters-bar">
        <select id="threat-filter-class" className="filter-select" value={threat} onChange={(e) => setThreat(e.target.value)}>
          {THREAT_CLASSES.map((t) => <option key={t}>{t}</option>)}
        </select>
        <select id="threat-filter-sev" className="filter-select" value={severity} onChange={(e) => setSeverity(e.target.value)}>
          {SEVERITIES.map((s) => <option key={s}>{s}</option>)}
        </select>
      </div>

      {loading ? (
        <div className="loading-center"><div className="spinner" /></div>
      ) : filtered.length === 0 ? (
        <div className="empty-state">
          <div className="empty-state-icon">🛡️</div>
          <p>No threats detected under these filters.</p>
        </div>
      ) : (
        <div className="grid-auto">
          {filtered.map((a) => <ThreatCard key={a.id} alert={a} />)}
        </div>
      )}
    </div>
  );
}
