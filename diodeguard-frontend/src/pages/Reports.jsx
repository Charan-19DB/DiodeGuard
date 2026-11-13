import { useEffect, useState } from 'react';
import { dashboard as dashboardApi, alerts as alertsApi, MOCK_SUMMARY, MOCK_ALERTS } from '../api/api';
import { TrafficAreaChart, ThreatDistributionChart } from '../components/TrafficChart';

const USE_MOCK = import.meta.env.VITE_USE_MOCK === 'true';

export default function Reports() {
  const [summary, setSummary]   = useState(null);
  const [timeline, setTimeline] = useState([]);
  const [alertsList, setAlertsList] = useState([]);
  const [loading, setLoading]   = useState(true);
  const [hours, setHours]       = useState(24);

  useEffect(() => {
    const fetch = async () => {
      setLoading(true);
      try {
        if (USE_MOCK) {
          setSummary(MOCK_SUMMARY);
          setAlertsList(MOCK_ALERTS);
          setTimeline(Array.from({ length: hours }, (_, i) => ({
            timestamp: new Date(Date.now() - (hours - 1 - i) * 3600000).toISOString(),
            count: Math.floor(Math.random() * 40),
          })));
        } else {
          const [s, t, a] = await Promise.all([
            dashboardApi.summary(),
            dashboardApi.timeline(hours),
            alertsApi.list({ limit: 300 }),
          ]);
          setSummary(s);
          setTimeline(t);
          setAlertsList(a);
        }
      } catch {
        setSummary(MOCK_SUMMARY);
        setAlertsList(MOCK_ALERTS);
      } finally {
        setLoading(false);
      }
    };
    fetch();
  }, [hours]);

  const activeAlerts = alertsList.length > 0 ? alertsList : MOCK_ALERTS;
  const threatDist = activeAlerts.reduce((acc, a) => {
    acc[a.threat_class] = (acc[a.threat_class] || 0) + 1;
    return acc;
  }, {});

  const threatDistArr = Object.entries(threatDist).map(([threat_class, count]) => ({ threat_class, count }));

  const handleExport = () => {
    const report = { generated_at: new Date().toISOString(), summary, timeline };
    const blob   = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url    = URL.createObjectURL(blob);
    const a      = document.createElement('a');
    a.href = url; a.download = `diodeguard-report-${Date.now()}.json`;
    a.click(); URL.revokeObjectURL(url);
  };

  const s = summary || MOCK_SUMMARY;

  return (
    <div>
      <div className="page-header">
        <div className="page-title-group">
          <h1 className="page-title">Reports</h1>
          <p className="page-subtitle">Aggregated threat intelligence and trend analysis</p>
        </div>
        <div style={{ display: 'flex', gap: '0.75rem' }}>
          <select id="report-hours" className="filter-select" value={hours} onChange={(e) => setHours(+e.target.value)}>
            {[6,12,24,48,72].map((h) => <option key={h} value={h}>Last {h}h</option>)}
          </select>
          <button id="btn-export-report" className="btn btn-primary btn-sm" onClick={handleExport}>
            ⬇ Export JSON
          </button>
        </div>
      </div>

      {loading ? (
        <div className="loading-center"><div className="spinner" /></div>
      ) : (
        <>
          {/* Summary table */}
          <div className="card" style={{ marginBottom: '1.5rem' }}>
            <h3 style={{ marginBottom: '1rem' }}>📋 Summary Statistics</h3>
            <div className="table-wrapper">
              <table>
                <thead><tr><th>Metric</th><th>Value</th></tr></thead>
                <tbody>
                  {[
                    ['Total Alerts', s.total_alerts],
                    ['Critical', s.critical_alerts],
                    ['High', s.high_alerts],
                    ['Medium', s.medium_alerts],
                    ['Low', s.low_alerts],
                    ['Unacknowledged', s.unacknowledged],
                    ['Total Flows', s.total_flows?.toLocaleString()],
                    ['Alerts (24h)', s.alerts_last_24h],
                    ['Detection Rate', `${s.detection_rate}%`],
                    ['Top Threat Class', s.top_threat_class],
                  ].map(([k, v]) => (
                    <tr key={k}>
                      <td className="td-primary">{k}</td>
                      <td className="td-mono">{v}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <div className="grid-2">
            <div className="card">
              <h3 style={{ marginBottom: '1rem' }}>⚡ Alert Timeline</h3>
              <TrafficAreaChart data={timeline} />
            </div>
            <div className="card">
              <h3 style={{ marginBottom: '1rem' }}>🎯 Threat Distribution</h3>
              <ThreatDistributionChart data={threatDistArr} />
            </div>
          </div>
        </>
      )}
    </div>
  );
}
