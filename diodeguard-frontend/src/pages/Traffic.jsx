import { useEffect, useState } from 'react';
import { traffic as trafficApi } from '../api/api';

const USE_MOCK = import.meta.env.VITE_USE_MOCK === 'true';

const MOCK_FLOWS = Array.from({ length: 20 }, (_, i) => ({
  id: `flow-id-${i}`,
  flow_id: `flow-${1000 + i}`,
  timestamp: new Date(Date.now() - i * 180000).toISOString(),
  src_ip: `10.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${i + 1}`,
  dst_ip: `203.0.113.${(i % 10) + 1}`,
  src_port: 10000 + i * 1000,
  dst_port: [80, 443, 53, 22, 25, 8080][i % 6],
  protocol: ['TCP', 'UDP', 'TCP', 'TCP', 'UDP', 'TCP'][i % 6],
  features: { bytes: Math.floor(Math.random() * 100000), pkts: Math.floor(Math.random() * 500) },
}));

export default function Traffic() {
  const [data, setData]         = useState([]);
  const [loading, setLoading]   = useState(true);
  const [protocol, setProtocol] = useState('All');
  const [search, setSearch]     = useState('');

  useEffect(() => {
    const fetch = async () => {
      try {
        setData(USE_MOCK ? MOCK_FLOWS : await trafficApi.list({ limit: 100 }));
      } catch { setData(MOCK_FLOWS); }
      finally { setLoading(false); }
    };
    fetch();
  }, []);

  const filtered = data.filter((f) => {
    if (protocol !== 'All' && f.protocol !== protocol) return false;
    if (search && !f.src_ip?.includes(search) && !f.dst_ip?.includes(search) && !f.flow_id?.includes(search)) return false;
    return true;
  });

  return (
    <div>
      <div className="page-header">
        <div className="page-title-group">
          <h1 className="page-title">Traffic</h1>
          <p className="page-subtitle">Passively observed flow records</p>
        </div>
        <span style={{ fontSize: '0.875rem', color: 'var(--text-muted)' }}>{filtered.length} flows</span>
      </div>

      <div className="filters-bar">
        <input
          id="traffic-search"
          className="input"
          style={{ maxWidth: 260 }}
          placeholder="Search IP or flow ID..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <select id="traffic-protocol" className="filter-select" value={protocol} onChange={(e) => setProtocol(e.target.value)}>
          {['All','TCP','UDP','ICMP'].map((p) => <option key={p}>{p}</option>)}
        </select>
      </div>

      {loading ? (
        <div className="loading-center"><div className="spinner" /></div>
      ) : (
        <div className="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>Flow ID</th><th>Timestamp</th><th>Src IP</th>
                <th>Dst IP</th><th>Src Port</th><th>Dst Port</th>
                <th>Protocol</th><th>Bytes</th><th>Pkts</th>
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 ? (
                <tr><td colSpan={9} style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>
                  No flows found</td></tr>
              ) : filtered.map((f) => (
                <tr key={f.id}>
                  <td className="td-mono td-primary">{f.flow_id}</td>
                  <td className="td-mono">{new Date(f.timestamp).toLocaleString()}</td>
                  <td className="td-mono">{f.src_ip}</td>
                  <td className="td-mono">{f.dst_ip}</td>
                  <td>{f.src_port}</td>
                  <td>{f.dst_port}</td>
                  <td>
                    <span style={{
                      background: f.protocol === 'TCP' ? 'rgba(0,212,255,0.1)' : 'rgba(6,255,165,0.1)',
                      color: f.protocol === 'TCP' ? 'var(--brand-primary)' : 'var(--brand-accent)',
                      padding: '0.15rem 0.5rem', borderRadius: 4, fontSize: '0.75rem', fontWeight: 600,
                    }}>{f.protocol}</span>
                  </td>
                  <td>{f.features?.bytes?.toLocaleString() || '—'}</td>
                  <td>{f.features?.pkts || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
