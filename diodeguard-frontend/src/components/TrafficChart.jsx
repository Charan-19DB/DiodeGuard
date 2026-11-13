import {
  AreaChart, Area, BarChart, Bar, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
} from 'recharts';

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div style={{
      background: 'var(--bg-card)', border: '1px solid var(--glass-border)',
      borderRadius: '8px', padding: '0.75rem 1rem', fontSize: '0.8125rem',
    }}>
      <p style={{ color: 'var(--text-muted)', marginBottom: '0.25rem' }}>{label}</p>
      {payload.map((p) => (
        <p key={p.name} style={{ color: p.color }}>
          {p.name}: <strong>{p.value}</strong>
        </p>
      ))}
    </div>
  );
};

export function TrafficAreaChart({ data = [] }) {
  const formatted = data.map((d) => ({
    time: new Date(d.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    alerts: d.count,
  }));

  return (
    <ResponsiveContainer width="100%" height={220}>
      <AreaChart data={formatted} margin={{ top: 5, right: 10, left: -10, bottom: 0 }}>
        <defs>
          <linearGradient id="alertGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%"  stopColor="#00d4ff" stopOpacity={0.25} />
            <stop offset="95%" stopColor="#00d4ff" stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" />
        <XAxis dataKey="time" tick={{ fill: '#4a5568', fontSize: 11 }} axisLine={false} tickLine={false} />
        <YAxis tick={{ fill: '#4a5568', fontSize: 11 }} axisLine={false} tickLine={false} />
        <Tooltip content={<CustomTooltip />} />
        <Area type="monotone" dataKey="alerts" name="Alerts" stroke="#00d4ff"
          strokeWidth={2} fill="url(#alertGrad)" dot={false} activeDot={{ r: 4 }} />
      </AreaChart>
    </ResponsiveContainer>
  );
}

export function ThreatDistributionChart({ data = [] }) {
  const COLORS = {
    DDoS: '#ff2d55', BotnetC2: '#bf5af2', DGA: '#ff9f0a',
    EncryptedMalware: '#ff375f', Recon: '#00d4ff', Exfiltration: '#06ffa5',
  };

  return (
    <ResponsiveContainer width="100%" height={220}>
      <BarChart data={data} margin={{ top: 5, right: 10, left: -10, bottom: 0 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" />
        <XAxis dataKey="threat_class" tick={{ fill: '#4a5568', fontSize: 10 }} axisLine={false} tickLine={false} />
        <YAxis tick={{ fill: '#4a5568', fontSize: 11 }} axisLine={false} tickLine={false} />
        <Tooltip content={<CustomTooltip />} />
        <Bar dataKey="count" name="Count" radius={[4, 4, 0, 0]} label={false}>
          {data.map((entry, index) => (
            <Cell key={`cell-${index}`} fill={COLORS[entry.threat_class] || '#00d4ff'} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
