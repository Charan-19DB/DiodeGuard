const THREAT_ICONS = {
  DDoS:             '🌊',
  BotnetC2:         '🤖',
  DGA:              '🔀',
  EncryptedMalware: '🔐',
  Recon:            '🔍',
  Exfiltration:     '📤',
};

export default function ThreatCard({ alert }) {
  const {
    threat_class, confidence_score, severity,
    src_ip, dst_ip, dst_port, protocol, evidence, timestamp,
  } = alert;

  const icon  = THREAT_ICONS[threat_class] || '⚠️';
  const pct   = Math.round(confidence_score * 100);
  const time  = new Date(timestamp).toLocaleTimeString();

  return (
    <article className="threat-card">
      <div className="threat-header">
        <span className={`threat-class-badge threat-class-badge--${threat_class}`}>
          {icon} {threat_class}
        </span>
        <span className={`severity-badge severity-badge--${severity}`}>
          {severity}
        </span>
      </div>

      <div className="confidence-bar">
        <div className="confidence-label">
          <span>Confidence</span>
          <span style={{ color: pct >= 90 ? 'var(--severity-critical)' : 'var(--brand-primary)' }}>
            {pct}%
          </span>
        </div>
        <div className="confidence-track">
          <div className="confidence-fill" style={{ width: `${pct}%` }} />
        </div>
      </div>

      <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
        <span>🖥 {src_ip}</span>
        <span>→ {dst_ip}:{dst_port}</span>
        <span>📡 {protocol}</span>
        <span>🕒 {time}</span>
      </div>

      {evidence && Object.keys(evidence).length > 0 && (
        <div className="alert-evidence">
          {Object.entries(evidence).slice(0, 4).map(([k, v]) => (
            <span key={k} className="evidence-pill">
              {k}: {typeof v === 'number' ? v.toLocaleString() : v}
            </span>
          ))}
        </div>
      )}
    </article>
  );
}
