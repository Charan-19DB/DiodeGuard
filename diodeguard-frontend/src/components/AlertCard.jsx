const SEV_ICONS = {
  Critical: '🔴', High: '🟠', Medium: '🟡', Low: '🟢',
};

const THREAT_ICONS = {
  DDoS:'🌊', BotnetC2:'🤖', DGA:'🔀',
  EncryptedMalware:'🔐', Recon:'🔍', Exfiltration:'📤',
};

export default function AlertCard({ alert, onAcknowledge }) {
  const {
    id, threat_class, confidence_score, severity,
    src_ip, dst_ip, dst_port, protocol,
    evidence, timestamp, acknowledged,
  } = alert;

  const sevIcon    = SEV_ICONS[severity] || '⚠️';
  const threatIcon = THREAT_ICONS[threat_class] || '⚠️';
  const pct        = Math.round(confidence_score * 100);
  const time       = new Date(timestamp).toLocaleString();

  return (
    <article
      className={`alert-card alert-card--${severity} ${acknowledged ? 'acknowledged' : ''}`}
      style={{ opacity: acknowledged ? 0.55 : 1 }}
      id={`alert-${id}`}
    >
      <div className="alert-icon">{sevIcon}</div>

      <div className="alert-body">
        <div className="alert-title">
          {threatIcon} {threat_class}
          {acknowledged && (
            <span style={{ marginLeft: '0.5rem', fontSize: '0.7rem',
              color: 'var(--severity-low)', fontWeight: 400 }}>✓ Acknowledged</span>
          )}
        </div>
        <div className="alert-meta">
          <span>{pct}% confidence</span>
          <span>·</span>
          <span>{src_ip} → {dst_ip}:{dst_port}</span>
          <span>·</span>
          <span>{protocol}</span>
          <span>·</span>
          <span>{time}</span>
        </div>
        {evidence && Object.keys(evidence).length > 0 && (
          <div className="alert-evidence">
            {Object.entries(evidence).slice(0, 5).map(([k, v]) => (
              <span key={k} className="evidence-pill">
                {k}: {typeof v === 'number' ? v.toLocaleString() : v}
              </span>
            ))}
          </div>
        )}
      </div>

      <div className="alert-actions">
        <span className={`severity-badge severity-badge--${severity}`}>{severity}</span>
        {!acknowledged && onAcknowledge && (
          <button
            className="btn btn-ghost btn-sm"
            onClick={() => onAcknowledge(id)}
            id={`ack-btn-${id}`}
            title="Acknowledge alert"
          >
            ✓ Ack
          </button>
        )}
      </div>
    </article>
  );
}
