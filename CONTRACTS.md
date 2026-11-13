# DiodeGuard System Contracts & Interface Specifications 🛡️

This document defines the interface contracts, data models, messaging topics, and API standards shared across all three tracks of the **DiodeGuard** system:
- **Track A:** `diodeguard-ml` (Feature extraction, Model inference, Kafka consumer)
- **Track B:** `diodeguard-backend` (FastAPI REST service, PostgreSQL storage, RBAC)
- **Track C:** `diodeguard-frontend` (React security operations dashboard)

---

## 1. Network Data Diode Boundary

```
[ Dirty / Monitored Network ]
             │ (Raw Optical Tap / SPAN)
             ▼
     ┌──────────────┐
     │  Hardware    │
     │  Data Diode  │ (Physical Rx-only fiber, Tx photodiode physically removed)
     └──────┬───────┘
            │
            ▼ (Unidirectional Ingest)
┌────────────────────────────────────────────────────────────────────────┐
│ Passive Monitoring Enclave                                             │
│                                                                        │
│  [Network Sniffer / Replayer] ──> Kafka Topic: "unidirectional-traffic"│
│                                                  │                     │
│                                                  ▼                     │
│                                          [ML Pipeline]                 │
│                                                  │                     │
│                                                  ▼                     │
│                                      PostgreSQL / REST API             │
│                                                  │                     │
│                                                  ▼                     │
│                                      [React Dashboard]                 │
└────────────────────────────────────────────────────────────────────────┘
```

> **Security Invariant:** No network packets or acknowledgements can flow backwards across the data diode. All detection, state tracking, and alert synthesis operates strictly on forward traffic flows.

---

## 2. Kafka Messaging Contracts

### Topic: `unidirectional-traffic`
- **Producer:** `stream_replay.py` or Zeek/NFStream flow exporter.
- **Consumer:** `pipeline/kafka_consumer.py`.
- **Key:** `flow_id` (string).
- **Format:** JSON.

#### Schema:
```json
{
  "flow_id": "flw-6f8e71b2-297d-4b95-a864-10ecbc039e14",
  "timestamp": "2026-10-15T10:30:00.123456+00:00",
  "src_ip": "192.168.10.45",
  "dst_ip": "10.0.0.8",
  "src_port": 49152,
  "dst_port": 443,
  "protocol": "TCP",
  "features": {
    "packets_per_sec": 12450.5,
    "bytes_per_sec": 8420000.0,
    "src_ip_entropy": 0.12,
    "dst_port_entropy": 0.05,
    "flow_duration": 4.25,
    "packet_size_mean": 1380.0,
    "packet_size_std": 240.2,
    "syn_ratio": 0.98,
    "udp_ratio": 0.0,
    "icmp_ratio": 0.0,
    "inter_arrival_mean": 0.0008,
    "inter_arrival_std": 0.0001,
    "unique_dst_ports": 1,
    "upload_download_ratio": 0.92
  }
}
```

---

## 3. Alert Contract & Threat Classes

When model confidence meets or exceeds `ALERT_CONFIDENCE_THRESHOLD` (default: **0.75**), an alert record is emitted.

### Threat Classification Taxonomy

| Threat Class | Detection Paradigm | Primary Model Architecture | Severity Thresholds |
| :--- | :--- | :--- | :--- |
| **DDoS** | Supervised | LightGBM / XGBoost | Med: 0.75-0.85, High: 0.85-0.92, Crit: >0.92 |
| **BotnetC2** | Supervised / Windowed | Random Forest + Redis State | Med: 0.75-0.85, High: 0.85-0.92, Crit: >0.92 |
| **DGA** | Lexical Supervised | 1D-CNN / Random Forest | Med: 0.75-0.85, High: 0.85-0.92, Crit: >0.92 |
| **EncryptedMalware** | Metadata Supervised | XGBoost (TLS metadata / JA3) | Med: 0.75-0.85, High: 0.85-0.92, Crit: >0.92 |
| **Recon** | Unsupervised Anomaly | Isolation Forest / OCSVM | Med: 0.75-0.85, High: 0.85-0.92, Crit: >0.92 |
| **Exfiltration** | Unsupervised Anomaly | Extended Isolation Forest | Med: 0.75-0.85, High: 0.85-0.92, Crit: >0.92 |

### Alert Payload Schema
```json
{
  "id": "e3b0c442-98fc-1c14-9af0-2b9a7f34c219",
  "flow_id": "flw-6f8e71b2-297d-4b95-a864-10ecbc039e14",
  "timestamp": "2026-10-15T10:30:00.123456+00:00",
  "threat_class": "DDoS",
  "confidence_score": 0.945,
  "severity": "Critical",
  "src_ip": "192.168.10.45",
  "dst_ip": "10.0.0.8",
  "src_port": 49152,
  "dst_port": 443,
  "protocol": "TCP",
  "evidence": {
    "model_name": "ddos_lightgbm_v1",
    "top_contributing_features": {
      "packets_per_sec": 12450.5,
      "syn_ratio": 0.98
    },
    "heuristic_flags": ["HIGH_SYN_BURST", "LOW_DST_PORT_ENTROPY"]
  },
  "acknowledged": false,
  "acknowledged_by": null,
  "acknowledged_at": null,
  "created_at": "2026-10-15T10:30:01.000000+00:00"
}
```

---

## 4. REST API Endpoint Specifications

Base URL: `http://localhost:8000/api/v1`

### Authentication (`/auth`)
- `POST /auth/register` — Create new user (admin or analyst).
- `POST /auth/login` — Authenticate and receive JWT bearer token.
- `GET /auth/me` — Retrieve current authenticated user profile.

### Dashboard (`/dashboard`)
- `GET /dashboard/summary` — Returns active alert counts, critical counts, flows/sec, diode health status.
- `GET /dashboard/timeline?minutes=60` — Aggregated time-bucketed event counts for charting.

### Alerts (`/alerts`)
- `GET /alerts?page=1&page_size=50&severity=Critical&threat_class=DDoS` — Filtered alerts list.
- `GET /alerts/{id}` — Single alert detail with evidence payload.
- `POST /alerts/{id}/ack` — Acknowledge an alert (requires Analyst or Admin).

### Threats (`/threats`)
- `GET /threats` — High-confidence threat feed (confidence >= 0.75).
- `GET /threats/{id}` — Detailed threat breakdown.

### Traffic (`/traffic`)
- `POST /traffic/ingest` — Ingest raw flow record.
- `GET /traffic?page=1&limit=50` — Query ingested network flows.
- `GET /traffic/{flow_id}` — Query specific flow record by ID.

### Detection Models (`/detection`)
- `GET /detection/models` — List all registered ML models with hash integrity, version, and performance metrics.
- `POST /detection/predict` — On-demand inference test endpoint.

### Users Admin (`/users`)
- `GET /users` — Admin only: list all platform users.
- `DELETE /users/{id}` — Admin only: deactivate/remove user.

---

## 5. Model Integrity Guarantee

All models saved in `diodeguard-ml/models/saved/` must provide a companion `<model_name>_hash.txt` file containing the SHA-256 digest of the serialized joblib artifact. 

During initialization in `detector.py`:
1. The `.joblib` binary is read into memory.
2. The SHA-256 digest is computed on the byte content.
3. If the digest does not match `<model_name>_hash.txt`, the detector halts startup with a security violation error.
